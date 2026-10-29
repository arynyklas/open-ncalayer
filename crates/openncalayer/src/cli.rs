//! The command line: `run` (the default), `tls init|import|status`, `cms-verify`,
//! `nm install|uninstall|status` and `integration install|uninstall|status`.
//!
//! Messages for the user are in Russian, like the rest of the user-facing text.

use std::borrow::Cow;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use oncl_basics::Locale;
use oncl_desktop::original::EntryState;
use oncl_ipc::IpcListener;
use oncl_pki::http::UreqTransport;
use oncl_pki::pkix::CaSet;
use oncl_tls::{
    AUTO_RENEW_BEFORE, RENEW_BEFORE, TargetOs, TlsFiles, TlsInfo, TlsSource, TlsWarning,
    instructions, load_info, server_config, sha1_grouped,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::cms_verify::{Online, Options, cms_verify_report_with, parse_certificates};
use crate::lifecycle::{self, Choice, Event, Executables, Installation, Integration, Step};
use crate::nm::{self, Item, NmLayout, Report, State};
use crate::paths::Paths;
use crate::server::listen_port;
use crate::settings::load_settings;

/// Exit code: TLS is not set up yet.
pub const EXIT_TLS_NOT_CONFIGURED: u8 = 2;
/// Exit code: the port is taken.
pub const EXIT_PORT_BUSY: u8 = 3;
/// Exit code: another OpenNCALayer of this user, session and data directory is running.
pub const EXIT_ALREADY_RUNNING: u8 = 4;

#[derive(Debug, Parser)]
#[command(
    name = "openncalayer",
    version,
    about = "OpenNCALayer — свободная замена NCALayer: подпись ЭЦП НУЦ РК для сайтов через wss://127.0.0.1"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Запустить сервер (по умолчанию)")]
    Run {
        #[arg(
            long,
            help = "Если wss не запускается (TLS не настроен или повреждён, порт занят или недоступен), работать только для расширения браузера"
        )]
        allow_no_wss: bool,
        #[arg(
            long,
            help = "Без значка в области уведомлений: для сеансов без графической оболочки и автоматических тестов"
        )]
        no_tray: bool,
    },
    #[command(about = "Сертификат HTTPS/WSS-сервера")]
    Tls {
        #[command(subcommand)]
        command: TlsCommand,
    },
    #[command(about = "Проверить CMS-подпись (PEM или DER): подписи, цепочки, сроки, отзыв")]
    CmsVerify {
        #[arg(help = "Файл подписи (.p7s, .cms, PEM или DER)")]
        file: PathBuf,
        #[arg(long, help = "Подписанные данные для подписи без вложенных данных")]
        content: Option<PathBuf>,
        #[arg(
            long,
            value_name = "FILE",
            help = "Сертификаты CA (PEM, можно несколько в файле, или DER) вместо встроенных сертификатов НУЦ; можно указать несколько раз"
        )]
        chain: Vec<PathBuf>,
        #[arg(long, help = "Не проверять отзыв: без запросов OCSP и CRL")]
        offline: bool,
    },
    #[command(about = "Хост native messaging для расширения браузера")]
    Nm {
        #[command(subcommand)]
        command: NmCommand,
    },
    #[command(
        about = "Встраивание в систему этого пользователя: relay браузеров, наш автозапуск, автозапуск оригинального NCALayer"
    )]
    Integration {
        #[command(subcommand)]
        command: IntegrationCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum TlsCommand {
    #[command(about = "Выпустить локальный центр сертификации и сертификат сервера")]
    Init {
        #[arg(long, help = "Перевыпустить, даже если TLS уже настроен")]
        force: bool,
    },
    #[command(about = "Использовать свой сертификат сервера")]
    Import {
        #[arg(long, help = "Цепочка сертификатов в PEM: сертификат сервера первым")]
        chain: PathBuf,
        #[arg(long, help = "Закрытый ключ сертификата сервера в PEM")]
        key: PathBuf,
    },
    #[command(about = "Показать состояние сертификата сервера")]
    Status,
}

#[derive(Debug, Subcommand)]
pub enum NmCommand {
    #[command(about = "Установить relay и зарегистрировать его в браузерах")]
    Install {
        #[arg(
            long,
            help = "Исполняемый файл relay (по умолчанию nmhost рядом с openncalayer)"
        )]
        relay: Option<PathBuf>,
        #[arg(
            long,
            help = "Установить в каталог-песочницу, без реестра и профилей браузеров"
        )]
        sandbox: Option<PathBuf>,
    },
    #[command(about = "Удалить relay и его регистрацию в браузерах")]
    Uninstall {
        #[arg(long, help = "Каталог-песочница из `nm install --sandbox`")]
        sandbox: Option<PathBuf>,
    },
    #[command(about = "Показать, установлен ли relay и где он зарегистрирован")]
    Status {
        #[arg(long, help = "Каталог-песочница из `nm install --sandbox`")]
        sandbox: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum IntegrationCommand {
    #[command(
        about = "Встроить, как при установке: зарегистрировать relay, включить наш автозапуск, отключить автозапуск оригинала"
    )]
    Install,
    #[command(
        about = "Убрать встраивание перед удалением программы: relay, наш автозапуск; вернуть автозапуск оригинала. Данные остаются"
    )]
    Uninstall,
    #[command(about = "Показать, как программа встроена")]
    Status,
}

/// Everything `run` sets up before the servers start: data paths, logging, the bound IPC
/// endpoint of the browser extension bridge and the wss server's TLS configuration and bound
/// listening socket (non-blocking, for tokio), or why wss is off.
pub struct Daemon {
    pub paths: Paths,
    pub ipc: IpcListener,
    pub wss: Result<(Arc<rustls::ServerConfig>, TcpListener), WssFailure>,
}

/// Why the wss server is off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WssOff {
    /// TLS is not set up.
    TlsNotConfigured,
    /// The TLS files cannot be read or used.
    TlsUnusable,
    /// Another program holds the port.
    PortBusy(u16),
    /// The port cannot be opened for another reason.
    PortUnavailable(u16),
}

impl WssOff {
    /// A short line for the tray in `l`; the details are in the log.
    pub fn text(self, l: Locale) -> String {
        match (self, l) {
            (WssOff::TlsNotConfigured, Locale::Ru) => {
                "TLS не настроен: нет сертификата для браузера".to_owned()
            }
            (WssOff::TlsNotConfigured, Locale::Kk) => {
                "TLS бапталмаған: браузерге арналған сертификат жоқ".to_owned()
            }
            (WssOff::TlsNotConfigured, Locale::En) => {
                "TLS is not set up: there is no certificate for browsers".to_owned()
            }
            (WssOff::TlsUnusable, Locale::Ru) => {
                "Сертификат для браузера не загружается".to_owned()
            }
            (WssOff::TlsUnusable, Locale::Kk) => {
                "Браузерге арналған сертификат жүктелмейді".to_owned()
            }
            (WssOff::TlsUnusable, Locale::En) => {
                "The certificate for browsers cannot be loaded".to_owned()
            }
            (WssOff::PortBusy(p), Locale::Ru) => {
                format!("Порт {p} занят (возможно, оригинальным NCALayer)")
            }
            (WssOff::PortBusy(p), Locale::Kk) => {
                format!("{p} порты бос емес (мүмкін, түпнұсқа NCALayer)")
            }
            (WssOff::PortBusy(p), Locale::En) => {
                format!("Port {p} is in use (perhaps by the original NCALayer)")
            }
            (WssOff::PortUnavailable(p), Locale::Ru) => format!("Не удалось открыть порт {p}"),
            (WssOff::PortUnavailable(p), Locale::Kk) => format!("{p} портын ашу мүмкін болмады"),
            (WssOff::PortUnavailable(p), Locale::En) => format!("Cannot open port {p}"),
        }
    }
}

/// What `run` does in [`prepare_run`] once this process is the only daemon of its data
/// directory, and when the start ends cleanly.
pub trait AtStart {
    /// The IPC endpoint is bound (no other daemon runs), before TLS and the port are
    /// looked at. An `Err` ends the start with its exit code.
    ///
    /// # Errors
    ///
    /// The exit code the start ends with.
    fn started(&mut self, paths: &Paths) -> Result<(), ExitCode>;

    /// The start ends with P1's exit code for TLS not set up or a busy port, an outcome
    /// of the setup and not a failure of the program.
    fn ends_cleanly(&mut self);
}

/// Prepares `run`: data paths and logging, the panic hook, the IPC endpoint, `at_start`,
/// then TLS and the port. On failure the message is already printed and the exit code
/// returned: [`EXIT_ALREADY_RUNNING`], [`EXIT_TLS_NOT_CONFIGURED`], [`EXIT_PORT_BUSY`] or 1.
/// With `allow_no_wss` any failure to start the wss server (TLS not set up or unusable, the
/// port busy or not bindable) only turns it off, with a warning in the log. With
/// `tray_session` (a tray is to show the problem) so do TLS not set up and a busy port: the
/// TLS wizard or stopping the original NCALayer lets wss start later; `run` still ends with
/// the [`WssFailure`] if the tray cannot be shown.
pub async fn prepare_run(
    allow_no_wss: bool,
    tray_session: bool,
    at_start: &mut dyn AtStart,
) -> Result<Daemon, ExitCode> {
    let paths = data_paths()?;
    if let Err(e) = crate::logging::init(&paths.logs()) {
        warn!(dir = %paths.logs().display(), error = %e, "file logging is disabled");
    }
    // As early as the log takes entries: panics of the start (the updater's hook included)
    // and of the windowing libraries go to the log, not as raw text to stderr only.
    std::panic::set_hook(Box::new(|info| tracing::error!(%info, "panic")));
    prepare_in(paths, listen_port(), allow_no_wss, tray_session, at_start).await
}

/// [`prepare_run`] in `paths`, wss on `port`.
async fn prepare_in(
    paths: Paths,
    port: u16,
    allow_no_wss: bool,
    tray_session: bool,
    at_start: &mut dyn AtStart,
) -> Result<Daemon, ExitCode> {
    let ipc = bind_ipc(&paths.data).await?;
    at_start.started(&paths)?;
    let wss = match open_wss(&paths.tls(), port) {
        Ok(wss) => Ok(wss),
        Err(failure) if allow_no_wss => {
            warn!(
                code = failure.code,
                reason = %failure.message,
                "wss is off; serving the browser extension only"
            );
            Err(failure)
        }
        Err(failure) if tray_session && failure.fixed_in_the_tray() => {
            // `run` exits with the code after all if no tray can be shown.
            warn!(
                code = failure.code,
                reason = %failure.message,
                "wss is off until it can start; the tray is to tell the user"
            );
            Err(failure)
        }
        Err(failure) => {
            if failure.fixed_in_the_tray() {
                at_start.ends_cleanly();
            }
            return Err(failure.report());
        }
    };
    info!(data = %paths.data.display(), "daemon prepared");
    Ok(Daemon { paths, ipc, wss })
}

/// Binds the IPC endpoint of `data`.
async fn bind_ipc(data: &Path) -> Result<IpcListener, ExitCode> {
    let endpoint = oncl_ipc::endpoint(data).map_err(|e| {
        eprintln!("Не удалось определить канал для расширения браузера: {e}");
        ExitCode::FAILURE
    })?;
    match oncl_ipc::bind(&endpoint).await {
        Ok(listener) => {
            info!(%endpoint, "bridge listening");
            Ok(listener)
        }
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            eprintln!("OpenNCALayer уже запущен");
            Err(ExitCode::from(EXIT_ALREADY_RUNNING))
        }
        Err(e) => {
            eprintln!("Не удалось открыть канал {endpoint} для расширения браузера: {e}");
            Err(ExitCode::FAILURE)
        }
    }
}

/// The wss server's TLS configuration from `files` and its listening socket on
/// `127.0.0.1:port` (non-blocking, for tokio).
///
/// # Errors
///
/// TLS is not set up or cannot be used, or the port cannot be bound.
pub fn open_wss(
    files: &TlsFiles,
    port: u16,
) -> Result<(Arc<rustls::ServerConfig>, TcpListener), WssFailure> {
    configured(files)?;
    let tls = server_config(files).map_err(|e| {
        WssFailure::new(
            1,
            WssOff::TlsUnusable,
            format!(
                "Не удалось загрузить сертификат сервера из {}: {e}",
                files.dir.display()
            ),
        )
    })?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map_err(|e| {
        if port_busy(&e) {
            WssFailure::new(
                EXIT_PORT_BUSY,
                WssOff::PortBusy(port),
                format!("Порт {port} занят (возможно, запущен оригинальный NCALayer)"),
            )
        } else {
            WssFailure::new(
                1,
                WssOff::PortUnavailable(port),
                format!("Не удалось открыть порт 127.0.0.1:{port}: {e}"),
            )
        }
    })?;
    listener.set_nonblocking(true).map_err(|e| {
        WssFailure::new(
            1,
            WssOff::PortUnavailable(port),
            format!("Не удалось настроить порт 127.0.0.1:{port}: {e}"),
        )
    })?;
    info!("listening on 127.0.0.1:{port}");
    Ok((Arc::new(tls), listener))
}

/// A failed step of a command: the message for the user, the exit code and, for the wss
/// server, why it is off.
#[derive(Debug)]
pub struct WssFailure {
    pub code: u8,
    pub off: WssOff,
    pub message: String,
}

impl WssFailure {
    fn new(code: u8, off: WssOff, message: String) -> Self {
        WssFailure { code, off, message }
    }

    /// Whether the tray lets the user lift it without a restart: TLS not set up (the TLS
    /// wizard), the port busy (stopping the original NCALayer).
    pub fn fixed_in_the_tray(&self) -> bool {
        matches!(self.off, WssOff::TlsNotConfigured | WssOff::PortBusy(_))
    }

    /// Prints the message; returns the exit code.
    pub fn report(self) -> ExitCode {
        eprintln!("{}", self.message);
        ExitCode::from(self.code)
    }
}

/// Whether binding failed because another socket holds the port. A Java server (such as
/// the original NCALayer) binds with `SO_EXCLUSIVEADDRUSE` on Windows, which makes a second
/// bind fail with `WSAEACCES` rather than `WSAEADDRINUSE`.
fn port_busy(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::AddrInUse
        || (cfg!(windows) && e.kind() == io::ErrorKind::PermissionDenied)
}

fn data_paths() -> Result<Paths, ExitCode> {
    Paths::detect().map_err(|e| {
        eprintln!("Не удалось определить каталог данных: {e}");
        ExitCode::FAILURE
    })
}

/// The stored [`TlsInfo`], or why there is none.
fn configured(files: &TlsFiles) -> Result<TlsInfo, WssFailure> {
    match load_info(files) {
        Ok(Some(info)) => Ok(info),
        Ok(None) => Err(WssFailure::new(
            EXIT_TLS_NOT_CONFIGURED,
            WssOff::TlsNotConfigured,
            "TLS не настроен: выполните `openncalayer tls init`".to_owned(),
        )),
        Err(e) => Err(WssFailure::new(
            1,
            WssOff::TlsUnusable,
            format!("Не удалось прочитать {}: {e}", files.info().display()),
        )),
    }
}

/// With feature `e2e-prompter`: a JSON file of dialog answers that `run` uses instead of
/// windows, e.g. `[{"storage":{"path":"…","password":"…"}},{"key":0},{"cancel_storage":null}]`
/// (also `{"jks":{"path","password"}}`, `{"cancel_key":null}`,
/// `{"csr":{"dir","password"}}`, `{"cancel_csr":null}`, `{"import":{"dir","password"}}`,
/// `{"cancel_import":null}`, `{"file":"…"}`, `{"cancel_file":null}`, `{"password":"…"}`,
/// `{"cancel_password":null}`).
#[cfg(feature = "e2e-prompter")]
pub const E2E_PROMPTER_VAR: &str = "ONCL_E2E_PROMPTER";

/// The scripted prompter of the file in [`E2E_PROMPTER_VAR`], if the variable is set. On
/// failure the message is already printed and exit code 1 returned.
#[cfg(feature = "e2e-prompter")]
pub fn e2e_prompter() -> Result<Option<oncl_basics::testing::ScriptedPrompter>, ExitCode> {
    let Some(path) = std::env::var_os(E2E_PROMPTER_VAR) else {
        return Ok(None);
    };
    let steps = fs::read_to_string(&path)
        .map_err(|e| e.to_string())
        .and_then(|text| parse_steps(&text))
        .map_err(|e| {
            eprintln!("{E2E_PROMPTER_VAR}: {}: {e}", Path::new(&path).display());
            ExitCode::FAILURE
        })?;
    Ok(Some(oncl_basics::testing::ScriptedPrompter::new(steps)))
}

/// The steps of an [`E2E_PROMPTER_VAR`] file.
#[cfg(feature = "e2e-prompter")]
fn parse_steps(text: &str) -> Result<Vec<oncl_basics::testing::Step>, String> {
    use oncl_basics::testing::Step;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum StepSpec {
        Storage { path: PathBuf, password: String },
        Jks { path: PathBuf, password: String },
        CancelStorage,
        Key(usize),
        CancelKey,
        Csr { dir: PathBuf, password: String },
        CancelCsr,
        Import { dir: PathBuf, password: String },
        CancelImport,
        File(PathBuf),
        CancelFile,
        Password(String),
        CancelPassword,
    }

    let specs: Vec<StepSpec> = serde_json::from_str(text).map_err(|e| e.to_string())?;
    Ok(specs
        .into_iter()
        .map(|spec| match spec {
            StepSpec::Storage { path, password } => Step::Storage { path, password },
            StepSpec::Jks { path, password } => Step::Jks { path, password },
            StepSpec::CancelStorage => Step::CancelStorage,
            StepSpec::Key(index) => Step::Key(index),
            StepSpec::CancelKey => Step::CancelKey,
            StepSpec::Csr { dir, password } => Step::Csr { dir, password },
            StepSpec::CancelCsr => Step::CancelCsr,
            StepSpec::Import { dir, password } => Step::Import { dir, password },
            StepSpec::CancelImport => Step::CancelImport,
            StepSpec::File(path) => Step::File(path),
            StepSpec::CancelFile => Step::CancelFile,
            StepSpec::Password(password) => Step::Password(password),
            StepSpec::CancelPassword => Step::CancelPassword,
        })
        .collect())
}

/// `tls init|import|status`.
pub fn tls(command: TlsCommand) -> ExitCode {
    let paths = match data_paths() {
        Ok(paths) => paths,
        Err(code) => return code,
    };
    let files = paths.tls();
    let result = match command {
        TlsCommand::Init { force } => tls_init(&files, force),
        TlsCommand::Import { chain, key } => tls_import(&files, &chain, &key),
        TlsCommand::Status => tls_status(&files),
    };
    result.unwrap_or_else(|code| code)
}

/// `user@host` for the CA name, from the environment.
pub fn label() -> String {
    let var = |names: &[&str]| {
        names
            .iter()
            .find_map(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
    };
    let user = var(&["USERNAME", "USER", "LOGNAME"]);
    let host = var(&["COMPUTERNAME", "HOSTNAME"]).or_else(|| {
        fs::read_to_string("/etc/hostname")
            .ok()
            .map(|h| h.trim().to_owned())
            .filter(|h| !h.is_empty())
    });
    match (user, host) {
        (Some(user), Some(host)) => format!("{user}@{host}"),
        (Some(name), None) | (None, Some(name)) => name,
        (None, None) => "local".to_owned(),
    }
}

fn tls_init(files: &TlsFiles, force: bool) -> Result<ExitCode, ExitCode> {
    let previous = match load_info(files) {
        Ok(previous) => previous,
        // A damaged tls.json is replaced with --force.
        Err(e) if force => {
            eprintln!(
                "Не удалось прочитать {}: {e}; файлы будут перезаписаны.",
                files.info().display()
            );
            None
        }
        Err(e) => {
            eprintln!(
                "Не удалось прочитать {}: {e}. Чтобы выпустить сертификат заново, выполните \
                 `openncalayer tls init --force`.",
                files.info().display()
            );
            return Err(ExitCode::FAILURE);
        }
    };
    if previous.is_some() && !force {
        eprintln!(
            "TLS уже настроен ({}). Чтобы выпустить новый сертификат, выполните \
             `openncalayer tls init --force`.",
            files.dir.display()
        );
        return Err(ExitCode::FAILURE);
    }
    let material = oncl_tls::generate(OffsetDateTime::now_utc(), &label()).map_err(|e| {
        eprintln!("Не удалось выпустить сертификат: {e}");
        ExitCode::FAILURE
    })?;
    save_and_explain(files, &material, previous.as_ref())
}

fn tls_import(files: &TlsFiles, chain: &Path, key: &Path) -> Result<ExitCode, ExitCode> {
    let read = |path: &Path| {
        fs::read_to_string(path).map_err(|e| {
            eprintln!("Не удалось прочитать {}: {e}", path.display());
            ExitCode::FAILURE
        })
    };
    let chain = read(chain)?;
    let key = Zeroizing::new(read(key)?);
    let material = oncl_tls::import(&chain, &key, OffsetDateTime::now_utc()).map_err(|e| {
        eprintln!("Сертификат не подходит: {e}");
        ExitCode::FAILURE
    })?;
    for warning in &material.warnings {
        match warning {
            TlsWarning::ValidityOver825Days => println!(
                "Предупреждение: сертификат действует дольше 825 дней — браузеры Apple его не \
                 примут."
            ),
        }
    }
    // Unreadable metadata only loses the hint about a previous local CA.
    let previous = load_info(files).ok().flatten();
    save_and_explain(files, &material, previous.as_ref())
}

/// Saves `material`, then prints how to trust it (and to drop a replaced local CA).
fn save_and_explain(
    files: &TlsFiles,
    material: &oncl_tls::TlsMaterial,
    previous: Option<&TlsInfo>,
) -> Result<ExitCode, ExitCode> {
    oncl_tls::save(files, material).map_err(|e| {
        eprintln!("Не удалось сохранить файлы в {}: {e}", files.dir.display());
        ExitCode::FAILURE
    })?;
    if let Some(TlsInfo {
        source: TlsSource::Own,
        ca_sha1: Some(old),
        ..
    }) = previous
    {
        println!(
            "Прежний локальный центр сертификации (SHA-1 {}) больше не используется: удалите \
             его из хранилищ доверия (кнопка «Удалить старый» в мастере «Сертификат для \
             браузера…» или вручную, см. «Удаление» ниже). Его копия — в {}.",
            sha1_grouped(old),
            files.replaced_dir().display()
        );
        println!();
    }
    print!(
        "{}",
        instructions(TargetOs::current(), files, &material.info, listen_port())
    );
    Ok(ExitCode::SUCCESS)
}

fn tls_status(files: &TlsFiles) -> Result<ExitCode, ExitCode> {
    let info = configured(files).map_err(WssFailure::report)?;
    println!("Каталог: {}", files.dir.display());
    match &info.source {
        TlsSource::Own => {
            println!("Источник: локальный центр сертификации OpenNCALayer (tls init)");
        }
        TlsSource::Mkcert { caroot, .. } if info.source.renews_itself() => println!(
            "Источник: центр сертификации mkcert ({}), перевыпуск автоматический",
            caroot.display()
        ),
        TlsSource::Mkcert { caroot, .. } => println!(
            "Источник: центр сертификации mkcert ({}), согласие на перевыпуск отозвано",
            caroot.display()
        ),
        TlsSource::Imported => println!("Источник: импортированный сертификат (tls import)"),
    }
    if let Some(sha1) = &info.ca_sha1 {
        println!(
            "Отпечаток SHA-1 центра сертификации: {}",
            sha1_grouped(sha1)
        );
    }
    if let Some(sha256) = &info.ca_sha256 {
        println!(
            "Отпечаток SHA-256 центра сертификации: {}",
            sha256.to_ascii_uppercase()
        );
    }
    println!(
        "Отпечаток SHA-256 сертификата сервера: {}",
        info.leaf_sha256.to_ascii_uppercase()
    );
    match OffsetDateTime::parse(&info.leaf_not_after, &Rfc3339) {
        Ok(not_after) => {
            println!("Сертификат сервера действует до: {}", info.leaf_not_after);
            let auto = info.source.renews_itself();
            let renew = not_after
                - if auto {
                    AUTO_RENEW_BEFORE
                } else {
                    RENEW_BEFORE
                };
            let days = (renew - OffsetDateTime::now_utc()).whole_days();
            match &info.source {
                _ if auto => println!(
                    "Дней до перевыпуска: {} (OpenNCALayer перевыпустит сертификат сам после {})",
                    days.max(0),
                    ru_date(renew)
                ),
                _ if days > 0 => println!(
                    "Дней до перевыпуска: {days} (перевыпустить до {})",
                    ru_date(renew)
                ),
                TlsSource::Own | TlsSource::Mkcert { .. } => println!(
                    "Дней до перевыпуска: 0 — перевыпустите сертификат сейчас \
                     (`openncalayer tls init --force` или мастер «Сертификат для браузера…»)"
                ),
                TlsSource::Imported => println!(
                    "Дней до перевыпуска: 0 — перевыпустите сертификат сейчас \
                     (`openncalayer tls import`)"
                ),
            }
        }
        Err(_) => println!("Сертификат сервера действует до: {}", info.leaf_not_after),
    }
    println!("Создан: {} ({})", info.created_at, info.generator);
    println!(
        "Самопроверка: https://127.0.0.1:{}/openncalayer/selftest",
        listen_port()
    );
    if let Err(e) = server_config(files) {
        println!("Ошибка: сервер не сможет загрузить сертификат: {e}");
        return Err(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// `dd.MM.yyyy` in UTC, as the trust instructions write dates.
fn ru_date(t: OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    format!("{:02}.{:02}.{:04}", t.day(), u8::from(t.month()), t.year())
}

/// `nm install|uninstall|status`: exit code 0 on success, otherwise 1 (for `status`: when
/// a part is missing or broken).
pub fn nm(command: NmCommand) -> ExitCode {
    let result = match command {
        NmCommand::Install { relay, sandbox } => nm_install(relay, sandbox.as_deref()),
        NmCommand::Uninstall { sandbox } => nm_uninstall(sandbox.as_deref()),
        NmCommand::Status { sandbox } => nm_status(sandbox.as_deref()),
    };
    result.unwrap_or_else(|code| code)
}

/// The sandbox under `sandbox`, otherwise the layout of this user.
fn nm_layout(sandbox: Option<&Path>) -> Result<NmLayout, ExitCode> {
    match sandbox {
        Some(root) => Ok(NmLayout::sandbox(root)),
        None => NmLayout::detect(&data_paths()?).map_err(|e| {
            eprintln!("Не удалось определить, куда устанавливать хост native messaging: {e}");
            ExitCode::FAILURE
        }),
    }
}

fn nm_install(relay: Option<PathBuf>, sandbox: Option<&Path>) -> Result<ExitCode, ExitCode> {
    // The relay reaches the daemon of this data directory, in a sandbox too.
    let paths = data_paths()?;
    let layout = nm_layout(sandbox)?;
    let executables = executables()?;
    let daemon = executables.program;
    let relay = relay.unwrap_or(executables.relay);
    if !relay.is_file() {
        eprintln!(
            "Relay не найден: {}. Укажите его через --relay",
            relay.display()
        );
        return Err(ExitCode::FAILURE);
    }
    let report = nm::install(&layout, &relay, &daemon, &paths.data).map_err(|e| {
        eprintln!("Не удалось установить хост native messaging: {e}");
        ExitCode::FAILURE
    })?;
    print_nm_report(&report);
    println!("Каталог данных демона: {}", paths.data.display());
    if report.has_in_use() {
        println!(
            "Старые файлы relay заняты запущенным браузером и будут удалены при следующей \
             установке"
        );
    }
    if report.has_errors() {
        eprintln!(
            "Не все браузеры зарегистрированы: исправьте ошибки выше и повторите \
             `openncalayer nm install`"
        );
        return Err(ExitCode::FAILURE);
    }
    warn_if_no_browser(&report, State::Written);
    Ok(ExitCode::SUCCESS)
}

fn nm_uninstall(sandbox: Option<&Path>) -> Result<ExitCode, ExitCode> {
    let layout = nm_layout(sandbox)?;
    let report = nm::uninstall(&layout).map_err(|e| {
        eprintln!("Не удалось удалить хост native messaging: {e}");
        ExitCode::FAILURE
    })?;
    print_nm_report(&report);
    if report.has_in_use() {
        eprintln!(
            "Relay запущен браузером: закройте браузер и повторите `openncalayer nm uninstall`"
        );
    }
    if report.has_errors() {
        eprintln!("Не всё удалось удалить: см. ошибки выше");
    }
    if report.has_in_use() || report.has_errors() {
        return Err(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

fn nm_status(sandbox: Option<&Path>) -> Result<ExitCode, ExitCode> {
    let layout = nm_layout(sandbox)?;
    let report = nm::status(&layout);
    print_nm_report(&report);
    if !report.is_healthy() {
        eprintln!(
            "Хост native messaging не установлен или повреждён: выполните `openncalayer nm install`"
        );
        return Err(ExitCode::FAILURE);
    }
    warn_if_no_browser(&report, State::Present);
    Ok(ExitCode::SUCCESS)
}

/// Says so if no manifest of `report` is in `state`.
fn warn_if_no_browser(report: &Report, state: State) {
    let any = report
        .entries
        .iter()
        .any(|entry| matches!(entry.item, Item::Manifest { .. }) && entry.state == state);
    if !any {
        println!(
            "Не найден ни один браузер: запустите браузер хотя бы раз и повторите \
             `openncalayer nm install`"
        );
    }
}

/// One line per entry: what, where, its state.
fn print_nm_report(report: &Report) {
    for entry in &report.entries {
        let item: Cow<'_, str> = match &entry.item {
            Item::Relay => "Relay".into(),
            Item::RelayConfig => "Файл настроек relay".into(),
            Item::OldRelay => "Старый файл relay".into(),
            Item::Manifest { browser } => format!("Манифест для {browser}").into(),
            Item::RegistryKey => "Ключ реестра".into(),
            Item::TempFile => "Временный файл".into(),
        };
        let state: Cow<'_, str> = match &entry.state {
            State::Written => "записан".into(),
            State::Removed => "удалён".into(),
            State::Present => "на месте".into(),
            State::Missing => "отсутствует".into(),
            State::Skipped => "пропущен: каталог браузера не найден".into(),
            State::InUse => "занят запущенным процессом".into(),
            State::Invalid(why) => format!("ошибка: {why}").into(),
        };
        println!("{item}: {} — {state}", entry.location);
    }
}

/// The programs of this process, or the message printed and exit code 1.
fn executables() -> Result<Executables, ExitCode> {
    lifecycle::executables().map_err(|e| {
        eprintln!("Не удалось определить путь к openncalayer: {e}");
        ExitCode::FAILURE
    })
}

/// `integration install|uninstall|status`: exit code 0 on success, otherwise 1 (for
/// `status`: when this user's desktop is not integrated as installing leaves it).
pub fn integration(command: IntegrationCommand) -> ExitCode {
    let run = || -> Result<ExitCode, ExitCode> {
        let paths = data_paths()?;
        // Every step goes to the log too (the .pkg's postinstall output is Installer's).
        if let Err(e) = crate::logging::init_files(&paths.logs()) {
            eprintln!("Журнал не пишется в {}: {e}", paths.logs().display());
        }
        let integration = Integration::for_this_user(&paths).map_err(|e| {
            eprintln!("Не удалось определить автозапуск и браузеры этого пользователя: {e}");
            ExitCode::FAILURE
        })?;
        let event = match command {
            IntegrationCommand::Install => Event::Install,
            IntegrationCommand::Uninstall => Event::Uninstall,
            IntegrationCommand::Status => return Ok(integration_status(&integration)),
        };
        let outcome = integration.run(event);
        for (step, result) in &outcome.steps {
            match result {
                Ok(()) => println!("{}", step_text(*step)),
                Err(e) => eprintln!("{}: ошибка: {e}", step_text(*step)),
            }
        }
        if !outcome.succeeded() {
            eprintln!("Не всё удалось: исправьте ошибки выше и повторите команду");
        } else if event == Event::Uninstall {
            println!(
                "Каталог данных остаётся: {} (настройки, сертификаты, журналы)",
                paths.data.display()
            );
        }
        Ok(lifecycle::exit_code(&outcome))
    };
    run().unwrap_or_else(|code| code)
}

/// What a lifecycle step did, for the user.
fn step_text(step: Step) -> &'static str {
    match step {
        Step::RegisterRelay => "Relay браузеров зарегистрирован",
        Step::RefreshRelay => "Relay браузеров обновлён",
        Step::RelayLeftOff => "Relay браузеров не зарегистрирован и оставлен так",
        Step::UnregisterRelay => "Relay браузеров и его регистрация удалены",
        Step::EnableAutostart => "Автозапуск OpenNCALayer включён",
        Step::RefreshAutostart => "Автозапуск OpenNCALayer обновлён",
        Step::AutostartLeftOff => "Автозапуск OpenNCALayer выключен и оставлен так",
        Step::RemoveAutostart => "Автозапуск OpenNCALayer удалён",
        Step::DisableOriginal => "Автозапуск оригинального NCALayer этого пользователя отключён",
        Step::RestoreOriginal => "Автозапуск оригинального NCALayer возвращён",
        Step::SaveRecord => "Установка записана",
        Step::RemoveRecord => "Запись об установке удалена",
    }
}

/// Prints how this user's desktop is integrated and what to do about it; exit code 1 if it
/// is not as installing leaves it ([`integration_ok`]).
fn integration_status(integration: &Integration) -> ExitCode {
    let exe = std::env::current_exe().unwrap_or_default();
    let installation = Installation::detect(&exe);
    let kind = match &installation {
        Installation::Velopack => "установлена установщиком (обновляется сама)".to_owned(),
        Installation::PackageManager(manager) => {
            format!("установлена пакетным менеджером {manager} (обновляет он)")
        }
        Installation::Portable => "переносная копия (сама не обновляется)".to_owned(),
    };
    println!(
        "Программа: {} — {kind}",
        integration.executables.program.display()
    );
    let record = integration.record();
    match &record {
        Ok(Some(record)) => {
            println!(
                "Встроена: версия {} для {}",
                record.version,
                record.program.display()
            );
            for choice in Choice::ALL {
                println!(
                    "  {}: {}",
                    choice_text(choice),
                    if record.done.contains(&choice) {
                        "сделано"
                    } else {
                        "не сделано"
                    }
                );
            }
        }
        Ok(None) => println!("Не встроена"),
        Err(e) => println!("Запись об установке не читается: {e}"),
    }
    let relay = nm::status(&integration.nm);
    println!(
        "Relay браузеров: {}",
        if relay.is_healthy() {
            "зарегистрирован"
        } else if lifecycle::relay_registered(&relay) {
            "повреждён (`openncalayer nm status`)"
        } else {
            "не зарегистрирован"
        }
    );
    let autostart = integration.autostart.enabled();
    match &autostart {
        Ok(on) => println!(
            "Автозапуск OpenNCALayer: {}",
            if *on {
                "включён"
            } else {
                "выключен"
            }
        ),
        Err(e) => println!("Автозапуск OpenNCALayer: не читается: {e}"),
    }
    let disabled =
        oncl_desktop::original::original_autostart(&integration.original, &integration.journal())
            .entries
            .iter()
            .filter(|e| e.state == EntryState::DisabledByUs)
            .count();
    println!("Записей автозапуска оригинала, отключённых OpenNCALayer: {disabled}");
    let leftovers = lifecycle::relay_registered(&relay)
        || matches!(autostart, Ok(true) | Err(_))
        || disabled > 0;
    if let Some(advice) = integration_advice(&record, &installation, leftovers) {
        println!("{advice}");
    }
    if integration_ok(&record, &relay) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// What to do about the integration, if anything: finish an unfinished installation, have
/// a failed refresh redone (the daemon of an installed copy does it at its start; a portable
/// copy never does), or, without a record, install, or remove what a failed uninstallation
/// left behind (`leftovers`: our relay, our autostart or the original disabled by us).
fn integration_advice(
    record: &io::Result<Option<lifecycle::Record>>,
    installation: &Installation,
    leftovers: bool,
) -> Option<&'static str> {
    match record {
        Ok(Some(r)) if !r.complete() => {
            Some("Установка не закончена: выполните `openncalayer integration install`")
        }
        Ok(Some(r)) if r.failed && *installation == Installation::Portable => Some(
            "Последнее обновление встраивания не удалось: выполните `openncalayer integration install` ещё раз",
        ),
        Ok(Some(r)) if r.failed => Some(
            "Последнее обновление встраивания не удалось: оно повторится при следующем запуске программы",
        ),
        Ok(Some(_)) => None,
        Ok(None) | Err(_) if leftovers => Some(
            "Остались следы встраивания (relay, автозапуск или отключённый оригинал): убрать их — `openncalayer integration uninstall`, встроить заново — `openncalayer integration install`",
        ),
        Ok(None) | Err(_) => Some("Встроить: `openncalayer integration install`"),
    }
}

/// What installing does once, for the user.
fn choice_text(choice: Choice) -> &'static str {
    match choice {
        Choice::Relay => "регистрация relay браузеров",
        Choice::Autostart => "включение автозапуска OpenNCALayer",
        Choice::Original => "отключение автозапуска оригинала",
    }
}

/// Whether this user's desktop is integrated as installing leaves it: a record with every
/// choice made and no failed refresh, and a relay that is either not registered (the user
/// may have removed it) or registered whole.
fn integration_ok(record: &io::Result<Option<lifecycle::Record>>, relay: &Report) -> bool {
    let record_ok = matches!(record, Ok(Some(r)) if r.complete() && !r.failed);
    record_ok && (relay.is_healthy() || !lifecycle::relay_registered(relay))
}

/// `cms-verify <file> [--content <file>] [--chain <file>]... [--offline]`: prints
/// [`cms_verify_report_with`] against the CA certificates of the `chain` files (each PEM,
/// every `CERTIFICATE` block, or DER) or, without any, the embedded NCA set; unless
/// `offline`, over the network ([`UreqTransport`] through the proxy of `settings.json`) with
/// the CRL cache in `<data_dir>/crl`.
/// Exit code 0 when the report ends with `OK`, otherwise 1.
pub fn cms_verify(
    file: &Path,
    content: Option<&Path>,
    chain: &[PathBuf],
    offline: bool,
) -> ExitCode {
    let read = |path: &Path| fs::read(path).map_err(|e| format!("{}: {e}", path.display()));
    let inputs = read(file).and_then(|cms| {
        let content = content.map(read).transpose()?;
        let cas = if chain.is_empty() {
            CaSet::nca_production()
        } else {
            let mut certs = Vec::new();
            for path in chain {
                let bytes = read(path)?;
                certs.extend(
                    parse_certificates(&bytes).map_err(|e| format!("{}: {e}", path.display()))?,
                );
            }
            CaSet::new(certs)
        };
        Ok((cms, content, cas))
    });
    let (cms, content, cas) = match inputs {
        Ok(inputs) => inputs,
        Err(e) => {
            println!("FAIL: {e}");
            return ExitCode::FAILURE;
        }
    };
    let http;
    let online = if offline {
        None
    } else {
        let paths = match data_paths() {
            Ok(paths) => paths,
            Err(code) => return code,
        };
        http = UreqTransport::with_proxy(load_settings(&paths.settings()).proxy);
        Some(Online {
            http: &http,
            crl_dir: paths.crl(),
        })
    };
    let opts = Options {
        cas,
        online,
        // Whole seconds: the report prints it as the validation time.
        now: OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .expect("0 is a valid nanosecond"),
    };
    let (report, ok) = cms_verify_report_with(&cms, content.as_deref(), &opts);
    print!("{report}");
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integration_advice_points_where_the_state_needs() {
        let record = |done: &[Choice], failed| {
            Ok(Some(lifecycle::Record {
                program: PathBuf::from("/opt/openncalayer"),
                version: "1.0.0".to_owned(),
                done: done.iter().copied().collect(),
                failed,
            }))
        };
        let installed = Installation::Velopack;
        let portable = Installation::Portable;
        assert_eq!(
            integration_advice(&record(&Choice::ALL, false), &installed, true),
            None
        );
        let advice = |r: &io::Result<Option<lifecycle::Record>>, i: &Installation, l: bool| {
            integration_advice(r, i, l).unwrap().to_owned()
        };
        assert!(
            advice(&record(&[Choice::Relay], false), &installed, true)
                .contains("integration install")
        );
        // A failed refresh is redone by an installed copy's daemon, not by a portable one.
        assert!(
            advice(&record(&Choice::ALL, true), &installed, true).contains("при следующем запуске")
        );
        let portable_advice = advice(&record(&Choice::ALL, true), &portable, true);
        assert!(
            portable_advice.contains("integration install"),
            "{portable_advice}"
        );
        assert!(
            !portable_advice.contains("при следующем запуске"),
            "{portable_advice}"
        );
        // After a failed uninstallation (no record, leftovers) the advice is to finish it.
        assert!(advice(&Ok(None), &installed, true).contains("integration uninstall"));
        assert!(
            advice(&Err(io::Error::other("bad")), &portable, true)
                .contains("integration uninstall")
        );
        let clean = advice(&Ok(None), &installed, false);
        assert!(clean.contains("integration install") && !clean.contains("uninstall"));
    }

    #[test]
    fn integration_status_fails_until_installing_is_done() {
        let record = |done: &[Choice], failed| {
            Ok(Some(lifecycle::Record {
                program: PathBuf::from("/opt/openncalayer"),
                version: "1.0.0".to_owned(),
                done: done.iter().copied().collect(),
                failed,
            }))
        };
        let entry = |item, state| nm::Entry {
            item,
            location: "x".to_owned(),
            state,
        };
        let healthy = Report {
            entries: vec![entry(Item::Relay, State::Present)],
        };
        let removed = Report {
            entries: vec![entry(Item::Relay, State::Missing)],
        };
        let broken = Report {
            entries: vec![
                entry(Item::Relay, State::Missing),
                entry(Item::RegistryKey, State::Present),
            ],
        };
        assert!(integration_ok(&record(&Choice::ALL, false), &healthy));
        // The user unregistered the extension: still as installing left it.
        assert!(integration_ok(&record(&Choice::ALL, false), &removed));
        assert!(!integration_ok(&record(&Choice::ALL, false), &broken));
        assert!(!integration_ok(&record(&[Choice::Relay], false), &healthy));
        assert!(!integration_ok(&record(&Choice::ALL, true), &healthy));
        assert!(!integration_ok(&Ok(None), &healthy));
        assert!(!integration_ok(&Err(io::Error::other("bad")), &healthy));
    }

    /// What [`prepare_in`] told the start hooks: `started` calls, `ends_cleanly` calls.
    #[derive(Default)]
    struct Hooks {
        started: usize,
        clean: usize,
        refuse: Option<u8>,
    }

    impl AtStart for Hooks {
        fn started(&mut self, _: &Paths) -> Result<(), ExitCode> {
            self.started += 1;
            self.refuse.map_or(Ok(()), |code| Err(ExitCode::from(code)))
        }

        fn ends_cleanly(&mut self) {
            self.clean += 1;
        }
    }

    /// `prepare_in` on a free port in `dir`: its exit code, if it fails.
    fn prepare(dir: &Path, tray_session: bool, hooks: &mut Hooks) -> Option<u8> {
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let paths = Paths {
            data: dir.to_owned(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        match runtime.block_on(prepare_in(paths, port, false, tray_session, hooks)) {
            Ok(_) => None,
            Err(code) => Some((1..=4u8).find(|c| ExitCode::from(*c) == code).unwrap_or(0)),
        }
    }

    #[test]
    fn start_hooks_run_after_the_single_instance_check() {
        // TLS not set up without a tray: P1's exit 2, a clean end.
        let dir = tempfile::tempdir().unwrap();
        let mut hooks = Hooks::default();
        assert_eq!(
            prepare(dir.path(), false, &mut hooks),
            Some(EXIT_TLS_NOT_CONFIGURED)
        );
        assert_eq!((hooks.started, hooks.clean), (1, 1));

        // TLS unusable, in a tray session: exit 1, not a clean end (the start counted).
        let files = Paths {
            data: dir.path().to_owned(),
        }
        .tls();
        fs::create_dir_all(&files.dir).unwrap();
        fs::write(files.info(), "not json").unwrap();
        let mut hooks = Hooks::default();
        assert_eq!(prepare(dir.path(), true, &mut hooks), Some(1));
        assert_eq!((hooks.started, hooks.clean), (1, 0));

        // The hook ends the start (an update rolled back): its code, nothing else runs.
        let mut hooks = Hooks {
            refuse: Some(4),
            ..Hooks::default()
        };
        assert_eq!(prepare(dir.path(), true, &mut hooks), Some(4));
        assert_eq!((hooks.started, hooks.clean), (1, 0));
    }

    #[test]
    fn default_command_is_run() {
        assert!(
            Cli::try_parse_from(["openncalayer"])
                .unwrap()
                .command
                .is_none()
        );
        let cli = Cli::try_parse_from(["openncalayer", "tls", "init", "--force"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Tls {
                command: TlsCommand::Init { force: true }
            })
        ));
        let cli =
            Cli::try_parse_from(["openncalayer", "cms-verify", "a.p7s", "--content", "a"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::CmsVerify { ref chain, offline: false, .. }) if chain.is_empty()
        ));
        let cli = Cli::try_parse_from([
            "openncalayer",
            "cms-verify",
            "a.p7s",
            "--chain",
            "ca.der",
            "--chain",
            "root.pem",
            "--offline",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::CmsVerify { ref chain, offline: true, content: None, .. })
                if chain == &[PathBuf::from("ca.der"), PathBuf::from("root.pem")]
        ));
        let cli = Cli::try_parse_from(["openncalayer", "run"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Run {
                allow_no_wss: false,
                no_tray: false
            })
        ));
        let cli =
            Cli::try_parse_from(["openncalayer", "run", "--allow-no-wss", "--no-tray"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Run {
                allow_no_wss: true,
                no_tray: true
            })
        ));
    }

    #[test]
    fn wss_off_is_told_in_the_tray_language() {
        let off = WssOff::PortBusy(13579);
        assert_eq!(
            off.text(Locale::Ru),
            "Порт 13579 занят (возможно, оригинальным NCALayer)"
        );
        assert_eq!(
            off.text(Locale::En),
            "Port 13579 is in use (perhaps by the original NCALayer)"
        );
        for l in [Locale::Ru, Locale::Kk, Locale::En] {
            let texts = [
                WssOff::TlsNotConfigured,
                WssOff::TlsUnusable,
                WssOff::PortBusy(1),
                WssOff::PortUnavailable(1),
            ]
            .map(|off| off.text(l));
            for (i, text) in texts.iter().enumerate() {
                assert!(!texts[..i].contains(text), "{l:?}: {text}");
            }
        }
        assert_ne!(
            WssOff::TlsNotConfigured.text(Locale::Kk),
            WssOff::TlsNotConfigured.text(Locale::Ru)
        );
    }

    /// What a tray session lets start without wss: TLS not set up and a busy port, which the
    /// TLS wizard and stopping the original fix; a broken certificate still ends `run`.
    #[test]
    fn only_tls_missing_and_a_busy_port_wait_for_the_tray() {
        let dir = tempfile::tempdir().unwrap();
        let files = TlsFiles {
            dir: dir.path().join("tls"),
        };
        let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = held.local_addr().unwrap().port();
        let missing = open_wss(&files, port).unwrap_err();
        assert_eq!(missing.off, WssOff::TlsNotConfigured);
        assert_eq!(missing.code, EXIT_TLS_NOT_CONFIGURED);
        assert!(missing.fixed_in_the_tray());

        let material = oncl_tls::generate(OffsetDateTime::now_utc(), "cli").unwrap();
        oncl_tls::save(&files, &material).unwrap();
        let busy = open_wss(&files, port).unwrap_err();
        assert_eq!(busy.off, WssOff::PortBusy(port));
        assert_eq!(busy.code, EXIT_PORT_BUSY);
        assert!(busy.fixed_in_the_tray());
        drop(held);
        let (_, listener) = open_wss(&files, port).unwrap();
        assert_eq!(listener.local_addr().unwrap().port(), port);
        drop(listener);

        fs::write(
            files.dir.join("server.key"),
            "-----BEGIN PRIVATE KEY-----\nAAAA\n",
        )
        .unwrap();
        let broken = open_wss(&files, port).unwrap_err();
        assert_eq!(broken.off, WssOff::TlsUnusable);
        assert!(!broken.fixed_in_the_tray());
    }

    #[cfg(feature = "e2e-prompter")]
    #[test]
    fn e2e_steps_parse() {
        use oncl_basics::testing::Step;

        let steps = parse_steps(
            r#"[{"storage":{"path":"k.p12","password":"pw"}},{"key":1},
                {"cancel_storage":null},{"cancel_key":null},
                {"jks":{"path":"k.jks","password":"pw"}},
                {"csr":{"dir":"d","password":""}},{"cancel_csr":null},
                {"import":{"dir":"d","password":"Qwerty12"}},{"cancel_import":null},
                {"file":"f.cer"},{"cancel_file":null},
                {"password":"Secret1"},{"cancel_password":null}]"#,
        )
        .unwrap();
        assert!(matches!(
            steps.as_slice(),
            [
                Step::Storage { path, password },
                Step::Key(1),
                Step::CancelStorage,
                Step::CancelKey,
                Step::Jks { .. },
                Step::Csr { .. },
                Step::CancelCsr,
                Step::Import { .. },
                Step::CancelImport,
                Step::File(file),
                Step::CancelFile,
                Step::Password(secret),
                Step::CancelPassword,
            ] if path == Path::new("k.p12") && password == "pw" && file == Path::new("f.cer")
                && secret == "Secret1"
        ));
        assert!(parse_steps(r#"[{"wait":null}]"#).is_err());
        assert!(parse_steps("{}").is_err());
    }
}
