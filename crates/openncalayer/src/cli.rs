//! The command line: `run` (the default), `tls init|import|status`, `cms-verify` and
//! `nm install|uninstall|status`.
//!
//! Messages for the user are in Russian, like the rest of the user-facing text.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use clap::{Parser, Subcommand};
use oncl_ipc::IpcListener;
use oncl_pki::cert::{self, Certificate};
use oncl_pki::cms::{self, VerifiedSigner};
use oncl_pki::crl::{self, CrlCache, CrlStatus};
use oncl_pki::http::{HttpTransport, UreqTransport};
use oncl_pki::info::cert_info;
use oncl_pki::ocsp::{self, CertStatus};
use oncl_pki::pkix::{CaSet, PathError, build_path, validation_time};
use oncl_pki::tsp::{TspError, verify_token_for};
use oncl_tls::{
    RENEW_BEFORE, TargetOs, TlsFiles, TlsInfo, TlsSource, TlsWarning, instructions, load_info,
    server_config, sha1_grouped,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::nm::{self, Item, NmLayout, Report, State};
use crate::paths::Paths;
use crate::server::listen_port;

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
            help = "Сертификат CA (PEM или DER) вместо встроенных сертификатов НУЦ; можно указать несколько раз"
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

/// Everything `run` sets up before the servers start: data paths, logging, the bound IPC
/// endpoint of the browser extension bridge and, unless it is off, the wss server's TLS
/// configuration and bound listening socket (non-blocking, for tokio).
pub struct Daemon {
    pub paths: Paths,
    pub ipc: IpcListener,
    pub wss: Option<(Arc<rustls::ServerConfig>, TcpListener)>,
}

/// Prepares `run`: data paths and logging, the IPC endpoint, then TLS and the port. On
/// failure the message is already printed and the exit code returned:
/// [`EXIT_ALREADY_RUNNING`], [`EXIT_TLS_NOT_CONFIGURED`], [`EXIT_PORT_BUSY`] or 1. With
/// `allow_no_wss` any failure to start the wss server (TLS not set up or unusable, the port
/// busy or not bindable) only turns it off, with a warning in the log.
pub async fn prepare_run(allow_no_wss: bool) -> Result<Daemon, ExitCode> {
    let paths = data_paths()?;
    if let Err(e) = crate::logging::init(&paths.logs()) {
        warn!(dir = %paths.logs().display(), error = %e, "file logging is disabled");
    }
    let ipc = bind_ipc(&paths.data).await?;
    let wss = match open_wss(&paths) {
        Ok(wss) => Some(wss),
        Err(failure) if allow_no_wss => {
            warn!(
                code = failure.code,
                reason = %failure.message,
                "wss is off; serving the browser extension only"
            );
            None
        }
        Err(failure) => return Err(failure.report()),
    };
    info!(data = %paths.data.display(), "daemon started");
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

/// The wss server's TLS configuration and listening socket.
fn open_wss(paths: &Paths) -> Result<(Arc<rustls::ServerConfig>, TcpListener), Failure> {
    let files = paths.tls();
    configured(&files)?;
    let tls = server_config(&files).map_err(|e| {
        Failure::new(
            1,
            format!(
                "Не удалось загрузить сертификат сервера из {}: {e}",
                files.dir.display()
            ),
        )
    })?;
    let port = listen_port();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map_err(|e| {
        if port_busy(&e) {
            Failure::new(
                EXIT_PORT_BUSY,
                format!("Порт {port} занят (возможно, запущен оригинальный NCALayer)"),
            )
        } else {
            Failure::new(1, format!("Не удалось открыть порт 127.0.0.1:{port}: {e}"))
        }
    })?;
    listener.set_nonblocking(true).map_err(|e| {
        Failure::new(
            1,
            format!("Не удалось настроить порт 127.0.0.1:{port}: {e}"),
        )
    })?;
    info!("listening on 127.0.0.1:{port}");
    Ok((Arc::new(tls), listener))
}

/// A failed step of a command: the message for the user and the exit code.
struct Failure {
    code: u8,
    message: String,
}

impl Failure {
    fn new(code: u8, message: String) -> Self {
        Failure { code, message }
    }

    /// Prints the message; returns the exit code.
    fn report(self) -> ExitCode {
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
fn configured(files: &TlsFiles) -> Result<TlsInfo, Failure> {
    match load_info(files) {
        Ok(Some(info)) => Ok(info),
        Ok(None) => Err(Failure::new(
            EXIT_TLS_NOT_CONFIGURED,
            "TLS не настроен: выполните `openncalayer tls init`".to_owned(),
        )),
        Err(e) => Err(Failure::new(
            1,
            format!("Не удалось прочитать {}: {e}", files.info().display()),
        )),
    }
}

/// With feature `e2e-prompter`: a JSON file of dialog answers that `run` uses instead of
/// windows, e.g. `[{"storage":{"path":"…","password":"…"}},{"key":0},{"cancel_storage":null}]`
/// (also `{"cancel_key":null}`).
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
        CancelStorage,
        Key(usize),
        CancelKey,
    }

    let specs: Vec<StepSpec> = serde_json::from_str(text).map_err(|e| e.to_string())?;
    Ok(specs
        .into_iter()
        .map(|spec| match spec {
            StepSpec::Storage { path, password } => Step::Storage { path, password },
            StepSpec::CancelStorage => Step::CancelStorage,
            StepSpec::Key(index) => Step::Key(index),
            StepSpec::CancelKey => Step::CancelKey,
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

fn current_os() -> TargetOs {
    if cfg!(windows) {
        TargetOs::Windows
    } else if cfg!(target_os = "macos") {
        TargetOs::MacOs
    } else {
        TargetOs::Linux
    }
}

/// `user@host` for the CA name, from the environment.
fn label() -> String {
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
        source: TlsSource::Generated,
        ca_sha1: Some(old),
        ..
    }) = previous
    {
        println!(
            "Прежний локальный центр сертификации (SHA-1 {}) больше не используется: удалите \
             его из хранилищ доверия.",
            sha1_grouped(old)
        );
        println!();
    }
    print!(
        "{}",
        instructions(current_os(), files, &material.info, listen_port())
    );
    Ok(ExitCode::SUCCESS)
}

fn tls_status(files: &TlsFiles) -> Result<ExitCode, ExitCode> {
    let info = configured(files).map_err(Failure::report)?;
    println!("Каталог: {}", files.dir.display());
    println!(
        "Источник: {}",
        match info.source {
            TlsSource::Generated => "локальный центр сертификации OpenNCALayer (tls init)",
            TlsSource::Imported => "импортированный сертификат (tls import)",
        }
    );
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
            let renew = not_after - RENEW_BEFORE;
            let days = (renew - OffsetDateTime::now_utc()).whole_days();
            if days > 0 {
                println!(
                    "Дней до перевыпуска: {days} (перевыпустить до {})",
                    ru_date(renew)
                );
            } else {
                println!(
                    "Дней до перевыпуска: 0 — перевыпустите сертификат сейчас ({})",
                    match info.source {
                        TlsSource::Generated => "`openncalayer tls init --force`",
                        TlsSource::Imported => "`openncalayer tls import`",
                    }
                );
            }
        }
        Err(_) => println!("Сертификат сервера действует до: {}", info.leaf_not_after),
    }
    println!("Создан: {} ({})", info.created_at, info.generator);
    println!("Самопроверка: https://127.0.0.1:{}/", listen_port());
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
    let daemon = std::env::current_exe().map_err(|e| {
        eprintln!("Не удалось определить путь к openncalayer: {e}");
        ExitCode::FAILURE
    })?;
    let relay = relay.unwrap_or_else(|| daemon.with_file_name(nm::relay_file_name()));
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

/// `cms-verify <file> [--content <file>] [--chain <file>]... [--offline]`: prints
/// [`cms_verify_report_with`] against the CAs of `chain` (PEM or DER, one certificate per
/// file) or, without any, the embedded NCA set, over the network ([`UreqTransport`]) with
/// the CRL cache in `<data_dir>/crl`. Exit code 0 when the report ends with `OK`,
/// otherwise 1.
pub fn cms_verify(
    file: &Path,
    content: Option<&Path>,
    chain: &[PathBuf],
    offline: bool,
) -> ExitCode {
    let paths = match data_paths() {
        Ok(paths) => paths,
        Err(code) => return code,
    };
    let read = |path: &Path| fs::read(path).map_err(|e| format!("{}: {e}", path.display()));
    let inputs = read(file).and_then(|cms| {
        let content = content.map(read).transpose()?;
        let cas = if chain.is_empty() {
            CaSet::nca_production()
        } else {
            let certs = chain.iter().map(|path| {
                read(path).and_then(|bytes| {
                    parse_certificate(&bytes).map_err(|e| format!("{}: {e}", path.display()))
                })
            });
            CaSet::new(certs.collect::<Result<_, _>>()?)
        };
        Ok((cms, content, cas))
    });
    let (report, ok) = match inputs {
        Ok((cms, content, cas)) => {
            let opts = CmsVerifyOptions {
                cas,
                http: &UreqTransport,
                crl_dir: paths.crl(),
                offline,
                now: OffsetDateTime::now_utc(),
            };
            cms_verify_report_with(&cms, content.as_deref(), &opts)
        }
        Err(e) => (format!("FAIL: {e}\n"), false),
    };
    print!("{report}");
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// A certificate in PEM (the first block) or DER.
fn parse_certificate(input: &[u8]) -> Result<Certificate, String> {
    cert::parse(&pem_or_der(input)?).map_err(|e| e.to_string())
}

/// The line before `OK` in a [`cms_verify_report_with`] made with `offline`: what `OK` does
/// not mean.
pub const NOT_CHECKED: &str = "not checked: revocation";

/// The last line of a [`cms_verify_report_with`] when only revocation data is missing.
const INDETERMINATE: &str = "INDETERMINATE: revocation data unavailable";

/// What `cms-verify` checks signer certificates against, and how.
pub struct CmsVerifyOptions<'a> {
    /// CAs certification paths are built through: the embedded NCA set or `--chain`.
    pub cas: CaSet,
    /// Transport of OCSP requests and CRL downloads.
    pub http: &'a dyn HttpTransport,
    /// CRL cache directory, normally `<data_dir>/crl`.
    pub crl_dir: PathBuf,
    /// Revocation is not checked: no OCSP, no CRL.
    pub offline: bool,
    /// The current time: OCSP responses and CRLs must be current at it, and it is the
    /// validation time of a signer with neither a time-stamp nor signingTime.
    pub now: OffsetDateTime,
}

/// Verifies a CMS signature, PEM or DER/BER, over its encapsulated content or `content`,
/// and the certificate of every signer as of its validation time: the genTime of its
/// verified time-stamp token, else its signingTime, else `opts.now`.
///
/// The report has a block per signer (numbered from 0, as in error messages):
/// - `signer <n>: CN=<cn>, IIN=<iin|->, alg=<SigAlg>, signingTime=<RFC 3339|->`;
/// - `timestamp: yes|no`: whether the signer carries a time-stamp token;
/// - `chain: <issuer CN> -> … -> <anchor CN>` or `chain: FAIL <PathError>`: the path
///   through `opts.cas` at the validation time (at the certificate's notAfter once it has
///   expired: its own validity is the next line);
/// - `validity: ok at <RFC 3339>` or `validity: FAIL`: the certificate at the validation
///   time;
/// - `tsa chain: …`, for a verified token: the TSA certificate's path at genTime;
/// - `revocation: good (ocsp)`, `revocation: revoked <RFC 3339> [after signing ](ocsp|crl)`,
///   `revocation: unavailable (<error>)` or `revocation: not checked (--offline)`: the signer
///   by OCSP, every CA of the path between it and the anchor by the CRL of its issuer. A
///   revocation after the validation time does not invalidate the signature.
///
/// The last line is `OK` if everything holds (with `offline`, after the line
/// [`NOT_CHECKED`]); `FAIL: <error>` with the first failure of a signature, time-stamp,
/// path, validity or revocation; otherwise, when revocation data is missing,
/// `INDETERMINATE: revocation data unavailable`. Returns the report and whether it is
/// `OK`.
pub fn cms_verify_report_with(
    input: &[u8],
    content: Option<&[u8]>,
    opts: &CmsVerifyOptions<'_>,
) -> (String, bool) {
    let mut report = String::new();
    let ok = match describe(input, content, opts, &mut report) {
        Ok(true) => {
            if opts.offline {
                let _ = writeln!(report, "{NOT_CHECKED}");
            }
            let _ = writeln!(report, "OK");
            true
        }
        Ok(false) => {
            let _ = writeln!(report, "{INDETERMINATE}");
            false
        }
        Err(e) => {
            let _ = writeln!(report, "FAIL: {e}");
            false
        }
    };
    (report, ok)
}

/// Writes the signer blocks: the first failure is the error, otherwise whether the
/// revocation status of every signer is known (or not to be checked).
fn describe(
    input: &[u8],
    content: Option<&[u8]>,
    opts: &CmsVerifyOptions<'_>,
    report: &mut String,
) -> Result<bool, String> {
    let der = pem_or_der(input)?;
    let signers = cms::verify(&der, content).map_err(|e| e.to_string())?;
    let mut failure = None;
    let mut known = true;
    for (n, signer) in signers.iter().enumerate() {
        match describe_signer(n, signer, opts, report) {
            Ok(revocation_known) => known &= revocation_known,
            Err(e) => {
                failure.get_or_insert(e);
            }
        }
    }
    failure.map_or(Ok(known), Err)
}

/// Writes the block of signer `n`: its first failure is the error, otherwise whether its
/// revocation status is known (or not to be checked).
fn describe_signer(
    n: usize,
    signer: &VerifiedSigner,
    opts: &CmsVerifyOptions<'_>,
    report: &mut String,
) -> Result<bool, String> {
    let mut failure = None;
    let info = cert_info(&signer.cert);
    let signing_time = signer.signing_time.map_or_else(|| "-".to_owned(), rfc3339);
    let _ = writeln!(
        report,
        "signer {n}: CN={}, IIN={}, alg={:?}, signingTime={signing_time}",
        info.subject_cn.as_deref().unwrap_or("-"),
        info.iin.as_deref().unwrap_or("-"),
        signer.sig_alg,
    );

    let token = signer.timestamp_token.as_ref().and_then(|token| {
        verify_token_for(token, &signer.signature)
            .map_err(|e| {
                failure.get_or_insert_with(|| match e {
                    TspError::ImprintMismatch => {
                        format!("time-stamp of signer {n} does not cover its signature")
                    }
                    e => format!("time-stamp of signer {n}: {e}"),
                });
            })
            .ok()
    });
    let stamped = if signer.timestamp_token.is_some() {
        "yes"
    } else {
        "no"
    };
    let _ = writeln!(report, "timestamp: {stamped}");

    let at = token
        .as_ref()
        .map(|(tst, _)| tst.gen_time)
        .or(signer.signing_time)
        .unwrap_or(opts.now);
    let path = build_path(&signer.cert, &opts.cas, validation_time(&signer.cert, at));
    let _ = writeln!(report, "chain: {}", chain_line(&path));
    if let Err(e) = &path {
        failure.get_or_insert_with(|| format!("certificate chain of signer {n}: {e}"));
    }

    if info.not_before <= at && at <= info.not_after {
        let _ = writeln!(report, "validity: ok at {}", rfc3339(at));
    } else {
        let _ = writeln!(report, "validity: FAIL");
        failure.get_or_insert_with(|| {
            format!("certificate of signer {n} is not valid at {}", rfc3339(at))
        });
    }

    if let Some((tst, tsa)) = &token {
        let tsa_path = build_path(tsa, &opts.cas, tst.gen_time);
        let _ = writeln!(report, "tsa chain: {}", chain_line(&tsa_path));
        if let Err(e) = &tsa_path {
            failure
                .get_or_insert_with(|| format!("time-stamp certificate chain of signer {n}: {e}"));
        }
    }

    let revocation = match &path {
        _ if opts.offline => Revocation::NotChecked,
        Ok(path) => revocation(path, at, opts),
        Err(_) => Revocation::Unavailable("no certification path".to_owned()),
    };
    let _ = write!(report, "revocation: ");
    let known = match revocation {
        Revocation::Good => {
            let _ = writeln!(report, "good (ocsp)");
            true
        }
        Revocation::NotChecked => {
            let _ = writeln!(report, "not checked (--offline)");
            true
        }
        Revocation::Unavailable(e) => {
            let _ = writeln!(report, "unavailable ({e})");
            false
        }
        Revocation::Revoked(revoked) if revoked.time > at => {
            let _ = writeln!(
                report,
                "revoked {} after signing ({})",
                rfc3339(revoked.time),
                revoked.source
            );
            true
        }
        Revocation::Revoked(revoked) => {
            let (time, source) = (rfc3339(revoked.time), revoked.source);
            let _ = writeln!(report, "revoked {time} ({source})");
            failure.get_or_insert_with(|| match revoked.ca {
                None => format!("certificate of signer {n} is revoked at {time} ({source})"),
                Some(ca) => format!(
                    "CA certificate CN={ca} in the chain of signer {n} is revoked at {time} \
                     ({source})"
                ),
            });
            true
        }
    };
    failure.map_or(Ok(known), Err)
}

/// Revocation status of a signer's certification path.
enum Revocation {
    /// The signer is good by OCSP, every CA below the anchor by CRL.
    Good,
    /// A certificate of the path is revoked: the first one found revoked at or before the
    /// validation time, else the earliest revocation after it.
    Revoked(Revoked),
    /// Some status is unknown: why.
    Unavailable(String),
    /// `--offline`.
    NotChecked,
}

/// A revoked certificate of a signer's path.
struct Revoked {
    /// Revocation time.
    time: OffsetDateTime,
    /// `ocsp` or `crl`.
    source: &'static str,
    /// The CN of the CA, or `None` for the signer itself.
    ca: Option<String>,
}

/// Revocation status of `path` (`[signer, issuer, …, anchor]`) for the validation time
/// `at`: the signer by OCSP, then each CA between it and the anchor by the CRL of its
/// issuer (through the cache in `opts.crl_dir`). A revocation at or before `at` ends the
/// check; one after `at` is reported only if every status is known.
fn revocation(path: &[Certificate], at: OffsetDateTime, opts: &CmsVerifyOptions<'_>) -> Revocation {
    let Some(issuer) = path.get(1) else {
        return Revocation::Unavailable("signer certificate is a trust anchor".to_owned());
    };
    let mut unavailable: Option<String> = None;
    let mut later: Option<Revoked> = None;
    let mut found = |revoked: Revoked| {
        if revoked.time <= at {
            return Some(revoked);
        }
        if later.as_ref().is_none_or(|l| revoked.time < l.time) {
            later = Some(revoked);
        }
        None
    };

    match ocsp::check(
        &path[0],
        issuer,
        &opts.cas,
        opts.http,
        opts.now,
        ocsp::TIMEOUT,
    ) {
        Ok(CertStatus::Good) => {}
        Ok(CertStatus::Revoked { time, .. }) => {
            let revoked = Revoked {
                time,
                source: "ocsp",
                ca: None,
            };
            if let Some(revoked) = found(revoked) {
                return Revocation::Revoked(revoked);
            }
        }
        Ok(CertStatus::Unknown) => {
            unavailable = Some("OCSP responder does not know the certificate".to_owned());
        }
        Err(e) => unavailable = Some(e.to_string()),
    }

    let cache = CrlCache::new(&opts.crl_dir);
    for pair in path[1..].windows(2) {
        let (ca, issuer) = (&pair[0], &pair[1]);
        match crl::check(ca, issuer, &cache, opts.http, opts.now) {
            Ok(CrlStatus::Good) => {}
            Ok(CrlStatus::Revoked { time, .. }) => {
                let revoked = Revoked {
                    time,
                    source: "crl",
                    ca: Some(cert_name(ca)),
                };
                if let Some(revoked) = found(revoked) {
                    return Revocation::Revoked(revoked);
                }
            }
            Err(e) => {
                unavailable.get_or_insert_with(|| {
                    format!("CRL of CA certificate CN={}: {e}", cert_name(ca))
                });
            }
        }
    }

    match (unavailable, later) {
        (Some(why), _) => Revocation::Unavailable(why),
        (None, Some(revoked)) => Revocation::Revoked(revoked),
        (None, None) => Revocation::Good,
    }
}

/// `<issuer CN> -> … -> <anchor CN>` of a path (the certificate itself for a path of one),
/// or `FAIL <PathError>`.
fn chain_line(path: &Result<Vec<Certificate>, PathError>) -> String {
    match path {
        Ok(path) => path[1.min(path.len() - 1)..]
            .iter()
            .map(cert_name)
            .collect::<Vec<_>>()
            .join(" -> "),
        Err(e) => format!("FAIL {e:?}"),
    }
}

/// The subject CN of `cert`, or its whole subject without one.
fn cert_name(cert: &Certificate) -> String {
    cert_info(cert)
        .subject_cn
        .unwrap_or_else(|| cert.tbs_certificate().subject().to_string())
}

/// RFC 3339, or the formatting error (only for years beyond 9999).
fn rfc3339(time: OffsetDateTime) -> String {
    time.format(&Rfc3339).unwrap_or_else(|e| e.to_string())
}

/// The DER of a PEM input (the first block, any label), or the input as is.
fn pem_or_der(input: &[u8]) -> Result<Cow<'_, [u8]>, String> {
    let text = input.trim_ascii_start();
    if !text.starts_with(b"-----BEGIN ") {
        return Ok(Cow::Borrowed(input));
    }
    let text = std::str::from_utf8(text).map_err(|_| "PEM is not ASCII text".to_owned())?;
    let mut body = String::new();
    for line in text.lines().skip(1).map(str::trim) {
        if line.starts_with("-----END ") {
            return STANDARD
                .decode(&body)
                .map(Cow::Owned)
                .map_err(|e| format!("PEM: {e}"));
        }
        body.push_str(line);
    }
    Err("PEM: no END line".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_detection() {
        assert_eq!(pem_or_der(b"\x30\x03").unwrap(), &b"\x30\x03"[..]);
        let pem = "\r\n-----BEGIN CMS-----\r\nMAM=\r\n-----END CMS-----\r\n";
        assert_eq!(pem_or_der(pem.as_bytes()).unwrap(), &b"\x30\x03"[..]);
        assert!(pem_or_der(b"-----BEGIN CMS-----\nMAM=\n").is_err());
        assert!(pem_or_der(b"-----BEGIN CMS-----\n!!\n-----END CMS-----\n").is_err());
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
                allow_no_wss: false
            })
        ));
        let cli = Cli::try_parse_from(["openncalayer", "run", "--allow-no-wss"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Run { allow_no_wss: true })
        ));
    }

    #[cfg(feature = "e2e-prompter")]
    #[test]
    fn e2e_steps_parse() {
        use oncl_basics::testing::Step;

        let steps = parse_steps(
            r#"[{"storage":{"path":"k.p12","password":"pw"}},{"key":1},
                {"cancel_storage":null},{"cancel_key":null}]"#,
        )
        .unwrap();
        assert!(matches!(
            steps.as_slice(),
            [
                Step::Storage { path, password },
                Step::Key(1),
                Step::CancelStorage,
                Step::CancelKey,
            ] if path == Path::new("k.p12") && password == "pw"
        ));
        assert!(parse_steps(r#"[{"wait":null}]"#).is_err());
        assert!(parse_steps("{}").is_err());
    }
}
