//! The command line: `run` (the default), `tls init|import|status` and `cms-verify`.
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
use oncl_pki::cms;
use oncl_pki::info::cert_info;
use oncl_pki::tsp::{TspError, verify_token_for};
use oncl_tls::{
    RENEW_BEFORE, TargetOs, TlsFiles, TlsInfo, TlsSource, TlsWarning, instructions, load_info,
    server_config, sha1_grouped,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::paths::Paths;
use crate::server::listen_port;

/// Exit code: TLS is not set up yet.
pub const EXIT_TLS_NOT_CONFIGURED: u8 = 2;
/// Exit code: the port is taken.
pub const EXIT_PORT_BUSY: u8 = 3;

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
    Run,
    #[command(about = "Сертификат HTTPS/WSS-сервера")]
    Tls {
        #[command(subcommand)]
        command: TlsCommand,
    },
    #[command(about = "Проверить CMS-подпись (PEM или DER)")]
    CmsVerify {
        #[arg(help = "Файл подписи (.p7s, .cms, PEM или DER)")]
        file: PathBuf,
        #[arg(long, help = "Подписанные данные для подписи без вложенных данных")]
        content: Option<PathBuf>,
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

/// Everything `run` sets up before the server starts: data paths, logging, the TLS
/// configuration and the bound listening socket (non-blocking, for tokio).
pub struct Daemon {
    pub paths: Paths,
    pub tls: Arc<rustls::ServerConfig>,
    pub listener: TcpListener,
}

/// Prepares `run`. On failure the message is already printed and the exit code returned:
/// [`EXIT_TLS_NOT_CONFIGURED`], [`EXIT_PORT_BUSY`] or 1.
pub fn prepare_run() -> Result<Daemon, ExitCode> {
    let paths = data_paths()?;
    if let Err(e) = crate::logging::init(&paths.logs()) {
        warn!(dir = %paths.logs().display(), error = %e, "file logging is disabled");
    }
    let files = paths.tls();
    configured(&files)?;
    let tls = server_config(&files).map_err(|e| {
        eprintln!(
            "Не удалось загрузить сертификат сервера из {}: {e}",
            files.dir.display()
        );
        ExitCode::FAILURE
    })?;
    let port = listen_port();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map_err(|e| {
        if port_busy(&e) {
            eprintln!("Порт {port} занят (возможно, запущен оригинальный NCALayer)");
            ExitCode::from(EXIT_PORT_BUSY)
        } else {
            eprintln!("Не удалось открыть порт 127.0.0.1:{port}: {e}");
            ExitCode::FAILURE
        }
    })?;
    listener.set_nonblocking(true).map_err(|e| {
        eprintln!("Не удалось настроить порт 127.0.0.1:{port}: {e}");
        ExitCode::FAILURE
    })?;
    info!(data = %paths.data.display(), "listening on 127.0.0.1:{port}");
    Ok(Daemon {
        paths,
        tls: Arc::new(tls),
        listener,
    })
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

/// The stored [`TlsInfo`], or the "not configured" message and exit code.
fn configured(files: &TlsFiles) -> Result<TlsInfo, ExitCode> {
    match load_info(files) {
        Ok(Some(info)) => Ok(info),
        Ok(None) => {
            eprintln!("TLS не настроен: выполните `openncalayer tls init`");
            Err(ExitCode::from(EXIT_TLS_NOT_CONFIGURED))
        }
        Err(e) => {
            eprintln!("Не удалось прочитать {}: {e}", files.info().display());
            Err(ExitCode::FAILURE)
        }
    }
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
    let info = configured(files)?;
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

/// `cms-verify <file> [--content <file>]`: prints [`cms_verify_report`]; exit code 0 when
/// it ends with `OK`, otherwise 1.
pub fn cms_verify(file: &Path, content: Option<&Path>) -> ExitCode {
    let read = |path: &Path| fs::read(path).map_err(|e| format!("{}: {e}", path.display()));
    let inputs = read(file).and_then(|cms| Ok((cms, content.map(read).transpose()?)));
    let (report, ok) = match inputs {
        Ok((cms, content)) => cms_verify_report(&cms, content.as_deref()),
        Err(e) => (format!("FAIL: {e}\n"), false),
    };
    print!("{report}");
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// The line before `OK` in a [`cms_verify_report`]: what `OK` does not mean.
pub const NOT_CHECKED: &str = "not checked: certificate chains, validity periods, revocation";

/// Verifies a CMS signature, PEM or DER/BER, over its encapsulated content or `content`.
///
/// The report has a block per signer (numbered from 0, as in error messages):
/// `signer <n>: CN=<cn>, IIN=<iin|->, alg=<SigAlg>, signingTime=<RFC 3339|->` and
/// `timestamp: yes|no` (whether the signer carries a time-stamp token); its last line is
/// `OK` if every signature verifies and every token verifies and covers its signer's
/// signature, otherwise `FAIL: <error>`. Returns the report and whether it is `OK`.
/// Certificate chains, validity and revocation are not checked, and an `OK` report says
/// so in the line [`NOT_CHECKED`] before `OK`.
pub fn cms_verify_report(input: &[u8], content: Option<&[u8]>) -> (String, bool) {
    let mut report = String::new();
    match describe(input, content, &mut report) {
        Ok(()) => {
            let _ = writeln!(report, "{NOT_CHECKED}\nOK");
            (report, true)
        }
        Err(e) => {
            let _ = writeln!(report, "FAIL: {e}");
            (report, false)
        }
    }
}

/// Writes the signer blocks; the first failure is the error.
fn describe(input: &[u8], content: Option<&[u8]>, report: &mut String) -> Result<(), String> {
    let der = pem_or_der(input)?;
    let signers = cms::verify(&der, content).map_err(|e| e.to_string())?;
    let mut failure = None;
    for (n, signer) in signers.iter().enumerate() {
        let info = cert_info(&signer.cert);
        let signing_time = match signer.signing_time.map(|t| t.format(&Rfc3339)) {
            Some(Ok(t)) => t,
            Some(Err(e)) => e.to_string(),
            None => "-".to_owned(),
        };
        let _ = writeln!(
            report,
            "signer {n}: CN={}, IIN={}, alg={:?}, signingTime={signing_time}",
            info.subject_cn.as_deref().unwrap_or("-"),
            info.iin.as_deref().unwrap_or("-"),
            signer.sig_alg,
        );
        let timestamp = match &signer.timestamp_token {
            Some(token) => {
                if let Err(e) = verify_token_for(token, &signer.signature) {
                    failure.get_or_insert_with(|| match e {
                        TspError::ImprintMismatch => {
                            format!("time-stamp of signer {n} does not cover its signature")
                        }
                        e => format!("time-stamp of signer {n}: {e}"),
                    });
                }
                "yes"
            }
            None => "no",
        };
        let _ = writeln!(report, "timestamp: {timestamp}");
    }
    failure.map_or(Ok(()), Err)
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
        assert!(matches!(cli.command, Some(Command::CmsVerify { .. })));
    }
}
