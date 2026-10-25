//! The relay: its config, its own frames, reaching the daemon and moving frames between the
//! browser's stdio and the daemon's IPC endpoint.

use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use oncl_ipc::{
    IpcStream, NM_OUT_LIMIT, connect, endpoint, read_frame, read_nm_frame, write_frame,
    write_nm_frame,
};
use serde::{Deserialize, Serialize};
use tokio::io::{ReadHalf, Stdout, WriteHalf};
use tokio::sync::Mutex;
use tokio::time::{Instant, sleep};

use crate::spawn;

/// Version of the relay, sent in its `relay` frame.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Name of the config file next to the relay's executable.
const CONFIG_FILE: &str = "nmhost.json";

/// Pause between attempts to reach a daemon the relay has started.
const RETRY_EVERY: Duration = Duration::from_millis(200);
/// How long a daemon the relay has started gets to open its endpoint.
const START_PATIENCE: Duration = Duration::from_secs(15);
/// Exit code of a daemon that found the endpoint taken (`openncalayer`'s
/// `EXIT_ALREADY_RUNNING`): another daemon is starting, the relay keeps waiting for it.
const EXIT_ALREADY_RUNNING: i32 = 4;

/// `nmhost.json`, written next to the relay by `openncalayer nm install`.
#[derive(Debug, Deserialize)]
pub struct RelayConfig {
    /// The daemon's data directory; selects its IPC endpoint.
    pub data_dir: PathBuf,
    /// The `openncalayer` executable, started when no daemon listens.
    pub daemon: PathBuf,
}

impl RelayConfig {
    /// Reads the config at `path`. Both paths must be absolute: a relative `daemon` would be
    /// looked up in the browser's search path and working directory.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text =
            std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let config: Self = serde_json::from_slice(&text)
            .map_err(|e| format!("{} is invalid: {e}", path.display()))?;
        for (field, value) in [("data_dir", &config.data_dir), ("daemon", &config.daemon)] {
            if !value.is_absolute() {
                return Err(format!(
                    "{}: {field} {} is not an absolute path",
                    path.display(),
                    value.display()
                ));
            }
        }
        Ok(config)
    }
}

/// Why the relay ends while the browser still listens; the `code` of its `error` frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Code {
    RelayConfig,
    DaemonUnavailable,
    DaemonUntrusted,
    DaemonGone,
    Protocol,
}

impl Code {
    fn exit_code(self) -> u8 {
        match self {
            Self::DaemonGone => 0,
            _ => 1,
        }
    }
}

#[derive(Debug)]
struct Failure {
    code: Code,
    message: String,
}

impl Failure {
    fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// The relay's own frames to the browser.
#[derive(Serialize)]
#[serde(tag = "t", rename_all = "lowercase")]
enum Frame<'a> {
    Relay { v: u8, version: &'a str },
    Error { code: Code, message: &'a str },
}

/// The browser's end of the relay's stdout: whoever writes a frame holds the lock for the
/// whole frame.
type BrowserOut = Arc<Mutex<Stdout>>;

/// Runs the relay to its end; the process exit code.
pub async fn run() -> u8 {
    let out = Arc::new(Mutex::new(tokio::io::stdout()));
    let Err(failure) = relay(&out).await else {
        return 0;
    };
    eprintln!("nmhost: {:?}: {}", failure.code, failure.message);
    let mut out = out.lock().await;
    let frame = Frame::Error {
        code: failure.code,
        message: &failure.message,
    };
    // The browser may be gone already; nobody to tell then.
    let _ = send(&mut out, &frame).await;
    // The lock goes with this function, and the runtime stops right after it: no frame of
    // the daemon can follow the error.
    failure.code.exit_code()
}

/// `Ok` once the browser has hung up.
async fn relay(out: &BrowserOut) -> Result<(), Failure> {
    let config = config_path()
        .and_then(|path| RelayConfig::load(&path))
        .map_err(|message| Failure::new(Code::RelayConfig, message))?;
    let hello = Frame::Relay {
        v: 1,
        version: VERSION,
    };
    if send(&mut *out.lock().await, &hello).await.is_err() {
        return Ok(());
    }
    let daemon = reach_daemon(&config).await?;
    pump(daemon, out).await
}

fn config_path() -> Result<PathBuf, String> {
    std::env::current_exe()
        .map(|exe| exe.with_file_name(CONFIG_FILE))
        .map_err(|e| format!("cannot locate the relay executable: {e}"))
}

async fn send(out: &mut Stdout, frame: &Frame<'_>) -> io::Result<()> {
    let json = serde_json::to_vec(frame).map_err(io::Error::other)?;
    write_nm_frame(out, &json).await
}

/// Connects to the daemon of `config`, starting it if none listens.
async fn reach_daemon(config: &RelayConfig) -> Result<IpcStream, Failure> {
    let ep = endpoint(&config.data_dir).map_err(|e| {
        Failure::new(
            Code::DaemonUnavailable,
            format!("no IPC endpoint for {}: {e}", config.data_dir.display()),
        )
    })?;
    match connect(&ep).await {
        Ok(stream) => return Ok(stream),
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {}
        Err(e) => return Err(refused(&ep, &e)),
    }
    let mut started = Some(
        spawn::daemon(&config.daemon, &config.data_dir).map_err(|e| {
            Failure::new(
                Code::DaemonUnavailable,
                format!("cannot start {}: {e}", config.daemon.display()),
            )
        })?,
    );
    let deadline = Instant::now() + START_PATIENCE;
    loop {
        sleep(RETRY_EVERY).await;
        let e = match connect(&ep).await {
            Ok(stream) => return Ok(stream),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return Err(refused(&ep, &e)),
            Err(e) => e,
        };
        // A daemon that died at startup is not waited for; one that found another daemon
        // starting (exit 4) leaves the wait to that one.
        if let Some(child) = &mut started {
            match child.try_wait() {
                Ok(None) => {}
                Ok(Some(status)) if status.code() == Some(EXIT_ALREADY_RUNNING) => started = None,
                Ok(Some(status)) => {
                    return Err(Failure::new(
                        Code::DaemonUnavailable,
                        format!("{} exited at startup: {status}", config.daemon.display()),
                    ));
                }
                Err(_) => started = None,
            }
        }
        if Instant::now() >= deadline {
            return Err(Failure::new(
                Code::DaemonUnavailable,
                format!(
                    "the daemon did not open {ep} within {} s: {e}",
                    START_PATIENCE.as_secs()
                ),
            ));
        }
    }
}

fn refused(ep: &oncl_ipc::Endpoint, e: &io::Error) -> Failure {
    if e.kind() == ErrorKind::PermissionDenied {
        Failure::new(
            Code::DaemonUntrusted,
            format!("{ep} is not served by this user: {e}"),
        )
    } else {
        Failure::new(
            Code::DaemonUnavailable,
            format!("cannot connect to {ep}: {e}"),
        )
    }
}

/// Moves frames both ways until either side ends.
async fn pump(daemon: IpcStream, out: &BrowserOut) -> Result<(), Failure> {
    let (from_daemon, mut to_daemon) = tokio::io::split(daemon);
    // A task of its own rather than a `select!` branch: when the browser side ends first, a
    // frame half written to stdout must be finished, not dropped, before the error frame.
    let downstream = tokio::spawn(daemon_to_browser(from_daemon, Arc::clone(out)));
    tokio::select! {
        end = browser_to_daemon(&mut to_daemon) => end,
        joined = downstream => {
            joined.unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))
        }
    }
}

async fn browser_to_daemon(to_daemon: &mut WriteHalf<IpcStream>) -> Result<(), Failure> {
    let mut stdin = tokio::io::stdin();
    loop {
        let frame = match read_nm_frame(&mut stdin).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(e) => {
                return Err(Failure::new(
                    Code::Protocol,
                    format!("bad frame from the browser: {e}"),
                ));
            }
        };
        write_frame(to_daemon, &frame).await.map_err(|e| {
            Failure::new(Code::DaemonGone, format!("cannot write to the daemon: {e}"))
        })?;
    }
}

async fn daemon_to_browser(
    mut from_daemon: ReadHalf<IpcStream>,
    out: BrowserOut,
) -> Result<(), Failure> {
    loop {
        let frame = match read_frame(&mut from_daemon).await {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                return Err(Failure::new(
                    Code::DaemonGone,
                    "the daemon closed the connection",
                ));
            }
            Err(e) if e.kind() == ErrorKind::InvalidData => {
                return Err(Failure::new(
                    Code::Protocol,
                    format!("bad frame from the daemon: {e}"),
                ));
            }
            Err(e) => {
                return Err(Failure::new(
                    Code::DaemonGone,
                    format!("lost the connection to the daemon: {e}"),
                ));
            }
        };
        if frame.len() > NM_OUT_LIMIT {
            return Err(Failure::new(
                Code::Protocol,
                format!(
                    "frame of {} bytes from the daemon exceeds the browser's limit of \
                     {NM_OUT_LIMIT}",
                    frame.len()
                ),
            ));
        }
        if write_nm_frame(&mut *out.lock().await, &frame)
            .await
            .is_err()
        {
            // The browser has hung up.
            return Ok(());
        }
    }
}
