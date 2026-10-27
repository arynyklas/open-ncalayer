//! `openncalayer`: see [`openncalayer::cli`].

use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use clap::Parser;
use oncl_basics::{Locale, Prompter};
use oncl_ipc::IpcListener;
use oncl_pki::http::UreqTransport;
use oncl_protocol::Registry;
use oncl_ui::{SlintPrompter, TrayCommand, TrayHandle, TrayState};
use openncalayer::cli::{self, Cli, Command};
use openncalayer::{JsonSettings, ServerConfig, build_registry, load_settings, serve, serve_ipc};
use tokio::runtime::Runtime;
use tokio::sync::Notify;

/// How long `run` waits for the server thread once the dialogs' event loop has ended.
const SERVER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> ExitCode {
    let command = Cli::parse().command.unwrap_or(Command::Run {
        allow_no_wss: false,
        no_tray: false,
    });
    match command {
        Command::Run {
            allow_no_wss,
            no_tray,
        } => run(allow_no_wss, !no_tray),
        Command::Tls { command } => cli::tls(command),
        Command::CmsVerify {
            file,
            content,
            chain,
            offline,
        } => cli::cms_verify(&file, content.as_deref(), &chain, offline),
        Command::Nm { command } => cli::nm(command),
    }
}

/// The servers run on a tokio runtime in a background thread; the main thread runs the
/// event loop of the dialogs and the tray, as windowing systems require. «Выход» in the
/// tray stops the servers, and a stopped server ends the loop; closing windows does not.
/// With feature `e2e-prompter` and its script set there are no windows: without a tray the
/// main thread only waits for the servers. A tray that cannot be shown is only logged.
fn run(allow_no_wss: bool, with_tray: bool) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("Не удалось запустить сервер: {e}");
            return ExitCode::FAILURE;
        }
    };
    let daemon = match runtime.block_on(cli::prepare_run(allow_no_wss)) {
        Ok(daemon) => daemon,
        Err(code) => return code,
    };
    // Panics (e.g. of the windowing libraries) go to the log, not as raw text to stderr only.
    std::panic::set_hook(Box::new(|info| tracing::error!(%info, "panic")));
    let scripted = match scripted_prompter() {
        Ok(scripted) => scripted,
        Err(code) => return code,
    };
    let windows = scripted.is_none();
    let settings = load_settings(&daemon.paths.settings());
    let registry = build_registry(
        scripted.unwrap_or_else(|| Arc::new(SlintPrompter::new())),
        Arc::new(JsonSettings::new(daemon.paths.settings())),
        Arc::new(UreqTransport::with_proxy(settings.proxy.clone())),
        // The windows arrive in P5; until then a request to open one is only logged.
        Arc::new(|window| tracing::info!(?window, "window requested; not available yet")),
    );
    let stop = Arc::new(Notify::new());
    let tray = if with_tray {
        start_tray(
            settings.ui_locale(),
            daemon.paths.logs(),
            daemon.wss_off,
            Arc::clone(&stop),
        )
    } else {
        None
    };
    let event_loop = windows || tray.is_some();
    let (ipc, wss) = (daemon.ipc, daemon.wss);
    let server = thread::Builder::new().name("server".into()).spawn(move || {
        let result = runtime.block_on(serve_all(ipc, wss, Arc::new(registry), stop));
        if let Err(e) = &result {
            tracing::error!(error = %e, "server stopped");
        }
        stop_runtime(runtime);
        if event_loop {
            oncl_ui::quit();
        }
        result
    });
    let server = match server {
        Ok(server) => server,
        Err(e) => {
            eprintln!("Не удалось запустить сервер: {e}");
            return ExitCode::FAILURE;
        }
    };
    if !event_loop {
        return exit_code(server.join());
    }
    if let Err(e) = oncl_ui::run_event_loop() {
        if !windows {
            // Only the tray needed the loop: the servers carry on without it.
            tracing::warn!(error = %e, "the system tray is unavailable; running without it");
            drop(tray);
            return exit_code(server.join());
        }
        tracing::error!(error = %e, "signing dialogs are unavailable");
        eprintln!("Не удалось показать окна подписи: {e}");
        if cfg!(target_os = "linux") {
            eprintln!(
                "Нужны графический сеанс (DISPLAY или WAYLAND_DISPLAY) и библиотеки окон, \
                 в Debian и Ubuntu — пакет libxkbcommon-x11-0."
            );
        }
        return ExitCode::FAILURE;
    }
    // The icon goes before the process does (on Windows a dead process's icon lingers).
    drop(tray);
    match join_within(server, SERVER_JOIN_TIMEOUT) {
        Some(result) => exit_code(result),
        None => {
            tracing::error!("the dialog event loop ended while the server is running");
            ExitCode::FAILURE
        }
    }
}

/// The exit code of the joined server thread.
fn exit_code(server: thread::Result<io::Result<()>>) -> ExitCode {
    match server {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(_)) | Err(_) => ExitCode::FAILURE,
    }
}

/// The tray in `locale` with `warning` shown, or `None` (logged) if it cannot be shown. Its
/// commands run on the event loop: «Выход» notifies `stop`, «Журнал» opens `logs`.
fn start_tray(
    locale: Locale,
    logs: PathBuf,
    warning: Option<String>,
    stop: Arc<Notify>,
) -> Option<TrayHandle> {
    let tray = oncl_ui::start_tray(locale, move |command| match command {
        TrayCommand::Quit => {
            tracing::info!("quit from the tray");
            stop.notify_one();
        }
        TrayCommand::OpenLogs => open_folder(&logs),
        TrayCommand::Settings
        | TrayCommand::TlsWizard
        | TrayCommand::About
        | TrayCommand::StopOriginal => {
            tracing::info!(?command, "window requested; not available yet");
        }
    });
    match tray {
        Ok(tray) => {
            tray.set_state(TrayState { warning });
            Some(tray)
        }
        Err(e) => {
            tracing::warn!(error = %e, "the system tray is unavailable; running without it");
            None
        }
    }
}

/// Shows `dir`, created if missing, in the file manager without waiting for it.
fn open_folder(dir: &Path) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::warn!(dir = %dir.display(), error = %e, "cannot create the directory");
        return;
    }
    let mut command = file_manager(dir);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match command.spawn() {
        // Reaped in the background: a file manager may take its time to return.
        Ok(mut child) => {
            if let Err(e) = thread::Builder::new()
                .name("file-manager".into())
                .spawn(move || child.wait())
            {
                tracing::warn!(error = %e, "cannot wait for the file manager");
            }
        }
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "cannot open the file manager");
        }
    }
}

/// The command that shows `dir` in the platform's file manager.
fn file_manager(dir: &Path) -> std::process::Command {
    let program = if cfg!(windows) {
        "explorer"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let mut command = std::process::Command::new(program);
    command.arg(dir);
    command
}

/// The prompter of the `e2e-prompter` script, if the feature is on and the script set.
fn scripted_prompter() -> Result<Option<Arc<dyn Prompter>>, ExitCode> {
    #[cfg(feature = "e2e-prompter")]
    let scripted = cli::e2e_prompter()?.map(|p| Arc::new(p) as Arc<dyn Prompter>);
    #[cfg(not(feature = "e2e-prompter"))]
    let scripted = None;
    Ok(scripted)
}

/// The bridge and, unless it is off, the wss server, until either stops or `stop` is
/// notified.
async fn serve_all(
    ipc: IpcListener,
    wss: Option<(Arc<rustls::ServerConfig>, TcpListener)>,
    registry: Arc<Registry>,
    stop: Arc<Notify>,
) -> io::Result<()> {
    let stopped = async move {
        stop.notified().await;
        tracing::info!("stopping the servers");
        Ok(())
    };
    let Some((tls, listener)) = wss else {
        return tokio::select! {
            result = serve_ipc(ipc, registry) => result,
            result = stopped => result,
        };
    };
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let cfg = ServerConfig::new(tls, Arc::clone(&registry));
    tokio::select! {
        result = serve_ipc(ipc, registry) => result,
        result = serve(listener, cfg) => result,
        result = stopped => result,
    }
}

/// Drops `runtime` without waiting for its blocking tasks: a signing flow may be blocked in
/// a dialog that will never answer once the server has stopped.
fn stop_runtime(runtime: Runtime) {
    runtime.shutdown_background();
}

/// Joins `thread` if it finishes within `timeout`; `None` leaves it running.
fn join_within<T>(thread: JoinHandle<T>, timeout: Duration) -> Option<thread::Result<T>> {
    let deadline = Instant::now() + timeout;
    while !thread.is_finished() {
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
    Some(thread.join())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn join_gives_up_on_a_running_thread() {
        let done = thread::spawn(|| 7);
        assert_eq!(
            join_within(done, Duration::from_secs(5)).unwrap().unwrap(),
            7
        );

        let (tx, rx) = mpsc::channel::<()>();
        let stuck = thread::spawn(move || rx.recv());
        let started = Instant::now();
        assert!(join_within(stuck, Duration::from_millis(100)).is_none());
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(tx);
    }

    #[test]
    fn runtime_stops_despite_a_blocked_task() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (tx, rx) = mpsc::channel::<()>();
        // Like a signing flow waiting for a dialog that never answers.
        drop(runtime.spawn_blocking(move || rx.recv()));
        let started = Instant::now();
        stop_runtime(runtime);
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(tx);
    }

    /// `serve_all` with the bridge in `dir` and, if `wss`, a wss server on a free port;
    /// `stop` notified before it starts.
    async fn serve_all_stopped(dir: &Path, wss: bool) -> io::Result<()> {
        let ipc = oncl_ipc::bind(&oncl_ipc::endpoint(dir).unwrap())
            .await
            .unwrap();
        let wss = wss.then(|| {
            let files = oncl_tls::TlsFiles {
                dir: dir.join("tls"),
            };
            let material = oncl_tls::generate(time::OffsetDateTime::now_utc(), "stop").unwrap();
            oncl_tls::save(&files, &material).unwrap();
            let tls = Arc::new(oncl_tls::server_config(&files).unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            (tls, listener)
        });
        let stop = Arc::new(Notify::new());
        // Like «Выход» picked before the servers got to wait for it.
        stop.notify_one();
        tokio::time::timeout(
            Duration::from_secs(10),
            serve_all(ipc, wss, Arc::new(Registry::default()), stop),
        )
        .await
        .expect("the servers did not stop")
    }

    #[test]
    fn stop_ends_the_servers() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        for wss in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            runtime
                .block_on(serve_all_stopped(dir.path(), wss))
                .unwrap_or_else(|e| panic!("wss {wss}: {e}"));
        }
    }

    #[test]
    fn file_manager_opens_the_directory() {
        let dir = Path::new("data").join("logs");
        let command = file_manager(&dir);
        let expected = if cfg!(windows) {
            "explorer"
        } else if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        assert_eq!(command.get_program(), expected);
        assert_eq!(command.get_args().collect::<Vec<_>>(), [dir.as_os_str()]);
    }
}
