//! `openncalayer`: see [`openncalayer::cli`].

use std::io;
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use clap::Parser;
use oncl_basics::Prompter;
use oncl_ipc::IpcListener;
use oncl_pki::http::UreqTransport;
use oncl_protocol::Registry;
use oncl_ui::SlintPrompter;
use openncalayer::cli::{self, Cli, Command};
use openncalayer::{JsonSettings, ServerConfig, build_registry, serve, serve_ipc};
use tokio::runtime::Runtime;

/// How long `run` waits for the server thread once the dialogs' event loop has ended.
const SERVER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> ExitCode {
    let command = Cli::parse().command.unwrap_or(Command::Run {
        allow_no_wss: false,
    });
    match command {
        Command::Run { allow_no_wss } => run(allow_no_wss),
        Command::Tls { command } => cli::tls(command),
        Command::CmsVerify { file, content } => cli::cms_verify(&file, content.as_deref()),
        Command::Nm { command } => cli::nm(command),
    }
}

/// The servers run on a tokio runtime in a background thread; the main thread runs the
/// dialogs' event loop, as windowing systems require. A stopped server ends the loop. With
/// feature `e2e-prompter` and its script set, there are no windows: the main thread only
/// waits for the servers.
fn run(allow_no_wss: bool) -> ExitCode {
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
    let registry = build_registry(
        scripted.unwrap_or_else(|| Arc::new(SlintPrompter::new())),
        Arc::new(JsonSettings::new(daemon.paths.settings())),
        Arc::new(UreqTransport),
    );
    let (ipc, wss) = (daemon.ipc, daemon.wss);
    let server = thread::Builder::new().name("server".into()).spawn(move || {
        let result = runtime.block_on(serve_all(ipc, wss, Arc::new(registry)));
        if let Err(e) = &result {
            tracing::error!(error = %e, "server stopped");
        }
        stop_runtime(runtime);
        if windows {
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
    if !windows {
        return match server.join() {
            Ok(Ok(())) => ExitCode::SUCCESS,
            Ok(Err(_)) | Err(_) => ExitCode::FAILURE,
        };
    }
    if let Err(e) = oncl_ui::run_event_loop() {
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
    match join_within(server, SERVER_JOIN_TIMEOUT) {
        Some(Ok(Ok(()))) => ExitCode::SUCCESS,
        Some(Ok(Err(_)) | Err(_)) => ExitCode::FAILURE,
        None => {
            tracing::error!("the dialog event loop ended while the server is running");
            ExitCode::FAILURE
        }
    }
}

/// The prompter of the `e2e-prompter` script, if the feature is on and the script set.
fn scripted_prompter() -> Result<Option<Arc<dyn Prompter>>, ExitCode> {
    #[cfg(feature = "e2e-prompter")]
    let scripted = cli::e2e_prompter()?.map(|p| Arc::new(p) as Arc<dyn Prompter>);
    #[cfg(not(feature = "e2e-prompter"))]
    let scripted = None;
    Ok(scripted)
}

/// The bridge and, unless it is off, the wss server, until either stops.
async fn serve_all(
    ipc: IpcListener,
    wss: Option<(Arc<rustls::ServerConfig>, TcpListener)>,
    registry: Arc<Registry>,
) -> io::Result<()> {
    let Some((tls, listener)) = wss else {
        return serve_ipc(ipc, registry).await;
    };
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let cfg = ServerConfig::new(tls, Arc::clone(&registry));
    tokio::select! {
        result = serve_ipc(ipc, registry) => result,
        result = serve(listener, cfg) => result,
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
}
