//! `openncalayer`: see [`openncalayer::cli`].

use std::process::ExitCode;
use std::sync::Arc;
use std::thread;

use clap::Parser;
use oncl_pki::tsp::UreqTransport;
use oncl_ui::SlintPrompter;
use openncalayer::cli::{self, Cli, Command};
use openncalayer::{JsonSettings, ServerConfig, build_registry, serve};

fn main() -> ExitCode {
    match Cli::parse().command.unwrap_or(Command::Run) {
        Command::Run => run(),
        Command::Tls { command } => cli::tls(command),
        Command::CmsVerify { file, content } => cli::cms_verify(&file, content.as_deref()),
    }
}

/// The server runs on a tokio runtime in a background thread; the main thread runs the
/// dialogs' event loop, as windowing systems require. A stopped server ends the loop.
fn run() -> ExitCode {
    let daemon = match cli::prepare_run() {
        Ok(daemon) => daemon,
        Err(code) => return code,
    };
    let registry = build_registry(
        Arc::new(SlintPrompter::new()),
        Arc::new(JsonSettings::new(daemon.paths.settings())),
        Arc::new(UreqTransport),
    );
    let cfg = ServerConfig::new(daemon.tls, Arc::new(registry));
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
    let listener = daemon.listener;
    let server = thread::Builder::new().name("server".into()).spawn(move || {
        let result = runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener)?;
            serve(listener, cfg).await
        });
        if let Err(e) = &result {
            tracing::error!(error = %e, "server stopped");
        }
        oncl_ui::quit();
        result
    });
    let server = match server {
        Ok(server) => server,
        Err(e) => {
            eprintln!("Не удалось запустить сервер: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = oncl_ui::run_event_loop() {
        tracing::error!(error = %e, "signing dialogs are unavailable");
        eprintln!("Не удалось показать окна подписи: {e}");
        return ExitCode::FAILURE;
    }
    match server.join() {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(_)) | Err(_) => ExitCode::FAILURE,
    }
}
