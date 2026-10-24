//! `openncalayer`: see [`openncalayer::cli`].

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use oncl_basics::{KeyPrompt, Prompt, Prompter, StorageAnswer, StoragePrompt};
use oncl_pki::tsp::UreqTransport;
use openncalayer::cli::{self, Cli, Command};
use openncalayer::{JsonSettings, ServerConfig, build_registry, serve};

fn main() -> ExitCode {
    match Cli::parse().command.unwrap_or(Command::Run) {
        Command::Run => run(),
        Command::Tls { command } => cli::tls(command),
        Command::CmsVerify { file, content } => cli::cms_verify(&file, content.as_deref()),
    }
}

fn run() -> ExitCode {
    let daemon = match cli::prepare_run() {
        Ok(daemon) => daemon,
        Err(code) => return code,
    };
    let registry = build_registry(
        Arc::new(NoDialogs),
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
    let result = runtime.block_on(async {
        let listener = tokio::net::TcpListener::from_std(daemon.listener)?;
        serve(listener, cfg).await
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "server stopped");
            ExitCode::FAILURE
        }
    }
}

/// The signing dialogs are not part of this build yet: every dialog is cancelled, so
/// sites get the original's "cancelled" answer.
struct NoDialogs;

impl NoDialogs {
    fn cancelled<T>(origin: &str) -> Prompt<T> {
        tracing::warn!(
            origin,
            "signing dialogs are not available in this build: cancelled"
        );
        Prompt::Cancelled
    }
}

impl Prompter for NoDialogs {
    fn storage(&self, p: &StoragePrompt) -> Prompt<StorageAnswer> {
        Self::cancelled(&p.origin)
    }

    fn key(&self, p: &KeyPrompt) -> Prompt<usize> {
        Self::cancelled(&p.origin)
    }
}
