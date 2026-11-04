use clap::{Parser, Subcommand};
use oncl_pki::private_fs::PrivateDirectory;
use oncl_server::{
    auth::TokenSecret,
    config::ServerConfig,
    service::{ServiceHost, serve, tls_configuration},
};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};

#[derive(Parser)]
#[command(
    name = "oncl-server",
    version,
    about = "Explicitly enabled headless service; never installs trust or autostart"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        enable_api: bool,
        /// Explicit operator control pipe: one newline or EOF gracefully stops.
        #[arg(long)]
        shutdown_stdin: bool,
    },
    /// Write a fresh 256-bit token to an owner-only file; print verifier only.
    TokenCreate {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        name: String,
    },
    /// Put operator material (server.toml, key container, password, TLS key) into a private
    /// directory, from stdin or --input; never overwrites, never echoes the bytes.
    InstallFile {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        input: Option<PathBuf>,
    },
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => {
            eprintln!(
                "oncl-server: startup or execution refused (check operator configuration and private mounts)"
            );
            std::process::ExitCode::FAILURE
        }
    }
}
fn run() -> io::Result<()> {
    match Cli::parse().command {
        None => Ok(()),
        Some(Command::TokenCreate { directory, name }) => {
            let directory = if directory.exists() {
                PrivateDirectory::open(&directory)?
            } else {
                PrivateDirectory::create(&directory)?
            };
            let token = TokenSecret::generate()?;
            let mut file = directory.create_file(&name)?;
            file.write_all(token.bearer().as_bytes())?;
            file.sync_all()?;
            directory.sync()?;
            println!("verifier={}", token.verifier().encoded());
            Ok(())
        }
        Some(Command::InstallFile {
            directory,
            name,
            input,
        }) => {
            let bytes = oncl_server::install::install(
                &directory,
                &name,
                input.as_deref(),
                &mut io::stdin().lock(),
            )?;
            println!("installed {name} ({bytes} bytes)");
            Ok(())
        }
        Some(Command::Serve {
            config,
            enable_api,
            shutdown_stdin,
        }) => {
            let mut config = ServerConfig::read(&config)?;
            config.enabled |= enable_api;
            if !config.enabled {
                println!("disabled: no listener");
                return Ok(());
            }
            config.validate()?;
            let tls = tls_configuration(&config)?;
            let host = ServiceHost::new(config.clone())?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .max_blocking_threads(config.blocking_workers)
                .enable_all()
                .build()?;
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            let control = if shutdown_stdin {
                Some(std::thread::spawn(move || {
                    let mut byte = [0];
                    while io::stdin().read(&mut byte).is_ok_and(|n| n != 0) {
                        if byte[0] == b'\n' {
                            break;
                        }
                    }
                    let _ = stop_tx.send(());
                }))
            } else {
                drop(stop_tx);
                None
            };
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind(config.bind).await?;
                let address = listener.local_addr()?;
                let host = host.for_listener(address)?;
                println!("listening {address}");
                io::stdout().flush()?;
                let shutdown = async move {
                    if shutdown_stdin {
                        let _ = stop_rx.await;
                    } else {
                        let _ = tokio::signal::ctrl_c().await;
                    }
                };
                serve(listener, host, tls, shutdown).await
            })?;
            if let Some(control) = control {
                control
                    .join()
                    .map_err(|_| io::Error::other("operator control failed"))?;
            }
            println!("stopped: owned listener and workers released");
            Ok(())
        }
    }
}
