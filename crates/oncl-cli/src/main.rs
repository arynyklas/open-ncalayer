mod args;
mod bounded;
mod control;
mod families;
mod jose;
mod jose_args;
mod local;
mod output;
mod public;
mod reports;
mod secrets;
mod sign;
mod terminal;
use clap::{CommandFactory, Parser};
fn diagnostic(arguments: std::fmt::Arguments<'_>) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr().lock(), "{arguments}");
}
fn main() {
    std::process::exit(entry());
}
fn entry() -> i32 {
    let cli = match args::Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            return match error.kind() {
                clap::error::ErrorKind::DisplayHelp => {
                    let _ = args::Cli::command().print_help();
                    0
                }
                clap::error::ErrorKind::DisplayVersion => {
                    println!("oncl {}", env!("CARGO_PKG_VERSION"));
                    0
                }
                _ => {
                    crate::diagnostic(format_args!(
                        "oncl: UsageError; use --help (argument values withheld)"
                    ));
                    1
                }
            };
        }
    };
    let _signals = match control::Signals::install() {
        Ok(signals) => signals,
        Err(_) => {
            crate::diagnostic(format_args!("oncl: SignalSetupFailed"));
            return 1;
        }
    };
    let control = match control::Control::new(std::time::Duration::from_secs(cli.timeout_seconds)) {
        Ok(control) => std::sync::Arc::new(control),
        Err(_) => {
            crate::diagnostic(format_args!("oncl: InvalidTimeout"));
            return 1;
        }
    };
    if let Err(code) = cli.preflight() {
        crate::diagnostic(format_args!("oncl: {code}"));
        return 1;
    }
    match local::run(&cli, control) {
        Ok(exit) => exit,
        Err(error) => {
            crate::diagnostic(format_args!(
                "oncl: {:?}; applied={:?}",
                error.code(),
                error.applied_state()
            ));
            if error.code() == oncl_core::ErrorCode::Cancelled {
                130
            } else {
                1
            }
        }
    }
}
