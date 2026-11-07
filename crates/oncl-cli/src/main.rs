mod args;
mod batch;
mod bounded;
mod control;
mod evidence;
mod families;
mod jose;
mod jose_args;
mod keysrc;
mod legacy;
mod local;
mod output;
mod pem;
mod plugin;
mod plugin_list;
mod public;
mod remote;
mod reports;
mod secrets;
mod sign;
mod terminal;
mod wsse;
use clap::Parser;
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
                // The help of the command asked for (`oncl plugin call --help` lists its flags).
                clap::error::ErrorKind::DisplayHelp => {
                    let _ = error.print();
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
    // `--endpoint` is the only way to leave this process; the failure contract is the same
    // `oncl: <code>; applied=<state>` line and exit status for local and remote runs.
    let outcome = if cli.endpoint.is_some() {
        remote::run(&cli, control)
    } else {
        local::run(&cli, control).map_err(remote::Failure::from)
    };
    match outcome {
        Ok(exit) => exit,
        Err(failure) => {
            match &failure.subcode {
                Some(subcode) => crate::diagnostic(format_args!(
                    "oncl: {}; subcode={subcode}; applied={:?}",
                    failure.code, failure.applied
                )),
                None => crate::diagnostic(format_args!(
                    "oncl: {}; applied={:?}",
                    failure.code, failure.applied
                )),
            }
            if failure.cancelled { 130 } else { 1 }
        }
    }
}
