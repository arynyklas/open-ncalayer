//! The installer entry WinGet runs: `openncalayer-<version>-win-<arch>-winget-setup.exe --silent`.
//!
//! See [`oncl_winget_setup`] for what it does. The command line is `--silent` (required: the
//! entry shows no window of its own and never installs on a guess), and `--wait <seconds>`
//! (how long a busy OpenNCALayer is waited for; default 180). The exit codes are
//! [`oncl_winget_setup::Exit`]; 0 is the only success.

use std::process::ExitCode;
use std::time::Duration;

use oncl_winget_setup::{Exit, Report};

/// How long a busy OpenNCALayer is waited for when `--wait` does not say.
const DEFAULT_WAIT: Duration = Duration::from_secs(180);

const USAGE: &str = "usage: <installer> --silent [--wait <seconds>]\n\
    \n\
    Installs or updates OpenNCALayer for the current user. A running OpenNCALayer is asked to \
    finish what it is doing and hold still; it is never stopped by force. Exit code 0 means the \
    installed version is the one this installer carries; any other code means it is not (4: \
    OpenNCALayer is busy, try again later).";

fn usage(message: &str) -> Report {
    Report {
        exit: Exit::Usage,
        message: format!("{message}\n{USAGE}"),
    }
}

/// `--silent [--wait N]`: the wait, or why the command line is not understood.
fn parse(args: impl Iterator<Item = String>) -> Result<Option<Duration>, Report> {
    let mut silent = false;
    let mut wait = DEFAULT_WAIT;
    let mut args = args;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--silent" => silent = true,
            "--wait" => {
                let seconds = args
                    .next()
                    .and_then(|value| value.parse::<u32>().ok())
                    .ok_or_else(|| usage("--wait needs a number of seconds"))?;
                wait = Duration::from_secs(u64::from(seconds));
            }
            "--help" | "-h" | "/?" => {
                println!("{USAGE}");
                return Ok(None);
            }
            other => return Err(usage(&format!("unknown argument {other:?}"))),
        }
    }
    if silent {
        Ok(Some(wait))
    } else {
        Err(usage("--silent is required"))
    }
}

fn report(report: Report) -> ExitCode {
    eprintln!("{}", report.message);
    ExitCode::from(report.exit as u8)
}

fn main() -> ExitCode {
    let wait = match parse(std::env::args().skip(1)) {
        Ok(Some(wait)) => wait,
        Ok(None) => return ExitCode::SUCCESS,
        Err(failure) => return report(failure),
    };
    run(wait)
}

#[cfg(windows)]
fn run(wait: Duration) -> ExitCode {
    match oncl_winget_setup::production(wait) {
        Ok(config) => report(oncl_winget_setup::run(&config)),
        Err(e) => report(Report {
            exit: Exit::Failed,
            message: format!("the installation of this user cannot be located: {e}"),
        }),
    }
}

#[cfg(not(windows))]
fn run(_wait: Duration) -> ExitCode {
    report(Report {
        exit: Exit::Unsupported,
        message: "the WinGet installer entry of OpenNCALayer works on Windows only; nothing \
                  was installed"
            .to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> impl Iterator<Item = String> {
        list.iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn only_silent_installs_and_only_known_arguments_are_taken() {
        assert_eq!(parse(args(&["--silent"])).unwrap(), Some(DEFAULT_WAIT));
        assert_eq!(
            parse(args(&["--wait", "5", "--silent"])).unwrap(),
            Some(Duration::from_secs(5))
        );
        assert_eq!(parse(args(&["--help"])).unwrap(), None);
        for bad in [
            &[][..],
            &["--wait", "5"],
            &["--silent", "--wait"],
            &["--silent", "--wait", "soon"],
            &["--silent", "--nolaunch"],
            &["/S"],
        ] {
            let err = parse(args(bad)).unwrap_err();
            assert_eq!(err.exit, Exit::Usage, "{bad:?}");
        }
    }
}
