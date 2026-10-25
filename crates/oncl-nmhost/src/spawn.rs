//! Starting the daemon detached from the relay and the browser.

use std::io;
use std::path::Path;
use std::process::Stdio;

use tokio::process::{Child, Command};

/// Starts `<daemon> run --allow-no-wss` with the relay's environment plus `ONCL_DATA_DIR`,
/// detached: the daemon outlives the relay and the browser, has no console, and holds none
/// of the browser's pipes (its stdio is the null device). The child is only watched for an
/// early exit, never killed.
pub fn daemon(daemon: &Path, data_dir: &Path) -> io::Result<Child> {
    let mut command = Command::new(daemon);
    command
        .args(["run", "--allow-no-wss"])
        .env("ONCL_DATA_DIR", data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    start(&mut command)
}

#[cfg(unix)]
fn start(command: &mut Command) -> io::Result<Child> {
    // Out of the browser's process group: signals to the browser's group miss the daemon.
    command.process_group(0).spawn()
}

#[cfg(windows)]
fn start(command: &mut Command) -> io::Result<Child> {
    use oncl_ipc::process::{
        CREATE_BREAKAWAY_FROM_JOB, DETACHED_CREATION_FLAGS, breakaway_refused,
        prepare_detached_spawn,
    };

    if let Err(e) = prepare_detached_spawn() {
        eprintln!("nmhost: the daemon may inherit the browser's pipes: {e}");
    }
    match command
        .creation_flags(DETACHED_CREATION_FLAGS | CREATE_BREAKAWAY_FROM_JOB)
        .spawn()
    {
        Err(e) if breakaway_refused(&e) => command.creation_flags(DETACHED_CREATION_FLAGS).spawn(),
        spawned => spawned,
    }
}
