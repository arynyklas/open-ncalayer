//! Starting the daemon detached from the relay and the browser.

use std::io;
use std::path::Path;
use std::process::Stdio;

use tokio::process::Command;

/// Starts `<daemon> run --allow-no-wss` with the relay's environment plus `ONCL_DATA_DIR`,
/// detached: the daemon outlives the relay and the browser, has no console, and holds none
/// of the browser's pipes (its stdio is the null device). It is not waited for.
pub fn daemon(daemon: &Path, data_dir: &Path) -> io::Result<()> {
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
fn start(command: &mut Command) -> io::Result<()> {
    // Out of the browser's process group: signals to the browser's group miss the daemon.
    command.process_group(0).spawn().map(drop)
}

#[cfg(windows)]
fn start(command: &mut Command) -> io::Result<()> {
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
    use windows_sys::Win32::System::Threading::{
        CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
    };

    keep_stdio_from_children();
    let detached = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    // Out of the browser's job too, so that closing the browser does not kill the daemon.
    match command
        .creation_flags(detached | CREATE_BREAKAWAY_FROM_JOB)
        .spawn()
    {
        Ok(_) => Ok(()),
        // The job forbids breakaway.
        Err(e) if e.raw_os_error() == i32::try_from(ERROR_ACCESS_DENIED).ok() => {
            command.creation_flags(detached).spawn().map(drop)
        }
        Err(e) => Err(e),
    }
}

/// Makes the relay's standard handles non-inheritable.
///
/// Children inherit every inheritable handle of the process (std passes `bInheritHandles`),
/// not only the stdio set up for them, and the browser hands the relay inheritable pipe
/// ends. A daemon holding them would keep the browser's pipes open after the relay exits.
#[cfg(windows)]
fn keep_stdio_from_children() {
    use windows_sys::Win32::Foundation::{
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: plain call; the result is checked before use.
        let handle = unsafe { GetStdHandle(id) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            continue;
        }
        // SAFETY: `handle` is a standard handle of this process, open for its lifetime.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
            eprintln!(
                "nmhost: cannot keep a standard handle from the daemon: {}",
                io::Error::last_os_error()
            );
        }
    }
}
