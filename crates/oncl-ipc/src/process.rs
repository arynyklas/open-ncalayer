//! Starting the daemon detached from a relay that the browser runs (Windows).
//!
//! The relay starts the daemon with [`DETACHED_CREATION_FLAGS`], first together with
//! [`CREATE_BREAKAWAY_FROM_JOB`] and, if [`breakaway_refused`], without it. Before that it
//! calls [`prepare_detached_spawn`] so that the daemon holds none of the browser's pipes.
//! Uses only kernel32 functions present on Windows 7 SP1.

use std::io;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};

/// Creation flags of a detached daemon: no console of its own or inherited
/// (`DETACHED_PROCESS`), and out of the relay's console process group, so Ctrl+C and
/// Ctrl+Break sent to the relay's group miss it (`CREATE_NEW_PROCESS_GROUP`).
pub const DETACHED_CREATION_FLAGS: u32 = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;

/// Creation flag taking the daemon out of the relay's job object, so that the browser
/// closing its job (Firefox: kill on close) does not kill the daemon. Refused when the job
/// does not allow breakaway: see [`breakaway_refused`].
pub use windows_sys::Win32::System::Threading::CREATE_BREAKAWAY_FROM_JOB;

/// Whether a spawn with [`CREATE_BREAKAWAY_FROM_JOB`] failed because the job forbids
/// breakaway (`ERROR_ACCESS_DENIED`); the spawn should then be repeated without the flag.
#[must_use]
pub fn breakaway_refused(e: &io::Error) -> bool {
    e.raw_os_error() == i32::try_from(ERROR_ACCESS_DENIED).ok()
}

/// Makes the standard handles of this process non-inheritable.
///
/// Children inherit every inheritable handle of the process (std spawns with
/// `bInheritHandles`), not only the stdio set up for them, and the browser hands the relay
/// inheritable pipe ends. A daemon holding them would keep the browser's pipes open after
/// the relay exits, so the browser would never see the relay's end. Call it before spawning
/// the daemon; the relay itself keeps using its handles as before.
///
/// # Errors
///
/// The first failure of `SetHandleInformation`; every handle is still tried.
pub fn prepare_detached_spawn() -> io::Result<()> {
    let mut result = Ok(());
    for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: plain call; the result is checked before use.
        let handle = unsafe { GetStdHandle(id) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            continue;
        }
        // SAFETY: `handle` is a standard handle of this process, open for its lifetime.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 && result.is_ok() {
            result = Err(io::Error::last_os_error());
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Foundation::GetHandleInformation;

    use super::*;

    #[test]
    fn standard_handles_are_no_longer_inherited() {
        prepare_detached_spawn().expect("prepare");
        for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            // SAFETY: plain call; the result is checked before use.
            let handle = unsafe { GetStdHandle(id) };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                continue;
            }
            let mut flags = 0;
            // SAFETY: `handle` is an open standard handle; `flags` is a valid out pointer.
            let ok = unsafe { GetHandleInformation(handle, &mut flags) };
            assert_ne!(ok, 0, "{}", io::Error::last_os_error());
            assert_eq!(flags & HANDLE_FLAG_INHERIT, 0, "std handle {id}");
        }
    }

    #[test]
    fn breakaway_refusal_is_access_denied_only() {
        let denied = io::Error::from_raw_os_error(ERROR_ACCESS_DENIED.cast_signed());
        assert!(breakaway_refused(&denied));
        assert!(!breakaway_refused(&io::Error::from_raw_os_error(2)));
        assert!(!breakaway_refused(&io::Error::other("no os error")));
    }
}
