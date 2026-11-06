//! The processes of the current user that run a program from an installation.
//!
//! Velopack's `Setup.exe` ends every process whose image lies under the installation's root
//! before it replaces the installation. The entry looks for the same processes first, to
//! know whether a program is running that it has to ask, never to end one itself.

use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

/// A running process whose program is under a root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Running {
    /// The process id.
    pub pid: u32,
    /// The path of its image.
    pub image: PathBuf,
}

/// `path` as text for comparisons: made absolute where it exists, without the verbatim
/// prefix, in lower case (Windows compares paths without regard to case).
fn key(path: &Path) -> String {
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    let text = path.to_string_lossy();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    text.to_lowercase()
}

/// Whether `image` lies under `root`: `root` as a directory, not as a prefix of a name.
fn under(root: &str, image: &str) -> bool {
    image
        .strip_prefix(root)
        .is_some_and(|rest| rest.starts_with('\\') || rest.starts_with('/'))
}

/// The processes of this user whose image lies under `root`. A process this user cannot
/// open (another user's, a protected one) is not listed: it cannot be this user's program.
///
/// # Errors
///
/// The list of processes cannot be taken.
pub fn running_from(root: &Path) -> io::Result<Vec<Running>> {
    let root = key(root);
    // SAFETY: plain call; the result is checked before use.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let mut found = Vec::new();
    // SAFETY: an all-zero PROCESSENTRY32W is a valid value to fill in; `dwSize` is set as
    // the API requires.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = u32::try_from(size_of::<PROCESSENTRY32W>()).expect("small struct");
    // SAFETY: `snapshot` is a valid snapshot handle and `entry` a valid out pointer.
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != FALSE;
    while more {
        if let Some(image) = image_of(entry.th32ProcessID)
            && under(&root, &key(&image))
        {
            found.push(Running {
                pid: entry.th32ProcessID,
                image,
            });
        }
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot, &mut entry) } != FALSE;
    }
    // SAFETY: `snapshot` is open and not used again.
    unsafe { CloseHandle(snapshot) };
    Ok(found)
}

/// Ends process `pid` if `wanted` accepts its image path. The process is opened once and the
/// path is read and the process terminated on that same handle, so a recycled pid can never
/// be ended by mistake. Whether it was ended.
pub fn terminate_if(pid: u32, wanted: impl FnOnce(&Path) -> bool) -> bool {
    use windows_sys::Win32::System::Threading::{PROCESS_TERMINATE, TerminateProcess};
    // SAFETY: plain call; the handle is checked and closed below.
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            FALSE,
            pid,
        )
    };
    if process.is_null() {
        return false;
    }
    let mut ended = false;
    if let Some(image) = image_of_handle(process)
        && wanted(&image)
    {
        // SAFETY: `process` is open with the terminate right.
        ended = unsafe { TerminateProcess(process, 1) } != FALSE;
    }
    // SAFETY: `process` is open and not used again.
    unsafe { CloseHandle(process) };
    ended
}

/// The image path of process `pid`, if this user may ask for it.
pub fn image_of(pid: u32) -> Option<PathBuf> {
    // SAFETY: plain call; the handle is checked and closed below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
    if process.is_null() {
        return None;
    }
    let image = image_of_handle(process);
    // SAFETY: `process` is open and not used again.
    unsafe { CloseHandle(process) };
    image
}

fn image_of_handle(process: windows_sys::Win32::Foundation::HANDLE) -> Option<PathBuf> {
    let mut buffer = vec![0u16; 32_768];
    let mut len = u32::try_from(buffer.len()).expect("fits");
    // SAFETY: `process` is open with the query right; `buffer` has `len` units.
    let ok = unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut len) };
    (ok != FALSE).then(|| PathBuf::from(std::ffi::OsString::from_wide(&buffer[..len as usize])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_root_is_a_directory_not_a_prefix_of_a_name() {
        assert!(under(
            r"root\openncalayer",
            r"root\openncalayer\current\x.exe"
        ));
        assert!(!under(
            r"root\openncalayer",
            r"root\openncalayer-other\x.exe"
        ));
        assert!(!under(r"root\openncalayer", r"root\openncalayer"));
    }

    #[test]
    fn this_test_program_is_found_under_its_own_directory() {
        let exe = std::env::current_exe().unwrap();
        let dir = exe.parent().unwrap();
        let running = running_from(dir).unwrap();
        assert!(
            running.iter().any(|p| p.pid == std::process::id()),
            "{running:?}"
        );
        // Not under an unrelated directory, and case does not matter.
        let other = tempfile::tempdir().unwrap();
        assert!(running_from(other.path()).unwrap().is_empty());
        let upper = PathBuf::from(dir.to_string_lossy().to_uppercase());
        assert!(
            running_from(&upper)
                .unwrap()
                .iter()
                .any(|p| p.pid == std::process::id())
        );
    }
}
