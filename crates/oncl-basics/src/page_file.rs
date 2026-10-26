//! Paths a page names, as every module reads them: only local paths, only regular disk
//! files, at most [`MAX_PAGE_FILE`] bytes. Device namespaces (a "file" that may be a pipe
//! that never answers) and network paths (whose opening sends the user's credentials to a
//! host the page chose) are refused before anything touches the file system.

use std::io::Read as _;
use std::path::{Path, PathBuf};

/// Largest page-named file read, as for the modules' other large inputs (the XMLDSig input
/// limit and the native-messaging frame are 64 MiB too).
pub const MAX_PAGE_FILE: u64 = 64 << 20;

/// A file a page names, read.
pub struct PageFile {
    /// The file's contents.
    pub data: Vec<u8>,
    /// The path the dialogs show: absolute and normalized, so the user sees the file that
    /// is read.
    pub shown: String,
}

/// Why a page-named file is not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageFileError {
    /// Not a local regular disk file, or it cannot be read.
    NotFound,
    /// Over [`MAX_PAGE_FILE`] bytes.
    TooLarge,
}

impl PageFile {
    /// Reads `path` if [`local_page_path`] accepts it and it is a regular file (symbolic
    /// links followed) of at most [`MAX_PAGE_FILE`] bytes; on Windows the opened handle must
    /// also be a disk file, not a pipe or a character device.
    ///
    /// # Errors
    ///
    /// [`PageFileError::NotFound`] for anything else that cannot be read,
    /// [`PageFileError::TooLarge`].
    pub fn read(path: &str) -> Result<PageFile, PageFileError> {
        let path = local_page_path(path).ok_or(PageFileError::NotFound)?;
        Self::read_file(path)
    }

    /// Reads a file the user chose in a dialog (which may have been pre-filled with a
    /// [`local_page_path`]): as [`PageFile::read`], but a network path is read, as the
    /// user's own choice; a device namespace path is still refused.
    ///
    /// # Errors
    ///
    /// As [`PageFile::read`].
    pub fn read_chosen(path: &Path) -> Result<PageFile, PageFileError> {
        let text = path.to_str().ok_or(PageFileError::NotFound)?;
        if is_device_path(text) {
            return Err(PageFileError::NotFound);
        }
        Self::read_file(path)
    }

    /// A regular disk file of at most [`MAX_PAGE_FILE`] bytes.
    fn read_file(path: &Path) -> Result<PageFile, PageFileError> {
        let meta = std::fs::metadata(path).map_err(|_| PageFileError::NotFound)?;
        if !meta.is_file() {
            return Err(PageFileError::NotFound);
        }
        if meta.len() > MAX_PAGE_FILE {
            return Err(PageFileError::TooLarge);
        }
        let file = std::fs::File::open(path).map_err(|_| PageFileError::NotFound)?;
        if !is_disk_file(&file) {
            return Err(PageFileError::NotFound);
        }
        let mut data = Vec::new();
        file.take(MAX_PAGE_FILE + 1)
            .read_to_end(&mut data)
            .map_err(|_| PageFileError::NotFound)?;
        if data.len() as u64 > MAX_PAGE_FILE {
            return Err(PageFileError::TooLarge);
        }
        Ok(PageFile {
            data,
            shown: shown_path(path).display().to_string(),
        })
    }
}

/// `path` if a page may name it: not a device namespace path ([`is_device_path`]) and not
/// a network path ([`is_network_path`]). Nothing is looked up.
pub fn local_page_path(path: &str) -> Option<&Path> {
    (!is_device_path(path) && !is_network_path(path)).then(|| Path::new(path))
}

/// Whether `path` names a Windows device namespace (`\\.\pipe\…`, `\\?\GLOBALROOT\…`,
/// `\??\…`; either slash), where a "file" may be a pipe that never answers. `\\?\C:\…` and
/// `\\?\UNC\…` are not device paths. Always false elsewhere.
pub fn is_device_path(path: &str) -> bool {
    if !cfg!(windows) {
        return false;
    }
    let p = windows_prefix(path);
    if p.starts_with(r"\\.\") || p.starts_with(r"\??\") {
        return true;
    }
    if let Some(rest) = p.strip_prefix(r"\\?\") {
        let drive = rest.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && rest.as_bytes().get(1) == Some(&b':');
        return !(drive || is_unc_marker(rest));
    }
    false
}

/// Whether `path` names a network location: on Windows a UNC path (`\\host\share\…`,
/// `\\?\UNC\host\…`; either slash), elsewhere a path starting with `//` (which POSIX leaves
/// to the system to interpret).
pub fn is_network_path(path: &str) -> bool {
    if !cfg!(windows) {
        return path.starts_with("//");
    }
    let p = windows_prefix(path);
    if let Some(rest) = p.strip_prefix(r"\\?\") {
        return is_unc_marker(rest);
    }
    p.starts_with(r"\\") && !p.starts_with(r"\\.\")
}

/// The first characters of `path` with `/` as `\`, as Windows reads both.
fn windows_prefix(path: &str) -> String {
    path.chars()
        .take(8)
        .map(|c| if c == '/' { '\\' } else { c })
        .collect()
}

/// Whether the rest of a `\\?\` path starts with `UNC\`.
fn is_unc_marker(rest: &str) -> bool {
    rest.get(..4)
        .is_some_and(|s| s.eq_ignore_ascii_case(r"UNC\"))
}

/// Whether `file` is a disk file (`GetFileType` is `FILE_TYPE_DISK`), not a pipe or a
/// character device. Always true elsewhere (the metadata check covers FIFOs and devices).
#[cfg(windows)]
fn is_disk_file(file: &std::fs::File) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_DISK, GetFileType};
    // SAFETY: the handle is the open file's, valid for the call.
    unsafe { GetFileType(file.as_raw_handle()) == FILE_TYPE_DISK }
}

#[cfg(not(windows))]
fn is_disk_file(_: &std::fs::File) -> bool {
    true
}

/// The absolute path of `path` as the file system resolves it: on Windows lexically (as
/// Windows opens it), elsewhere with symbolic links resolved.
fn shown_path(path: &Path) -> PathBuf {
    #[cfg(not(windows))]
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_paths() {
        assert!(is_network_path("//host/share/k.p12"));
        assert!(!is_network_path("/home/k.p12"));
        assert!(!is_network_path("k.p12"));
        assert!(local_page_path("//host/share").is_none());
        assert!(local_page_path("/tmp/x").is_some());
        if cfg!(windows) {
            for unc in [
                r"\\host\share\k.p12",
                r"\/host/share",
                "//host/share",
                r"\\?\UNC\host\share\k.p12",
                r"//?/unc/host/share",
            ] {
                assert!(is_network_path(unc), "{unc}");
                assert!(!is_device_path(unc), "{unc}");
                assert!(local_page_path(unc).is_none(), "{unc}");
            }
            for local in [
                r"C:\k.p12",
                r"\\?\C:\k.p12",
                r"\k.p12",
                r"\\.\pipe\x",
                r"\??\C:\x",
            ] {
                assert!(!is_network_path(local), "{local}");
            }
            for device in [r"\\.\pipe\x", r"//./NUL", r"\??\C:\x", r"\\?\GLOBALROOT\x"] {
                assert!(is_device_path(device), "{device}");
                assert!(local_page_path(device).is_none(), "{device}");
            }
            assert!(local_page_path(r"\\?\C:\k.p12").is_some());
        } else {
            assert!(!is_network_path(r"\\host\share"));
            assert!(!is_device_path(r"\\.\pipe\x"));
        }
    }

    #[test]
    fn page_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f.bin");
        std::fs::write(&file, b"data").unwrap();
        let read = PageFile::read(file.to_str().unwrap()).ok().unwrap();
        assert_eq!(read.data, b"data");
        assert!(Path::new(&read.shown).is_absolute());
        assert_eq!(
            PageFile::read(dir.path().to_str().unwrap()).err(),
            Some(PageFileError::NotFound)
        );
        assert_eq!(
            PageFile::read(dir.path().join("gone").to_str().unwrap()).err(),
            Some(PageFileError::NotFound)
        );
        assert_eq!(
            PageFile::read("//host/share/f.bin").err(),
            Some(PageFileError::NotFound)
        );
        // A chosen file is read like a page's, network paths aside.
        assert_eq!(PageFile::read_chosen(&file).ok().unwrap().data, b"data");
        assert_eq!(
            PageFile::read_chosen(dir.path()).err(),
            Some(PageFileError::NotFound)
        );
        if cfg!(windows) {
            assert_eq!(
                PageFile::read_chosen(Path::new(r"\\.\pipe\x")).err(),
                Some(PageFileError::NotFound)
            );
        }
    }

    /// A pipe reached through the network redirector (`\\localhost\pipe\…`) passes the
    /// metadata step as an empty regular file, so `GetFileType` is what refuses it before a
    /// read that would block forever. Each step opens a pipe instance, so several listen.
    /// Skipped when the system offers no redirector.
    #[cfg(windows)]
    #[test]
    fn chosen_network_pipe_is_refused_by_its_file_type() {
        use std::time::Duration;
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
        use windows_sys::Win32::System::Pipes::{
            CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
        };

        // Listening instances that never answer: reading from one blocks forever.
        let name = format!("oncl-basics-test-{}", std::process::id());
        let wide: Vec<u16> = format!(r"\\.\pipe\{name}")
            .encode_utf16()
            .chain([0])
            .collect();
        let servers: Vec<_> = (0..8)
            .map(|_| {
                // SAFETY: a valid NUL-terminated name and no security attributes.
                let server = unsafe {
                    CreateNamedPipeW(
                        wide.as_ptr(),
                        PIPE_ACCESS_DUPLEX,
                        PIPE_TYPE_BYTE | PIPE_WAIT,
                        PIPE_UNLIMITED_INSTANCES,
                        4096,
                        4096,
                        0,
                        std::ptr::null(),
                    )
                };
                assert_ne!(server, INVALID_HANDLE_VALUE);
                server
            })
            .collect();

        let path = PathBuf::from(format!(r"\\localhost\pipe\{name}"));
        match std::fs::metadata(&path) {
            Ok(meta) => {
                // What `read_file` sees before it opens the file.
                assert!(meta.is_file() && meta.len() == 0, "{meta:?}");
                let file = std::fs::File::open(&path).unwrap();
                assert!(!is_disk_file(&file), "the redirector hands out the pipe");
                drop(file);

                let (done, finished) = std::sync::mpsc::channel();
                let chosen = path.clone();
                std::thread::spawn(move || {
                    let _ = done.send(PageFile::read_chosen(&chosen).err());
                });
                assert_eq!(
                    finished.recv_timeout(Duration::from_secs(10)),
                    Ok(Some(PageFileError::NotFound)),
                    "refused at once, not read"
                );
            }
            Err(e) => eprintln!("skipped: {} is not reachable: {e}", path.display()),
        }
        for server in servers {
            // SAFETY: each handle is a pipe instance created above, closed once.
            unsafe { CloseHandle(server) };
        }
    }
}
