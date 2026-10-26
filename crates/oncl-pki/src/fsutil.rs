//! Atomic file replacement shared by the CRL cache and the key files.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Who may read a file written by [`write_atomically`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Access {
    /// The process default (`0666 & !umask` on Unix).
    Default,
    /// The owner only: mode `0600` on Unix, for private key material. On Windows the file
    /// gets the ACL inherited from its directory (the temporary file is created there, and
    /// the rename keeps it); no ACL is set explicitly.
    Private,
}

/// Writes `body` to `path` through a temporary file next to it, flushed to disk, and a
/// rename: a reader sees the old file or the new one, never a part. The temporary file
/// (`<name>.<pid>-<n>.tmp`) is created with `access` and removed on failure; the rename
/// gives `path` the temporary file's permissions. The directory must exist.
///
/// `path` is first made absolute lexically ([`std::path::absolute`]: on Windows `.` and
/// `..` collapse the way Windows opens the path, on Unix only `.` goes), and the
/// temporary file is named from that path's file name, so it never names `path` itself.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidInput`] if the last component of `path` is empty, `.` or `..`
/// (on Windows also any name of dots and spaces only, which Windows strips to nothing):
/// such a path may name an existing file through a lexical `..` (`k.p12\a\..` is `k.p12`
/// on Windows), and is refused before anything is created. Any I/O error otherwise.
pub(crate) fn write_atomically(path: &Path, body: &[u8], access: Access) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let target = target(path)?;
    let Some(name) = target.file_name() else {
        return Err(no_file_name(path));
    };
    let mut tmp_name = OsString::from(name);
    tmp_name.push(format!(
        ".{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = target.with_file_name(tmp_name);
    let written = create_new(&tmp, access)
        .and_then(|mut file| {
            file.write_all(body)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, &target));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// The absolute form of `path`, refusing a last component that names no file.
fn target(path: &Path) -> io::Result<PathBuf> {
    let raw = path.as_os_str().as_encoded_bytes();
    let last = raw
        .rsplit(|&b| b == b'/' || (cfg!(windows) && b == b'\\'))
        .next()
        .unwrap_or_default();
    let names_no_file = if cfg!(windows) {
        // Windows drops trailing dots and spaces of the last component.
        last.iter().all(|&b| b == b'.' || b == b' ')
    } else {
        matches!(last, b"" | b"." | b"..")
    };
    if names_no_file {
        return Err(no_file_name(path));
    }
    std::path::absolute(path)
}

fn no_file_name(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{} does not name a file", path.display()),
    )
}

#[cfg(unix)]
fn create_new(path: &Path, access: Access) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    if access == Access::Private {
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(not(unix))]
fn create_new(path: &Path, _access: Access) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(dir: &Path) -> Vec<OsString> {
        let mut names: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn replaces_through_a_temporary_file_named_after_the_target() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = dir.path().join("key.p12");
        fs::write(&key, b"old").unwrap();
        write_atomically(&key, b"new", Access::Private).unwrap();
        assert_eq!(fs::read(&key).unwrap(), b"new");
        // `.` components go before the target is resolved.
        write_atomically(
            &dir.path().join(".").join("key.p12"),
            b"dot",
            Access::Private,
        )
        .unwrap();
        assert_eq!(fs::read(&key).unwrap(), b"dot");
        assert_eq!(names(dir.path()), ["key.p12"], "no temporary file left");

        // A failed write leaves no temporary file either.
        let missing = dir.path().join("missing").join("key.p12");
        let err = write_atomically(&missing, b"new", Access::Private).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
        assert_eq!(names(dir.path()), ["key.p12"]);
    }

    #[test]
    fn refuses_paths_that_name_no_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = dir.path().join("key.p12");
        fs::write(&key, b"key").unwrap();
        let base = key.as_os_str().to_owned();
        let mut odd = vec![".", "..", "a/..", "a/.", ""];
        if cfg!(windows) {
            odd.extend([r"a\..", r"a\.", "a\\", r"a\...", r"a\.. "]);
        }
        for suffix in odd {
            let mut path = base.clone();
            path.push(format!("/{suffix}"));
            let err = write_atomically(Path::new(&path), b"new", Access::Private).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{suffix:?}: {err}");
            assert_eq!(fs::read(&key).unwrap(), b"key", "{suffix:?}");
            assert_eq!(names(dir.path()), ["key.p12"], "{suffix:?}");
        }
        for path in [Path::new(""), Path::new("."), Path::new("..")] {
            let err = write_atomically(path, b"new", Access::Private).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{path:?}");
        }
    }

    /// Windows resolves `k.p12\a\..` lexically to `k.p12`, so the file can be read through
    /// it; the write must neither touch nor delete the key file.
    #[cfg(windows)]
    #[test]
    fn dot_dot_after_a_key_file_keeps_the_key_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let key = dir.path().join("key.p12");
        fs::write(&key, b"key").unwrap();
        let through = dir.path().join(r"key.p12\a\..");
        assert_eq!(
            fs::read(&through).unwrap(),
            b"key",
            "Windows opens the key file"
        );
        let err = write_atomically(&through, b"new", Access::Private).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        assert_eq!(fs::read(&key).unwrap(), b"key");
        assert_eq!(names(dir.path()), ["key.p12"]);
    }

    #[cfg(unix)]
    #[test]
    fn private_replacement_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        let private = dir.path().join("key.p12");
        // An existing world-readable file becomes owner-only on replacement.
        fs::write(&private, b"old").unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o644)).unwrap();
        write_atomically(&private, b"new", Access::Private).unwrap();
        assert_eq!(fs::read(&private).unwrap(), b"new");
        let mode = fs::metadata(&private).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let public = dir.path().join("cache.crl");
        write_atomically(&public, b"crl", Access::Default).unwrap();
        let mode = fs::metadata(&public).unwrap().permissions().mode() & 0o777;
        assert_ne!(mode & 0o600, 0, "the owner reads and writes");
    }
}
