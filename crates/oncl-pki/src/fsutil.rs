//! Atomic file replacement shared by the CRL cache and the key files.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
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
/// (`<stem>.<pid>-<n>.tmp`) is created with `access` and removed on failure; the rename
/// gives `path` the temporary file's permissions. The directory must exist.
pub(crate) fn write_atomically(path: &Path, body: &[u8], access: Access) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!(
        "{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let written = create_new(&tmp, access)
        .and_then(|mut file| {
            file.write_all(body)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, path));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn private_replacement_is_owner_only() {
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
