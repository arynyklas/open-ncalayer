//! Atomic file replacement shared by the CRL cache and the key files.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Writes `body` to `path` through a temporary file next to it, flushed to disk, and a
/// rename: a reader sees the old file or the new one, never a part. The temporary file
/// (`<stem>.<pid>-<n>.tmp`) is removed on failure. The directory must exist.
pub(crate) fn write_atomically(path: &Path, body: &[u8]) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!(
        "{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let written = File::create_new(&tmp)
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
