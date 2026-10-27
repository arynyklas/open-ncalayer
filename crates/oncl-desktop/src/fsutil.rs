//! Whole-file replacement of the small files this crate keeps.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Writes `bytes` to `path` through `<path>.tmp`, flushed to disk, and a rename, creating the
/// missing directories: a reader sees the old file or the new one. No `.tmp` stays on
/// failure.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let result = File::create(&tmp)
        .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
        .and_then(|()| fs::rename(&tmp, path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_the_file_and_leaves_no_temporary_file() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("a").join("b.json");
        write_atomic(&f, b"1").unwrap();
        write_atomic(&f, b"22").unwrap();
        assert_eq!(fs::read(&f).unwrap(), b"22");
        assert!(!d.path().join("a").join("b.json.tmp").exists());

        // A directory where the file should go: the rename fails.
        let dir = d.path().join("dir");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("inside"), b"x").unwrap();
        write_atomic(&dir, b"1").unwrap_err();
        assert!(!d.path().join("dir.tmp").exists());
    }
}
