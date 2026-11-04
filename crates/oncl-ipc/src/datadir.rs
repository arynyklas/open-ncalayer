//! Where the data directory of a user is: the one rule the daemon and everything that must
//! find its endpoints (the relay, an installer) share.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

/// Overrides the data directory (tests and development runs).
pub const DATA_DIR_VAR: &str = "ONCL_DATA_DIR";

/// The data directory from the environment `var`: [`DATA_DIR_VAR`] if set and not empty,
/// otherwise `%APPDATA%\OpenNCALayer` (Windows),
/// `~/Library/Application Support/OpenNCALayer` (macOS) or
/// `${XDG_DATA_HOME:-~/.local/share}/openncalayer` (other Unix). Not yet made absolute.
///
/// # Errors
///
/// [`io::ErrorKind::NotFound`] if the variables the platform default needs are not set.
pub fn data_dir_from(var: impl Fn(&str) -> Option<OsString>) -> io::Result<PathBuf> {
    let set = |name: &str| var(name).filter(|v| !v.is_empty());
    if let Some(dir) = set(DATA_DIR_VAR) {
        return Ok(dir.into());
    }
    let missing = |name: &str| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{name} is not set; set {DATA_DIR_VAR} to choose the data directory"),
        )
    };
    if cfg!(windows) {
        let app_data = set("APPDATA").ok_or_else(|| missing("APPDATA"))?;
        Ok(Path::new(&app_data).join("OpenNCALayer"))
    } else if cfg!(target_os = "macos") {
        let home = set("HOME").ok_or_else(|| missing("HOME"))?;
        Ok(Path::new(&home).join("Library/Application Support/OpenNCALayer"))
    } else {
        // The XDG Base Directory spec ignores relative values.
        let data_home = match set("XDG_DATA_HOME").map(PathBuf::from) {
            Some(dir) if dir.is_absolute() => dir,
            _ => {
                let home = set("HOME").ok_or_else(|| missing("HOME"))?;
                Path::new(&home).join(".local/share")
            }
        };
        Ok(data_home.join("openncalayer"))
    }
}
