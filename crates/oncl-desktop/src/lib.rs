//! OpenNCALayer's desktop integration without windows: [`settings`] (`settings.json` in the
//! data directory) and [`autostart`] (our entry started at login).

pub mod autostart;
pub mod settings;

pub use autostart::{Autostart, AutostartPaths, FileAutostart};
#[cfg(windows)]
pub use autostart::{RegistryAutostart, RegistryBase};
pub use settings::{ProxySetting, Settings};

use std::io;
use std::path::Path;

use oncl_pki::fsutil::{Access, write_atomically};

/// Writes `bytes` to `path` atomically with `access` ([`write_atomically`]), creating the
/// missing directories first.
fn write_file(path: &Path, bytes: &[u8], access: Access) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    write_atomically(path, bytes, access)
}
