//! The original NCALayer next to ours: whether it is installed, its autostart entries and
//! who holds the port, as the settings window shows them ([`OriginalControl`]).
//!
//! Disabling moves the original's autostart entries aside without deleting them, restoring
//! puts them back. Until that exists, [`Unavailable`] reports nothing found and refuses both.

use std::io;
use std::path::PathBuf;

/// What starts the original at login.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// A shortcut in the user's Startup folder (Windows).
    StartupShortcut,
    /// The `NCALayer` value of `HKLM\…\Run` (Windows), for every user: only an administrator
    /// can change it.
    MachineRun,
    /// An XDG autostart desktop entry (Linux).
    DesktopEntry,
}

/// One autostart entry of the original.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutostartEntry {
    pub kind: EntryKind,
    /// The file, or the registry value as `HKLM\…\Run\NCALayer`.
    pub path: PathBuf,
    /// Whether it starts the original at login (not moved aside or hidden).
    pub enabled: bool,
}

/// The original NCALayer as found on this system.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OriginalStatus {
    /// Whether the original is installed.
    pub found: bool,
    /// Its autostart entries, enabled or disabled by us.
    pub autostart: Vec<AutostartEntry>,
    /// The program holding our port, if it is not us (for the user).
    pub port_owner: Option<String>,
}

/// What [`OriginalControl::disable`] or [`OriginalControl::restore`] changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The entries moved aside, hidden or put back.
    pub changed: Vec<PathBuf>,
}

/// The settings window's view of the original NCALayer.
pub trait OriginalControl: Send + Sync {
    /// The original as it is now.
    fn status(&self) -> OriginalStatus;

    /// Stops the original's autostart entries of this user from starting it, keeping them.
    ///
    /// # Errors
    ///
    /// An entry cannot be changed; a repeated call finishes the job.
    fn disable(&self) -> io::Result<Report>;

    /// Puts back what [`OriginalControl::disable`] changed.
    ///
    /// # Errors
    ///
    /// An entry cannot be put back; a repeated call finishes the job.
    fn restore(&self) -> io::Result<Report>;
}

/// The original NCALayer before its detection exists: nothing is found, and nothing can
/// be disabled or restored.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unavailable;

impl OriginalControl for Unavailable {
    fn status(&self) -> OriginalStatus {
        OriginalStatus::default()
    }

    fn disable(&self) -> io::Result<Report> {
        Err(not_available())
    }

    fn restore(&self) -> io::Result<Report> {
        Err(not_available())
    }
}

fn not_available() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "the original NCALayer cannot be managed yet",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_finds_nothing_and_changes_nothing() {
        assert_eq!(Unavailable.status(), OriginalStatus::default());
        for result in [Unavailable.disable(), Unavailable.restore()] {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        }
    }
}
