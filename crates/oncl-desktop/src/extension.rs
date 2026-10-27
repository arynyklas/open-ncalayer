//! The browser extension's native messaging host as the settings window shows it
//! ([`BrowserExtension`]): the daemon implements it with `openncalayer nm`.

use std::io;
use std::path::PathBuf;

/// Whether the extension can reach the daemon.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtensionStatus {
    /// The relay and its config are in place, as registration writes them.
    pub installed: bool,
    /// The browsers whose host manifest is in place.
    pub browsers: Vec<String>,
    /// Something registration writes is missing or broken while other parts are there.
    pub broken: bool,
}

/// Why registering or removing the host failed.
#[derive(Debug)]
pub enum ExtensionError {
    /// The relay to install is not at this path (next to the program).
    RelayMissing(PathBuf),
    /// A running browser holds the installed relay: close the browser and retry.
    RelayInUse,
    /// Anything else, with the details.
    Io(io::Error),
}

impl From<io::Error> for ExtensionError {
    fn from(e: io::Error) -> Self {
        ExtensionError::Io(e)
    }
}

/// Registration of the native messaging host (`openncalayer nm install|uninstall|status`).
pub trait BrowserExtension: Send + Sync {
    /// What is registered now.
    fn status(&self) -> ExtensionStatus;

    /// Installs the relay and registers it with the browsers that are present.
    ///
    /// # Errors
    ///
    /// The relay is missing or cannot be installed, or some browser cannot be registered.
    fn register(&self) -> Result<ExtensionStatus, ExtensionError>;

    /// Removes the relay and its registrations.
    ///
    /// # Errors
    ///
    /// A running browser holds the relay, or something cannot be removed.
    fn unregister(&self) -> Result<ExtensionStatus, ExtensionError>;
}
