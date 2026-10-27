//! The browser extension's native messaging host as the settings window shows it
//! ([`BrowserExtension`]): the daemon implements it with `openncalayer nm`.

use std::io;

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

/// Registration of the native messaging host (`openncalayer nm install|uninstall|status`).
pub trait BrowserExtension: Send + Sync {
    /// What is registered now.
    fn status(&self) -> ExtensionStatus;

    /// Installs the relay and registers it with the browsers that are present.
    ///
    /// # Errors
    ///
    /// The relay cannot be installed, or some browser cannot be registered (the message
    /// says which).
    fn register(&self) -> io::Result<ExtensionStatus>;

    /// Removes the relay and its registrations.
    ///
    /// # Errors
    ///
    /// Something cannot be removed, e.g. the relay a running browser holds (the message
    /// says what).
    fn unregister(&self) -> io::Result<ExtensionStatus>;
}
