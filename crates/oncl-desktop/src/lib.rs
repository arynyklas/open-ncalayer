//! OpenNCALayer's desktop integration without windows: [`settings`] (`settings.json` in the
//! data directory), [`autostart`] (our entry started at login) and the HKCU [`registry`]
//! helpers they share with the native messaging host setup.

pub mod autostart;
mod fsutil;
pub mod registry;
pub mod settings;

pub use autostart::{Autostart, AutostartPaths, FileAutostart};
#[cfg(windows)]
pub use autostart::{RegistryAutostart, RegistryBase};
pub use settings::{ProxySetting, Settings};
