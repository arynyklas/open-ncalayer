//! OpenNCALayer dialogs and windows in Slint: [`SlintPrompter`] shows the storage dialog
//! (storage, key store file, password) and the key dialog of the signing flow, the
//! certificate request dialog (storage, folder, password), the certificate installation
//! dialog (folder, new password), the system file chooser for paths a page asks for, and the
//! legacy Applet's password dialog. [`open_window`] shows the settings window, the TLS
//! wizard, the About window and the plugin window; [`ask_stop_original`] asks before the
//! original NCALayer holding the port is stopped; [`ask_install_plugin`] asks before a
//! plugin is installed; [`start_tray`] shows the system tray icon, its menu and its
//! notifications.
//!
//! Slint runs on the main thread in [`run_event_loop`]; the prompter is called from
//! other threads and blocks them until the user answers, and tray commands arrive there.
//! Fixed dialog texts are translated through the bundled `po/<lang>` catalogs; texts Rust
//! composes are in [`view`], [`settings_view`], [`tls_wizard`], [`plugins_view`], the
//! windows to stop the original and to install a plugin, and the tray module.

pub mod about_view;
mod foreground;
mod install_plugin;
#[cfg(test)]
mod offscreen;
pub mod plugins_view;
mod prompter;
#[cfg(test)]
mod screenshots;
pub mod settings_view;
mod stop_original;
pub mod tls_wizard;
mod tray;
pub mod view;
mod windows;
mod worker;

pub use about_view::AboutInfo;
pub use install_plugin::{InstallPluginRequest, ask_install_plugin};
pub use plugins_view::{PluginActionError, PluginsServices, PluginsView, refresh_plugins_window};
pub use prompter::{SlintPrompter, quit, run_event_loop, run_on_event_loop, when_event_loop_runs};
pub use settings_view::SettingsServices;
pub use stop_original::{StopOriginal, Stopped, ask_stop_original};
pub use tls_wizard::TlsWizardServices;
pub use tray::{
    ActionTarget, Notification, NotificationAction, TrayCommand, TrayError, TrayHandle, TrayState,
    start_tray,
};
pub use windows::{
    DesktopWindow, DesktopWindows, any_window_open, open_window, set_desktop_windows,
};

mod ui {
    slint::include_modules!();
}
