//! OpenNCALayer dialogs and windows in Slint: [`SlintPrompter`] shows the storage dialog
//! (storage, key store file, password) and the key dialog of the signing flow, the
//! certificate request dialog (storage, folder, password), the certificate installation
//! dialog (folder, new password), the system file chooser for paths a page asks for, and the
//! legacy Applet's password dialog. [`open_window`] shows the settings window, the TLS
//! wizard and the About window; [`start_tray`] shows the system tray icon, its menu and its
//! notifications.
//!
//! Slint runs on the main thread in [`run_event_loop`]; the prompter is called from
//! other threads and blocks them until the user answers, and tray commands arrive there.
//! Fixed dialog texts are translated through the bundled `po/<lang>` catalogs; texts Rust
//! composes are in [`view`], [`settings_view`], [`tls_wizard`] and the tray module.

pub mod about_view;
mod foreground;
#[cfg(test)]
mod offscreen;
mod prompter;
#[cfg(test)]
mod screenshots;
pub mod settings_view;
pub mod tls_wizard;
mod tray;
pub mod view;
mod windows;
mod worker;

pub use about_view::AboutInfo;
pub use prompter::{SlintPrompter, quit, run_event_loop, run_on_event_loop, when_event_loop_runs};
pub use settings_view::SettingsServices;
pub use tls_wizard::TlsWizardServices;
pub use tray::{
    ActionTarget, Notification, NotificationAction, TrayCommand, TrayError, TrayHandle, TrayState,
    start_tray,
};
pub use windows::{DesktopWindow, DesktopWindows, open_window, set_desktop_windows};

mod ui {
    slint::include_modules!();
}
