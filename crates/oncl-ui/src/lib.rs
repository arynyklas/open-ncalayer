//! OpenNCALayer dialogs in Slint: [`SlintPrompter`] shows the storage dialog (storage, key
//! store file, password) and the key dialog of the signing flow, the certificate request
//! dialog (storage, folder, password), the certificate installation dialog (folder, new
//! password), the system file chooser for paths a page asks for, and the legacy Applet's
//! password dialog. [`start_tray`] shows the system tray icon and its menu.
//!
//! Slint runs on the main thread in [`run_event_loop`]; the prompter is called from
//! other threads and blocks them until the user answers, and tray commands arrive there.
//! Fixed dialog texts are translated through the bundled `po/<lang>` catalogs; texts Rust
//! composes are in [`view`] and the tray module.

mod foreground;
mod prompter;
mod tray;
pub mod view;

pub use prompter::{SlintPrompter, quit, run_event_loop};
pub use tray::{TrayCommand, TrayError, TrayHandle, TrayState, start_tray};

mod ui {
    slint::include_modules!();
}
