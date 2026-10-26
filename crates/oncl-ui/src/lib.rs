//! OpenNCALayer dialogs in Slint: [`SlintPrompter`] shows the storage dialog (storage, key
//! store file, password) and the key dialog of the signing flow, the certificate request
//! dialog (storage, folder, password), the certificate installation dialog (folder, new
//! password), and the system file chooser for paths a page asks for.
//!
//! Slint runs on the main thread in [`run_event_loop`]; the prompter is called from
//! other threads and blocks them until the user answers. Fixed dialog texts are
//! translated through the bundled `po/<lang>` catalogs; texts Rust composes are in
//! [`view`].

mod foreground;
mod prompter;
pub mod view;

pub use prompter::{SlintPrompter, quit, run_event_loop};

mod ui {
    slint::include_modules!();
}
