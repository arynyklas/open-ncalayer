//! OpenNCALayer signing dialogs in Slint: [`SlintPrompter`] shows the storage dialog
//! (storage, key store file, password) and the key dialog for the signing flow.
//!
//! Slint runs on the main thread in [`run_event_loop`]; the prompter is called from
//! other threads and blocks them until the user answers. Fixed dialog texts are
//! translated through the bundled `po/<lang>` catalogs; texts Rust composes are in
//! [`view`].

mod prompter;
pub mod view;

pub use prompter::{SlintPrompter, quit, run_event_loop};

mod ui {
    slint::include_modules!();
}
