//! OpenNCALayer's plugins, as files:
//!
//! - [`manifest`]: `plugin.toml`, what a plugin is and may do ([`Manifest`]), and the URL
//!   prefixes it may reach ([`HttpPrefix`]);
//! - [`package`]: the `.onclp` package, a zip of `plugin.toml` and `plugin.wasm`
//!   ([`Package`]).
//!
//! The format is described in `docs/design/plugins.md`.

pub mod manifest;
pub mod package;

pub use manifest::{Capabilities, HttpPrefix, Localized, Manifest, Replaces};
pub use package::{MAX_MANIFEST, MAX_PACKAGE, MAX_WASM, PACKAGE_EXT, Package};

use std::io;

/// Why a package or a manifest is refused.
#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    /// The package is bigger than [`MAX_PACKAGE`], or one of its files unpacks to more than
    /// its limit ([`MAX_MANIFEST`], [`MAX_WASM`]).
    #[error("the plugin package or one of its files is too large")]
    TooLarge,
    /// The package is not a readable zip archive, or the data of a file in it is corrupt.
    #[error("the plugin package is not a valid zip archive")]
    NotZip,
    /// The package does not hold exactly `plugin.toml` and `plugin.wasm` at its root, or
    /// `plugin.wasm` is not a WebAssembly module.
    #[error("the plugin package's files are wrong: {0}")]
    Entries(String),
    /// `plugin.toml` is not TOML of the expected shape, or breaks a rule of the format.
    #[error("the plugin manifest is malformed: {0}")]
    Manifest(String),
    /// The package file could not be read.
    #[error("the plugin package could not be read: {0}")]
    Io(#[from] io::Error),
}
