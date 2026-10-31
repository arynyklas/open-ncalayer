//! OpenNCALayer's plugins:
//!
//! - [`manifest`]: `plugin.toml`, what a plugin is and may do ([`Manifest`]), and the URL
//!   prefixes it may reach ([`HttpPrefix`]);
//! - [`package`]: the `.onclp` package, a zip of `plugin.toml` and `plugin.wasm`
//!   ([`Package`]);
//! - the runtime: a module checked against the ABI of [`oncl_pdk::abi`] ([`Engine`],
//!   [`Compiled`]), instantiated per session ([`Instance`]) with the host functions of its
//!   capabilities ([`HostServices`]);
//! - [`store`]: the installed plugins in `<data>/plugins/` ([`Store`]);
//! - [`modules`]: the loaded plugins as the daemon's dynamic modules ([`PluginModules`]);
//! - the modules built into the core, run as guests of the same runtime ([`Builtins`]),
//!   and what the core tells them about itself ([`core`]);
//! - the [`cause`] of the core's failures a guest tells apart.
//!
//! The format, the ABI and the limits are described in `docs/design/plugins.md`.

mod builtins;
mod caps;
pub mod cause;
pub mod core;
mod host;
pub mod manifest;
pub mod modules;
pub mod package;
mod runtime;
pub mod store;

pub use builtins::{
    BUILTIN_FUEL, BUILTIN_HIGH_WATER, BUILTIN_ID_PREFIX, BUILTIN_IDLE, BUILTIN_MAX_MEMORY,
    BUILTIN_MAX_TRANSFER, BuiltinInfo, BuiltinLimits, BuiltinSource, BuiltinStats, Builtins,
};
pub use caps::{
    HTTP_TIMEOUT, MAX_HTTP_BODY, MAX_HTTP_REQUESTS, MAX_KEY_HANDLES, MAX_SECRETS, NCA_PKI_HOSTS,
    SharedState, nca_pki_hosts,
};
pub use host::HostServices;
pub use manifest::{
    Capabilities, HttpPrefix, Localized, Manifest, OriginPattern, Replaces, is_symbolic_name,
};
pub use modules::{BUILT_IN, LoadedInfo, MemoryLimits, OnMissing, PluginModules};
pub use oncl_pdk::abi::ABI_VERSION;
pub use package::{MAX_MANIFEST, MAX_PACKAGE, MAX_WASM, PACKAGE_EXT, Package, archive};
pub use runtime::{
    Compiled, Engine, INSTANCE_HIGH_WATER, Instance, InstanceLimits, LoadError, MAX_INSTANCES,
    MAX_MEMORY, MAX_TRANSFER, MEMORY_BUDGET, PLUGIN_ERROR_REPLY, PROCESS_FUEL, PluginError,
    SessionContext, Trust,
};
pub use store::{Installed, Source, Store, StoreError, StoreState};
pub use url::Url;

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
