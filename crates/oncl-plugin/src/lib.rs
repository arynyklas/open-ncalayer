//! OpenNCALayer's plugins:
//!
//! - [`manifest`]: `plugin.toml`, what a plugin is and may do ([`Manifest`]), and the URL
//!   prefixes it may reach ([`HttpPrefix`]);
//! - `package` (feature `distribution`): the `.onclp` zip package of `plugin.toml`
//!   and `plugin.wasm`;
//! - the runtime: a module checked against the ABI of [`oncl_pdk::abi`] ([`Engine`],
//!   [`Compiled`]), instantiated per session ([`Instance`]) with the host functions of its
//!   capabilities ([`HostServices`]);
//! - `store` and `modules` (feature `distribution`): installed plugins and desktop routing;
//! - the modules built into the core, run as guests of the same runtime ([`Builtins`]),
//!   and what the core tells them about itself ([`core`]);
//! - the [`cause`] of the core's failures a guest tells apart.
//!
//! The format, the ABI and the limits are described in `docs/design/plugins.md`.

mod builtins;
mod caps;
pub mod cause;
pub mod core;
pub mod headless;
mod host;
pub mod manifest;
pub mod manual;
#[cfg(feature = "distribution")]
pub mod modules;
pub mod operations;
#[cfg(feature = "distribution")]
pub mod package;
mod runtime;
#[cfg(feature = "distribution")]
pub mod store;

#[cfg(not(target_pointer_width = "64"))]
pub use builtins::PROCESS_RESERVE;
pub use builtins::{
    BUILTIN_FUEL, BUILTIN_HIGH_WATER, BUILTIN_ID_PREFIX, BUILTIN_IDLE, BUILTIN_KEPT_BUDGET,
    BUILTIN_MAX_KEPT, BUILTIN_MAX_LIVE, BUILTIN_MAX_MEMORY, BUILTIN_MAX_MODULES, BUILTIN_MAX_REPLY,
    BUILTIN_MAX_TRANSFER, BuiltinInfo, BuiltinLimits, BuiltinSource, BuiltinStats, Builtins,
};
pub use caps::{
    DEFAULT_OCSP, DEFAULT_TSA, HTTP_TIMEOUT, MAX_HTTP_BODY, MAX_HTTP_REQUESTS, MAX_KEY_HANDLES,
    MAX_SECRETS, NCA_PKI_HOSTS, SharedState, nca_pki_hosts,
};
pub use host::HostServices;
pub use manifest::{
    Added, Capabilities, HttpPrefix, Localized, Manifest, OriginPattern, Replaces, is_symbolic_name,
};
#[cfg(feature = "distribution")]
pub use modules::{BUILT_IN, LoadedInfo, MemoryLimits, OnMissing, PluginModules};
pub use oncl_pdk::abi::ABI_VERSION;
#[cfg(feature = "distribution")]
pub use package::{MAX_MANIFEST, MAX_PACKAGE, MAX_WASM, PACKAGE_EXT, Package, archive};
pub use runtime::{
    Compiled, Engine, INSTANCE_HIGH_WATER, Instance, InstanceLimits, LoadError, MAX_INSTANCES,
    MAX_MEMORY, MAX_TRANSFER, MEMORY_BUDGET, PLUGIN_ERROR_REPLY, PROCESS_FUEL, PluginError,
    SessionContext, Trust,
};
#[cfg(feature = "distribution")]
pub use store::{Installed, Source, Store, StoreError, StoreState};
pub use url::Url;

use std::io;

/// Why a package or a manifest is refused.
#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    /// The package or one of its files exceeds the distribution package limits.
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
    /// `[[operations]]` break a rule of the format.
    #[error("the plugin manifest's operations are wrong: {0}")]
    Operation(#[from] operations::OperationError),
    /// The package file could not be read.
    #[error("the plugin package could not be read: {0}")]
    Io(#[from] io::Error),
}
