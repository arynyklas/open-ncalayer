//! OpenNCALayer development tasks. `main.rs` is a thin CLI over these modules,
//! so xtask integration tests can call them as `xtask::…`.

pub mod builtins;
pub mod e2e;
pub mod ext;
pub mod fetch;
pub mod fixtures;
pub mod imports;
pub mod index;
pub mod interop;
pub mod licenses;
pub mod ncanode;
pub mod package;
pub mod platform;
#[path = "platform/interop.rs"]
pub mod platform_interop;
pub mod plugin;
pub mod plugin_ops;
pub mod plugin_ports;
pub mod privacy;
pub mod registry;
pub mod release_features;
pub mod sdk_delivery;
pub mod sign;
pub mod token_emu;
pub mod upstream;
pub mod win7;
pub mod winget;
