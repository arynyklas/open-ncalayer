//! OpenNCALayer development tasks. `main.rs` is a thin CLI over these modules,
//! so xtask integration tests can call them as `xtask::…`.

pub mod fetch;
pub mod fixtures;
pub mod interop;
