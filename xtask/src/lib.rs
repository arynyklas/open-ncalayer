//! OpenNCALayer development tasks. `main.rs` is a thin CLI over these modules,
//! so xtask integration tests can call them as `xtask::…`.

pub mod e2e;
pub mod ext;
pub mod fetch;
pub mod fixtures;
pub mod imports;
pub mod index;
pub mod interop;
pub mod licenses;
pub mod ncanode;
pub mod sign;
