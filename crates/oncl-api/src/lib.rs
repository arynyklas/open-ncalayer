#![recursion_limit = "1024"]
//! Implemented wire contracts only. Enabling `server` adds HTTP routing, not a
//! service, key store, desktop state or an authority factory.
pub mod dto;
pub mod error;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod multipart;
#[cfg(feature = "server")]
pub mod openapi;
#[cfg(feature = "server")]
pub mod server;
