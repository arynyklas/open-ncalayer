#![recursion_limit = "1024"]
//! Implemented wire contracts only. Enabling `server` adds HTTP routing, not a
//! service, key store, desktop state or an authority factory.
#[cfg(feature = "client")]
pub mod client;
pub mod dto;
pub mod error;
#[cfg(feature = "server")]
pub mod multipart;
#[cfg(feature = "server")]
pub mod openapi;
#[cfg(feature = "server")]
pub mod server;
