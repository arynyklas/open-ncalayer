//! The OpenNCALayer daemon: an NCALayer-compatible WebSocket server on
//! `wss://127.0.0.1:13579` (plus a self-test page over HTTPS on the same port), its data
//! directory and settings, logging and the command line.

pub mod cli;
mod http;
mod logging;
mod paths;
mod server;
mod settings;

pub use paths::{DATA_DIR_VAR, Paths};
pub use server::{
    DEFAULT_PORT, IDLE_TIMEOUT, MAX_MESSAGE, MAX_PORT, PORT_VAR, ServerConfig, build_registry,
    listen_port, listen_port_from, serve,
};
pub use settings::JsonSettings;
