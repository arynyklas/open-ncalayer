//! The OpenNCALayer daemon: an NCALayer-compatible WebSocket server on
//! `wss://127.0.0.1:13579` (plus a self-test page over HTTPS on the same port), the bridge
//! to the browser extension over local IPC, the registration of its native messaging host,
//! its data directory and settings, what its settings window works with, logging,
//! signature checking (`cms-verify`) and the command line.

mod bridge;
pub mod cli;
pub mod cms_verify;
pub mod desktop;
mod http;
mod logging;
pub mod nm;
mod paths;
mod server;
mod session;
mod settings;

pub use bridge::{NM_FRAME_LIMIT, serve_ipc, split_message};
pub use paths::{DATA_DIR_VAR, Paths};
pub use server::{
    DEFAULT_PORT, IDLE_TIMEOUT, MAX_MESSAGE, MAX_PORT, PORT_VAR, ServerConfig, build_registry,
    listen_port, listen_port_from, serve,
};
pub use settings::{JsonSettings, LiveProxyTransport, load_settings};
