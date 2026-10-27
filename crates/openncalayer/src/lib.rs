//! The OpenNCALayer daemon: an NCALayer-compatible WebSocket server on
//! `wss://127.0.0.1:13579` (plus a self-test page over HTTPS on the same port) that can start
//! later in the running daemon, the bridge to the browser extension over local IPC, the
//! registration of its native messaging host, its data directory and settings, what its
//! settings window and TLS wizard work with, the certificate's renewal and what the tray tells
//! the user, its self-update, logging, signature checking (`cms-verify`) and the command line.

mod bridge;
pub mod cli;
pub mod cms_verify;
pub mod desktop;
mod http;
mod logging;
pub mod nm;
pub mod notices;
mod paths;
pub mod renewal;
mod server;
mod session;
mod settings;
pub mod update;
pub mod wss;

pub use bridge::{NM_FRAME_LIMIT, serve_ipc, split_message};
pub use paths::{DATA_DIR_VAR, Paths};
pub use server::{
    DEFAULT_PORT, IDLE_TIMEOUT, LiveTls, MAX_MESSAGE, MAX_PORT, PORT_VAR, ServerConfig,
    build_registry, listen_port, listen_port_from, serve,
};
pub use session::requests_idle;
pub use settings::{JsonSettings, LiveProxyTransport, load_settings};
