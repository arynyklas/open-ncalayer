//! Local IPC of OpenNCALayer: the daemon listens on an endpoint, the native messaging relay
//! (`nmhost`) connects to it.
//!
//! - [`endpoint`] computes the endpoint of the current user, session and data directory: a
//!   named pipe on Windows, a Unix domain socket elsewhere. [`bind`] and [`connect`] open it
//!   and check that the other side runs as the same user.
//! - [`read_frame`]/[`write_frame`] frame IPC messages (`u32` little-endian length);
//!   [`read_nm_frame`]/[`write_nm_frame`] frame the browser's native messaging stdio.
//! - [`ids`] holds the native messaging host name and the extension ids.
//! - [`maintenance`] is the management endpoint an installer asks the running program to hold
//!   still on while the program is replaced.
//! - `process` (Windows only) helps the relay start the daemon detached from the browser.

mod datadir;
mod endpoint;
mod frame;
pub mod ids;
pub mod maintenance;
#[cfg(windows)]
pub mod process;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub use datadir::{DATA_DIR_VAR, data_dir_from};
pub use endpoint::{Endpoint, IpcListener, IpcStream, bind, connect, endpoint};
pub use frame::{MAX_FRAME, NM_OUT_LIMIT, read_frame, read_nm_frame, write_frame, write_nm_frame};
