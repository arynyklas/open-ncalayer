//! Local IPC of OpenNCALayer: the daemon listens on an endpoint, the native messaging relay
//! (`nmhost`) connects to it.
//!
//! - [`endpoint`] computes the endpoint of the current user, session and data directory: a
//!   named pipe on Windows, a Unix domain socket elsewhere. [`bind`] and [`connect`] open it
//!   and check that the other side runs as the same user.
//! - [`read_frame`]/[`write_frame`] frame IPC messages (`u32` little-endian length);
//!   [`read_nm_frame`]/[`write_nm_frame`] frame the browser's native messaging stdio.
//! - [`ids`] holds the native messaging host name and the extension ids.
//! - `process` (Windows only) helps the relay start the daemon detached from the browser.

mod endpoint;
mod frame;
pub mod ids;
#[cfg(windows)]
pub mod process;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub use endpoint::{Endpoint, IpcListener, IpcStream, bind, connect, endpoint};
pub use frame::{MAX_FRAME, NM_OUT_LIMIT, read_frame, read_nm_frame, write_frame, write_nm_frame};
