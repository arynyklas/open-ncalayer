//! The IPC endpoint of a (user, session, data directory) and connections over it.

use std::fmt;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(unix)]
use crate::unix as sys;
#[cfg(windows)]
use crate::windows as sys;

/// Where the daemon listens and the relay connects: a named pipe on Windows, a Unix domain
/// socket elsewhere. Both sides compute it with [`endpoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint(pub(crate) sys::Address);

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// The endpoint of the current user and session for the data directory `data_dir`.
///
/// - Windows: `\\.\pipe\OpenNCALayer-<hex16>`, `hex16` being the first 8 bytes of SHA-256
///   of `<user SID>|<session id>|<absolute data_dir>`.
/// - Linux: `$XDG_RUNTIME_DIR/openncalayer-<hex16>.sock` (`hex16` of
///   `<uid>|<absolute data_dir>`) if `XDG_RUNTIME_DIR` is set, otherwise
///   `<data_dir>/daemon.sock`; macOS: always `<data_dir>/daemon.sock`.
/// - Unix paths longer than 100 bytes become `/tmp/openncalayer-<uid>/<hex16>.sock`.
///
/// # Errors
///
/// Failures to make `data_dir` absolute or (Windows) to query the user SID or session.
pub fn endpoint(data_dir: &Path) -> io::Result<Endpoint> {
    let data_dir = std::path::absolute(data_dir)?;
    sys::endpoint(&data_dir).map(Endpoint)
}

/// The first 8 bytes of SHA-256 of `prefix` followed by `path`, as 16 lowercase hex digits.
pub(crate) fn hex16(prefix: &str, path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    // UTF-8 for valid Unicode paths; raw bytes (Unix) or WTF-8 (Windows) otherwise.
    hasher.update(path.as_os_str().as_encoded_bytes());
    hasher.finalize()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Listens on an [`Endpoint`]; created by [`bind`].
#[derive(Debug)]
pub struct IpcListener(sys::Listener);

/// Binds `ep`.
///
/// On Windows the pipe is created as the first instance, with a DACL granting access only
/// to the current user and `SYSTEM`, and remote clients are rejected. On Unix the socket
/// directory is checked (or created) to be at most 0700 and owned by the user, a stale
/// socket file left by a dead server is replaced, and the socket gets mode 0600.
///
/// # Errors
///
/// - [`io::ErrorKind::AddrInUse`] if a live server already holds `ep`;
/// - [`io::ErrorKind::PermissionDenied`] (Unix) if the socket directory belongs to another
///   user or is accessible to others and cannot be tightened;
/// - other I/O and OS errors.
pub async fn bind(ep: &Endpoint) -> io::Result<IpcListener> {
    sys::bind(&ep.0).await.map(IpcListener)
}

impl IpcListener {
    /// Waits for the next client.
    ///
    /// On Windows the connected pipe instance is handed out and the next instance is created
    /// right away. On Unix, clients of another user are dropped silently.
    ///
    /// # Errors
    ///
    /// I/O and OS errors of the transport.
    pub async fn accept(&mut self) -> io::Result<IpcStream> {
        self.0.accept().await.map(IpcStream)
    }
}

/// A connection over an [`Endpoint`].
#[derive(Debug)]
pub struct IpcStream(sys::Stream);

/// Connects to `ep` and checks that the server runs as the current user.
///
/// # Errors
///
/// - [`io::ErrorKind::NotFound`] or [`io::ErrorKind::ConnectionRefused`] if no server
///   listens on `ep`;
/// - [`io::ErrorKind::PermissionDenied`] if the server runs as another user or cannot be
///   checked;
/// - other I/O and OS errors.
pub async fn connect(ep: &Endpoint) -> io::Result<IpcStream> {
    sys::connect(&ep.0).await.map(IpcStream)
}

impl AsyncRead for IpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for IpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex16_is_sha256_prefix() {
        // python: hashlib.sha256(b"a|b").hexdigest()[:16]
        assert_eq!(hex16("a|", Path::new("b")), "0eab8a0a3380abf4");
    }

    #[test]
    fn listener_and_stream_can_move_between_tasks() {
        fn assert_send_unpin<T: Send + Unpin + 'static>() {}
        assert_send_unpin::<IpcListener>();
        assert_send_unpin::<IpcStream>();
        assert_send_unpin::<Endpoint>();
    }

    #[test]
    fn endpoint_is_stable_and_depends_on_data_dir() {
        let base = std::env::temp_dir();
        let one = endpoint(&base.join("oncl-ipc-one")).unwrap();
        let again = endpoint(&base.join("oncl-ipc-one")).unwrap();
        let other = endpoint(&base.join("oncl-ipc-other")).unwrap();
        assert_eq!(one, again);
        assert_eq!(one.to_string(), again.to_string());
        assert_ne!(one, other);
        assert_ne!(one.to_string(), other.to_string());
    }

    #[test]
    fn endpoint_of_relative_dir_is_absolute() {
        let relative = endpoint(Path::new("oncl-ipc-rel")).unwrap();
        let absolute = endpoint(&std::env::current_dir().unwrap().join("oncl-ipc-rel")).unwrap();
        assert_eq!(relative, absolute);
    }
}
