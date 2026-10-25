//! Unix domain socket transport.

use std::fmt;
use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use tokio::net::{UnixListener, UnixStream};

use crate::endpoint::hex16;

/// Socket paths longer than this fall back to `/tmp` (`sun_path` is 104 bytes on macOS and
/// 108 on Linux, including the terminating NUL).
const MAX_SOCKET_PATH: usize = 100;

/// A connection over a Unix domain socket.
pub(crate) type Stream = UnixStream;

/// The socket path and the kind of directory it lives in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Address {
    path: PathBuf,
    dir: SocketDir,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.path.display(), f)
    }
}

/// Who manages the directory of the socket, which decides how [`bind`] treats it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketDir {
    /// `$XDG_RUNTIME_DIR`: the session manager keeps it 0700; only checked.
    Runtime,
    /// The data directory: created if missing, tightened to 0700 if wider.
    Data,
    /// `/tmp/openncalayer-<uid>`: created 0700; an existing one is checked.
    Fallback,
}

/// The address of the current user for the absolute `data_dir`.
pub(crate) fn endpoint(data_dir: &Path) -> io::Result<Address> {
    // macOS has no XDG runtime directory: the socket always goes to the data directory.
    let runtime_dir = if cfg!(target_os = "macos") {
        None
    } else {
        std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
    };
    Ok(address(data_dir, runtime_dir.as_deref(), current_uid()))
}

/// The address for `data_dir`, the runtime directory and `uid`, without looking at the
/// environment. A relative or empty runtime directory is ignored (XDG requires an absolute
/// path).
fn address(data_dir: &Path, runtime_dir: Option<&Path>, uid: u32) -> Address {
    let hex = hex16(&format!("{uid}|"), data_dir);
    let preferred = match runtime_dir.filter(|dir| dir.is_absolute()) {
        Some(dir) => Address {
            path: dir.join(format!("openncalayer-{hex}.sock")),
            dir: SocketDir::Runtime,
        },
        None => Address {
            path: data_dir.join("daemon.sock"),
            dir: SocketDir::Data,
        },
    };
    if preferred.path.as_os_str().len() <= MAX_SOCKET_PATH {
        return preferred;
    }
    Address {
        path: PathBuf::from(format!("/tmp/openncalayer-{uid}/{hex}.sock")),
        dir: SocketDir::Fallback,
    }
}

/// A listening socket; clients of other users are dropped.
#[derive(Debug)]
pub(crate) struct Listener {
    inner: UnixListener,
    uid: u32,
}

pub(crate) async fn bind(addr: &Address) -> io::Result<Listener> {
    let uid = current_uid();
    let dir = addr
        .path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket path has no parent"))?;
    prepare_dir(dir, addr.dir, uid)?;
    let inner = match UnixListener::bind(&addr.path) {
        Ok(listener) => listener,
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            remove_stale(&addr.path).await?;
            UnixListener::bind(&addr.path)?
        }
        Err(e) => return Err(e),
    };
    fs::set_permissions(&addr.path, Permissions::from_mode(0o600))?;
    Ok(Listener { inner, uid })
}

impl Listener {
    pub(crate) async fn accept(&mut self) -> io::Result<Stream> {
        loop {
            let (stream, _) = self.inner.accept().await?;
            if stream.peer_cred().is_ok_and(|cred| cred.uid() == self.uid) {
                return Ok(stream);
            }
        }
    }
}

pub(crate) async fn connect(addr: &Address) -> io::Result<Stream> {
    let stream = UnixStream::connect(&addr.path).await?;
    let server_uid = stream.peer_cred()?.uid();
    let uid = current_uid();
    if server_uid != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is served by uid {server_uid}, not {uid}",
                addr.path.display()
            ),
        ));
    }
    Ok(stream)
}

/// Makes sure `dir` exists, belongs to `uid` and is at most 0700.
fn prepare_dir(dir: &Path, kind: SocketDir, uid: u32) -> io::Result<()> {
    let meta = match kind {
        SocketDir::Runtime => fs::metadata(dir)?,
        SocketDir::Data => {
            fs::create_dir_all(dir)?;
            let meta = fs::metadata(dir)?;
            if meta.uid() == uid && meta.mode() & 0o077 != 0 {
                fs::set_permissions(dir, Permissions::from_mode(meta.mode() & 0o700))?;
                fs::metadata(dir)?
            } else {
                meta
            }
        }
        SocketDir::Fallback => {
            if let Err(e) = DirBuilder::new().mode(0o700).create(dir)
                && e.kind() != io::ErrorKind::AlreadyExists
            {
                return Err(e);
            }
            // Not followed: a symlink planted by someone else must not be trusted.
            fs::symlink_metadata(dir)?
        }
    };
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "socket directory {} must be a directory of uid {uid} with mode 0700 or \
                 narrower (owner {}, mode {:o})",
                dir.display(),
                meta.uid(),
                meta.mode() & 0o7777
            ),
        ));
    }
    Ok(())
}

/// Removes the socket file at `path` unless a live server answers on it.
async fn remove_stale(path: &Path) -> io::Result<()> {
    if UnixStream::connect(path).await.is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("a server already listens on {}", path.display()),
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("{} exists and is not a socket", path.display()),
        )),
        // Gone in the meantime: the next bind decides.
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_dir_holds_hashed_socket() {
        let addr = address(
            Path::new("/srv/oncl"),
            Some(Path::new("/run/user/1000")),
            1000,
        );
        // python: hashlib.sha256(b"1000|/srv/oncl").hexdigest()[:16]
        assert_eq!(
            addr.path,
            Path::new("/run/user/1000/openncalayer-8ea222d74a70a38e.sock")
        );
        assert_eq!(addr.dir, SocketDir::Runtime);
    }

    #[test]
    fn no_runtime_dir_uses_data_dir() {
        for runtime in [None, Some(Path::new("")), Some(Path::new("relative"))] {
            let addr = address(Path::new("/srv/oncl"), runtime, 1000);
            assert_eq!(addr.path, Path::new("/srv/oncl/daemon.sock"));
            assert_eq!(addr.dir, SocketDir::Data);
        }
    }

    #[test]
    fn long_data_dir_falls_back_to_tmp() {
        let data_dir = PathBuf::from(format!("/{}", "d".repeat(149)));
        assert_eq!(data_dir.as_os_str().len(), 150);
        let addr = address(&data_dir, None, 1234);
        let hex = hex16("1234|", &data_dir);
        assert_eq!(
            addr.path,
            PathBuf::from(format!("/tmp/openncalayer-1234/{hex}.sock"))
        );
        assert_eq!(addr.dir, SocketDir::Fallback);

        // A long runtime directory falls back the same way.
        let runtime = PathBuf::from(format!("/{}", "r".repeat(99)));
        let addr = address(Path::new("/srv/oncl"), Some(&runtime), 1234);
        assert_eq!(addr.dir, SocketDir::Fallback);
    }

    #[test]
    fn path_of_exactly_100_bytes_is_kept() {
        // "/" + 87 bytes + "/daemon.sock" (12 bytes) = 100 bytes.
        let data_dir = PathBuf::from(format!("/{}", "d".repeat(87)));
        let addr = address(&data_dir, None, 1);
        assert_eq!(addr.path.as_os_str().len(), 100);
        assert_eq!(addr.dir, SocketDir::Data);
    }

    #[tokio::test]
    async fn stale_socket_file_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let addr = address(dir.path(), None, current_uid());
        // A socket file whose server is gone.
        drop(std::os::unix::net::UnixListener::bind(&addr.path).unwrap());
        assert!(addr.path.exists());

        let mut listener = bind(&addr).await.expect("stale socket replaced");
        let (accepted, connected) = tokio::join!(listener.accept(), connect(&addr));
        accepted.unwrap();
        connected.unwrap();
    }

    #[tokio::test]
    async fn regular_file_is_not_removed() {
        let dir = tempfile::tempdir().unwrap();
        let addr = address(dir.path(), None, current_uid());
        fs::write(&addr.path, b"not a socket").unwrap();
        let err = bind(&addr).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(fs::read(&addr.path).unwrap(), b"not a socket");
    }

    #[tokio::test]
    async fn modes_are_0700_and_0600() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        fs::create_dir(&data_dir).unwrap();
        fs::set_permissions(&data_dir, Permissions::from_mode(0o755)).unwrap();
        let addr = address(&data_dir, None, current_uid());
        let _listener = bind(&addr).await.unwrap();
        assert_eq!(fs::metadata(&data_dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&addr.path).unwrap().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn open_runtime_dir_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), Permissions::from_mode(0o755)).unwrap();
        let addr = address(Path::new("/srv/oncl"), Some(dir.path()), current_uid());
        let err = bind(&addr).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
