//! Real endpoints: bind, connect and talk over the platform transport.

use std::io::ErrorKind;

use oncl_ipc::{Endpoint, bind, connect, endpoint, read_frame, write_frame};
use tempfile::TempDir;

/// An endpoint of a fresh data directory, unique per test.
fn unique_endpoint() -> (TempDir, Endpoint) {
    #[cfg(unix)]
    isolate_runtime_dir();
    let dir = tempfile::tempdir().expect("tempdir");
    let ep = endpoint(dir.path()).expect("endpoint");
    (dir, ep)
}

/// Points `XDG_RUNTIME_DIR` at a private test directory so that sockets never land in the
/// user's real runtime directory, and returns the real one. Runs once, before any test of
/// this binary reads the environment.
///
/// The directory, `<temp dir>/oncl-ipc-rt-<uid>` (0700), is short so that Linux socket paths
/// stay on the XDG branch instead of the 100-byte `/tmp` fallback, and stable so that runs
/// do not pile up directories: each listener removes its own files on drop.
#[cfg(unix)]
fn isolate_runtime_dir() -> Option<&'static std::path::Path> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::path::PathBuf;
    use std::sync::LazyLock;

    static REAL_RUNTIME_DIR: LazyLock<Option<PathBuf>> = LazyLock::new(|| {
        let real = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        // The owner of a fresh directory is this process's uid (no libc in dev-deps).
        let probe = tempfile::tempdir().expect("probe tempdir");
        let uid = std::fs::metadata(probe.path())
            .expect("probe metadata")
            .uid();
        let dir = std::env::temp_dir().join(format!("oncl-ipc-rt-{uid}"));
        if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            assert_eq!(e.kind(), ErrorKind::AlreadyExists, "{}: {e}", dir.display());
        }
        // `bind` itself refuses the directory unless it is ours and at most 0700.
        // SAFETY: every test forces this first and `LazyLock` blocks the others until the
        // variable is set, so no other thread of this binary reads the environment meanwhile.
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", &dir) };
        real
    });
    REAL_RUNTIME_DIR.as_deref()
}

#[tokio::test]
async fn bind_connect_echo() {
    let (_dir, ep) = unique_endpoint();
    let mut listener = bind(&ep).await.expect("bind");
    let server = tokio::spawn(async move {
        // Two clients in a row: the second one needs the next pipe instance on Windows.
        for _ in 0..2 {
            let mut stream = listener.accept().await.expect("accept");
            while let Some(frame) = read_frame(&mut stream).await.expect("server read") {
                write_frame(&mut stream, &frame)
                    .await
                    .expect("server write");
            }
        }
    });

    for round in 0..2u8 {
        let mut client = connect(&ep).await.expect("connect");
        for payload in [vec![], vec![round], vec![round; 70_000]] {
            write_frame(&mut client, &payload)
                .await
                .expect("client write");
            let echo = read_frame(&mut client).await.expect("client read");
            assert_eq!(echo, Some(payload));
        }
    }
    server.await.expect("server task");
}

#[tokio::test]
async fn second_bind_is_addr_in_use() {
    let (_dir, ep) = unique_endpoint();
    let _first = bind(&ep).await.expect("first bind");
    let err = bind(&ep).await.expect_err("second bind must fail");
    assert_eq!(err.kind(), ErrorKind::AddrInUse, "{err}");
}

#[tokio::test]
async fn connect_without_server_is_not_found_or_refused() {
    let (_dir, ep) = unique_endpoint();
    let err = connect(&ep).await.expect_err("no server");
    assert!(
        matches!(
            err.kind(),
            ErrorKind::NotFound | ErrorKind::ConnectionRefused
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn rebind_after_listener_drop() {
    let (_dir, ep) = unique_endpoint();
    drop(bind(&ep).await.expect("first bind"));
    let _again = bind(&ep).await.expect("bind after drop");
}

#[cfg(unix)]
#[tokio::test]
async fn socket_stays_out_of_real_dirs_and_is_removed() {
    use std::path::PathBuf;

    let real_runtime_dir = isolate_runtime_dir();
    let (_dir, ep) = unique_endpoint();
    // Wherever the endpoint resolved to (XDG dir, data dir or `/tmp` fallback; macOS
    // ignores XDG), it is not in the user's real runtime or data directory.
    let socket = PathBuf::from(ep.to_string());
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    let real_data_dir = if cfg!(target_os = "macos") {
        home.join("Library/Application Support/OpenNCALayer")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map_or_else(|| home.join(".local/share"), PathBuf::from)
            .join("openncalayer")
    };
    for real in real_runtime_dir
        .into_iter()
        .chain([real_data_dir.as_path()])
    {
        assert!(
            !socket.starts_with(real),
            "{} is under {}",
            socket.display(),
            real.display()
        );
    }

    let lock = PathBuf::from(format!("{}.lock", socket.display()));
    let listener = bind(&ep).await.expect("bind");
    assert!(socket.exists());
    assert!(lock.exists());
    drop(listener);
    assert!(!socket.exists());
    assert!(!lock.exists());
}
