//! Real endpoints: bind, connect and talk over the platform transport.

use std::io::ErrorKind;

use oncl_ipc::{Endpoint, bind, connect, endpoint, read_frame, write_frame};
use tempfile::TempDir;

/// An endpoint of a fresh data directory, unique per test.
fn unique_endpoint() -> (TempDir, Endpoint) {
    let dir = tempfile::tempdir().expect("tempdir");
    let ep = endpoint(dir.path()).expect("endpoint");
    (dir, ep)
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
