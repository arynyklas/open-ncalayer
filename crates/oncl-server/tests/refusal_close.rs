//! A server that answers before it has read the whole request (a refusal decided from the
//! metadata part, before the documents) must let the client finish writing and read the
//! answer. Closing at once, with the rest of the request still in flight, makes the server's
//! TCP stack reset the connection, and the reset can erase the answer from the client's
//! receive queue (RFC 9112 section 9.6): the client sees a broken pipe or a reset instead of
//! the typed refusal.

use axum::{Router, http::StatusCode, routing::post};
use oncl_server::service::{LINGER, LINGER_BYTES, serve_connection};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{Instant, timeout},
};

/// How long a step may take on a loaded runner before it is called stuck.
const STUCK: Duration = Duration::from_secs(30);

/// A connection to a server task that refuses every POST without reading its body.
async fn refusing_server() -> (TcpStream, JoinHandle<io::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (socket, peer) = listener.accept().await.unwrap();
    let router = Router::new().route("/", post(|| async { (StatusCode::FORBIDDEN, "refused") }));
    let server = tokio::spawn(serve_connection(
        socket,
        peer,
        router,
        Duration::from_secs(5),
        Instant::now() + Duration::from_secs(120),
    ));
    (client, server)
}

fn head(content_length: u64) -> Vec<u8> {
    format!("POST / HTTP/1.1\r\nHost: refusal.test\r\nContent-Length: {content_length}\r\n\r\n")
        .into_bytes()
}

/// Reads until the whole refusal (`403`, the text `refused`) has arrived.
async fn read_refusal(client: &mut TcpStream) {
    let mut received = Vec::new();
    let mut chunk = [0u8; 1024];
    while !received.ends_with(b"refused") {
        let n = timeout(STUCK, client.read(&mut chunk))
            .await
            .expect("the refusal arrives")
            .expect("the client reads the refusal, not a reset");
        assert_ne!(
            n, 0,
            "the connection ended before the refusal: {received:?}"
        );
        received.extend_from_slice(&chunk[..n]);
    }
    assert!(received.starts_with(b"HTTP/1.1 403"), "{received:?}");
}

#[tokio::test]
async fn a_client_still_writing_when_the_server_answers_reads_the_answer() {
    let (mut client, server) = refusing_server().await;
    let body = LINGER_BYTES / 2;
    let first = 16 << 10;
    let mut start = head(body);
    start.extend(std::iter::repeat_n(b'x', first));
    client.write_all(&start).await.unwrap();
    // The server refuses without having read the body.
    read_refusal(&mut client).await;
    // The rest of the body is still accepted, and discarded.
    let chunk = vec![b'x'; 64 << 10];
    let mut left = body - first as u64;
    while left > 0 {
        let n = left.min(chunk.len() as u64) as usize;
        client
            .write_all(&chunk[..n])
            .await
            .expect("the server reads on until the client has sent what it announced");
        left -= n as u64;
    }
    client.shutdown().await.unwrap();
    let mut rest = Vec::new();
    timeout(STUCK, client.read_to_end(&mut rest))
        .await
        .expect("the connection ends")
        .expect("the connection ends in an orderly close, not a reset");
    assert!(rest.is_empty(), "{rest:?}");
    timeout(STUCK, server)
        .await
        .expect("the server ends the connection")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_client_that_never_stops_sending_is_cut_off_after_the_bound() {
    let (client, server) = refusing_server().await;
    let (mut read, mut write) = client.into_split();
    write.write_all(&head(u64::MAX / 2)).await.unwrap();
    let writer = tokio::spawn(async move {
        let chunk = vec![b'x'; 64 << 10];
        while write.write_all(&chunk).await.is_ok() {}
    });
    let started = Instant::now();
    timeout(LINGER + STUCK, server)
        .await
        .expect("the linger is bounded in bytes and time, whatever the client does")
        .unwrap()
        .unwrap();
    assert!(started.elapsed() < LINGER + STUCK);
    // The refusal had been sent before the cut.
    let mut answer = Vec::new();
    let _ = timeout(STUCK, read.read_to_end(&mut answer)).await;
    writer.abort();
}

#[tokio::test]
async fn a_client_that_closes_after_the_answer_does_not_hold_the_connection() {
    let (mut client, server) = refusing_server().await;
    client.write_all(&head(0)).await.unwrap();
    read_refusal(&mut client).await;
    drop(client);
    let started = Instant::now();
    timeout(STUCK, server)
        .await
        .expect("the server ends the connection")
        .unwrap()
        .unwrap();
    assert!(
        started.elapsed() < LINGER / 2,
        "{:?} after the client closed",
        started.elapsed()
    );
}
