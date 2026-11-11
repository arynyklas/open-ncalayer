//! A server that answers before it has read the whole request (a refusal decided from the
//! metadata part, before the documents) must let the client finish writing and read the
//! answer. Closing at once, with the rest of the request still in flight, makes the server's
//! TCP stack reset the connection, and the reset can erase the answer from the client's
//! receive queue (RFC 9112 section 9.6): the client sees a broken pipe or a reset instead of
//! the typed refusal.
//!
//! The wait for the client is bounded, and these tests pin each bound: the bytes it reads,
//! the time it takes, and what it holds for the operation while it waits.

#[path = "server_support/mod.rs"]
mod support;

use axum::{Router, http::StatusCode, routing::post};
use oncl_server::service::serve_connection;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{Instant, timeout},
};

/// The documented time bound (`docs/user/http-api.md`, `docs/user/server.md`): an answered
/// connection stays open for what the client still sends for at most this long.
const LINGER: Duration = Duration::from_secs(1);
/// The documented byte bound: the server reads and discards at most about this much.
const LINGER_BYTES: u64 = 8 << 20;
/// What the server may have read besides the drain itself and the part of its last read
/// that goes past the bound: the request head and what hyper buffers before it answers.
const READ_MARGIN: u64 = 1 << 20;
/// How long a step may take on a loaded runner before it is called stuck.
const STUCK: Duration = Duration::from_secs(30);
/// How far past the time bound a connection may end on a loaded runner. The connection
/// that is not cut at the time bound lasts until its own deadline (120 s here).
const SLACK: Duration = Duration::from_secs(10);

/// The server's end of a connection; counts the bytes the server reads from it.
struct Counted {
    stream: TcpStream,
    read: Arc<AtomicU64>,
}
impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.stream).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            self.read
                .fetch_add((buf.filled().len() - before) as u64, Ordering::Relaxed);
        }
        poll
    }
}
impl AsyncWrite for Counted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// A connection to a server task that refuses every POST without reading its body, and the
/// count of the bytes that server task reads from the connection.
async fn refusing_server() -> (TcpStream, JoinHandle<io::Result<()>>, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (socket, peer) = listener.accept().await.unwrap();
    let read = Arc::new(AtomicU64::new(0));
    let router = Router::new().route("/", post(|| async { (StatusCode::FORBIDDEN, "refused") }));
    let server = tokio::spawn(serve_connection(
        Counted {
            stream: socket,
            read: read.clone(),
        },
        peer,
        router,
        Duration::from_secs(5),
        Instant::now() + Duration::from_secs(120),
    ));
    (client, server, read)
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
    let (mut client, server, _) = refusing_server().await;
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

/// A client that sends as fast as it can, with a body it announces far larger than the
/// bound, is cut off after the byte bound: the server reads about `LINGER_BYTES` of it and
/// no more, however long the client keeps sending. The cut is asserted by the bytes the
/// server actually read (the client may push more into the kernel buffers before it sees
/// the reset), and the answer, sent before the cut, still reached the client.
#[tokio::test]
async fn a_client_that_never_stops_sending_is_cut_off_after_the_byte_bound() {
    let (client, server, read) = refusing_server().await;
    let (mut reader, mut writer) = client.into_split();
    // The client reads as the answer arrives: a reset at the cut can erase what the
    // application has not read yet, on some platforms.
    let answer = tokio::spawn(async move {
        let mut received = Vec::new();
        let mut chunk = [0u8; 1024];
        while let Ok(n) = reader.read(&mut chunk).await {
            if n == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..n]);
        }
        received
    });
    writer.write_all(&head(u64::MAX / 2)).await.unwrap();
    let sender = tokio::spawn(async move {
        let chunk = vec![b'x'; 64 << 10];
        while writer.write_all(&chunk).await.is_ok() {}
    });
    timeout(LINGER + SLACK, server)
        .await
        .expect("the wait for the client is bounded, whatever the client does")
        .unwrap()
        .unwrap();
    let read = read.load(Ordering::Relaxed);
    assert!(
        read <= LINGER_BYTES + READ_MARGIN,
        "the server read {read} bytes of a client that never stops: the byte bound is {LINGER_BYTES}"
    );
    let answer = timeout(STUCK, answer)
        .await
        .expect("the client's read ends")
        .unwrap();
    assert!(
        answer.starts_with(b"HTTP/1.1 403") && answer.ends_with(b"refused"),
        "the refusal had been sent before the cut: {answer:?}"
    );
    sender.abort();
}

/// A client that sends nothing more after the answer, and keeps its socket open, is waited
/// for until the time bound and not past it. The bound is asserted from the moment before
/// the request is sent, so the wait cannot have started earlier than that.
#[tokio::test]
async fn a_client_that_stalls_after_the_answer_is_cut_off_at_the_time_bound() {
    let (mut client, server, _) = refusing_server().await;
    let started = Instant::now();
    let mut start = head(1 << 20);
    start.extend(std::iter::repeat_n(b'x', 16 << 10));
    client.write_all(&start).await.unwrap();
    read_refusal(&mut client).await;
    // From here the client sends nothing and keeps its socket open.
    timeout(LINGER + SLACK, server)
        .await
        .expect("a stalled client does not hold the connection past the time bound")
        .unwrap()
        .unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= LINGER * 4 / 5,
        "the server did not wait for the client: it ended {elapsed:?} after the request"
    );
    // The server had read everything the client sent: the close is an orderly one.
    let mut rest = Vec::new();
    timeout(STUCK, client.read_to_end(&mut rest))
        .await
        .expect("the connection has ended")
        .expect("the connection ends in an orderly close, not a reset");
    assert!(rest.is_empty(), "{rest:?}");
}

#[tokio::test]
async fn a_client_that_closes_after_the_answer_does_not_hold_the_connection() {
    let (mut client, server, _) = refusing_server().await;
    let started = Instant::now();
    client.write_all(&head(0)).await.unwrap();
    read_refusal(&mut client).await;
    drop(client);
    timeout(STUCK, server)
        .await
        .expect("the server ends the connection")
        .unwrap()
        .unwrap();
    // A server that did not see the close would wait out the whole time bound, which starts
    // after the request: it would end no sooner than `LINGER` after `started`.
    assert!(
        started.elapsed() < LINGER,
        "the server ended {:?} after the request, as if it had waited out the time bound",
        started.elapsed()
    );
}

/// An answer larger than the socket buffers, to a request whose body is never read, arrives
/// whole: the staged close must flush the answer before it shuts the sending side down.
#[tokio::test]
async fn a_large_answer_to_an_unread_body_arrives_whole() {
    const ANSWER: usize = 32 << 20;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (socket, peer) = listener.accept().await.unwrap();
    let router = Router::new().route("/", post(|| async { vec![b'y'; ANSWER] }));
    let server = tokio::spawn(serve_connection(
        socket,
        peer,
        router,
        Duration::from_secs(5),
        Instant::now() + Duration::from_secs(120),
    ));
    let mut start = head(1 << 30);
    start.extend(std::iter::repeat_n(b'x', 4096));
    client.write_all(&start).await.unwrap();
    let mut answer = Vec::new();
    timeout(STUCK, client.read_to_end(&mut answer))
        .await
        .expect("the answer ends")
        .expect("the answer is read, not reset");
    let split = answer.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(answer.len() - split, ANSWER, "the answer arrived whole");
    drop(client);
    let _ = timeout(STUCK, server).await;
}

const HASH_REQUEST: &[u8] = br#"{"metadata":{"items":[{"id":"held","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"held","role":"document"}]},"documents":{"doc":"abc"}}"#;

/// What an answered connection holds for its operation (its `max_in_flight` slot, the
/// scratch and the resources of its response) is released when the answer is out, not when
/// the client has closed: a client that keeps its socket open after the answer, for the whole
/// time bound, must not keep the next client waiting. One slot, a short admission wait: the
/// second request is refused with 503 after the wait if the first still holds its slot.
#[test]
fn an_answered_client_that_keeps_its_socket_open_does_not_hold_the_operation_slot() {
    use std::io::{Read, Write};
    let process = support::Process::configured("127.0.0.1:0", |root| {
        format!(
            "scratch_directory = {}\nmax_in_flight = 1\nblocking_workers = 1\nqueue_capacity = 1\nadmission_wait_ms = 400",
            support::toml_path(&root.join("scratch"))
        )
    });
    let mut first = std::net::TcpStream::connect(process.address).unwrap();
    first.set_read_timeout(Some(STUCK)).unwrap();
    write!(
        first,
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        process.address,
        process.token.as_str(),
        HASH_REQUEST.len()
    )
    .unwrap();
    first.write_all(HASH_REQUEST).unwrap();
    // The server shuts its sending side down once the answer is out; the client does not
    // close its own, and keeps `first` open to the end of the test.
    let mut answer = Vec::new();
    first.read_to_end(&mut answer).unwrap();
    let text = String::from_utf8_lossy(&answer);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("\"status\":\"completed\""), "{text}");
    let (status, body) = support::runtime().block_on(support::request(
        process.address,
        &process.token,
        "/v1/operations",
        HASH_REQUEST,
        &[("content-type", "application/json")],
        None,
    ));
    assert_eq!(
        status,
        200,
        "the second client found the slot taken by a client that was already answered: {}",
        String::from_utf8_lossy(&body)
    );
    drop(first);
    process.stop();
}
