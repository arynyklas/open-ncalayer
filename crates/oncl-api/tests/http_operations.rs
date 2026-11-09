#![cfg(feature = "server")]
use oncl_server::{
    auth::TokenSecret,
    config::{Permission, ServerConfig, TokenConfig},
    service::{ServiceHost, serve},
};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Running {
    address: std::net::SocketAddr,
    token: zeroize::Zeroizing<String>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    _directory: tempfile::TempDir,
    host: Arc<ServiceHost>,
}
impl Running {
    async fn start() -> Self {
        Self::start_with(|_| {}).await
    }
    async fn start_with(configure: impl FnOnce(&mut ServerConfig)) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let secret = TokenSecret::generate().unwrap();
        let mut config = ServerConfig {
            enabled: true,
            audit_directory: directory.path().join("audit"),
            scratch_directory: directory.path().join("scratch"),
            ..ServerConfig::default()
        };
        config.tokens.push(TokenConfig {
            id: "test".into(),
            verifier: secret.verifier().encoded(),
            actions: vec![Permission::Hash],
            keys: vec![],
            inline_pkcs12: false,
            metadata_aliases: vec![],
        });
        configure(&mut config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let host = ServiceHost::new(config)
            .unwrap()
            .for_listener(address)
            .unwrap();
        let (shutdown, stop) = tokio::sync::oneshot::channel();
        let h = host.clone();
        let task = tokio::spawn(async move {
            serve(listener, h, None, async {
                let _ = stop.await;
            })
            .await
        });
        Self {
            address,
            token: secret.bearer(),
            task,
            shutdown,
            _directory: directory,
            host,
        }
    }
    async fn request(&self, content_type: &str, body: &[u8], token: &str) -> (u16, Vec<u8>) {
        let mut stream = tokio::net::TcpStream::connect(self.address).await.unwrap();
        let headers = format!(
            "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.address,
            token,
            content_type,
            body.len()
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut result = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut result))
            .await
            .unwrap()
            .unwrap();
        let status = std::str::from_utf8(&result[..12]).unwrap()[9..12]
            .parse()
            .unwrap();
        let end = result.windows(4).position(|s| s == b"\r\n\r\n").unwrap() + 4;
        (status, result[end..].to_vec())
    }
    async fn chunked(&self, body: &[u8], split: usize) -> (u16, Vec<u8>) {
        let mut stream = tokio::net::TcpStream::connect(self.address).await.unwrap();
        let headers = format!(
            "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            self.address,
            self.token.as_str()
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
        for chunk in body.chunks(split) {
            stream
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await
                .unwrap();
            stream.write_all(chunk).await.unwrap();
            stream.write_all(b"\r\n").await.unwrap();
        }
        stream.write_all(b"0\r\n\r\n").await.unwrap();
        let mut result = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut result))
            .await
            .unwrap()
            .unwrap();
        let status = std::str::from_utf8(&result[..12]).unwrap()[9..12]
            .parse()
            .unwrap();
        let end = result.windows(4).position(|s| s == b"\r\n\r\n").unwrap() + 4;
        (status, result[end..].to_vec())
    }
    async fn stop(self) {
        let _ = self.shutdown.send(());
        self.task.await.unwrap().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json_small_dispatches_actual_sdk_hash_and_mandatory_terminal() {
    let service = Running::start().await;
    let body=br#"{"metadata":{"items":[{"id":"first","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"first","role":"document"}]},"documents":{"doc":"abc"}}"#;
    let (status, response) = service
        .request("application/json", body, &service.token)
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let text = String::from_utf8(response).unwrap();
    assert!(text.contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    assert!(text.contains("\"type\":\"final\""));
    assert!(text.contains("\"status\":\"completed\""));
    assert!(text.contains("\"item_id\":\"first\""));
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_authority_injection_invalid_tokens_and_revocation_are_rejected() {
    let service = Running::start().await;
    let body=br#"{"metadata":{"items":[{"id":"first","operation":{"kind":"hash","algorithm":"sha256","input":"doc","grant":{"sign":true}}}],"parts":[]},"documents":{}}"#;
    let (status, _) = service
        .request("application/json", body, &service.token)
        .await;
    assert_eq!(status, 400);
    let (status, _) = service
        .request("application/json", body, &"00".repeat(32))
        .await;
    assert_eq!(status, 403);
    service.host.policy.revoke("test").unwrap();
    let (status, _) = service
        .request("application/json", body, &service.token)
        .await;
    assert_eq!(status, 403);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multipart_unknown_length_and_legal_large_wire_chunks_use_actual_sdk_bytes() {
    let service = Running::start().await;
    let metadata = r#"{"items":[{"id":"first","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"first","role":"document"}]}"#;
    let mut body=format!("--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"../../attacker.pdf\"\r\n\r\n").into_bytes();
    body.extend(std::iter::repeat_n(b'x', 70000));
    body.extend_from_slice(b"\r\n--b--\r\n");
    for split in [1, 3, 65536] {
        let (status, response) = service.chunked(&body, split).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
        let text = String::from_utf8(response).unwrap();
        assert!(text.contains("bca09f4a757d5571c7d9f3341d4301f3c391c090826acc1a3013c6bcb7c01722"));
        assert!(text.contains("\"bytes_in\":70000"));
        assert!(text.contains("\"type\":\"final\""));
    }
    assert!(!service._directory.path().join("attacker.pdf").exists());
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multipart_document_bytes_are_not_framing_but_epilogue_is_bounded() {
    let service = Running::start_with(|c| c.framing_bytes = 512).await;
    let metadata = r#"{"items":[{"id":"first","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"first","role":"document"}]}"#;
    let mut body=format!("--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"doc\"\r\n\r\n").into_bytes();
    body.extend(std::iter::repeat_n(b'x', 70000));
    body.extend_from_slice(b"\r\n--b--\r\n");
    let (status, response) = service.chunked(&body, 65536).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    body.extend(std::iter::repeat_n(b'e', 1000));
    let (status, response) = service.chunked(&body, 65536).await;
    assert_eq!(status, 413, "{}", String::from_utf8_lossy(&response));
    assert!(!String::from_utf8_lossy(&response).contains("\"status\":\"completed\""));
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_first_metadata_holds_the_upload_slot_and_the_shared_budget_but_no_in_flight_slot_until_the_deadline()
 {
    let service = Running::start_with(|c| {
        c.max_in_flight = 1;
        c.max_uploads = Some(1);
        // One operation may take the whole shared memory budget, so that what the upload in
        // progress holds of it is visible to a probe.
        c.total_memory = 64 << 20;
        c.memory_per_operation = 64 << 20;
        // Must outlast the first 503 probe on a loaded machine: the deadline is the
        // only thing that releases the held admission, so it is not a speed bound.
        c.operation_timeout_ms = 6_000;
        // Only the request line and headers are sent at once; keep this far above any
        // scheduling delay so a loaded machine cannot expire it before the body starts.
        c.header_timeout_ms = 5_000;
        c.admission_wait_ms = 100;
    })
    .await;
    let mut first = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let headers = format!(
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nTransfer-Encoding: chunked\r\n\r\n",
        service.address,
        service.token.as_str()
    );
    first.write_all(headers.as_bytes()).await.unwrap();
    let prefix = b"--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{";
    first
        .write_all(format!("{:x}\r\n", prefix.len()).as_bytes())
        .await
        .unwrap();
    first.write_all(prefix).await.unwrap();
    first.write_all(b"\r\n").await.unwrap();
    // The first admission is observable through the actual shared root bound,
    // not a timing assertion about cryptographic throughput.
    let body=br#"{"metadata":{"items":[{"id":"x","operation":{"kind":"hash","algorithm":"sha256","input":"d"}}],"parts":[{"name":"d","item_id":"x","role":"document"}]},"documents":{"d":"abc"}}"#;
    // The slow first request owns the only upload slot (it holds no in-flight slot: the
    // bound is the upload phase's own). Probe until a probe is refused with the typed 503;
    // a probe that came first completes at once and frees the slot again.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let waiting = std::time::Instant::now();
    loop {
        let (status, _) = service
            .request("application/json", body, &service.token)
            .await;
        if status == 503 {
            break;
        }
        assert_eq!(status, 200);
        assert!(
            waiting.elapsed() < Duration::from_secs(4),
            "slow first metadata must own the only upload slot"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The slow first request is still receiving its metadata. It holds shared budget (memory
    // of its frame reservation and parser): a probe that asks for nearly all of the memory
    // is refused. It holds no `max_in_flight` slot: the only one is free for a request that
    // is admitted the ordinary way.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let cancel = || std::sync::Arc::new(oncl_server::executor::Cancellation::new());
    let mut probe = service.host.engine.admit_intake(cancel()).unwrap();
    let nearly_all = probe.resources().limits().memory_bytes - 16 * 1024;
    assert!(
        probe.resources().reserve_memory(nearly_all).is_err(),
        "the upload in progress holds shared memory budget"
    );
    drop(probe);
    assert!(
        service.host.engine.slot_available(),
        "an upload in progress holds no max_in_flight slot"
    );
    drop(
        service
            .host
            .engine
            .admit(cancel())
            .expect("the only in-flight slot is free"),
    );
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), first.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 504"), "{text}");
    assert!(text.contains("DeadlineExceeded"));
    assert!(!text.contains("\"status\":\"completed\""));
    // Everything the request held is released with its end.
    let mut probe = service.host.engine.admit_intake(cancel()).unwrap();
    let all = probe.resources().limits().memory_bytes;
    probe
        .resources()
        .reserve_memory(all)
        .expect("the shared budget is free again");
    drop(probe);
    let (status, _) = service
        .request("application/json", body, &service.token)
        .await;
    assert_eq!(status, 200);
    service.stop().await;
}

const HASH_METADATA: &str = r#"{"items":[{"id":"first","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"first","role":"document"}]}"#;

fn cancellation() -> std::sync::Arc<oncl_server::executor::Cancellation> {
    std::sync::Arc::new(oncl_server::executor::Cancellation::new())
}

/// A request that has taken its whole body keeps its upload slot while it waits for a
/// `max_in_flight` slot, and frees it when it has one. The request passes the early capacity
/// check (a slot is free), is still sending, and the only slot is then taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queued_operation_keeps_its_upload_slot_until_it_has_an_in_flight_slot() {
    let service = Running::start_with(|c| {
        c.max_in_flight = 1;
        c.max_uploads = Some(2);
        c.admission_wait_ms = 20_000;
        c.operation_timeout_ms = 40_000;
        c.header_timeout_ms = 5_000;
    })
    .await;
    assert_eq!(service.host.upload_slots_free(), 2);
    let mut body = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{HASH_METADATA}\r\n--b\r\nContent-Disposition: form-data; name=\"doc\"\r\n\r\nabc"
    )
    .into_bytes();
    let (first, rest) = (body.clone(), b"\r\n--b--\r\n".to_vec());
    body.extend_from_slice(&rest);
    let mut stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let headers = format!(
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        service.address,
        service.token.as_str(),
        body.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(&first).await.unwrap();
    // The request is in its upload phase: it holds an upload slot (and no in-flight slot).
    let began = std::time::Instant::now();
    while service.host.upload_slots_free() != 1 {
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "no upload slot taken"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The only in-flight slot is taken, then the body ends: the operation queues for it.
    let hold = service.host.engine.admit(cancellation()).unwrap();
    stream.write_all(&rest).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        service.host.upload_slots_free(),
        1,
        "a queued operation keeps its upload slot until it has an in-flight slot"
    );
    drop(hold);
    let mut result = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut result))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&result);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    let began = std::time::Instant::now();
    while service.host.upload_slots_free() != 2 {
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "upload slot not freed"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    service.stop().await;
}

/// With the only `max_in_flight` slot busy, a request is refused after `admission_wait_ms`
/// without its body being read, as before the upload phase: the client is stopped by the
/// socket (it fills the buffers and blocks) rather than sending all of 64 MiB, and an
/// `Expect: 100-continue` client is never told to send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_server_refuses_before_the_body_is_read() {
    const CHUNK: usize = 64 * 1024;
    const CHUNKS: usize = 1024;
    let service = Running::start_with(|c| {
        c.max_in_flight = 1;
        c.admission_wait_ms = 300;
        c.operation_timeout_ms = 30_000;
        c.header_timeout_ms = 5_000;
    })
    .await;
    let hold = service.host.engine.admit(cancellation()).unwrap();
    let stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let (mut read, mut write) = stream.into_split();
    let headers = format!(
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        service.address,
        service.token.as_str()
    );
    // The client writes the headers and the first chunk in one go and then stops: the server
    // refuses and closes, and no unread data of ours is in flight at that moment (on Windows
    // a close with unread incoming data sends a reset that can discard the 503 in transit).
    let first = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{HASH_METADATA}\r\n--b\r\nContent-Disposition: form-data; name=\"doc\"\r\n\r\n"
    );
    let framed = [
        headers.as_bytes(),
        format!("{:x}\r\n", first.len()).as_bytes(),
        first.as_bytes(),
        b"\r\n",
    ]
    .concat();
    let started = std::time::Instant::now();
    write.write_all(&framed).await.unwrap();
    let sent = first.len();
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    let reply = tokio::time::timeout(Duration::from_secs(10), async {
        while !response.windows(4).any(|w| w == b"\r\n\r\n") {
            match read.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => response.extend_from_slice(&buffer[..n]),
            }
        }
    })
    .await;
    let elapsed = started.elapsed();
    assert!(reply.is_ok(), "no answer");
    let text = String::from_utf8_lossy(&response).into_owned();
    assert!(text.starts_with("HTTP/1.1 503"), "{text}");
    assert!(
        elapsed >= Duration::from_millis(250),
        "the refusal follows the admission wait, took {elapsed:?}"
    );
    // The body is not read for a busy server: nothing beyond the first chunk was offered, and
    // the 503 came while the client was idle rather than after it had sent everything.
    assert!(
        sent < CHUNK * CHUNKS / 2,
        "the client offered {sent} of {} bytes",
        CHUNK * CHUNKS
    );
    drop(write);

    // `Expect: 100-continue`, both body routes: the refusal is the first thing sent.
    for path in ["/v1/operations", "/v1/hash"] {
        let mut stream = tokio::net::TcpStream::connect(service.address)
            .await
            .unwrap();
        let content_type = if path == "/v1/hash" {
            "application/octet-stream"
        } else {
            "multipart/form-data; boundary=b"
        };
        stream
            .write_all(
                format!(
                    "POST {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {content_type}\r\nContent-Length: 10000000\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
                    service.address,
                    service.token.as_str()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), async {
            let mut buffer = [0u8; 4096];
            while !response.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => response.extend_from_slice(&buffer[..n]),
                }
            }
        })
        .await;
        assert!(read.is_ok(), "{path}: no answer to the headers");
        let text = String::from_utf8_lossy(&response).into_owned();
        assert!(text.starts_with("HTTP/1.1 503"), "{path}: {text}");
        assert!(!text.contains("100 Continue"), "{path}: {text}");
    }
    // The slot is free again: the same request is served.
    drop(hold);
    let mut body = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{HASH_METADATA}\r\n--b\r\nContent-Disposition: form-data; name=\"doc\"\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(b"abc\r\n--b--\r\n");
    let (status, response) = service.chunked(&body, 65536).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_epilogue_is_rejected_without_waiting_for_declared_tail() {
    let service = Running::start_with(|c| {
        c.framing_bytes = 512;
        c.operation_timeout_ms = 500;
        c.header_timeout_ms = 100;
        c.admission_wait_ms = 100;
    })
    .await;
    let metadata = r#"{"items":[{"id":"first","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"first","role":"document"}]}"#;
    let body = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"doc\"\r\n\r\nabc\r\n--b--\r\n{}",
        "x".repeat(1000)
    );
    let mut stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let headers = format!(
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        service.address,
        service.token.as_str(),
        body.len() + 10000
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(body.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 413"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    service.stop().await;
}

fn signed_cms(data: &[u8]) -> Vec<u8> {
    use oncl_pki::cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec};
    let fixture = oncl_testkit::synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&oncl_testkit::read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    cms::sign_spec(
        &key,
        &[],
        &SignSpec {
            content: Content::Data(data),
            encapsulate: true,
            cosign: CoSign::Never,
            econtent_type: None,
            digest: None,
            attrs: AttrSpec {
                content_type: true,
                message_digest: true,
                signing_certificate_v2: true,
                signing_time: None,
                extra: vec![],
            },
            certificates: CertSpec::Chain,
        },
    )
    .unwrap()
}
fn verification_multipart(cms: &[u8]) -> Vec<u8> {
    let metadata = r#"{"items":[{"id":"verification","operation":{"kind":"verify","profile":"cms","input":"signature"}}],"parts":[{"name":"signature","item_id":"verification","role":"document"}]}"#;
    let mut body=format!("--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"signature\"\r\n\r\n").into_bytes();
    body.extend_from_slice(cms);
    body.extend_from_slice(b"\r\n--b--\r\n");
    body
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json_bad_signature_is_completed_report() {
    let service = Running::start_with(|c| {
        c.tokens[0].actions.push(Permission::Verify);
        c.metadata_bytes = 67_108_864;
    })
    .await;
    let data = b"actual HTTP verification original bytes";
    let mut cms = signed_cms(data);
    let offset = cms.windows(data.len()).position(|w| w == data).unwrap();
    cms[offset] ^= 1;
    let (status, response) = service.chunked(&verification_multipart(&cms), 3).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let text = String::from_utf8_lossy(&response);
    assert!(text.contains("\"status\":\"completed\""), "{text}");
    assert!(text.contains("\"verdict\":\"Invalid\""), "{text}");
    assert!(text.contains("\"signature\":\"Failed\""), "{text}");
    service.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_verify_action_is_authorized_before_document_intake() {
    let service = Running::start().await;
    let cms = signed_cms(b"unprivileged verification");
    let (status, response) = service.chunked(&verification_multipart(&cms), 65536).await;
    assert_eq!(status, 403, "{}", String::from_utf8_lossy(&response));
    service.stop().await;
}

async fn unsent_tail(service: &Running, prefix: &[u8]) -> String {
    let mut stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let headers = format!(
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        service.address,
        service.token.as_str(),
        prefix.len() + 10000
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(prefix).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(response).unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proven_overlimit_part_headers_refuse_before_waiting_for_document() {
    let service = Running::start_with(|c| {
        c.framing_bytes = 512;
        c.operation_timeout_ms = 500;
        c.header_timeout_ms = 100;
        c.admission_wait_ms = 100;
    })
    .await;
    let metadata = r#"{"items":[{"id":"x","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"x","role":"document"}]}"#;
    for ending in ["", "\r\n\r\n"] {
        let prefix = format!(
            "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"doc\"\r\nX-Padding: {}{ending}",
            "x".repeat(1024)
        );
        let response = unsent_tail(&service, prefix.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 413"), "{response}");
        assert!(response.contains("\"code\":\"FramingLimit\""), "{response}");
    }
    service.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exhausted_header_credit_is_typed_resource_not_malformed_request() {
    let service = Running::start_with(|c| {
        c.operation_timeout_ms = 500;
        c.header_timeout_ms = 100;
        c.admission_wait_ms = 100;
    })
    .await;
    let prefix = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\nX-Padding: {}",
        "x".repeat(9000)
    );
    let response = unsent_tail(&service, prefix.as_bytes()).await;
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    assert!(
        response.contains("\"code\":\"MetadataLimit\""),
        "{response}"
    );
    service.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aggregate_wire_overflow_inside_metadata_keeps_original_limit() {
    let service = Running::start_with(|c| {
        c.input_bytes = 1;
        c.framing_bytes = 512;
        c.metadata_bytes = 67_108_864;
    })
    .await;
    let metadata = r#"{"items":[{"id":"x","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"x","role":"document"}]}"#;
    let metadata = format!("{}{}", " ".repeat(65520 - metadata.len()), metadata);
    let body = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"doc\"\r\n\r\n{}\r\n--b--\r\n",
        "x".repeat(2048)
    );
    let (status, response) = service.chunked(body.as_bytes(), 65536).await;
    assert_eq!(status, 413, "{}", String::from_utf8_lossy(&response));
    assert!(String::from_utf8_lossy(&response).contains("\"code\":\"FramingLimit\""));
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_operator_configured_roots_establish_the_verification_chain() {
    let fixture = oncl_testkit::synthetic("user-rsa-sign");
    let service = Running::start_with(|config| {
        config.tokens[0].actions.push(Permission::Verify);
        config.metadata_bytes = 67_108_864;
        config.pki.anchors = vec![fixture.root.clone()];
        config.pki.intermediates = vec![fixture.issuer.clone()];
    })
    .await;
    let cms = signed_cms(b"operator-configured trust, not payload authority");
    let (status, response) = service.chunked(&verification_multipart(&cms), 65536).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let text = String::from_utf8_lossy(&response);
    assert!(text.contains("\"chain\":\"Passed\""), "{text}");
    assert!(text.contains("\"signature\":\"Passed\""), "{text}");
    assert!(text.contains("\"policy\":\"StrictOnline\""), "{text}");
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn certificates_carried_by_the_container_are_not_operator_trust_anchors() {
    use oncl_pki::cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec};
    let fixture = oncl_testkit::synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&oncl_testkit::read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let candidates = vec![
        oncl_pki::cert::parse(&oncl_testkit::read(&fixture.issuer)).unwrap(),
        oncl_pki::cert::parse(&oncl_testkit::read(&fixture.root)).unwrap(),
    ];
    let cms = cms::sign_spec(
        &key,
        &[],
        &SignSpec {
            content: Content::Data(b"untrusted carried root"),
            encapsulate: true,
            cosign: CoSign::Never,
            econtent_type: None,
            digest: None,
            attrs: AttrSpec {
                content_type: true,
                message_digest: true,
                signing_certificate_v2: true,
                signing_time: None,
                extra: vec![],
            },
            certificates: CertSpec::Extra(candidates),
        },
    )
    .unwrap();
    let service = Running::start_with(|config| {
        config.tokens[0].actions.push(Permission::Verify);
        config.metadata_bytes = 67_108_864;
    })
    .await;
    let (status, response) = service.chunked(&verification_multipart(&cms), 65536).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let text = String::from_utf8_lossy(&response);
    assert!(text.contains("\"signature\":\"Passed\""), "{text}");
    assert!(!text.contains("\"chain\":\"Passed\""), "{text}");
    service.stop().await;
}

#[test]
fn operator_pki_address_pins_are_applied_not_ignored_or_resolved_from_wire() {
    use oncl_server::config::{PkiConfig, PkiEndpoint};
    for (address, permitted) in [("127.0.0.1:7777", true), ("127.0.0.2:7777", false)] {
        let directory = tempfile::tempdir().unwrap();
        let secret = TokenSecret::generate().unwrap();
        let config = ServerConfig {
            enabled: true,
            audit_directory: directory.path().join("audit"),
            tokens: vec![TokenConfig {
                id: "pki".into(),
                verifier: secret.verifier().encoded(),
                actions: vec![Permission::Verify],
                keys: vec![],
                inline_pkcs12: false,
                metadata_aliases: vec![],
            }],
            pki: PkiConfig {
                endpoints: vec![PkiEndpoint {
                    origin: "http://127.0.0.1:7777".into(),
                    addresses: vec![address.parse().unwrap()],
                }],
                ..PkiConfig::default()
            },
            ..ServerConfig::default()
        };
        let result = ServiceHost::new(config);
        assert_eq!(result.is_ok(), permitted);
        if !permitted {
            assert_eq!(
                result.err().unwrap().kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
    }
}

fn spool_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_file() {
            files.push(entry.path());
        } else if kind.is_dir() {
            files.extend(spool_files(&entry.path()));
        }
    }
    files
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_role_with_pdf_filename_is_not_reclassified_or_spooled() {
    let service = Running::start_with(|config| {
        config.operation_timeout_ms = 500;
        config.header_timeout_ms = 100;
        config.admission_wait_ms = 100;
    })
    .await;
    let scratch = service._directory.path().join("scratch");
    assert!(spool_files(&scratch).is_empty());
    let metadata = r#"{"items":[{"id":"hash","operation":{"kind":"hash","algorithm":"sha256","input":"secret"}}],"parts":[{"name":"secret","item_id":"hash","role":"secret"}]}"#;
    let prefix = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"secret\"; filename=\"../../do-not-create.pdf\"\r\nContent-Type: application/pdf\r\n\r\nM1-DECLARED-SECRET-DO-NOT-SPOOL"
    );
    let response = unsent_tail(&service, prefix.as_bytes()).await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(spool_files(&scratch).is_empty());
    assert!(!service._directory.path().join("do-not-create.pdf").exists());
    assert!(!response.contains("M1-DECLARED-SECRET-DO-NOT-SPOOL"));
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_128_document_parts_complete_over_actual_chunked_http() {
    let service = Running::start().await;
    let mut items = Vec::with_capacity(128);
    let mut parts = Vec::with_capacity(128);
    for index in 0..128 {
        items.push(serde_json::json!({"id":format!("item-{index}"),"operation":{"kind":"hash","algorithm":"sha256","input":format!("doc-{index}")}}));
        parts.push(serde_json::json!({"name":format!("doc-{index}"),"item_id":format!("item-{index}"),"role":"document"}));
    }
    let metadata =
        serde_json::to_string(&serde_json::json!({"items":items,"parts":parts})).unwrap();
    let mut body =
        format!("--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n")
            .into_bytes();
    for index in 0..128 {
        body.extend_from_slice(format!("--b\r\nContent-Disposition: form-data; name=\"doc-{index}\"; filename=\"client-name-{index}.bin\"\r\n\r\nabc\r\n").as_bytes());
    }
    body.extend_from_slice(b"--b--\r\n");
    let (status, response) = service.chunked(&body, 65536).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let final_result: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(final_result["type"], "final");
    assert_eq!(final_result["status"], "completed");
    let results = final_result["results"].as_array().unwrap();
    assert_eq!(results.len(), 128);
    for (index, result) in results.iter().enumerate() {
        assert_eq!(result["item_id"], format!("item-{index}"));
        assert_eq!(result["result"]["bytes_in"], 3);
        assert_eq!(
            result["result"]["digest"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    assert!(spool_files(&service._directory.path().join("scratch")).is_empty());
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_sdk_extraction_streams_binary_artifact_and_mandatory_final() {
    use http_body_util::{BodyExt, Full};
    let service =
        Running::start_with(|config| config.tokens[0].actions.push(Permission::Extract)).await;
    let payload = b"binary artifact exact\0bytes";
    let cms = signed_cms(payload);
    let metadata = r#"{"items":[{"id":"extraction","operation":{"kind":"extract","input":"container"}}],"parts":[{"name":"container","item_id":"extraction","role":"document"}]}"#;
    let mut body=format!("--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"container\"\r\n\r\n").into_bytes();
    body.extend_from_slice(&cms);
    body.extend_from_slice(b"\r\n--b--\r\n");
    let stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method("POST")
        .uri("/v1/operations")
        .header("host", service.address.to_string())
        .header(
            "authorization",
            format!("Bearer {}", service.token.as_str()),
        )
        .header("content-type", "multipart/form-data; boundary=b")
        .body(Full::new(axum::body::Bytes::from(body)))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let media: mime::Mime = content_type.parse().unwrap();
    assert_eq!(media.type_(), mime::MULTIPART);
    assert_eq!(media.subtype().as_str(), "mixed");
    let boundary = media.get_param(mime::BOUNDARY).unwrap().as_str().to_owned();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let source = futures_util::stream::once(async move { Ok::<_, std::io::Error>(bytes) });
    let mut parser = multer::Multipart::new(source, boundary);
    let mut artifact = None;
    let mut final_result = None;
    let mut progress = false;
    while let Some(field) = parser.next_field().await.unwrap() {
        assert!(
            final_result.is_none(),
            "parts after terminal final are not success"
        );
        match field.name().unwrap() {
            "progress" => {
                progress = true;
                field.bytes().await.unwrap();
            }
            "artifact" => {
                assert!(artifact.is_none());
                artifact = Some(field.bytes().await.unwrap());
            }
            "final" => {
                final_result = Some(
                    serde_json::from_slice::<serde_json::Value>(&field.bytes().await.unwrap())
                        .unwrap(),
                );
            }
            _ => panic!("unexpected response part"),
        }
    }
    assert!(progress);
    assert_eq!(artifact.unwrap().as_ref(), payload);
    let final_result = final_result.expect("no terminal result is never success");
    assert_eq!(final_result["type"], "final");
    assert_eq!(final_result["status"], "completed");
    assert_eq!(final_result["results"][0]["result"]["kind"], "extraction");
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_multipart_pending_progress_and_final_frames_recheck_original_deadline() {
    use http_body_util::BodyExt;
    use oncl_api::server::{HashHost, RequestMetadata};
    for final_queue in [false, true] {
        let service = Running::start_with(|config| {
            config.tokens[0].actions.push(Permission::Extract);
            config.max_in_flight = 1;
            config.operation_timeout_ms = 500;
            config.header_timeout_ms = 100;
            config.admission_wait_ms = 100;
        })
        .await;
        let cms = signed_cms(b"real deferred multipart");
        let metadata = r#"{"items":[{"id":"x","operation":{"kind":"extract","input":"c"}}],"parts":[{"name":"c","item_id":"x","role":"document"}]}"#;
        let mut bytes = format!("--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"c\"\r\n\r\n").into_bytes();
        bytes.extend_from_slice(&cms);
        bytes.extend_from_slice(b"\r\n--b--\r\n");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("host", service.address.to_string().parse().unwrap());
        headers.insert(
            "authorization",
            format!("Bearer {}", service.token.as_str())
                .parse()
                .unwrap(),
        );
        headers.insert(
            "content-type",
            "multipart/form-data; boundary=b".parse().unwrap(),
        );
        let response = service
            .host
            .operations(
                RequestMetadata {
                    peer: "127.0.0.1:45678".parse().unwrap(),
                    headers,
                    content_length: Some(bytes.len() as u64),
                },
                axum::body::Body::from(bytes),
            )
            .await
            .unwrap();
        let deadline = response
            .extensions()
            .get::<oncl_server::service::ResponseDelivery>()
            .unwrap()
            .deadline();
        let mut body = response.into_body();
        let held = loop {
            let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
            let name = if final_queue {
                "name=\"final\""
            } else {
                "name=\"progress\""
            };
            if frame
                .windows(name.len())
                .any(|value| value == name.as_bytes())
            {
                break frame;
            }
        };
        let slice = held.slice(0..1);
        drop(held);
        tokio::time::sleep(deadline.remaining()).await;
        let next = body.frame().await;
        match next {
            Some(Err(error)) => {
                let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
                let mut typed = false;
                while let Some(current) = source {
                    if matches!(
                        current.downcast_ref::<oncl_pki::resource::ProcessingError>(),
                        Some(oncl_pki::resource::ProcessingError::DeadlineExceeded)
                    ) {
                        typed = true;
                        break;
                    }
                    source = current.source();
                }
                assert!(typed, "typed original deadline lost: {error:?}");
            }
            _ => panic!("queued multipart data must not escape original deadline"),
        }
        drop(body);
        assert!(
            service
                .host
                .engine
                .admit(Arc::new(oncl_server::executor::Cancellation::new()))
                .is_err(),
            "a retained real multipart slice must keep its original root"
        );
        drop(slice);
        service.stop().await;
    }
}
