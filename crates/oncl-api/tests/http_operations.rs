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
async fn original_admission_holds_global_quota_during_first_metadata_and_deadline() {
    let service = Running::start_with(|c| {
        c.max_in_flight = 1;
        c.operation_timeout_ms = 250;
        c.header_timeout_ms = 100;
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
    let mut capacity = false;
    for _ in 0..20 {
        let (status, _) = service
            .request("application/json", body, &service.token)
            .await;
        if status == 503 {
            capacity = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        capacity,
        "slow first metadata must own the only original admission"
    );
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), first.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 504"), "{text}");
    assert!(text.contains("DeadlineExceeded"));
    assert!(!text.contains("\"status\":\"completed\""));
    let (status, _) = service
        .request("application/json", body, &service.token)
        .await;
    assert_eq!(status, 200);
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
