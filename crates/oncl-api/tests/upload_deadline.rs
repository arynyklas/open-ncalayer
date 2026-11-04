#![cfg(feature = "server")]
//! A deadline that expires while the client is still uploading must produce a typed
//! JSON error before any header is sent (never an empty reply / closed socket).
mod private_support;
use oncl_server::config::Permission;
use private_support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PASSWORD: &str = "upload-deadline-password";

/// Sends the headers and the first part of a multipart body, declares a longer
/// Content-Length and then goes silent: only the operation deadline can end it.
async fn stalled_upload(
    service: &Running,
    path: &str,
    prefix: &[u8],
    declared_tail: usize,
) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let headers = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {FORM}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        service.address,
        service.token.as_str(),
        prefix.len() + declared_tail
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(prefix).await.unwrap();
    let mut response = Vec::new();
    // No sleep: the server answers by itself when its original deadline expires.
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        stream.read_to_end(&mut response),
    )
    .await
    .expect("the server must answer or close by its own deadline")
    .ok();
    response
}

fn deadline_config(config: &mut oncl_server::config::ServerConfig) {
    config.operation_timeout_ms = 1500;
    config.header_timeout_ms = 1000;
    config.admission_wait_ms = 200;
    config.tokens[0].actions = vec![Permission::Sign, Permission::Hash];
}

fn assert_typed_deadline(response: &[u8]) {
    let text = String::from_utf8_lossy(response);
    assert!(
        text.starts_with("HTTP/1.1 504") || text.starts_with("HTTP/1.1 408"),
        "expected a typed 408/504 before headers, got {text:?}"
    );
    assert!(text.contains("\"code\":\"DeadlineExceeded\""), "{text}");
    assert!(text.contains("\"applied\":\"NotApplied\""), "{text}");
    assert!(!text.contains("\"status\":\"completed\""), "{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_route_deadline_during_document_upload_is_a_typed_not_applied_error() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(|config, dir| {
        config.inline_pkcs12 = true;
        config.tokens[0].inline_pkcs12 = true;
        config.pki = pki.config(dir);
        deadline_config(config);
    })
    .await;
    let metadata = r#"{"items":[{"id":"s1","operation":{"kind":"sign","profile":"cms","input":"doc","attached":true,"keys":[{"source":"inline","container":"p12","password":"pw"}]}}],"parts":[{"name":"p12","item_id":"s1","role":"secret"},{"name":"pw","item_id":"s1","role":"secret"},{"name":"doc","item_id":"s1","role":"document"}]}"#;
    let mut prefix = multipart(
        metadata,
        &[
            Part {
                name: "p12",
                filename: None,
                bytes: &p12,
            },
            Part {
                name: "pw",
                filename: None,
                bytes: PASSWORD.as_bytes(),
            },
        ],
    );
    // Drop the closing delimiter and open the document part with a few bytes.
    let closing = b"--b--\r\n";
    prefix.truncate(prefix.len() - closing.len());
    prefix.extend_from_slice(
        b"--b\r\nContent-Disposition: form-data; name=\"doc\"\r\n\r\nfirst bytes of a document that never completes",
    );
    let response = stalled_upload(&service, "/v1/operations", &prefix, 1 << 20).await;
    assert_typed_deadline(&response);
    // Nothing was applied: no BEGIN reached the audit journal.
    assert!(
        service
            .host
            .audit
            .records()
            .unwrap()
            .iter()
            .all(|r| !matches!(r.kind, oncl_server::audit::RecordKind::Begin)),
        "no private use may start before the document is complete"
    );
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hash_route_deadline_during_document_upload_is_a_typed_not_applied_error() {
    let service = Running::start_with(|config, _| deadline_config(config)).await;
    let metadata = r#"{"items":[{"id":"h","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"h","role":"document"}]}"#;
    let mut prefix = multipart(metadata, &[]);
    prefix.truncate(prefix.len() - b"--b--\r\n".len());
    prefix.extend_from_slice(
        b"--b\r\nContent-Disposition: form-data; name=\"doc\"\r\n\r\nfirst bytes of a document that never completes",
    );
    let response = stalled_upload(&service, "/v1/operations", &prefix, 1 << 20).await;
    assert_typed_deadline(&response);
    service.stop().await;
}

/// A client that keeps uploading (a few KiB every 50 ms) well past the deadline and
/// reads the reply concurrently: the typed error must reach it even though unread
/// request bytes are still in flight when the server answers.
async fn trickling_upload(service: &Running, prefix: &[u8], total: usize) -> Vec<u8> {
    let stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let (mut reader, mut writer) = stream.into_split();
    let headers = format!(
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {FORM}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        service.address,
        service.token.as_str(),
        prefix.len() + total
    );
    writer.write_all(headers.as_bytes()).await.unwrap();
    writer.write_all(prefix).await.unwrap();
    let feeder = tokio::spawn(async move {
        let chunk = vec![b'x'; 4096];
        for _ in 0..(total / chunk.len()) {
            if writer.write_all(&chunk).await.is_err() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    });
    let mut response = Vec::new();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        reader.read_to_end(&mut response),
    )
    .await
    .expect("the server must answer or close by its own deadline");
    feeder.abort();
    let _ = result; // A reset after a complete reply is not the failure under test.
    response
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_route_trickling_upload_past_the_deadline_gets_the_typed_error() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(|config, dir| {
        config.inline_pkcs12 = true;
        config.tokens[0].inline_pkcs12 = true;
        config.pki = pki.config(dir);
        deadline_config(config);
    })
    .await;
    let metadata = r#"{"items":[{"id":"s1","operation":{"kind":"sign","profile":"cms","input":"doc","attached":true,"keys":[{"source":"inline","container":"p12","password":"pw"}]}}],"parts":[{"name":"p12","item_id":"s1","role":"secret"},{"name":"pw","item_id":"s1","role":"secret"},{"name":"doc","item_id":"s1","role":"document"}]}"#;
    let mut prefix = multipart(
        metadata,
        &[
            Part {
                name: "p12",
                filename: None,
                bytes: &p12,
            },
            Part {
                name: "pw",
                filename: None,
                bytes: PASSWORD.as_bytes(),
            },
        ],
    );
    prefix.truncate(prefix.len() - b"--b--\r\n".len());
    prefix.extend_from_slice(b"--b\r\nContent-Disposition: form-data; name=\"doc\"\r\n\r\n");
    let response = trickling_upload(&service, &prefix, 1 << 20).await;
    assert_typed_deadline(&response);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hash_route_trickling_upload_past_the_deadline_gets_the_typed_error() {
    let service = Running::start_with(|config, _| deadline_config(config)).await;
    let metadata = r#"{"items":[{"id":"h","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"h","role":"document"}]}"#;
    let mut prefix = multipart(metadata, &[]);
    prefix.truncate(prefix.len() - b"--b--\r\n".len());
    prefix.extend_from_slice(b"--b\r\nContent-Disposition: form-data; name=\"doc\"\r\n\r\n");
    let response = trickling_upload(&service, &prefix, 1 << 20).await;
    assert_typed_deadline(&response);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deadline_during_secret_upload_is_a_typed_error_and_never_reaches_the_journal() {
    let pki = Pki::start();
    let service = Running::start_with(|config, dir| {
        config.inline_pkcs12 = true;
        config.tokens[0].inline_pkcs12 = true;
        config.pki = pki.config(dir);
        deadline_config(config);
    })
    .await;
    let metadata = r#"{"items":[{"id":"s1","operation":{"kind":"sign","profile":"cms","input":"doc","attached":true,"keys":[{"source":"inline","container":"p12","password":"pw"}]}}],"parts":[{"name":"p12","item_id":"s1","role":"secret"},{"name":"pw","item_id":"s1","role":"secret"},{"name":"doc","item_id":"s1","role":"document"}]}"#;
    let mut prefix = multipart(metadata, &[]);
    prefix.truncate(prefix.len() - b"--b--\r\n".len());
    prefix.extend_from_slice(
        b"--b\r\nContent-Disposition: form-data; name=\"p12\"\r\n\r\npartial container bytes",
    );
    let response = stalled_upload(&service, "/v1/operations", &prefix, 1 << 20).await;
    assert_typed_deadline(&response);
    assert!(
        service
            .host
            .audit
            .records()
            .unwrap()
            .iter()
            .all(|r| !matches!(r.kind, oncl_server::audit::RecordKind::Begin)),
        "no private use before the secret is complete"
    );
    service.stop().await;
}
