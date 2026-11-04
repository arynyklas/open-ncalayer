#![cfg(feature = "server")]
//! Real-socket `POST /v1/batch`: real RSA keys, the production durable audit guard,
//! the loopback PKI/TSA and independent OpenSSL oracles. Barriers are Condvar gates.
mod private_support;
use oncl_server::{
    audit::RecordKind,
    config::{Permission, ServerConfig},
};
use private_support::*;
use std::{path::Path, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PASSWORD: &str = "batch-secret-password-MARKER-91c2";

/// One manifest item with the parts it declares.
struct Item {
    id: &'static str,
    operation: String,
    secrets: Vec<(String, Vec<u8>)>,
    documents: Vec<(String, Vec<u8>)>,
}
fn sign_cms(id: &'static str, p12: &[u8], document: &[u8]) -> Item {
    Item {
        id,
        operation: format!(
            r#"{{"kind":"sign","profile":"cms","input":"{id}-doc","attached":true,"keys":[{{"source":"inline","container":"{id}-p12","password":"{id}-pw"}}]}}"#
        ),
        secrets: vec![
            (format!("{id}-p12"), p12.to_vec()),
            (format!("{id}-pw"), PASSWORD.as_bytes().to_vec()),
        ],
        documents: vec![(format!("{id}-doc"), document.to_vec())],
    }
}
fn sign_profile(id: &'static str, profile: &str, p12: &[u8], document: &[u8]) -> Item {
    let mut item = sign_cms(id, p12, document);
    item.operation = format!(
        r#"{{"kind":"sign","profile":"{profile}","input":"{id}-doc","keys":[{{"source":"inline","container":"{id}-p12","password":"{id}-pw"}}]}}"#
    );
    item
}
fn named_sign(id: &'static str, key: &str, document: &[u8]) -> Item {
    Item {
        id,
        operation: format!(
            r#"{{"kind":"sign","profile":"cms","input":"{id}-doc","attached":true,"keys":[{{"source":"named","name":"{key}"}}]}}"#
        ),
        secrets: vec![],
        documents: vec![(format!("{id}-doc"), document.to_vec())],
    }
}
fn verify_cms(id: &'static str, signature: &[u8]) -> Item {
    Item {
        id,
        operation: format!(r#"{{"kind":"verify","profile":"cms","input":"{id}-sig"}}"#),
        secrets: vec![],
        documents: vec![(format!("{id}-sig"), signature.to_vec())],
    }
}
fn hash(id: &'static str, document: &[u8]) -> Item {
    Item {
        id,
        operation: format!(r#"{{"kind":"hash","algorithm":"sha256","input":"{id}-doc"}}"#),
        secrets: vec![],
        documents: vec![(format!("{id}-doc"), document.to_vec())],
    }
}
/// (metadata JSON, secret parts then document parts in declared order)
fn manifest(items: &[Item]) -> (String, Vec<(String, Vec<u8>)>) {
    let mut entries = Vec::new();
    let mut parts = Vec::new();
    let mut secrets = Vec::new();
    let mut documents = Vec::new();
    for item in items {
        entries.push(format!(
            r#"{{"id":"{}","operation":{}}}"#,
            item.id, item.operation
        ));
        for (name, bytes) in &item.secrets {
            parts.push(format!(
                r#"{{"name":"{name}","item_id":"{}","role":"secret"}}"#,
                item.id
            ));
            secrets.push((name.clone(), bytes.clone()));
        }
    }
    for item in items {
        for (name, bytes) in &item.documents {
            parts.push(format!(
                r#"{{"name":"{name}","item_id":"{}","role":"document"}}"#,
                item.id
            ));
            documents.push((name.clone(), bytes.clone()));
        }
    }
    secrets.extend(documents);
    (
        format!(
            r#"{{"items":[{}],"parts":[{}]}}"#,
            entries.join(","),
            parts.join(",")
        ),
        secrets,
    )
}
fn body(items: &[Item]) -> Vec<u8> {
    let (metadata, parts) = manifest(items);
    let parts: Vec<Part<'_>> = parts
        .iter()
        .map(|(name, bytes)| Part {
            name,
            filename: None,
            bytes,
        })
        .collect();
    multipart(&metadata, &parts)
}
type Parts = Vec<(String, Option<String>, Vec<u8>)>;
fn batch_final(parts: &Parts) -> serde_json::Value {
    let (name, _, bytes) = parts.last().expect("mandatory terminal part");
    assert_eq!(name, "final", "last part must be the terminal record");
    let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(value["type"], "batch_final");
    assert_matches_schema("BatchFinalEvent", &value);
    for (name, _, bytes) in parts {
        if name == "progress" {
            assert_matches_schema("ProgressEvent", &serde_json::from_slice(bytes).unwrap());
        }
    }
    value
}
async fn run(service: &Running, items: &[Item]) -> (Parts, serde_json::Value) {
    let (status, content_type, response) = service.post_batch(FORM, body(items)).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let parts = mixed(&content_type, response).await;
    let done = batch_final(&parts);
    (parts, done)
}
fn service_config(
    pki: &Pki,
    tune: impl FnOnce(&mut ServerConfig) + 'static,
) -> impl FnOnce(&mut ServerConfig, &Path) + '_ {
    move |config, dir| {
        config.inline_pkcs12 = true;
        config.tokens[0].inline_pkcs12 = true;
        config.tokens[0].actions.extend([
            Permission::Verify,
            Permission::Hash,
            Permission::Extract,
            Permission::Batch,
        ]);
        config.memory_per_operation = 1 << 30;
        config.total_memory = 2 << 30;
        config.pki = pki.config(dir);
        tune(config);
    }
}
fn begins(service: &Running) -> Vec<Option<u16>> {
    service
        .host
        .audit
        .records()
        .unwrap()
        .iter()
        .filter(|r| r.kind == RecordKind::Begin)
        .map(|r| r.batch_item)
        .collect()
}
fn finals(service: &Running) -> Vec<(Option<u16>, bool)> {
    service
        .host
        .audit
        .records()
        .unwrap()
        .iter()
        .filter(|r| r.kind == RecordKind::Final)
        .map(|r| (r.batch_item, r.succeeded))
        .collect()
}
async fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
    let started = std::time::Instant::now();
    while !condition() {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(15),
            "timed out waiting for {what}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
async fn raw_request(
    service: &Running,
    content_type: &str,
    body: &[u8],
    keep_open: bool,
) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let head = format!(
        "POST /v1/batch HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        service.address,
        service.token.as_str(),
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        stream.read_to_end(&mut response),
    )
    .await;
    let _ = keep_open;
    response
}
/// A real CMS signature over `payload`, made through `/v1/operations`.
async fn presign(service: &Running, p12: &[u8], payload: &[u8]) -> Vec<u8> {
    let item = sign_cms("pre", p12, payload);
    let (metadata, parts) = manifest(&[item]);
    let parts: Vec<Part<'_>> = parts
        .iter()
        .map(|(name, bytes)| Part {
            name,
            filename: None,
            bytes,
        })
        .collect();
    let (status, content_type, response) = service.post(FORM, multipart(&metadata, &parts)).await;
    assert_eq!(status, 200);
    let parts = mixed(&content_type, response).await;
    artifact(&parts, "artifact-0").to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_batch_with_one_bad_source_keeps_exact_per_item_facts_and_verified_artifacts() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(service_config(&pki, |_| {})).await;
    let dir = tempfile::tempdir().unwrap();
    let a = b"first batch document";
    let b = b"last batch document";
    let mut tampered = presign(&service, &p12, b"signed then altered").await;
    let at = tampered
        .windows(b"signed then altered".len())
        .position(|w| w == b"signed then altered")
        .unwrap();
    tampered[at] ^= 0x01;
    assert_eq!(begins(&service).len(), 1, "pre-sign used the key once");
    let watch = SpoolWatch::start(
        service.scratch(),
        vec![PASSWORD.as_bytes().to_vec(), p12[..64].to_vec()],
    );
    let items = [
        sign_cms("sign-a", &p12, a),
        // A source the PDF signer cannot read: a non-terminal item failure.
        sign_profile("sign-pdf", "pdf", &p12, b"this is not a pdf"),
        verify_cms("verify-bad", &tampered),
        hash("hash", b"abc"),
        sign_cms("sign-b", &p12, b),
    ];
    let (parts, done) = run(&service, &items).await;
    assert!(!watch.finish(), "secrets never reach the spool");
    assert_eq!(done["status"], "partial", "{done}");
    assert_eq!(done["total"], 5);
    assert_eq!(done["attempted"], 5);
    assert_eq!(done["completed"], 4);
    assert!(done.get("stop").is_none(), "no terminal stop: {done}");
    let records = done["items"].as_array().unwrap();
    let ids: Vec<&str> = records
        .iter()
        .map(|r| r["item_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["sign-a", "sign-pdf", "verify-bad", "hash", "sign-b"]);
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record["index"], index);
    }
    // Item 0: signed, Applied, artifact verified by an independent OpenSSL.
    assert_eq!(records[0]["outcome"], "completed");
    assert_eq!(records[0]["applied"], "Applied");
    assert_eq!(records[0]["result"]["signers"][0], "Applied");
    let first = artifact(&parts, records[0]["result"]["artifact"].as_str().unwrap());
    assert_eq!(openssl_cms_verify(first, None, dir.path()).unwrap(), a);
    // Item 1: failed before key use, no artifact, NotApplied, typed code.
    assert_eq!(records[1]["outcome"], "failed");
    assert_eq!(records[1]["applied"], "NotApplied");
    assert_eq!(records[1]["error"]["applied"], "NotApplied");
    assert!(records[1].get("result").is_none());
    // Item 2: a bad signature is a COMPLETED item with an Invalid verdict.
    assert_eq!(records[2]["outcome"], "completed");
    assert_eq!(records[2]["verdict"], "Invalid");
    assert_eq!(records[2]["result"]["kind"], "verification");
    // Item 3: the exact digest of the captured bytes.
    assert_eq!(records[3]["outcome"], "completed");
    assert_eq!(
        records[3]["result"]["digest"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        records[3]["sources"][0]["sha256"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(records[3]["sources"][0]["bytes"], 3);
    // Item 4 ran after the failed item, and its artifact verifies too.
    assert_eq!(records[4]["outcome"], "completed");
    assert_eq!(records[4]["applied"], "Applied");
    let last = artifact(&parts, records[4]["result"]["artifact"].as_str().unwrap());
    assert_eq!(openssl_cms_verify(last, None, dir.path()).unwrap(), b);
    assert_eq!(
        parts.iter().filter(|(n, _, _)| n == "artifact").count(),
        2,
        "only finished outputs are delivered"
    );
    // The audit uses the original batch ordinals: items 0 and 4 only (after the pre-sign).
    assert_eq!(begins(&service), [None, Some(0), Some(4)]);
    assert_eq!(
        finals(&service),
        [(None, true), (Some(0), true), (Some(4), true)]
    );
    assert!(spool_files(&service.scratch()).is_empty());
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_ungranted_key_refuses_the_whole_batch_before_any_secret_or_document_is_read() {
    let pki = Pki::start();
    let pki_ref = &pki;
    let service = Running::start_with(|config, dir| {
        service_config(pki_ref, |config| {
            config.tokens[0].keys = vec!["granted".into()];
            config.tokens[0].inline_pkcs12 = false;
        })(config, dir)
    })
    .await;
    // Item 1 is granted; item 2 names a key this token does not hold. The declared
    // secret/document tail is never sent: the refusal must not wait for it.
    let items = [
        named_sign("one", "granted", b"x"),
        named_sign("two", "other", b"y"),
    ];
    let (metadata, _) = manifest(&items);
    let prefix = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"one-doc\"\r\n\r\nDOCUMENT-PREFIX-NEVER-READ"
    );
    let mut stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let head = format!(
        "POST /v1/batch HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {FORM}\r\nContent-Length: 4000000\r\nConnection: close\r\n\r\n",
        service.address,
        service.token.as_str(),
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(prefix.as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_string(&mut response),
    )
    .await
    .expect("refused without waiting for the 4 MB tail")
    .unwrap();
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(
        response.contains("\"code\":\"PermissionDenied\""),
        "{response}"
    );
    assert!(
        response.contains("\"applied\":\"NotApplied\""),
        "{response}"
    );
    assert!(begins(&service).is_empty(), "no item ran, no key was used");
    assert!(spool_files(&service.scratch()).is_empty());
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_batch_right_and_every_items_own_right_are_both_required() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    // Without the batch right, even a fully granted item list is refused.
    let service = Running::start_with(service_config(&pki, |config| {
        config.tokens[0]
            .actions
            .retain(|p| !matches!(p, Permission::Batch));
    }))
    .await;
    let (status, _, response) = service
        .post_batch(FORM, body(&[sign_cms("a", &p12, b"x")]))
        .await;
    assert_eq!(status, 403, "{}", String::from_utf8_lossy(&response));
    assert!(begins(&service).is_empty());
    service.stop().await;
    // With the batch right but without the verify action for one item: whole batch 403.
    let service = Running::start_with(service_config(&pki, |config| {
        config.tokens[0]
            .actions
            .retain(|p| !matches!(p, Permission::Verify));
    }))
    .await;
    let (status, _, response) = service
        .post_batch(
            FORM,
            body(&[sign_cms("a", &p12, b"x"), verify_cms("v", b"whatever")]),
        )
        .await;
    assert_eq!(status, 403, "{}", String::from_utf8_lossy(&response));
    assert!(
        begins(&service).is_empty(),
        "the granted item did not run either"
    );
    // The batch right does not grant /v1/operations access to anything extra.
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_and_authority_cannot_be_supplied_by_the_payload() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(service_config(&pki, |_| {})).await;
    let (metadata, parts) = manifest(&[sign_cms("a", &p12, b"payload")]);
    let parts: Vec<Part<'_>> = parts
        .iter()
        .map(|(name, bytes)| Part {
            name,
            filename: None,
            bytes,
        })
        .collect();
    // Every plausible spelling of a client-side approval or grant is an unknown field.
    for forged in [
        metadata.replacen('{', r#"{"approved":true,"#, 1),
        metadata.replacen('{', r#"{"authorize":true,"#, 1),
        metadata.replacen('{', r#"{"approval":{"plan":1},"#, 1),
        metadata.replacen(r#""kind":"sign""#, r#""kind":"sign","approved":true"#, 1),
        metadata.replacen(r#""id":"a""#, r#""id":"a","grant":["sign"]"#, 1),
        metadata.replacen(
            r#""role":"document""#,
            r#""role":"document","approved":true"#,
            1,
        ),
    ] {
        assert_ne!(forged, metadata);
        let (status, _, response) = service.post_batch(FORM, multipart(&forged, &parts)).await;
        assert_eq!(
            status,
            400,
            "{forged}: {}",
            String::from_utf8_lossy(&response)
        );
    }
    // Plugin items are not part of the SDK batch.
    let plugin = r#"{"items":[{"id":"p","operation":{"kind":"plugin","plugin":"vendor.x","operation":"run","args":"{}"}}],"parts":[]}"#;
    let (status, _, _) = service.post_batch(FORM, multipart(plugin, &[])).await;
    assert_eq!(status, 400);
    assert!(
        begins(&service).is_empty(),
        "no forged request reached a key"
    );
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_quota_stop_keeps_finished_artifacts_and_reports_the_rest_not_run() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(service_config(&pki, |config| {
        config.temp_per_operation = 420_000;
        config.total_temp = 420_000;
    }))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let small = vec![5u8; 20_000];
    let large = vec![6u8; 120_000];
    let items = [
        sign_cms("small", &p12, &small),
        sign_cms("large", &p12, &large),
        hash("after", b"abc"),
    ];
    let (parts, done) = run(&service, &items).await;
    assert_eq!(done["status"], "partial", "{done}");
    let records = done["items"].as_array().unwrap();
    assert_eq!(records[0]["outcome"], "completed", "{done}");
    assert_eq!(records[0]["applied"], "Applied");
    assert_eq!(records[1]["outcome"], "failed", "{done}");
    assert_eq!(records[1]["error"]["code"], "TempLimit", "{done}");
    assert!(
        records[1].get("result").is_none(),
        "no artifact for a failed item"
    );
    assert_eq!(records[2]["outcome"], "not_run", "{done}");
    assert_eq!(records[2]["applied"], "NotApplied");
    assert_eq!(done["stop"]["kind"], "item", "{done}");
    assert_eq!(done["stop"]["item_index"], 1);
    assert_eq!(done["stop"]["code"], "TempLimit");
    assert_eq!(done["attempted"], 2);
    assert_eq!(done["completed"], 1);
    // The first item's artifact was delivered and verifies; the failed one has none.
    let delivered: Vec<_> = parts.iter().filter(|(n, _, _)| n == "artifact").collect();
    assert_eq!(delivered.len(), 1, "{done}");
    let first = artifact(&parts, records[0]["result"]["artifact"].as_str().unwrap());
    assert_eq!(openssl_cms_verify(first, None, dir.path()).unwrap(), small);
    assert_eq!(begins(&service), [Some(0), Some(1)]);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deadline_mid_batch_aborts_without_a_terminal_record_and_audit_keeps_the_facts() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(service_config(&pki, |config| {
        config.max_in_flight = 1;
        config.operation_timeout_ms = 3_000;
        config.header_timeout_ms = 1_000;
        config.admission_wait_ms = 200;
        config.queue_capacity = 1;
    }))
    .await;
    // Item 1 is held inside the TSA until after the original deadline.
    pki.tsa_gate.hold();
    let items = [
        sign_cms("first", &p12, b"completed before the deadline"),
        sign_profile("second", "cades_t", &p12, b"held inside the TSA"),
        sign_cms("third", &p12, b"never reached"),
    ];
    let body = body(&items);
    let service = Arc::new(service);
    let request = {
        let service = service.clone();
        tokio::spawn(async move { raw_request(&service, FORM, &body, false).await })
    };
    wait_for("the second item's native work inside the TSA", || {
        pki.tsa_gate.entered() == 1
    })
    .await;
    let response = request.await.unwrap();
    // The status line was decided at approval (200 + streamed progress); the original
    // deadline then ended the stream: no terminal record, no closing delimiter.
    let text = String::from_utf8_lossy(&response).into_owned();
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(!text.contains("batch_final"), "{text}");
    assert!(!text.contains("\"status\":\"completed\""), "{text}");
    assert!(
        !text.contains("artifact-"),
        "nothing is published after the deadline"
    );
    // Native work is still inside the TSA: the original root is retained.
    assert_eq!(service.host.executor.running(), 1);
    assert!(
        service
            .host
            .engine
            .admit(Arc::new(oncl_server::executor::Cancellation::new()))
            .is_err(),
        "the expired response does not free the root"
    );
    pki.tsa_gate.release();
    wait_for("native return", || service.host.executor.running() == 0).await;
    // The durable journal holds the per-item truth with original ordinals.
    assert_eq!(begins(&service), [Some(0), Some(1)], "item 2 never began");
    let finals = finals(&service);
    assert_eq!(finals[0], (Some(0), true));
    assert_eq!(finals[1].0, Some(1));
    assert!(spool_files(&service.scratch()).is_empty());
    let service = Arc::try_unwrap(service).ok().unwrap();
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inflight_batch_holds_its_slot_and_overflow_never_touches_a_key() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Arc::new(
        Running::start_with(service_config(&pki, |config| {
            config.max_in_flight = 1;
            config.blocking_workers = 1;
            config.queue_capacity = 1;
            config.admission_wait_ms = 100;
            config.operation_timeout_ms = 20_000;
        }))
        .await,
    );
    pki.tsa_gate.hold();
    let held_body = body(&[sign_profile("held", "cades_t", &p12, b"held in the TSA")]);
    let held = {
        let service = service.clone();
        tokio::spawn(async move { service.post_batch(FORM, held_body).await })
    };
    wait_for("native work inside the TSA", || pki.tsa_gate.entered() == 1).await;
    assert_eq!(service.host.executor.running(), 1);
    let (status, _, response) = service
        .post_batch(FORM, body(&[sign_cms("overflow", &p12, b"refused")]))
        .await;
    assert_eq!(status, 503, "{}", String::from_utf8_lossy(&response));
    let error: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(error["code"], "CapacityExceeded");
    assert_eq!(error["applied"], "NotApplied");
    pki.tsa_gate.release();
    let (status, content_type, response) = held.await.unwrap();
    assert_eq!(status, 200);
    let done = batch_final(&mixed(&content_type, response).await);
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(
        begins(&service),
        [Some(0)],
        "the refused batch never used a key"
    );
    let service = Arc::try_unwrap(service).ok().unwrap();
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json_small_hash_batch_reports_exact_captured_sources_and_progress_positions() {
    let pki = Pki::start();
    let service = Running::start_with(service_config(&pki, |_| {})).await;
    let request = r#"{"metadata":{"items":[{"id":"h1","operation":{"kind":"hash","algorithm":"sha256","input":"a"}},{"id":"h2","operation":{"kind":"hash","algorithm":"sha512","input":"b"}}],"parts":[{"name":"a","item_id":"h1","role":"document"},{"name":"b","item_id":"h2","role":"document"}]},"documents":{"a":"abc","b":""}}"#;
    let (status, content_type, response) = service
        .post_path_as(
            service.token.as_str(),
            "/v1/batch",
            "application/json",
            request.as_bytes().to_vec(),
        )
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let parts = mixed(&content_type, response).await;
    let done = batch_final(&parts);
    assert_eq!(done["status"], "completed");
    assert_eq!(done["items"][0]["result"]["bytes_in"], 3);
    assert_eq!(done["items"][1]["result"]["bytes_in"], 0);
    assert_eq!(done["items"][1]["sources"][0]["bytes"], 0);
    assert!(
        begins(&service).is_empty(),
        "a key-less batch needs no audit binding"
    );
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deadline_during_a_batch_upload_is_a_typed_not_applied_error() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(service_config(&pki, |config| {
        config.operation_timeout_ms = 1_500;
        config.header_timeout_ms = 1_000;
        config.admission_wait_ms = 200;
    }))
    .await;
    let (metadata, parts) = manifest(&[sign_cms("a", &p12, b"d")]);
    let secrets: Vec<Part<'_>> = parts
        .iter()
        .filter(|(name, _)| name.ends_with("p12") || name.ends_with("pw"))
        .map(|(name, bytes)| Part {
            name,
            filename: None,
            bytes,
        })
        .collect();
    let mut prefix = multipart(&metadata, &secrets);
    prefix.truncate(prefix.len() - b"--b--\r\n".len());
    prefix.extend_from_slice(
        b"--b\r\nContent-Disposition: form-data; name=\"a-doc\"\r\n\r\nfirst bytes only",
    );
    let mut stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let head = format!(
        "POST /v1/batch HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {FORM}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        service.address,
        service.token.as_str(),
        prefix.len() + (1 << 20)
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&prefix).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        stream.read_to_end(&mut response),
    )
    .await
    .expect("answered by the server's own deadline")
    .ok();
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 504"), "{text}");
    assert!(text.contains("\"code\":\"DeadlineExceeded\""), "{text}");
    assert!(text.contains("\"applied\":\"NotApplied\""), "{text}");
    assert!(begins(&service).is_empty());
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn progress_names_the_current_item_while_it_is_held_and_the_final_follows() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(service_config(&pki, |config| {
        config.operation_timeout_ms = 30_000;
    }))
    .await;
    pki.tsa_gate.hold();
    let items = [
        hash("early", b"abc"),
        sign_profile("held", "cades_t", &p12, b"held in the TSA"),
    ];
    let body = body(&items);
    let mut stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let head = format!(
        "POST /v1/batch HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {FORM}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        service.address,
        service.token.as_str(),
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    // Read while item 2 is held inside the TSA: its progress position must arrive.
    let mut seen = Vec::new();
    let mut chunk = [0u8; 4096];
    while !String::from_utf8_lossy(&seen).contains("\"item_id\":\"held\"") {
        let n = tokio::time::timeout(std::time::Duration::from_secs(15), stream.read(&mut chunk))
            .await
            .expect("progress arrives while native work is held")
            .unwrap();
        assert_ne!(n, 0, "stream ended before the held item was reported");
        seen.extend_from_slice(&chunk[..n]);
    }
    let text = String::from_utf8_lossy(&seen).into_owned();
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("\"total\":2"), "{text}");
    assert!(
        !text.contains("batch_final"),
        "no terminal record yet: {text}"
    );
    pki.tsa_gate.release();
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.unwrap();
    let all = String::from_utf8_lossy(&[seen, rest].concat()).into_owned();
    assert!(all.contains("\"type\":\"batch_final\""), "{all}");
    assert!(all.contains("\"status\":\"completed\""), "{all}");
    service.stop().await;
}

fn cms_print(signature: &[u8], dir: &Path) -> String {
    let file = dir.join("print.p7s");
    std::fs::write(&file, signature).unwrap();
    let out = std::process::Command::new("openssl")
        .args(["cms", "-cmsout", "-print", "-inform", "DER", "-in"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}
/// GOST signing through the batch route. No independent GOST math exists here:
/// OpenSSL decodes the real wire OIDs; GOST validity is checked by the SDK verify item
/// of a second batch, with a tampered control that must be Invalid.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gost_batch_signatures_carry_the_gost_oids_and_verify_in_a_second_batch() {
    let pki = Pki::start();
    let dir = tempfile::tempdir().unwrap();
    for (fixture, signature_oid, digest_oid) in [
        (
            "user-gost2015-sign",
            "1.2.398.3.10.1.1.2.3.2",
            "1.2.398.3.10.1.3.3",
        ),
        (
            "user-gost2004-sign",
            "1.2.398.3.10.1.1.1.2",
            "1.2.398.3.10.1.3.1",
        ),
    ] {
        let p12 = container(&pki.leaf(fixture), PASSWORD);
        let service = Running::start_with(service_config(&pki, |_| {})).await;
        let payload = format!("GOST batch payload for {fixture}");
        let (parts, done) = run(&service, &[sign_cms("gost", &p12, payload.as_bytes())]).await;
        assert_eq!(done["status"], "completed", "{fixture}: {done}");
        assert_eq!(done["items"][0]["applied"], "Applied");
        let signature = artifact(&parts, "artifact-0").to_vec();
        let print = cms_print(&signature, dir.path());
        assert!(print.contains(signature_oid), "{fixture}: {signature_oid}");
        assert!(print.contains(digest_oid), "{fixture}: {digest_oid}");
        let mut tampered = signature.clone();
        let at = tampered
            .windows(payload.len())
            .position(|w| w == payload.as_bytes())
            .unwrap();
        tampered[at] ^= 1;
        let (_, done) = run(
            &service,
            &[verify_cms("good", &signature), verify_cms("bad", &tampered)],
        )
        .await;
        assert_eq!(done["status"], "completed", "{done}");
        assert_eq!(
            done["items"][0]["result"]["signers"][0]["signature"], "Passed",
            "{fixture}: {done}"
        );
        assert_eq!(done["items"][1]["verdict"], "Invalid", "{fixture}: {done}");
        assert_eq!(begins(&service), [Some(0)]);
        service.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_mid_batch_holds_the_root_to_native_return_and_later_items_never_begin() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(service_config(&pki, |config| {
        config.max_in_flight = 1;
        config.operation_timeout_ms = 30_000;
        config.admission_wait_ms = 200;
        config.queue_capacity = 1;
    }))
    .await;
    pki.tsa_gate.hold();
    let body = body(&[
        sign_cms("first", &p12, b"completed before the disconnect"),
        sign_profile("second", "cades_t", &p12, b"held inside the TSA"),
        sign_cms("third", &p12, b"never reached"),
    ]);
    let mut stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let head = format!(
        "POST /v1/batch HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {FORM}\r\nContent-Length: {}\r\n\r\n",
        service.address,
        service.token.as_str(),
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    wait_for("native work inside the TSA", || pki.tsa_gate.entered() == 1).await;
    assert_eq!(begins(&service), [Some(0), Some(1)]);
    drop(stream); // cancel: the client is gone mid-batch
    assert!(
        service
            .host
            .engine
            .admit(Arc::new(oncl_server::executor::Cancellation::new()))
            .is_err(),
        "disconnect must not free the original root while native work runs"
    );
    pki.tsa_gate.release();
    wait_for("native return", || service.host.executor.running() == 0).await;
    wait_for("the durable FINAL of the held item", || {
        finals(&service).len() == 2
    })
    .await;
    assert_eq!(finals(&service)[0], (Some(0), true));
    assert_ne!(
        format!(
            "{:?}",
            service
                .host
                .audit
                .records()
                .unwrap()
                .iter()
                .rev()
                .find(|r| r.kind == RecordKind::Final)
                .unwrap()
                .applied
        ),
        "NotApplied",
        "a cancel after use is never NotApplied"
    );
    assert_eq!(begins(&service), [Some(0), Some(1)], "item 3 never began");
    assert!(spool_files(&service.scratch()).is_empty());
    assert!(
        service
            .host
            .engine
            .admit(Arc::new(oncl_server::executor::Cancellation::new()))
            .is_ok()
    );
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_operation_families_share_the_same_batch_pipeline() {
    let pki = Pki::start();
    let leaf = pki.leaf("user-rsa-sign");
    let p12 = container(&leaf, PASSWORD);
    let cert = {
        use der::Encode;
        leaf.cert.to_der().unwrap()
    };
    let service = Running::start_with(service_config(&pki, |config| {
        config.tokens[0]
            .actions
            .extend([Permission::Inspect, Permission::Stamp]);
    }))
    .await;
    let attached = presign(&service, &p12, b"extract me from the batch").await;
    let jws = Item {
        id: "jws",
        operation: r#"{"kind":"jws_sign","serialization":"compact","input":"jws-doc","keys":[{"source":"inline","container":"jws-p12","password":"jws-pw"}]}"#.into(),
        secrets: vec![
            ("jws-p12".into(), p12.clone()),
            ("jws-pw".into(), PASSWORD.as_bytes().to_vec()),
        ],
        documents: vec![("jws-doc".into(), b"{\"payload\":true}".to_vec())],
    };
    let extract = Item {
        id: "extract",
        operation: r#"{"kind":"extract","input":"extract-doc"}"#.into(),
        secrets: vec![],
        documents: vec![("extract-doc".into(), attached)],
    };
    let inspect = Item {
        id: "inspect",
        operation: r#"{"kind":"inspect","target":{"type":"certificate","input":"inspect-doc"}}"#
            .into(),
        secrets: vec![],
        documents: vec![("inspect-doc".into(), cert)],
    };
    let stamp = Item {
        id: "stamp",
        operation: r#"{"kind":"stamp","input":"stamp-doc"}"#.into(),
        secrets: vec![],
        documents: vec![("stamp-doc".into(), b"stamp me".to_vec())],
    };
    let (parts, done) = run(&service, &[jws, extract, inspect, stamp]).await;
    assert_eq!(done["status"], "completed", "{done}");
    let records = done["items"].as_array().unwrap();
    assert_eq!(records[0]["result"]["kind"], "jws");
    assert_eq!(records[0]["applied"], "Applied");
    let token = artifact(&parts, records[0]["result"]["artifact"].as_str().unwrap());
    assert_eq!(
        token.iter().filter(|b| **b == b'.').count(),
        2,
        "compact JWS"
    );
    assert_eq!(records[1]["result"]["kind"], "extraction");
    assert_eq!(
        artifact(&parts, records[1]["result"]["artifact"].as_str().unwrap()),
        b"extract me from the batch"
    );
    assert_eq!(records[2]["result"]["kind"], "inspection");
    assert_eq!(records[2]["result"]["entries"].as_array().unwrap().len(), 1);
    assert_eq!(records[3]["result"]["kind"], "stamping");
    assert!(!artifact(&parts, records[3]["result"]["artifact"].as_str().unwrap()).is_empty());
    // Ordinals follow the manifest: the JWS is item 0; only that item used a key
    // (plus the pre-sign request outside the batch).
    assert_eq!(begins(&service), [None, Some(0)]);
    service.stop().await;
}

fn sign_with(id: &'static str, profile: &str, extra: &str, p12: &[u8], document: &[u8]) -> Item {
    let mut item = sign_cms(id, p12, document);
    item.operation = format!(
        r#"{{"kind":"sign","profile":"{profile}","input":"{id}-doc",{extra}"keys":[{{"source":"inline","container":"{id}-p12","password":"{id}-pw"}}]}}"#
    );
    item
}
fn der_len(bytes: &[u8]) -> usize {
    let first = bytes[1] as usize;
    if first < 0x80 {
        2 + first
    } else {
        let n = first & 0x7f;
        2 + n
            + bytes[2..2 + n]
                .iter()
                .fold(0usize, |a, b| (a << 8) | *b as usize)
    }
}
/// (covered bytes, embedded CMS) of the last signature, recomputed from /ByteRange.
fn last_pdf_signature(pdf: &[u8]) -> (Vec<u8>, Vec<u8>, usize) {
    let text = String::from_utf8_lossy(pdf);
    let start = text.rfind("/ByteRange").unwrap();
    let open = text[start..].find('[').unwrap() + start + 1;
    let close = text[open..].find(']').unwrap() + open;
    let n: Vec<usize> = text[open..close]
        .split_whitespace()
        .map(|v| v.parse().unwrap())
        .collect();
    let covered = [&pdf[n[0]..n[0] + n[1]], &pdf[n[2]..n[2] + n[3]]].concat();
    let mut cms: Vec<u8> = pdf[n[0] + n[1] + 1..n[2] - 1]
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect();
    cms.truncate(der_len(&cms));
    (covered, cms, n[2] - (n[0] + n[1]))
}
fn xml_oracle(xml: &[u8], dir: &Path) -> serde_json::Value {
    let file = dir.join("signed.xml");
    std::fs::write(&file, xml).unwrap();
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/oracles/xml_verify.py");
    let out = std::process::Command::new("python")
        .arg(script)
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

/// PDF and XML/XAdES in one batch with a bad source in the middle: every finished
/// artifact is checked by an independent oracle (OpenSSL over the recomputed
/// /ByteRange; lxml + cryptography for XMLDSig).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pdf_and_xml_items_in_one_batch_are_verified_by_independent_oracles() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    // Completed format reports retain their bounded metadata until the batch ends:
    // this many XML/PDF items need more than the 64 MiB per-operation test default.
    let service = Running::start_with(service_config(&pki, |config| {
        config.metadata_bytes = 128 << 20;
    }))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let pdf = include_bytes!("../../oncl-pdf/tests/fixtures/external-multipage.pdf");
    let xml = br#"<root xmlns:x="urn:x"><x:item Id="p">payload text</x:item><holder Id="s"></holder></root>"#;
    let extra = r#""target":"p","parent":"s","signature_id":"sig1","#;
    let items = [
        sign_with("pdf", "pdf", "", &p12, pdf),
        sign_with("broken", "xml", extra, &p12, b"<unclosed"),
        sign_with("xml", "xml", extra, &p12, xml),
        sign_with("xades", "xades_b", extra, &p12, xml),
    ];
    let (parts, done) = run(&service, &items).await;
    assert_eq!(done["status"], "partial", "{done}");
    let records = done["items"].as_array().unwrap();
    assert_eq!(records[0]["outcome"], "completed", "{done}");
    assert_eq!(records[1]["outcome"], "failed", "{done}");
    assert_eq!(records[1]["applied"], "NotApplied", "{done}");
    assert_eq!(records[2]["outcome"], "completed", "{done}");
    assert_eq!(records[3]["outcome"], "completed", "{done}");
    let signed_pdf = artifact(&parts, records[0]["result"]["artifact"].as_str().unwrap());
    assert!(signed_pdf.starts_with(pdf.as_slice()), "incremental update");
    let (covered, cms, gap) = last_pdf_signature(signed_pdf);
    assert_eq!(covered.len() + gap, signed_pdf.len());
    assert!(openssl_cms_verify(&cms, Some(&covered), dir.path()).is_some());
    let mut altered = covered.clone();
    altered[10] ^= 1;
    assert!(openssl_cms_verify(&cms, Some(&altered), dir.path()).is_none());
    for (index, xades) in [(2usize, false), (3usize, true)] {
        let signed = artifact(
            &parts,
            records[index]["result"]["artifact"].as_str().unwrap(),
        );
        let verdict = xml_oracle(signed, dir.path());
        assert_eq!(verdict["checked"], true, "{verdict}");
        for signature in verdict["signatures"].as_array().unwrap() {
            assert_eq!(signature["signature_valid"], true, "{verdict}");
            assert!(
                signature["references"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|r| r["match"] == true),
                "{verdict}"
            );
        }
        assert_eq!(
            xades,
            String::from_utf8_lossy(signed).contains("QualifyingProperties")
        );
    }
    assert_eq!(begins(&service), [Some(0), Some(2), Some(3)]);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_uses_the_same_precheck_including_the_tsa_policy_order() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    // Host without a TSA policy OID: XAdES-T is a configuration refusal (503) before any
    // secret or document is read, but only for a token that holds the rights.
    let service = Running::start_with(service_config(&pki, |config| {
        config.pki.tsa.as_mut().unwrap().policy = None;
    }))
    .await;
    let item = || {
        sign_with(
            "x",
            "xades_t",
            r#""target":"p","parent":"s","#,
            &p12,
            b"<r><a Id=\"p\"/><h Id=\"s\"/></r>",
        )
    };
    let (status, _, response) = service.post_batch(FORM, body(&[item()])).await;
    assert_eq!(status, 503, "{}", String::from_utf8_lossy(&response));
    assert!(String::from_utf8_lossy(&response).contains("MissingConfiguration"));
    assert!(begins(&service).is_empty());
    service.stop().await;
    // A token without the sign right learns nothing about the configuration: 403.
    let service = Running::start_with(service_config(&pki, |config| {
        config.pki.tsa.as_mut().unwrap().policy = None;
        config.tokens[0]
            .actions
            .retain(|p| !matches!(p, Permission::Sign));
    }))
    .await;
    let (status, _, response) = service.post_batch(FORM, body(&[item()])).await;
    assert_eq!(status, 403, "{}", String::from_utf8_lossy(&response));
    service.stop().await;
}

/// Completed XML/PDF reports keep their bounded metadata reservation (SDK ownership)
/// until the batch ends, so a batch of several XML signatures needs a proportionally
/// larger `metadata_bytes`. When it is exhausted the item fails with the typed code and
/// its honest Applied state, later items are `not_run` and the earlier artifact stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exhausted_retained_report_metadata_is_a_typed_item_stop_that_keeps_earlier_artifacts() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(service_config(&pki, |config| {
        config.metadata_bytes = 64 << 20;
    }))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let xml = br#"<root xmlns:x="urn:x"><x:item Id="p">payload text</x:item><holder Id="s"></holder></root>"#;
    let extra = r#""target":"p","parent":"s","signature_id":"sig1","#;
    let items = [
        sign_with("xml1", "xml", extra, &p12, xml),
        sign_with("xml2", "xml", extra, &p12, xml),
        hash("after", b"abc"),
    ];
    let (parts, done) = run(&service, &items).await;
    assert_eq!(done["status"], "partial", "{done}");
    let records = done["items"].as_array().unwrap();
    assert_eq!(records[0]["outcome"], "completed", "{done}");
    let first = artifact(&parts, records[0]["result"]["artifact"].as_str().unwrap());
    assert_eq!(xml_oracle(first, dir.path())["checked"], true);
    assert_eq!(records[1]["outcome"], "failed", "{done}");
    assert_eq!(records[1]["error"]["code"], "MetadataLimit", "{done}");
    assert_eq!(
        records[1]["applied"], records[1]["error"]["applied"],
        "the item reports the same honest Applied state as its error: {done}"
    );
    assert_eq!(records[2]["outcome"], "not_run", "{done}");
    assert_eq!(done["stop"]["code"], "MetadataLimit");
    assert_eq!(done["stop"]["item_index"], 1);
    assert!(parts.iter().filter(|(n, _, _)| n == "artifact").count() == 1);
    service.stop().await;
}
