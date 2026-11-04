#![cfg(feature = "server")]
//! Real-socket private operations (sign/extend) with independent OpenSSL oracles.
mod private_support;
use oncl_server::{audit::RecordKind, config::Permission};
use private_support::*;
use std::sync::Arc;

const PASSWORD: &str = "inline-secret-password-MARKER-7f3a";

fn sign_metadata(profile: &str, extra: &str) -> String {
    format!(
        r#"{{"items":[{{"id":"s1","operation":{{"kind":"sign","profile":"{profile}","input":"doc",{extra}"keys":[{{"source":"inline","container":"p12","password":"pw"}}]}}}}],"parts":[{{"name":"p12","item_id":"s1","role":"secret"}},{{"name":"pw","item_id":"s1","role":"secret"}},{{"name":"doc","item_id":"s1","role":"document"}}]}}"#
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inline_rsa_cms_create_is_audited_verified_by_openssl_and_never_spooled() {
    let pki = Pki::start();
    let leaf = pki.leaf("user-rsa-sign");
    let p12 = container(&leaf, PASSWORD);
    let service = Running::start_with(|config, dir| {
        config.inline_pkcs12 = true;
        config.tokens[0].inline_pkcs12 = true;
        config.pki = pki.config(dir);
    })
    .await;
    let payload = b"HTTP private CMS create payload \x00\x01\x02";
    let watch = SpoolWatch::start(
        service.scratch(),
        vec![PASSWORD.as_bytes().to_vec(), p12[..64].to_vec()],
    );
    let body = multipart(
        &sign_metadata("cms", r#""attached":true,"#),
        &[
            Part {
                name: "p12",
                filename: Some("key.pdf"),
                bytes: &p12,
            },
            Part {
                name: "pw",
                filename: None,
                bytes: PASSWORD.as_bytes(),
            },
            Part {
                name: "doc",
                filename: Some("../evil.pdf"),
                bytes: payload,
            },
        ],
    );
    let (status, content_type, response) = service.post(FORM, body).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    assert!(!watch.finish(), "secret reached the document spool");
    let parts = mixed(&content_type, response).await;
    let done = final_event(&parts);
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["results"][0]["result"]["kind"], "signing");
    assert_eq!(done["results"][0]["result"]["signers"][0], "Applied");
    assert_eq!(done["results"][0]["applied"], "Applied");
    let signature = artifact(&parts, "artifact-0");
    let directory = tempfile::tempdir().unwrap();
    // Independent oracle: OpenSSL verifies the attached CMS and recovers content.
    assert_eq!(
        openssl_cms_verify(signature, None, directory.path()).as_deref(),
        Some(payload.as_slice())
    );
    let mut altered = signature.to_vec();
    let at = altered
        .windows(payload.len())
        .position(|w| w == payload)
        .unwrap();
    altered[at] ^= 1;
    assert!(openssl_cms_verify(&altered, None, directory.path()).is_none());
    // Exactly one durable private use bound to this principal and exact InlineID.
    let records = service.host.audit.records().unwrap();
    let begin: Vec<_> = records
        .iter()
        .filter(|r| r.kind == RecordKind::Begin)
        .collect();
    let fin: Vec<_> = records
        .iter()
        .filter(|r| r.kind == RecordKind::Final)
        .collect();
    assert_eq!((begin.len(), fin.len()), (1, 1));
    assert!(fin[0].succeeded);
    assert_eq!(
        begin[0].operation_id,
        done["operation_id"].as_u64().unwrap()
    );
    assert!(spool_files(&service.scratch()).is_empty());
    assert!(pki.requests.load(std::sync::atomic::Ordering::SeqCst) > 0);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inline_key_without_client_right_is_refused_before_provider_or_audit() {
    let pki = Pki::start();
    let leaf = pki.leaf("user-rsa-sign");
    let p12 = container(&leaf, PASSWORD);
    let service = Running::start_with(|config, dir| {
        config.inline_pkcs12 = true; // global switch on, token right absent
        config.pki = pki.config(dir);
    })
    .await;
    let body = multipart(
        &sign_metadata("cms", ""),
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
            Part {
                name: "doc",
                filename: None,
                bytes: b"x",
            },
        ],
    );
    let (status, _, response) = service.post(FORM, body).await;
    assert_eq!(status, 403, "{}", String::from_utf8_lossy(&response));
    assert!(
        service
            .host
            .audit
            .records()
            .unwrap()
            .iter()
            .all(|r| r.kind != RecordKind::Begin)
    );
    assert_eq!(pki.requests.load(std::sync::atomic::Ordering::SeqCst), 0);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn named_operator_key_signs_only_with_exact_key_right() {
    let pki = Pki::start();
    let service = Running::start_with(|config, dir| {
        config.pki = pki.config(dir);
        named_key(config, dir, &pki, "ops-key", "user-rsa-sign");
        config.tokens[0].keys = vec!["ops-key".into()];
        config.tokens[0].actions.push(Permission::Verify);
    })
    .await;
    let metadata = r#"{"items":[{"id":"n1","operation":{"kind":"sign","profile":"cms","input":"doc","keys":[{"source":"named","name":"ops-key"}]}}],"parts":[{"name":"doc","item_id":"n1","role":"document"}]}"#;
    let body = multipart(
        metadata,
        &[Part {
            name: "doc",
            filename: None,
            bytes: b"named key content",
        }],
    );
    let (status, ct, response) = service.post(FORM, body).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let parts = mixed(&ct, response).await;
    assert_eq!(final_event(&parts)["status"], "completed");
    let dir = tempfile::tempdir().unwrap();
    let signature = artifact(&parts, "artifact-0");
    assert!(openssl_cms_verify(signature, Some(b"named key content"), dir.path()).is_some());
    assert!(openssl_cms_verify(signature, Some(b"named key contenT"), dir.path()).is_none());
    // A different alias is not authorized for this token.
    let other = metadata.replace("ops-key", "other-key");
    let body = multipart(
        &other,
        &[Part {
            name: "doc",
            filename: None,
            bytes: b"x",
        }],
    );
    let (status, _, _) = service.post(FORM, body).await;
    assert_eq!(status, 403);
    let begins = service
        .host
        .audit
        .records()
        .unwrap()
        .iter()
        .filter(|r| r.kind == RecordKind::Begin)
        .count();
    assert_eq!(begins, 1);
    service.stop().await;
}

fn inline_service_config(
    pki: &Pki,
) -> impl FnOnce(&mut oncl_server::config::ServerConfig, &std::path::Path) + '_ {
    move |config, dir| {
        config.inline_pkcs12 = true;
        config.tokens[0].inline_pkcs12 = true;
        config.tokens[0].actions.push(Permission::Extend);
        config.tokens[0].actions.push(Permission::Verify);
        config.memory_per_operation = 1 << 30;
        config.total_memory = 2 << 30;
        config.pki = pki.config(dir);
    }
}
async fn sign_inline(
    service: &Running,
    p12: &[u8],
    profile: &str,
    extra: &str,
    doc: &[u8],
) -> (u16, Vec<(String, Option<String>, Vec<u8>)>) {
    let body = multipart(
        &sign_metadata(profile, extra),
        &[
            Part {
                name: "p12",
                filename: None,
                bytes: p12,
            },
            Part {
                name: "pw",
                filename: None,
                bytes: PASSWORD.as_bytes(),
            },
            Part {
                name: "doc",
                filename: None,
                bytes: doc,
            },
        ],
    );
    let (status, ct, response) = service.post(FORM, body).await;
    if status != 200 {
        panic!("{status}: {}", String::from_utf8_lossy(&response));
    }
    (status, mixed(&ct, response).await)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cades_t_create_add_and_keyless_extend_use_actual_tsa_and_openssl_oracle() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(inline_service_config(&pki)).await;
    let dir = tempfile::tempdir().unwrap();
    let payload = b"CAdES over actual HTTP";
    // CAdES-B create (detached) then keyless extension to T through the HTTP route.
    let (_, parts) = sign_inline(&service, &p12, "cades_b", "", payload).await;
    let done = final_event(&parts);
    assert_eq!(done["status"], "completed", "{done}");
    let base = artifact(&parts, "artifact-0").to_vec();
    assert!(openssl_cms_verify(&base, Some(payload), dir.path()).is_some());
    let begins_before = service
        .host
        .audit
        .records()
        .unwrap()
        .iter()
        .filter(|r| r.kind == RecordKind::Begin)
        .count();
    let metadata = r#"{"items":[{"id":"e1","operation":{"kind":"extend","profile":"cades_t","input":"sig","detached":"content"}}],"parts":[{"name":"sig","item_id":"e1","role":"document"},{"name":"content","item_id":"e1","role":"document"}]}"#;
    let body = multipart(
        metadata,
        &[
            Part {
                name: "sig",
                filename: None,
                bytes: &base,
            },
            Part {
                name: "content",
                filename: None,
                bytes: payload,
            },
        ],
    );
    let (status, ct, response) = service.post(FORM, body).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let parts = mixed(&ct, response).await;
    let done = final_event(&parts);
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["results"][0]["result"]["kind"], "extension");
    assert_eq!(done["results"][0]["applied"], "NotApplied");
    let extended = artifact(&parts, "artifact-0");
    assert!(extended.len() > base.len());
    assert!(openssl_cms_verify(extended, Some(payload), dir.path()).is_some());
    // The signature-timestamp attribute (id-aa-signatureTimeStampToken) is present.
    let print = std::process::Command::new("openssl")
        .args(["cms", "-cmsout", "-print", "-inform", "DER", "-in"])
        .arg({
            let p = dir.path().join("ext.der");
            std::fs::write(&p, extended).unwrap();
            p
        })
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&print.stdout).contains("id-smime-aa-timeStampToken"));
    // Keyless: Extend never used a private key and wrote no new audit use.
    let records = service.host.audit.records().unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|r| r.kind == RecordKind::Begin)
            .count(),
        begins_before
    );
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cades_t_create_acquires_a_real_timestamp_during_private_use() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(inline_service_config(&pki)).await;
    let dir = tempfile::tempdir().unwrap();
    let payload = b"CAdES-T create";
    let (_, parts) = sign_inline(&service, &p12, "cades_t", r#""attached":true,"#, payload).await;
    assert_eq!(final_event(&parts)["status"], "completed");
    let sig = artifact(&parts, "artifact-0");
    assert_eq!(
        openssl_cms_verify(sig, None, dir.path()).as_deref(),
        Some(payload.as_slice())
    );
    let p = dir.path().join("t.der");
    std::fs::write(&p, sig).unwrap();
    let print = std::process::Command::new("openssl")
        .args(["cms", "-cmsout", "-print", "-inform", "DER", "-in"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&print.stdout).contains("id-smime-aa-timeStampToken"));
    service.stop().await;
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}
fn cms_print(bytes: &[u8], dir: &std::path::Path) -> String {
    let p = dir.join("print.der");
    std::fs::write(&p, bytes).unwrap();
    let out = std::process::Command::new("openssl")
        .args(["cms", "-cmsout", "-print", "-inform", "DER", "-in"])
        .arg(&p)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cms_add_cosigns_the_detached_container_with_a_second_private_use() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(inline_service_config(&pki)).await;
    let dir = tempfile::tempdir().unwrap();
    let payload = b"co-signed detached payload";
    let (_, parts) = sign_inline(&service, &p12, "cms", "", payload).await;
    let first = artifact(&parts, "artifact-0").to_vec();
    assert_eq!(count(&cms_print(&first, dir.path()), "messageDigest"), 1);
    let metadata = r#"{"items":[{"id":"a1","operation":{"kind":"sign","profile":"cms","mode":"add","input":"sig","detached":"content","keys":[{"source":"inline","container":"p12","password":"pw"}]}}],"parts":[{"name":"p12","item_id":"a1","role":"secret"},{"name":"pw","item_id":"a1","role":"secret"},{"name":"sig","item_id":"a1","role":"document"},{"name":"content","item_id":"a1","role":"document"}]}"#;
    let body = multipart(
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
            Part {
                name: "sig",
                filename: None,
                bytes: &first,
            },
            Part {
                name: "content",
                filename: None,
                bytes: payload,
            },
        ],
    );
    let (status, ct, response) = service.post(FORM, body).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let parts = mixed(&ct, response).await;
    assert_eq!(final_event(&parts)["status"], "completed");
    let second = artifact(&parts, "artifact-0");
    assert_eq!(count(&cms_print(second, dir.path()), "messageDigest"), 2);
    assert!(openssl_cms_verify(second, Some(payload), dir.path()).is_some());
    assert!(openssl_cms_verify(second, Some(b"other"), dir.path()).is_none());
    let begins = service
        .host
        .audit
        .records()
        .unwrap()
        .iter()
        .filter(|r| r.kind == RecordKind::Begin)
        .count();
    assert_eq!(begins, 2, "one durable private use per signing request");
    service.stop().await;
}

/// Bytes inside the last signature's `<...>` Contents gap (hex digits plus brackets).
fn hex_len(pdf: &[u8]) -> usize {
    let text = String::from_utf8_lossy(pdf);
    let at = text.rfind("/ByteRange").unwrap();
    let open = text[at..].find('[').unwrap() + at + 1;
    let close = text[open..].find(']').unwrap() + open;
    let n: Vec<usize> = text[open..close]
        .split_whitespace()
        .map(|v| v.parse().unwrap())
        .collect();
    assert_eq!(n[0], 0);
    n[2] - (n[0] + n[1])
}
fn der_len(bytes: &[u8]) -> usize {
    let first = bytes[1] as usize;
    if first < 0x80 {
        2 + first
    } else {
        let n = first & 0x7f;
        let len = bytes[2..2 + n]
            .iter()
            .fold(0usize, |a, b| (a << 8) | *b as usize);
        2 + n + len
    }
}
/// Independent oracle: recompute the signed bytes from /ByteRange and verify the
/// embedded CMS with OpenSSL.
fn pdf_signatures(pdf: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let text = String::from_utf8_lossy(pdf);
    let mut result = Vec::new();
    let mut from = 0;
    while let Some(at) = text[from..].find("/ByteRange") {
        let start = from + at;
        let open = text[start..].find('[').unwrap() + start + 1;
        let close = text[open..].find(']').unwrap() + open;
        let n: Vec<usize> = text[open..close]
            .split_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        let signed = [&pdf[n[0]..n[0] + n[1]], &pdf[n[2]..n[2] + n[3]]].concat();
        let hex = &pdf[n[0] + n[1] + 1..n[2] - 1];
        let mut cms: Vec<u8> = hex
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect();
        cms.truncate(der_len(&cms));
        result.push((signed, cms));
        from = close;
    }
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pdf_incremental_signature_verifies_against_the_exact_byterange_in_openssl() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(inline_service_config(&pki)).await;
    let dir = tempfile::tempdir().unwrap();
    let pdf = include_bytes!("../../oncl-pdf/tests/fixtures/external-multipage.pdf");
    let (_, parts) = sign_inline(&service, &p12, "pdf", "", pdf).await;
    let done = final_event(&parts);
    assert_eq!(done["status"], "completed", "{done}");
    let signed = artifact(&parts, "artifact-0");
    assert!(
        signed.starts_with(pdf.as_slice()),
        "incremental update preserves the original bytes"
    );
    let signatures = pdf_signatures(signed);
    let (covered, cms) = signatures.last().unwrap();
    assert_eq!(
        covered.len() + hex_len(signed),
        signed.len(),
        "the /ByteRange gap is exactly the signature hex and everything else is covered"
    );
    assert!(openssl_cms_verify(cms, Some(covered), dir.path()).is_some());
    let mut altered = covered.clone();
    altered[10] ^= 1;
    assert!(openssl_cms_verify(cms, Some(&altered), dir.path()).is_none());
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_failure_before_use_is_a_not_applied_terminal_failure_without_artifact() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(inline_service_config(&pki)).await;
    service
        .host
        .audit
        .inject_fault(oncl_server::audit::FaultPoint::BeforeWrite);
    let body = multipart(
        &sign_metadata("cms", ""),
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
            Part {
                name: "doc",
                filename: None,
                bytes: b"audit must come first",
            },
        ],
    );
    let (status, ct, response) = service.post(FORM, body).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let parts = mixed(&ct, response).await;
    let done = final_event(&parts);
    assert_eq!(done["status"], "failed", "{done}");
    assert_eq!(done["error"]["applied"], "NotApplied");
    assert_eq!(done["error"]["code"], "AuditUnavailable");
    assert!(
        parts.iter().all(|(n, _, _)| n != "artifact"),
        "no partial artifact on failure"
    );
    service.stop().await;
}

fn run_openssl(args: &[&str], input: &[u8], dir: &std::path::Path) -> String {
    let file = dir.join("openssl.in");
    std::fs::write(&file, input).unwrap();
    let mut command = std::process::Command::new("openssl");
    command.args(args).arg(&file);
    let out = command.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}
async fn operate(
    service: &Running,
    metadata: &str,
    parts: &[Part<'_>],
) -> (u16, Vec<(String, Option<String>, Vec<u8>)>, Vec<u8>) {
    let (status, ct, response) = service.post(FORM, multipart(metadata, parts)).await;
    if ct.starts_with("multipart/mixed") {
        (status, mixed(&ct, response.clone()).await, response)
    } else {
        if status == 200 {
            assert_matches_schema("FinalEvent", &serde_json::from_slice(&response).unwrap());
        }
        (status, Vec::new(), response)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inspect_certificate_cms_and_container_are_public_metadata_with_exact_alias_grants() {
    let pki = Pki::start();
    let leaf = pki.leaf("user-rsa-sign");
    let cert_der = {
        use der::Encode;
        leaf.cert.to_der().unwrap()
    };
    let p12 = container(&leaf, PASSWORD);
    let alias = leaf.alias.clone();
    let service = Running::start_with(|config, dir| {
        inline_service_config(&pki)(config, dir);
        config.tokens[0].actions.push(Permission::Inspect);
        config.tokens[0].metadata_aliases = vec![alias.clone()];
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let json = |status: u16, response: &[u8]| -> serde_json::Value {
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(response));
        serde_json::from_slice(response).unwrap()
    };
    let metadata = r#"{"items":[{"id":"i","operation":{"kind":"inspect","target":{"type":"certificate","input":"cert"}}}],"parts":[{"name":"cert","item_id":"i","role":"document"}]}"#;
    let (status, _, response) = operate(
        &service,
        metadata,
        &[Part {
            name: "cert",
            filename: None,
            bytes: &cert_der,
        }],
    )
    .await;
    let done = json(status, &response);
    let entry = &done["results"][0]["result"]["entries"][0];
    let serial = run_openssl(
        &["x509", "-inform", "DER", "-noout", "-serial", "-in"],
        &cert_der,
        dir.path(),
    );
    assert_eq!(
        serial.trim().to_lowercase().trim_start_matches("serial="),
        entry["serial_hex"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .trim_start_matches('0')
    );
    let fingerprint = run_openssl(
        &[
            "x509",
            "-inform",
            "DER",
            "-noout",
            "-fingerprint",
            "-sha256",
            "-in",
        ],
        &cert_der,
        dir.path(),
    );
    assert_eq!(
        fingerprint
            .trim()
            .rsplit('=')
            .next()
            .unwrap()
            .replace(':', "")
            .to_lowercase(),
        entry["sha256"].as_str().unwrap()
    );
    // Container: password and bytes are secret roles; only exact granted aliases show.
    let metadata = r#"{"items":[{"id":"c","operation":{"kind":"inspect","target":{"type":"container","container":"p12","password":"pw"}}}],"parts":[{"name":"p12","item_id":"c","role":"secret"},{"name":"pw","item_id":"c","role":"secret"}]}"#;
    let parts = [
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
    ];
    let watch = SpoolWatch::start(service.scratch(), vec![PASSWORD.as_bytes().to_vec()]);
    let (status, _, response) = operate(&service, metadata, &parts).await;
    assert!(!watch.finish());
    let done = json(status, &response);
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(
        done["results"][0]["result"]["entries"][0]["alias"],
        alias.as_str()
    );
    assert_eq!(
        done["results"][0]["result"]["integrity"],
        "PasswordMacVerified"
    );
    assert!(!String::from_utf8_lossy(&response).contains(PASSWORD));
    // CMS metadata
    let (_, sign_parts) = sign_inline(&service, &p12, "cms", "", b"inspect me").await;
    let sig = artifact(&sign_parts, "artifact-0").to_vec();
    let metadata = r#"{"items":[{"id":"m","operation":{"kind":"inspect","target":{"type":"cms","input":"sig"}}}],"parts":[{"name":"sig","item_id":"m","role":"document"}]}"#;
    let (status, _, response) = operate(
        &service,
        metadata,
        &[Part {
            name: "sig",
            filename: None,
            bytes: &sig,
        }],
    )
    .await;
    let done = json(status, &response);
    assert_eq!(done["results"][0]["result"]["cms"]["detached"], true);
    assert_eq!(done["results"][0]["result"]["cms"]["signer_count"], 1);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_stamp_and_verify_report_token_facts_and_bad_imprint_is_a_200_invalid() {
    let pki = Pki::start();
    let service = Running::start_with(|config, dir| {
        config.pki = pki.config(dir);
        config.tokens[0].actions = vec![Permission::Stamp, Permission::VerifyStamp];
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let data = b"standalone timestamped document";
    let metadata = r#"{"items":[{"id":"t","operation":{"kind":"stamp","input":"doc"}}],"parts":[{"name":"doc","item_id":"t","role":"document"}]}"#;
    let (status, parts, response) = operate(
        &service,
        metadata,
        &[Part {
            name: "doc",
            filename: None,
            bytes: data,
        }],
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let done = final_event(&parts);
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(
        done["results"][0]["applied"], "NotApplied",
        "a TSA request never uses a local private key"
    );
    let token = artifact(&parts, "artifact-0").to_vec();
    // Independent oracle: OpenSSL reads the message imprint inside the actual token.
    let text = run_openssl(
        &["ts", "-reply", "-token_in", "-text", "-in"],
        &token,
        dir.path(),
    );
    let digest = {
        let out = run_openssl(&["dgst", "-sha256", "-r"], data, dir.path());
        out.split_whitespace().next().unwrap().to_owned()
    };
    assert!(text.contains("Hash Algorithm: sha256"), "{text}");
    // The OpenSSL-decoded imprint must equal an independently computed digest.
    let imprint: String = text
        .lines()
        .skip_while(|l| !l.contains("Message data:"))
        .skip(1)
        .take_while(|l| l.contains(" - "))
        .filter_map(|l| l.split_once(" - "))
        .map(|(_, hex)| hex.split("  ").next().unwrap_or(""))
        .collect::<String>()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect();
    assert_eq!(imprint.to_lowercase(), digest);
    // Verification: matching data Valid; altered data Invalid but HTTP 200.
    let verify = r#"{"items":[{"id":"v","operation":{"kind":"verify_stamp","token":"token","data":"data"}}],"parts":[{"name":"token","item_id":"v","role":"document"},{"name":"data","item_id":"v","role":"document"}]}"#;
    let (status, _, response) = operate(
        &service,
        verify,
        &[
            Part {
                name: "token",
                filename: None,
                bytes: &token,
            },
            Part {
                name: "data",
                filename: None,
                bytes: data,
            },
        ],
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let good: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(
        good["results"][0]["result"]["timestamp"]["verdict"], "Valid",
        "{good}"
    );
    assert_eq!(
        good["results"][0]["result"]["timestamp"]["imprint"],
        "Matched"
    );
    let (status, _, response) = operate(
        &service,
        verify,
        &[
            Part {
                name: "token",
                filename: None,
                bytes: &token,
            },
            Part {
                name: "data",
                filename: None,
                bytes: b"another document",
            },
        ],
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let bad: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(bad["status"], "completed");
    assert_eq!(
        bad["results"][0]["result"]["timestamp"]["verdict"],
        "Invalid"
    );
    assert_eq!(
        bad["results"][0]["result"]["timestamp"]["imprint"],
        "Mismatched"
    );
    service.stop().await;
}

fn b64url_decode(text: &str) -> Vec<u8> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => panic!("not base64url"),
        } as u32;
        bits = (bits << 6) | v;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    out
}
/// Independent RS256 oracle: OpenSSL verifies header.payload with the leaf key.
fn openssl_rs256(token: &str, public_pem: &[u8], dir: &std::path::Path) -> bool {
    let mut parts = token.split('.');
    let (h, p, s) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    std::fs::write(dir.join("jws.pub"), public_pem).unwrap();
    std::fs::write(dir.join("jws.sig"), b64url_decode(s)).unwrap();
    std::fs::write(dir.join("jws.in"), format!("{h}.{p}")).unwrap();
    std::process::Command::new("openssl")
        .args(["dgst", "-sha256", "-verify"])
        .arg(dir.join("jws.pub"))
        .arg("-signature")
        .arg(dir.join("jws.sig"))
        .arg(dir.join("jws.in"))
        .output()
        .unwrap()
        .status
        .success()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jws_and_jwt_sign_verify_and_decode_are_separate_typed_operations() {
    let pki = Pki::start();
    let leaf = pki.leaf("user-rsa-sign");
    let p12 = container(&leaf, PASSWORD);
    let service = Running::start_with(|config, dir| {
        inline_service_config(&pki)(config, dir);
        config.tokens[0].actions.push(Permission::Extract);
        config.pki = pki.config(dir);
        config.pki.jwt.expected_issuer = Some("https://issuer.example".into());
        config.pki.jwt.expected_audience = Some("aud-1".into());
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let cert_der = {
        use der::Encode;
        leaf.cert.to_der().unwrap()
    };
    let pem = {
        let out = run_openssl(
            &["x509", "-inform", "DER", "-pubkey", "-noout", "-in"],
            &cert_der,
            dir.path(),
        );
        out.into_bytes()
    };
    // JWS compact over the payload.
    let payload = b"jws payload bytes";
    let metadata = r#"{"items":[{"id":"j","operation":{"kind":"jws_sign","serialization":"compact","input":"payload","keys":[{"source":"inline","container":"p12","password":"pw"}]}}],"parts":[{"name":"p12","item_id":"j","role":"secret"},{"name":"pw","item_id":"j","role":"secret"},{"name":"payload","item_id":"j","role":"document"}]}"#;
    let parts = [
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
        Part {
            name: "payload",
            filename: None,
            bytes: payload,
        },
    ];
    let (status, mixed_parts, response) = operate(&service, metadata, &parts).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    assert_eq!(
        final_event(&mixed_parts)["results"][0]["result"]["signers"][0],
        "Applied"
    );
    let jws = String::from_utf8(artifact(&mixed_parts, "artifact-0").to_vec()).unwrap();
    assert!(openssl_rs256(&jws, &pem, dir.path()));
    let mut forged = jws.clone().into_bytes();
    let at = jws.rfind('.').unwrap() + 3;
    forged[at] = if forged[at] == b'A' { b'B' } else { b'A' };
    assert!(!openssl_rs256(
        std::str::from_utf8(&forged).unwrap(),
        &pem,
        dir.path()
    ));
    // HTTP verify with host trust: valid; forged signature: 200 + Invalid.
    let verify = r#"{"items":[{"id":"v","operation":{"kind":"jws_verify","serialization":"compact","input":"jws"}}],"parts":[{"name":"jws","item_id":"v","role":"document"}]}"#;
    let (status, _, response) = operate(
        &service,
        verify,
        &[Part {
            name: "jws",
            filename: None,
            bytes: jws.as_bytes(),
        }],
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let good: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(good["results"][0]["result"]["verdict"], "Valid", "{good}");
    let (status, _, response) = operate(
        &service,
        verify,
        &[Part {
            name: "jws",
            filename: None,
            bytes: &forged,
        }],
    )
    .await;
    assert_eq!(status, 200);
    let bad: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(bad["results"][0]["result"]["verdict"], "Invalid");
    // JWT: encode, decode (never verified), verify claims separately.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let encode =
        |exp: u64| format!(r#"{{"iss":"https://issuer.example","aud":"aud-1","exp":{exp}}}"#);
    let metadata = r#"{"items":[{"id":"t","operation":{"kind":"jwt_encode","input":"claims","key":{"source":"inline","container":"p12","password":"pw"}}}],"parts":[{"name":"p12","item_id":"t","role":"secret"},{"name":"pw","item_id":"t","role":"secret"},{"name":"claims","item_id":"t","role":"document"}]}"#;
    let mut tokens = Vec::new();
    for exp in [now + 3600, now - 3600] {
        let claims = encode(exp);
        let parts = [
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
            Part {
                name: "claims",
                filename: None,
                bytes: claims.as_bytes(),
            },
        ];
        let (status, mixed_parts, response) = operate(&service, metadata, &parts).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
        let token = String::from_utf8(artifact(&mixed_parts, "artifact-0").to_vec()).unwrap();
        assert!(openssl_rs256(&token, &pem, dir.path()));
        tokens.push(token);
    }
    let verify = r#"{"items":[{"id":"v","operation":{"kind":"jwt_verify","input":"jwt"}}],"parts":[{"name":"jwt","item_id":"v","role":"document"}]}"#;
    let (_, _, response) = operate(
        &service,
        verify,
        &[Part {
            name: "jwt",
            filename: None,
            bytes: tokens[0].as_bytes(),
        }],
    )
    .await;
    let valid: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(valid["results"][0]["result"]["verdict"], "Valid", "{valid}");
    let (status, _, response) = operate(
        &service,
        verify,
        &[Part {
            name: "jwt",
            filename: None,
            bytes: tokens[1].as_bytes(),
        }],
    )
    .await;
    assert_eq!(status, 200);
    let expired: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(
        expired["results"][0]["result"]["signature_verdict"],
        "Valid"
    );
    assert_eq!(expired["results"][0]["result"]["claims_verdict"], "Invalid");
    assert_eq!(
        expired["results"][0]["result"]["claim_failures"][0],
        "Expired"
    );
    let decode = r#"{"items":[{"id":"d","operation":{"kind":"jwt_decode","input":"jwt"}}],"parts":[{"name":"jwt","item_id":"d","role":"document"}]}"#;
    let (_, _, response) = operate(
        &service,
        decode,
        &[Part {
            name: "jwt",
            filename: None,
            bytes: tokens[1].as_bytes(),
        }],
    )
    .await;
    let decoded: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(decoded["results"][0]["result"]["verified"], false);
    assert_eq!(
        decoded["results"][0]["result"]["issuer"],
        "https://issuer.example"
    );
    // alg=none is not a trust decision: a forged unsigned token is Invalid, not an error.
    let none = format!(
        "{}.{}.",
        "eyJhbGciOiJub25lIn0", "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0"
    );
    let (status, _, response) = operate(
        &service,
        verify,
        &[Part {
            name: "jwt",
            filename: None,
            bytes: none.as_bytes(),
        }],
    )
    .await;
    assert!(status == 400 || status == 200, "{status}");
    assert!(!String::from_utf8_lossy(&response).contains("\"verdict\":\"Valid\""));
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_signing_requests_do_not_consume_the_bounded_audit_binding_table() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(|config, dir| {
        inline_service_config(&pki)(config, dir);
        config.max_in_flight = 2;
    })
    .await;
    for round in 0..6 {
        let (_, parts) = sign_inline(
            &service,
            &p12,
            "cms",
            "",
            format!("round {round}").as_bytes(),
        )
        .await;
        assert_eq!(final_event(&parts)["status"], "completed", "round {round}");
    }
    let records = service.host.audit.records().unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|r| r.kind == RecordKind::Begin)
            .count(),
        6
    );
    assert_eq!(
        records
            .iter()
            .filter(|r| r.kind == RecordKind::Final)
            .count(),
        6
    );
    service.stop().await;
}

fn raw_metadata(service: &Running, length: usize) -> oncl_api::server::RequestMetadata {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("host", service.address.to_string().parse().unwrap());
    headers.insert(
        "authorization",
        format!("Bearer {}", service.token.as_str())
            .parse()
            .unwrap(),
    );
    headers.insert("content-type", FORM.parse().unwrap());
    oncl_api::server::RequestMetadata {
        peer: "127.0.0.1:45678".parse().unwrap(),
        headers,
        content_length: Some(length as u64),
    }
}

/// A held staged-artifact data slice keeps the original root and the SDK's own
/// spool after its deadline, while the native worker permit is already free.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn staged_artifact_slice_after_expiry_retains_root_and_temp_but_not_the_worker() {
    use http_body_util::BodyExt;
    use oncl_api::server::HashHost;
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(|config, dir| {
        inline_service_config(&pki)(config, dir);
        config.max_in_flight = 1;
        config.operation_timeout_ms = 4000;
        config.header_timeout_ms = 1000;
        config.admission_wait_ms = 500;
    })
    .await;
    let body = multipart(
        &sign_metadata("cms", r#""attached":true,"#),
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
            Part {
                name: "doc",
                filename: None,
                bytes: &vec![7u8; 600_000],
            },
        ],
    );
    let response = service
        .host
        .operations(
            raw_metadata(&service, body.len()),
            axum::body::Body::from(body),
        )
        .await
        .unwrap();
    let deadline = response
        .extensions()
        .get::<oncl_server::service::ResponseDelivery>()
        .unwrap()
        .deadline();
    let mut body = response.into_body();
    // Skip protocol frames until a genuine artifact data frame (large, binary).
    let held = loop {
        let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
        if frame.len() > 1000 {
            break frame;
        }
    };
    let slice = held.slice(0..1);
    drop(held);
    // The artifact exists as SDK scratch while the slice is retained.
    assert!(!spool_files(&service.scratch()).is_empty());
    assert_eq!(
        service.host.executor.running(),
        0,
        "native worker is free while output is held"
    );
    tokio::time::sleep(deadline.remaining()).await;
    assert!(
        matches!(body.frame().await, Some(Err(_))),
        "no data may escape the original deadline"
    );
    drop(body);
    assert!(
        service
            .host
            .engine
            .admit(Arc::new(oncl_server::executor::Cancellation::new()))
            .is_err(),
        "the last Bytes slice keeps the original root after expiry"
    );
    assert!(
        !spool_files(&service.scratch()).is_empty(),
        "and keeps its real scratch"
    );
    drop(slice);
    assert!(
        spool_files(&service.scratch()).is_empty(),
        "last drop cleans the SDK spool"
    );
    assert!(
        service
            .host
            .engine
            .admit(Arc::new(oncl_server::executor::Cancellation::new()))
            .is_ok()
    );
    service.stop().await;
}

/// A real peer that never reads the multipart response cannot hold the root,
/// worker or scratch past the original deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_reading_peer_of_a_large_artifact_response_is_cut_at_the_original_deadline() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(|config, dir| {
        inline_service_config(&pki)(config, dir);
        config.max_in_flight = 1;
        config.operation_timeout_ms = 3000;
        config.header_timeout_ms = 1000;
        config.admission_wait_ms = 500;
    })
    .await;
    let document = vec![9u8; 48 << 20];
    let body = multipart(
        &sign_metadata("cms", r#""attached":true,"#),
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
            Part {
                name: "doc",
                filename: None,
                bytes: &document,
            },
        ],
    );
    let mut stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let head = format!(
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {FORM}\r\nContent-Length: {}\r\n\r\n",
        service.address,
        service.token.as_str(),
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let started = std::time::Instant::now();
    // Read only the response head and the first frames, then stop reading.
    let mut head = vec![0u8; 2048];
    let mut got = 0;
    while got < 600 {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut head[got..]),
        )
        .await
        .expect("server produced the response head")
        .unwrap();
        assert!(n > 0, "closed before producing the head");
        got += n;
    }
    let text = String::from_utf8_lossy(&head[..got]).into_owned();
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "head produced, not a 413/503: {text}"
    );
    assert!(text.contains("multipart/mixed"));
    assert!(
        text.contains("\"type\":\"progress\""),
        "first frames were produced"
    );
    // The 48 MiB artifact cannot be written to a peer that does not read: the
    // server blocks on the socket until the ORIGINAL deadline ends the response.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    assert!(
        service
            .host
            .engine
            .admit(Arc::new(oncl_server::executor::Cancellation::new()))
            .is_err(),
        "while the write is pending the original root is still held"
    );
    // Still not reading: the server must release everything by itself when the
    // ORIGINAL deadline (3 s from admission) expires.
    let released_at = loop {
        if service
            .host
            .engine
            .admit(Arc::new(oncl_server::executor::Cancellation::new()))
            .is_ok()
        {
            break started.elapsed();
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(8),
            "never released"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    };
    assert!(
        released_at >= std::time::Duration::from_millis(1800)
            && released_at <= std::time::Duration::from_secs(5),
        "ended by the original deadline, not early or never: {released_at:?}"
    );
    // Only now drain: the buffered prefix ends without a terminal completed record.
    let mut received = got;
    let mut tail = Vec::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(8), stream.read(&mut buffer))
            .await
        {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => {
                received += n;
                if tail.len() < 4096 {
                    tail.extend_from_slice(&buffer[..n.min(4096)]);
                }
            }
            Err(_) => panic!("stream neither ended nor failed after the deadline"),
        }
    }
    assert!(
        received < 40 << 20,
        "the stalled artifact was not fully delivered ({received} bytes)"
    );
    assert!(!String::from_utf8_lossy(&tail).contains("\"status\":\"completed\""));
    wait_for("root and scratch released", || {
        service
            .host
            .engine
            .admit(Arc::new(oncl_server::executor::Cancellation::new()))
            .is_ok()
            && spool_files(&service.scratch()).is_empty()
    })
    .await;
    assert_eq!(service.host.executor.running(), 0);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_openapi_examples_are_accepted_by_the_running_service() {
    use http_body_util::{BodyExt, Empty};
    let service = Running::start_with(|config, _| {
        config.tokens[0].actions.push(Permission::Hash);
    })
    .await;
    let get = |token: Option<String>| {
        let address = service.address;
        async move {
            let stream = tokio::net::TcpStream::connect(address).await.unwrap();
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                    .await
                    .unwrap();
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let mut request = hyper::Request::builder()
                .method("GET")
                .uri("/v1/openapi.json")
                .header("host", address.to_string());
            if let Some(token) = token {
                request = request.header("authorization", format!("Bearer {token}"));
            }
            let response = sender
                .send_request(request.body(Empty::<axum::body::Bytes>::new()).unwrap())
                .await
                .unwrap();
            let status = response.status().as_u16();
            (
                status,
                response.into_body().collect().await.unwrap().to_bytes(),
            )
        }
    };
    assert_eq!(get(None).await.0, 403);
    let (status, bytes) = get(Some(service.token.to_string())).await;
    assert_eq!(status, 200);
    let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(document["openapi"], "3.1.0");
    let examples = &document["paths"]["/v1/operations"]["post"]["requestBody"]["content"]["multipart/form-data"]
        ["examples"];
    for name in [
        "hash",
        "sign_inline",
        "sign_named",
        "verify",
        "extend",
        "extract",
        "jws",
        "jwt_verify",
        "inspect",
        "stamp",
        "verify_stamp",
    ] {
        assert!(examples[name]["value"]["items"].is_array(), "{name}");
    }
    // The published hash example is a working request.
    let metadata = examples["hash"]["value"].to_string();
    let (status, ct, response) = service
        .post(
            FORM,
            multipart(
                &metadata,
                &[Part {
                    name: "doc",
                    filename: None,
                    bytes: b"abc",
                }],
            ),
        )
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    assert_eq!(ct, "application/json");
    let done: serde_json::Value = serde_json::from_slice(&response).unwrap();
    let published = &document["paths"]["/v1/operations"]["post"]["responses"]["200"]["content"]["application/json"]
        ["examples"]["hash"]["value"];
    assert_eq!(
        done["results"][0]["result"],
        published["results"][0]["result"]
    );
    assert_eq!(done["status"], published["status"]);
    // A completed Invalid example keeps HTTP 200 semantics in the description.
    assert_eq!(
        document["paths"]["/v1/operations"]["post"]["responses"]["200"]["content"]["application/json"]
            ["examples"]["verification_invalid_is_200"]["value"]["results"][0]["result"]["verdict"],
        "Invalid"
    );
    service.stop().await;
}

fn xml_oracle(xml: &[u8], dir: &std::path::Path) -> serde_json::Value {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enveloped_xml_and_xades_signatures_verify_in_lxml_and_cryptography() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(inline_service_config(&pki)).await;
    let dir = tempfile::tempdir().unwrap();
    let xml = br#"<root xmlns:x="urn:x"><x:item Id="p">payload text</x:item><holder Id="s"></holder></root>"#;
    for (profile, xades) in [("xml", false), ("xades_b", true)] {
        let (_, parts) = sign_inline(
            &service,
            &p12,
            profile,
            r#""target":"p","parent":"s","signature_id":"sig1","#,
            xml,
        )
        .await;
        let done = final_event(&parts);
        assert_eq!(done["status"], "completed", "{profile}: {done}");
        let signed = artifact(&parts, "artifact-0");
        let verdict = xml_oracle(signed, dir.path());
        assert_eq!(
            verdict["checked"], true,
            "oracle must check at least one reference per signature: {verdict}"
        );
        for signature in verdict["signatures"].as_array().unwrap() {
            assert_eq!(signature["supported"], true, "{verdict}");
            assert_eq!(signature["signature_valid"], true, "{profile}: {verdict}");
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
        // Altering signed content breaks the independent digest check.
        let altered = String::from_utf8_lossy(signed).replace("payload text", "payload texT");
        let broken = xml_oracle(altered.as_bytes(), dir.path());
        assert!(
            broken["signatures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["references"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r["match"] == false)),
            "{broken}"
        );
        // The service's own verifier agrees; tampering is a completed Invalid report.
        let verify = format!(
            r#"{{"items":[{{"id":"v","operation":{{"kind":"verify","profile":"{}","input":"doc"}}}}],"parts":[{{"name":"doc","item_id":"v","role":"document"}}]}}"#,
            if xades { "xades_b" } else { "xml" }
        );
        let (status, _, response) = operate(
            &service,
            &verify,
            &[Part {
                name: "doc",
                filename: None,
                bytes: altered.as_bytes(),
            }],
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
        let report: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(report["status"], "completed");
        assert_eq!(
            report["results"][0]["result"]["verdict"], "Invalid",
            "{report}"
        );
    }
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_signing_input_is_a_typed_not_applied_failure_not_a_transport_abort() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(inline_service_config(&pki)).await;
    let (_, parts) = sign_inline(&service, &p12, "pdf", "", b"this is not a pdf").await;
    let done = final_event(&parts);
    assert_eq!(done["status"], "failed", "{done}");
    assert_eq!(done["error"]["code"], "InvalidRequest");
    assert_eq!(done["error"]["applied"], "NotApplied");
    assert!(parts.iter().all(|(n, _, _)| n != "artifact"));
    let records = service.host.audit.records().unwrap();
    assert!(
        records.iter().all(|r| r.kind != RecordKind::Begin),
        "no private use for malformed input"
    );
    service.stop().await;
}

/// GOST over real sockets. OpenSSL here has no GOST provider, so there is NO
/// independent GOST signature/digest verifier in this environment: the oracle is
/// structural (OpenSSL parses the actual CMS and reports the GOST signature OID,
/// signed attributes and certificate), while GOST signature/digest correctness is
/// only checked by the SDK verifier (secondary) via the HTTP verify route, with a
/// tamper control. No independent GOST math is claimed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gost_cms_signatures_are_structurally_checked_and_sdk_verified_over_http() {
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
        let leaf = pki.leaf(fixture);
        let p12 = container(&leaf, PASSWORD);
        let service = Running::start_with(inline_service_config(&pki)).await;
        let payload = format!("GOST payload for {fixture}");
        let (_, parts) = sign_inline(
            &service,
            &p12,
            "cms",
            r#""attached":true,"#,
            payload.as_bytes(),
        )
        .await;
        let done = final_event(&parts);
        assert_eq!(done["status"], "completed", "{fixture}: {done}");
        assert_eq!(done["results"][0]["result"]["signers"][0], "Applied");
        let signature = artifact(&parts, "artifact-0").to_vec();
        let print = cms_print(&signature, dir.path());
        // OpenSSL decodes the actual wire OIDs (no GOST names: it has no GOST provider).
        assert!(
            print.contains(signature_oid),
            "{fixture}: signature OID {signature_oid}"
        );
        assert!(
            print.contains(digest_oid),
            "{fixture}: digest OID {digest_oid}"
        );
        assert_eq!(count(&print, "messageDigest"), 1);
        assert!(
            signature
                .windows(payload.len())
                .any(|w| w == payload.as_bytes()),
            "attached content"
        );
        // Secondary: SDK verify via the real route; tampered content is Invalid, HTTP 200.
        let verify = r#"{"items":[{"id":"v","operation":{"kind":"verify","profile":"cms","input":"sig"}}],"parts":[{"name":"sig","item_id":"v","role":"document"}]}"#;
        let (status, _, response) = operate(
            &service,
            verify,
            &[Part {
                name: "sig",
                filename: None,
                bytes: &signature,
            }],
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
        let good: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(
            good["results"][0]["result"]["signers"][0]["signature"], "Passed",
            "{fixture}: {good}"
        );
        let mut tampered = signature.clone();
        let at = tampered
            .windows(payload.len())
            .position(|w| w == payload.as_bytes())
            .unwrap();
        tampered[at] ^= 1;
        let (_, _, response) = operate(
            &service,
            verify,
            &[Part {
                name: "sig",
                filename: None,
                bytes: &tampered,
            }],
        )
        .await;
        let bad: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(bad["results"][0]["result"]["verdict"], "Invalid");
        service.stop().await;
    }
}

/// XMLDSig with a GOST-2015-512 key. No independent GOST verifier exists here:
/// lxml independently checks the document structure and reports the GOST URIs
/// the SDK wrote; GOST digest/signature validity is checked only by the SDK verify
/// route (secondary), with tamper controls.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gost_xmldsig_is_structurally_checked_and_sdk_verified_over_http() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-gost2015-sign"), PASSWORD);
    let service = Running::start_with(inline_service_config(&pki)).await;
    let xml = br#"<root><item Id="p">gost payload</item><holder Id="s"></holder></root>"#;
    let (_, parts) = sign_inline(
        &service,
        &p12,
        "xml",
        r#""target":"p","parent":"s","signature_id":"sig1","#,
        xml,
    )
    .await;
    assert_eq!(final_event(&parts)["status"], "completed");
    let signed = artifact(&parts, "artifact-0").to_vec();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("g.xml");
    std::fs::write(&file, &signed).unwrap();
    let out = std::process::Command::new("python")
        .arg("-c")
        .arg(
            r#"
import sys, json
from lxml import etree
DS='http://www.w3.org/2000/09/xmldsig#'
r=etree.parse(sys.argv[1]).getroot()
s=r.find('.//{%s}Signature'%DS)
si=s.find('{%s}SignedInfo'%DS)
print(json.dumps({'sig':si.find('{%s}SignatureMethod'%DS).get('Algorithm'),
 'digests':[d.get('Algorithm') for d in si.iter('{%s}DigestMethod'%DS)],
 'refs':[x.get('URI') for x in si.findall('{%s}Reference'%DS)],
 'has_cert':s.find('.//{%s}X509Certificate'%DS) is not None,
 'value_len':len(s.find('{%s}SignatureValue'%DS).text.split())}))
"#,
        )
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let facts: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        facts["sig"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("gost"),
        "{facts}"
    );
    assert!(
        facts["digests"].as_array().unwrap().iter().all(|d| d
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("gost")
            || d.as_str().unwrap().contains("streebog")),
        "{facts}"
    );
    assert_eq!(facts["refs"][0], "#p");
    assert_eq!(facts["has_cert"], true);
    let verify = r#"{"items":[{"id":"v","operation":{"kind":"verify","profile":"xml","input":"doc"}}],"parts":[{"name":"doc","item_id":"v","role":"document"}]}"#;
    let (_, _, response) = operate(
        &service,
        verify,
        &[Part {
            name: "doc",
            filename: None,
            bytes: &signed,
        }],
    )
    .await;
    let good: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(
        good["results"][0]["result"]["signers"][0]["signature"], "Passed",
        "{good}"
    );
    let altered = String::from_utf8_lossy(&signed).replace("gost payload", "gost payloaD");
    let (_, _, response) = operate(
        &service,
        verify,
        &[Part {
            name: "doc",
            filename: None,
            bytes: altered.as_bytes(),
        }],
    )
    .await;
    let bad: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(bad["results"][0]["result"]["verdict"], "Invalid");
    service.stop().await;
}

fn pyhanko(pdf: &[u8], leaf_der: &[u8], dir: &std::path::Path) -> serde_json::Value {
    let python = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/p03-oracle-env/Scripts/python.exe"
    );
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/oracles/pdf_pyhanko.py");
    std::fs::write(dir.join("o.pdf"), pdf).unwrap();
    std::fs::write(dir.join("leaf.der"), leaf_der).unwrap();
    let out = std::process::Command::new(python)
        .arg(script)
        .arg(dir.join("o.pdf"))
        .arg(dir.join("leaf.der"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pades_levels_over_http_validate_in_pyhanko() {
    let pki = Pki::start();
    let leaf = pki.leaf("user-rsa-sign");
    let leaf_der = {
        use der::Encode;
        leaf.cert.to_der().unwrap()
    };
    let p12 = container(&leaf, PASSWORD);
    let service = Running::start_with(inline_service_config(&pki)).await;
    let dir = tempfile::tempdir().unwrap();
    let pdf = include_bytes!("../../oncl-pdf/tests/fixtures/external-multipage.pdf");
    let inter = {
        use der::Encode;
        pki.inter.cert.to_der().unwrap()
    };
    for (level, expect_dss) in [
        ("pades_b", false),
        ("pades_t", false),
        ("pades_lt", true),
        ("pades_lta", true),
    ] {
        let with_evidence = expect_dss;
        let (evidence, evidence_parts) = if with_evidence {
            (
                r#""evidence":[{"kind":"certificate","input":"ev0"},{"kind":"crl","input":"ev1"},{"kind":"crl","input":"ev2"}],"#,
                r#",{"name":"ev0","item_id":"s1","role":"document"},{"name":"ev1","item_id":"s1","role":"document"},{"name":"ev2","item_id":"s1","role":"document"}"#,
            )
        } else {
            ("", "")
        };
        let metadata = format!(
            r#"{{"items":[{{"id":"s1","operation":{{"kind":"sign","profile":"{level}","input":"doc",{evidence}"keys":[{{"source":"inline","container":"p12","password":"pw"}}]}}}}],"parts":[{{"name":"p12","item_id":"s1","role":"secret"}},{{"name":"pw","item_id":"s1","role":"secret"}},{{"name":"doc","item_id":"s1","role":"document"}}{evidence_parts}]}}"#
        );
        let mut request_parts = vec![
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
            Part {
                name: "doc",
                filename: None,
                bytes: pdf,
            },
        ];
        if with_evidence {
            request_parts.push(Part {
                name: "ev0",
                filename: None,
                bytes: &inter,
            });
            request_parts.push(Part {
                name: "ev1",
                filename: None,
                bytes: &pki.crls[0],
            });
            request_parts.push(Part {
                name: "ev2",
                filename: None,
                bytes: &pki.crls[1],
            });
        }
        let (status, parts, response) = operate(&service, &metadata, &request_parts).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
        let done = final_event(&parts);
        assert_eq!(done["status"], "completed", "{level}: {done}");
        let signed = artifact(&parts, "artifact-0");
        let report = pyhanko(signed, &leaf_der, dir.path());
        let signatures = report["signatures"].as_array().unwrap();
        assert!(!signatures.is_empty(), "{level}: {report}");
        // The signer's signature (first signature) is intact and valid in pyHanko.
        assert_eq!(signatures[0]["intact"], true, "{level}: {report}");
        assert_eq!(signatures[0]["valid"], true, "{level}: {report}");
        assert_eq!(report["dss"].is_object(), expect_dss, "{level}: {report}");
        let first = &signatures[0];
        assert_eq!(
            first["has_timestamp_token"],
            level != "pades_b",
            "{level}: {report}"
        );
        assert_eq!(
            first["full_validation"],
            level == "pades_b",
            "{level}: {report}"
        );
        assert!(
            first["coverage"]
                .as_str()
                .unwrap()
                .contains("ENTIRE_REVISION")
                || first["coverage"].as_str().unwrap().contains("ENTIRE_FILE")
                || level != "pades_b",
            "{level}: {report}"
        );
        if level == "pades_lta" {
            let last = signatures.last().unwrap();
            assert_eq!(last["doc_timestamp"], true, "{level}: {report}");
            assert!(
                signatures.len() >= 2,
                "LTA adds a document timestamp: {report}"
            );
        }
        // Tamper control: a flipped covered byte breaks pyHanko's integrity check.
        let mut altered = signed.to_vec();
        // Change page text inside the signed original body: still a valid PDF, so
        // only a real digest/integrity break can be detected (not a parse failure).
        let at = pdf.windows(8).position(|w| w == b"preserve").unwrap();
        altered[at] = b'P';
        let broken = pyhanko(&altered, &leaf_der, dir.path());
        assert!(
            broken["signatures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["intact"] == false && s.get("integrity_exception").is_none()),
            "{level}: tamper must be a real integrity failure, not an exception: {broken}"
        );
    }
    service.stop().await;
}

fn running_with_tsa(
    pki: &Pki,
    tune: impl FnOnce(&mut oncl_server::config::ServerConfig) + 'static,
) -> impl FnOnce(&mut oncl_server::config::ServerConfig, &std::path::Path) + '_ {
    move |config, dir| {
        inline_service_config(pki)(config, dir);
        tune(config);
    }
}
fn begins(service: &Running) -> usize {
    service
        .host
        .audit
        .records()
        .unwrap()
        .iter()
        .filter(|r| r.kind == RecordKind::Begin)
        .count()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_rights_refuse_before_a_secret_byte_is_read() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let pki = Pki::start();
    // Token has Sign but no inline right although the global switch is on.
    let service = Running::start_with(|config, dir| {
        config.inline_pkcs12 = true;
        config.pki = pki.config(dir);
    })
    .await;
    let metadata = sign_metadata("cms", "");
    let prefix = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"p12\"\r\n\r\nSECRET-PREFIX-NEVER-READ"
    );
    let mut stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let head = format!(
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {FORM}\r\nContent-Length: 4000000\r\n\r\n",
        service.address,
        service.token.as_str()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(prefix.as_bytes()).await.unwrap();
    // The refusal arrives although 4 MB of declared body (the secret tail) never comes.
    let mut response = vec![0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read(&mut response),
    )
    .await
    .expect("refused without waiting for the unsent secret")
    .unwrap();
    let text = String::from_utf8_lossy(&response[..n]);
    assert!(text.starts_with("HTTP/1.1 403"), "{text}");
    assert!(!text.contains("SECRET-PREFIX-NEVER-READ"));
    assert_eq!(begins(&service), 0);
    assert_eq!(pki.requests.load(std::sync::atomic::Ordering::SeqCst), 0);
    // Passwordless inline keys are refused before bind or document capture.
    drop(stream);
    service.stop().await;
    let service = Running::start_with(inline_service_config(&pki)).await;
    let metadata = r#"{"items":[{"id":"s1","operation":{"kind":"sign","profile":"cms","input":"doc","keys":[{"source":"inline","container":"p12"}]}}],"parts":[{"name":"p12","item_id":"s1","role":"secret"},{"name":"doc","item_id":"s1","role":"document"}]}"#;
    let (status, _, _) = service
        .post(
            FORM,
            multipart(
                metadata,
                &[
                    Part {
                        name: "p12",
                        filename: None,
                        bytes: b"x",
                    },
                    Part {
                        name: "doc",
                        filename: None,
                        bytes: b"d",
                    },
                ],
            ),
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(begins(&service), 0);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spool_watcher_has_a_positive_control_and_sees_the_held_document_spool() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(inline_service_config(&pki)).await;
    // Positive control: the same watcher detects a planted needle in the spool.
    let planted = service.scratch().join("planted.bin");
    let watch = SpoolWatch::start(service.scratch(), vec![b"PLANTED-NEEDLE".to_vec()]);
    std::fs::write(&planted, b"xx PLANTED-NEEDLE xx").unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        watch.finish(),
        "positive control: watcher must detect a needle"
    );
    std::fs::remove_file(&planted).unwrap();
    // The real run: the TSA holds native work so the document snapshot stays on
    // disk for >1s while the watcher scans it; secrets must never be in it.
    pki.tsa_gate.hold();
    let document = b"document bytes that DO belong in the spool".to_vec();
    let watch = SpoolWatch::start(
        service.scratch(),
        vec![
            PASSWORD.as_bytes().to_vec(),
            p12[..64].to_vec(),
            document.clone(),
        ],
    );
    let service = Arc::new(service);
    let task = {
        let (service, p12, document) = (service.clone(), p12.clone(), document.clone());
        tokio::spawn(async move { sign_inline(&service, &p12, "cades_t", "", &document).await })
    };
    // Native work is provably inside the TSA call (document snapshot on disk): scan, then release.
    wait_for("native work inside the TSA", || pki.tsa_gate.entered() >= 1).await;
    wait_for("watcher scanned the held spool", || {
        watch.scanned.load(std::sync::atomic::Ordering::SeqCst) > 0
    })
    .await;
    pki.tsa_gate.release();
    let (_, parts) = task.await.unwrap();
    assert_eq!(final_event(&parts)["status"], "completed");
    let service = Arc::try_unwrap(service).ok().unwrap();
    let scanned = watch.scanned.load(std::sync::atomic::Ordering::SeqCst);
    let saw_document_or_secret = watch.finish();
    assert!(
        scanned > 0,
        "the watcher scanned real spool files while work was held"
    );
    // The needle list mixes the (allowed) document and secrets: only the document
    // may be seen, so assert separately that secrets were not.
    assert!(
        saw_document_or_secret,
        "control inside the real run: the document spool IS visible"
    );
    let watch = SpoolWatch::start(
        service.scratch(),
        vec![PASSWORD.as_bytes().to_vec(), p12[..64].to_vec()],
    );
    let (_, parts) = sign_inline(&service, &p12, "cades_t", "", &document).await;
    assert_eq!(final_event(&parts)["status"], "completed");
    assert!(watch.scanned.load(std::sync::atomic::Ordering::SeqCst) > 0);
    assert!(!watch.finish(), "secrets never reach the spool");
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn later_item_abort_after_an_applied_item_is_a_failed_final_with_applied_results() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(running_with_tsa(&pki, |config| {
        config.temp_per_operation = 300_000;
        config.total_temp = 300_000;
    }))
    .await;
    let small = vec![5u8; 20_000];
    let large = vec![6u8; 120_000];
    let metadata = r#"{"items":[{"id":"a","operation":{"kind":"sign","profile":"cms","input":"d1","attached":true,"keys":[{"source":"inline","container":"p12","password":"pw"}]}},{"id":"b","operation":{"kind":"sign","profile":"cms","input":"d2","attached":true,"keys":[{"source":"inline","container":"q12","password":"qw"}]}}],"parts":[{"name":"p12","item_id":"a","role":"secret"},{"name":"pw","item_id":"a","role":"secret"},{"name":"q12","item_id":"b","role":"secret"},{"name":"qw","item_id":"b","role":"secret"},{"name":"d1","item_id":"a","role":"document"},{"name":"d2","item_id":"b","role":"document"}]}"#;
    let (status, parts, response) = operate(
        &service,
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
            Part {
                name: "q12",
                filename: None,
                bytes: &p12,
            },
            Part {
                name: "qw",
                filename: None,
                bytes: PASSWORD.as_bytes(),
            },
            Part {
                name: "d1",
                filename: None,
                bytes: &small,
            },
            Part {
                name: "d2",
                filename: None,
                bytes: &large,
            },
        ],
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let done = final_event(&parts);
    assert_eq!(done["status"], "failed", "{done}");
    assert_eq!(done["results"][0]["applied"], "Applied", "{done}");
    assert_eq!(done["results"][0]["item_id"], "a");
    assert!(
        done["results"][0]["result"].get("artifact").is_none(),
        "withheld artifact id must not be listed"
    );
    assert!(parts.iter().all(|(n, _, _)| n != "artifact"));
    let records = service.host.audit.records().unwrap();
    assert!(
        records
            .iter()
            .any(|r| r.kind == RecordKind::Final && r.succeeded),
        "item a FINAL is durable"
    );
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deadline_after_signing_is_audited_applied_and_disconnect_holds_the_worker_to_native_return()
 {
    use tokio::io::AsyncWriteExt;
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(running_with_tsa(&pki, |config| {
        config.max_in_flight = 1;
        config.operation_timeout_ms = 20_000;
        config.admission_wait_ms = 200;
        config.queue_capacity = 1;
    }))
    .await;
    pki.tsa_gate.hold();
    let body = multipart(
        &sign_metadata("cades_t", ""),
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
            Part {
                name: "doc",
                filename: None,
                bytes: b"disconnect during private use",
            },
        ],
    );
    let mut stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let head = format!(
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {FORM}\r\nContent-Length: {}\r\n\r\n",
        service.address,
        service.token.as_str(),
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    wait_for("private use to begin", || begins(&service) == 1).await;
    wait_for("native work inside the TSA", || pki.tsa_gate.entered() == 1).await;
    assert_eq!(service.host.executor.running(), 1);
    drop(stream); // client disconnects during private use
    // The original root is held until native work returns, whatever the socket does.
    assert!(
        service
            .host
            .engine
            .admit(Arc::new(oncl_server::executor::Cancellation::new()))
            .is_err(),
        "disconnect must not free the original root while native work runs"
    );
    pki.tsa_gate.release(); // native work may now return
    wait_for("native return", || service.host.executor.running() == 0).await;
    wait_for("durable FINAL", || {
        service
            .host
            .audit
            .records()
            .unwrap()
            .iter()
            .any(|r| r.kind == RecordKind::Final)
    })
    .await;
    let records = service.host.audit.records().unwrap();
    let last = records
        .iter()
        .rev()
        .find(|r| r.kind == RecordKind::Final)
        .unwrap();
    assert_ne!(
        format!("{:?}", last.applied),
        "NotApplied",
        "a disconnect after use is never NotApplied"
    );
    assert!(
        spool_files(&service.scratch()).is_empty(),
        "no artifact or spool survives the disconnect"
    );
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
async fn max_in_flight_private_requests_hold_slots_and_overflow_is_a_not_applied_503() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Arc::new(
        Running::start_with(running_with_tsa(&pki, |config| {
            config.max_in_flight = 2;
            config.blocking_workers = 2;
            config.queue_capacity = 1;
            config.admission_wait_ms = 100;
            config.operation_timeout_ms = 20_000;
        }))
        .await,
    );
    pki.tsa_gate.hold();
    let mut held = Vec::new();
    for round in 0..2 {
        let service = service.clone();
        let p12 = p12.clone();
        held.push(tokio::spawn(async move {
            let body = multipart(
                &sign_metadata("cades_t", ""),
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
                    Part {
                        name: "doc",
                        filename: None,
                        bytes: format!("held {round}").as_bytes(),
                    },
                ],
            );
            service.post(FORM, body).await.0
        }));
    }
    wait_for("both native workers inside the TSA", || {
        pki.tsa_gate.entered() == 2
    })
    .await;
    assert_eq!(service.host.executor.running(), 2);
    let body = multipart(
        &sign_metadata("cms", ""),
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
            Part {
                name: "doc",
                filename: None,
                bytes: b"overflow",
            },
        ],
    );
    let (status, _, response) = service.post(FORM, body).await;
    assert_eq!(status, 503, "{}", String::from_utf8_lossy(&response));
    let error: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(error["code"], "CapacityExceeded");
    assert_eq!(error["applied"], "NotApplied");
    pki.tsa_gate.release();
    for task in held {
        assert_eq!(task.await.unwrap(), 200);
    }
    assert_eq!(
        begins(&service),
        2,
        "the refused request never touched the key"
    );
    let service = Arc::try_unwrap(service).ok().unwrap();
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cheap_failing_requests_do_not_starve_other_signers_of_audit_binding_slots() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(|config, dir| {
        inline_service_config(&pki)(config, dir);
        config.max_in_flight = 2;
    })
    .await;
    for round in 0..64 {
        let (_, parts) = sign_inline(
            &service,
            &p12,
            "pdf",
            "",
            format!("not a pdf {round}").as_bytes(),
        )
        .await;
        assert_eq!(final_event(&parts)["status"], "failed");
    }
    let (_, parts) = sign_inline(&service, &p12, "cms", "", b"still served").await;
    assert_eq!(final_event(&parts)["status"], "completed");
    assert_eq!(
        begins(&service),
        1,
        "rejected-before-use requests took no key use"
    );
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn extract_and_hash_responses_match_the_schema_and_unimplemented_routes_stay_absent() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(|config, dir| {
        inline_service_config(&pki)(config, dir);
        config.tokens[0].actions.push(Permission::Extract);
        config.tokens[0].actions.push(Permission::Hash);
    })
    .await;
    let (_, parts) = sign_inline(&service, &p12, "cms", r#""attached":true,"#, b"extract me").await;
    let sig = artifact(&parts, "artifact-0").to_vec();
    let metadata = r#"{"items":[{"id":"x","operation":{"kind":"extract","input":"c"}}],"parts":[{"name":"c","item_id":"x","role":"document"}]}"#;
    let (status, parts, _) = operate(
        &service,
        metadata,
        &[Part {
            name: "c",
            filename: None,
            bytes: &sig,
        }],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        final_event(&parts)["results"][0]["result"]["kind"],
        "extraction"
    );
    let metadata = r#"{"items":[{"id":"h","operation":{"kind":"hash","algorithm":"sha256","input":"d"}}],"parts":[{"name":"d","item_id":"h","role":"document"}]}"#;
    let (status, _, _) = operate(
        &service,
        metadata,
        &[Part {
            name: "d",
            filename: None,
            bytes: b"abc",
        }],
    )
    .await;
    assert_eq!(status, 200); // schema-validated inside `operate`
    // Routes that are not implemented must not be advertised nor served.
    let document = oncl_api::openapi::document();
    let mut paths: Vec<&str> = document["paths"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        [
            "/health",
            "/v1/batch",
            "/v1/hash",
            "/v1/openapi.json",
            "/v1/operations"
        ],
        "the published routes are exactly the implemented ones"
    );
    for path in &paths {
        for forbidden in ["plugin", "encrypt", "decrypt"] {
            assert!(!path.contains(forbidden), "{path}");
        }
    }
    // The batch contract is the exact terminal record the service serializes.
    let batch = &document["components"]["schemas"]["BatchFinalEvent"];
    let mut required: Vec<&str> = batch["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    required.sort();
    assert_eq!(
        required,
        [
            "attempted",
            "completed",
            "items",
            "operation_id",
            "status",
            "total",
            "type"
        ]
    );
    let mut item: Vec<&str> = document["components"]["schemas"]["BatchItemRecord"]["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    item.sort();
    assert_eq!(
        item,
        [
            "applied", "error", "index", "item_id", "outcome", "result", "sources", "verdict"
        ]
    );
    assert_eq!(
        document["components"]["schemas"]["BatchItemRecord"]["properties"]["outcome"]["enum"],
        serde_json::json!(["completed", "failed", "not_run"])
    );
    let mut kinds: Vec<String> = document["components"]["schemas"]["Operation"]["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            r["$ref"]
                .as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect();
    kinds.sort();
    let mut expected: Vec<String> = [
        "Hash",
        "Verify",
        "Extract",
        "Sign",
        "Extend",
        "Inspect",
        "Stamp",
        "VerifyStamp",
        "JwsSign",
        "JwsAdd",
        "JwsVerify",
        "JwtEncode",
        "JwtDecode",
        "JwtVerify",
        "Plugin",
    ]
    .iter()
    .map(|k| format!("{k}Operation"))
    .collect();
    expected.sort();
    assert_eq!(
        kinds, expected,
        "the published operation kinds are exactly the implemented ones"
    );
    let mut profiles: Vec<&str> = document["components"]["schemas"]["SignOperation"]["properties"]
        ["profile"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    profiles.sort();
    let mut implemented = vec![
        "cms",
        "cades_b",
        "cades_t",
        "cades_lt",
        "cades_lta",
        "pdf",
        "pades_b",
        "pades_t",
        "pades_lt",
        "pades_lta",
        "xml",
        "xades_b",
        "xades_t",
        "wsse",
        "xml_legacy",
        "xades_legacy_b",
        "xades_legacy_t",
    ];
    implemented.sort();
    assert_eq!(
        profiles, implemented,
        "sign profiles are exactly the implemented ones"
    );
    let text = document.to_string().to_lowercase();
    assert!(
        !text.contains("\"kind\":{\"const\":\"encrypt\"")
            && !text.contains("\"const\":\"decrypt\"")
    );
    for route in ["/v1/plugin", "/v1/plugins", "/v1/encrypt", "/v1/decrypt"] {
        let mut stream = tokio::net::TcpStream::connect(service.address)
            .await
            .unwrap();
        stream
            .write_all(format!("POST {route} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", service.address, service.token.as_str()).as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 404"), "{route}: {response}");
    }
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_xml_and_wsse_sign_verify_with_independent_lxml_oracle_and_shape_refusals() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(inline_service_config(&pki)).await;
    let dir = tempfile::tempdir().unwrap();
    // Kalkan-compatible legacy XMLDSig with XPath element selection.
    let xml = br#"<root><data Id="d">legacy payload</data><other>x</other></root>"#;
    let (_, parts) = sign_inline(&service, &p12, "xml_legacy", r#""element":"//data","signature_method":"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256","digest_method":"http://www.w3.org/2001/04/xmlenc#sha256","#, xml).await;
    let done = final_event(&parts);
    assert_eq!(done["status"], "completed", "{done}");
    let signed = artifact(&parts, "artifact-0");
    let verdict = xml_oracle(signed, dir.path());
    assert_eq!(verdict["checked"], true, "{verdict}");
    assert_eq!(
        verdict["signatures"][0]["signature_valid"], true,
        "{verdict}"
    );
    assert!(
        verdict["signatures"][0]["references"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["match"] == true)
    );
    assert_eq!(verdict["signatures"][0]["references"][0]["uri"], "#d");
    let altered = String::from_utf8_lossy(signed).replace("legacy payload", "legacy payloaD");
    let broken = xml_oracle(altered.as_bytes(), dir.path());
    assert!(
        broken["signatures"][0]["references"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["match"] == false)
    );
    // WS-Security Body signature.
    let soap = br#"<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header/><soapenv:Body><x:op xmlns:x="urn:x">hello</x:op></soapenv:Body></soapenv:Envelope>"#;
    let (_, parts) = sign_inline(&service, &p12, "wsse", r#""soap":"soap11","#, soap).await;
    let done = final_event(&parts);
    assert_eq!(done["status"], "completed", "{done}");
    let signed = artifact(&parts, "artifact-0");
    let verdict = xml_oracle(signed, dir.path());
    assert_eq!(verdict["checked"], true, "{verdict}");
    assert_eq!(
        verdict["signatures"][0]["signature_valid"], true,
        "{verdict}"
    );
    assert!(
        verdict["signatures"][0]["references"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["match"] == true),
        "{verdict}"
    );
    let verify = r#"{"items":[{"id":"v","operation":{"kind":"verify","profile":"wsse","soap":"soap11","input":"doc"}}],"parts":[{"name":"doc","item_id":"v","role":"document"}]}"#;
    let (status, _, response) = operate(
        &service,
        verify,
        &[Part {
            name: "doc",
            filename: None,
            bytes: signed,
        }],
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let report: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(
        report["results"][0]["result"]["signers"][0]["signature"], "Passed",
        "{report}"
    );
    // Unsupported combinations are refused from metadata alone: no key, no audit.
    let before = begins(&service);
    for (profile, extra) in [
        ("wsse", r#""target":"x","#),
        ("cms", r#""element":"//a","#),
        ("xml_legacy", r#""soap":"soap11","#),
        ("pdf", r#""mode":"add","#),
        ("xml", r#""attached":true,"#),
        ("cms", r#""evidence":[{"kind":"crl","input":"doc"}],"#),
    ] {
        let body = multipart(
            &sign_metadata(profile, extra),
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
                Part {
                    name: "doc",
                    filename: None,
                    bytes: b"x",
                },
            ],
        );
        let (status, _, _) = service.post(FORM, body).await;
        assert_eq!(status, 400, "{profile} {extra}");
    }
    assert_eq!(begins(&service), before);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xades_legacy_b_and_t_are_signed_over_http_and_checked_by_lxml() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(inline_service_config(&pki)).await;
    let dir = tempfile::tempdir().unwrap();
    let xml = br#"<root><data Id="d">xades legacy</data></root>"#;
    for profile in ["xades_legacy_b", "xades_legacy_t"] {
        let extra = r#""element":"//data","signature_method":"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256","digest_method":"http://www.w3.org/2001/04/xmlenc#sha256","#;
        let (_, parts) = sign_inline(&service, &p12, profile, extra, xml).await;
        let done = final_event(&parts);
        assert_eq!(done["status"], "completed", "{profile}: {done}");
        let signed = artifact(&parts, "artifact-0");
        let verdict = xml_oracle(signed, dir.path());
        assert_eq!(verdict["checked"], true, "{profile}: {verdict}");
        for signature in verdict["signatures"].as_array().unwrap() {
            assert_eq!(signature["signature_valid"], true, "{profile}: {verdict}");
            assert!(
                signature["references"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|r| r["match"] == true),
                "{verdict}"
            );
        }
        let text = String::from_utf8_lossy(signed);
        assert!(text.contains("SignedProperties"), "{profile}");
        assert_eq!(
            profile.ends_with('t'),
            text.contains("SignatureTimeStamp"),
            "{profile}"
        );
    }
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn named_key_inspection_reads_public_metadata_for_the_exact_granted_slot_only() {
    let pki = Pki::start();
    let leaf = pki.leaf("user-rsa-sign");
    let alias = leaf.alias.clone();
    let service = Running::start_with(|config, dir| {
        config.pki = pki.config(dir);
        named_key(config, dir, &pki, "ops-key", "user-rsa-sign");
        named_key(config, dir, &pki, "other-key", "user-rsa-sign");
        config.tokens[0].actions = vec![Permission::Inspect];
        config.tokens[0].keys = vec!["ops-key".into()];
    })
    .await;
    let metadata = |name: &str| {
        format!(
            r#"{{"items":[{{"id":"n","operation":{{"kind":"inspect","target":{{"type":"named","name":"{name}"}}}}}}],"parts":[]}}"#
        )
    };
    let (status, _, response) = service
        .post(FORM, multipart(&metadata("ops-key"), &[]))
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    assert_matches_schema("FinalEvent", &serde_json::from_slice(&response).unwrap());
    let done: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(done["results"][0]["result"]["target"], "named_key");
    assert_eq!(
        done["results"][0]["result"]["entries"][0]["alias"],
        alias.as_str()
    );
    assert!(!String::from_utf8_lossy(&response).contains("operator-held-password"));
    for name in ["other-key", "missing-key"] {
        let (status, _, _) = service.post(FORM, multipart(&metadata(name), &[])).await;
        assert_eq!(status, 403, "{name}");
    }
    assert_eq!(begins(&service), 0, "inspection never uses a private key");
    service.stop().await;
}

async fn start_with_cards(
    pki: &Pki,
    probe: Arc<private_support::cards::Probe>,
    keys: &[(&str, &str, &str)],
    tune: impl FnOnce(&mut oncl_server::config::ServerConfig),
) -> Running {
    use oncl_server::{
        auth::TokenSecret,
        config::{ServerConfig, TokenConfig},
        service::{ServiceHost, serve},
    };
    let directory = tempfile::tempdir().unwrap();
    let secret = TokenSecret::generate().unwrap();
    let mut config = ServerConfig {
        enabled: true,
        audit_directory: directory.path().join("audit"),
        scratch_directory: directory.path().join("scratch"),
        metadata_bytes: 67_108_864,
        ..ServerConfig::default()
    };
    config.pki = pki.config(directory.path());
    for (name, reader, alias) in keys {
        token_key(&mut config, directory.path(), name, reader, alias);
    }
    config.tokens.push(TokenConfig {
        id: "test".into(),
        verifier: secret.verifier().encoded(),
        actions: vec![Permission::Sign, Permission::Inspect],
        keys: keys.iter().map(|k| k.0.to_owned()).collect(),
        inline_pkcs12: false,
        metadata_aliases: vec![],
    });
    tune(&mut config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let host = ServiceHost::with_token_backend(config, probe)
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
    Running::from_parts(address, secret.bearer(), task, shutdown, directory, host)
}

fn named_sign(name: &str, doc: &str) -> (String, Vec<u8>) {
    (
        format!(
            r#"{{"items":[{{"id":"t","operation":{{"kind":"sign","profile":"cms","input":"doc","attached":true,"keys":[{{"source":"named","name":"{name}"}}]}}}}],"parts":[{{"name":"doc","item_id":"t","role":"document"}}]}}"#
        ),
        doc.as_bytes().to_vec(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_key_signs_over_http_serializes_per_device_and_fails_closed_without_a_card() {
    let pki = Pki::start();
    let leaf = pki.leaf("user-rsa-sign");
    let alias = leaf.alias.clone();
    let (probe, witness) = private_support::cards::backend(
        &[("reader-a", Some(leaf.clone())), ("empty-reader", None)],
        150,
    );
    let card_gate = probe.private_gate.clone();
    *probe.when.lock().unwrap() = Some(Arc::new(|| true));
    let service = Arc::new(
        start_with_cards(
            &pki,
            probe,
            &[
                ("card-a", "reader-a", &alias),
                ("no-card", "empty-reader", &alias),
                ("no-reader", "missing-reader", &alias),
            ],
            |config| {
                config.max_in_flight = 4;
                config.blocking_workers = 4;
                config.queue_capacity = 4;
                config.admission_wait_ms = 5000;
            },
        )
        .await,
    );
    let dir = tempfile::tempdir().unwrap();
    card_gate.hold();
    // Four concurrent requests on one reader: all sign, never two open card transactions.
    let mut tasks = Vec::new();
    for round in 0..4 {
        let service = service.clone();
        tasks.push(tokio::spawn(async move {
            let (metadata, doc) = named_sign("card-a", &format!("token payload {round}"));
            let (status, ct, response) = service
                .post(
                    FORM,
                    multipart(
                        &metadata,
                        &[Part {
                            name: "doc",
                            filename: None,
                            bytes: &doc,
                        }],
                    ),
                )
                .await;
            assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
            (round, mixed(&ct, response).await)
        }));
    }
    // All four requests are simultaneously admitted (native workers running) while
    // the first card transaction is held: the serialization is the device's, not admission's.
    wait_for("four admitted native workers", || {
        service.host.executor.running() == 4
    })
    .await;
    card_gate.release();
    for task in tasks {
        let (round, parts) = task.await.unwrap();
        assert_eq!(final_event(&parts)["status"], "completed");
        let content = format!("token payload {round}");
        assert_eq!(
            openssl_cms_verify(artifact(&parts, "artifact-0"), None, dir.path()).as_deref(),
            Some(content.as_bytes())
        );
    }
    assert_eq!(
        *witness.max.lock().unwrap().get("reader-a").unwrap(),
        1,
        "card transactions on one device never overlap"
    );
    assert!(
        *witness
            .transactions
            .lock()
            .unwrap()
            .get("reader-a")
            .unwrap()
            >= 4
    );
    assert_eq!(begins(&service), 4);
    // Fail closed: a reader without a card / a missing reader never reaches Begin and is NotApplied.
    for name in ["no-card", "no-reader"] {
        let (metadata, doc) = named_sign(name, "x");
        let (status, ct, response) = service
            .post(
                FORM,
                multipart(
                    &metadata,
                    &[Part {
                        name: "doc",
                        filename: None,
                        bytes: &doc,
                    }],
                ),
            )
            .await;
        // ONE response shape: a typed failed final in a multipart stream.
        assert_eq!(status, 200, "{name}");
        assert!(ct.starts_with("multipart/mixed"), "{name}: {ct}");
        let parts = mixed(&ct, response.clone()).await;
        let done = final_event(&parts);
        assert_eq!(done["status"], "failed", "{name}: {done}");
        assert_eq!(done["error"]["applied"], "NotApplied");
        assert!(parts.iter().all(|(n, _, _)| n != "artifact"));
        assert!(!String::from_utf8_lossy(&response).contains(private_support::cards::PIN));
    }
    assert_eq!(begins(&service), 4, "refused token use never wrote a BEGIN");
    let service = Arc::try_unwrap(service).ok().unwrap();
    // The PIN is never in the audit journal directory.
    let journal = spool_files(&service.directory.path().join("audit"));
    for file in journal {
        // The journal identity lock file is exclusively locked by the live service.
        let Ok(bytes) = std::fs::read(&file) else {
            continue;
        };
        assert!(
            !bytes
                .windows(private_support::cards::PIN.len())
                .any(|w| w == private_support::cards::PIN.as_bytes())
        );
    }
    service.stop().await;
}

const MESSAGE: &[u8] = b"plugin raw signing over HTTP";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plugin_route_uses_operator_grants_the_original_context_and_typed_refusals() {
    use oncl_pdk::abi::{self, Import};
    use oncl_server::config::{PluginConfig, PluginGrant};
    let pki = Pki::start();
    let leaf = pki.leaf("user-rsa-sign");
    let dir = tempfile::tempdir().unwrap();
    let write_plugin = |id: &str, calls: &[(Import, Vec<u8>)]| {
        let manifest = dir.path().join(format!("{id}.toml"));
        let wasm = dir.path().join(format!("{id}.wasm"));
        std::fs::write(&manifest, private_support::plugin::manifest(id)).unwrap();
        std::fs::write(&wasm, private_support::plugin::wasm(calls)).unwrap();
        (manifest, wasm)
    };
    let sign_raw = |handle: u32| {
        (
            Import::KeysSignRaw,
            abi::encode(&abi::SignRawArgs {
                handle,
                data: MESSAGE.to_vec().into(),
            }),
        )
    };
    let hash = (
        Import::Hash,
        abi::encode(&abi::HashArgs {
            alg: abi::HashAlg::Sha256,
            data: b"abc".to_vec().into(),
        }),
    );
    let confirm = (
        Import::DialogConfirm,
        abi::encode(&abi::ConfirmArgs {
            text: "Mandatory consent".into(),
        }),
    );
    type Spec<'a> = (&'a str, Vec<(Import, Vec<u8>)>, Vec<&'a str>, Vec<&'a str>);
    let specs: Vec<Spec<'_>> = vec![
        ("test.hash", vec![hash.clone()], vec!["hash"], vec![]),
        (
            "test.sign",
            vec![sign_raw(1)],
            vec!["keys_sign_raw"],
            vec!["ops-key"],
        ),
        (
            "test.nested",
            vec![hash.clone(), sign_raw(1)],
            vec!["hash"],
            vec!["ops-key"],
        ),
        (
            "test.dialog",
            vec![confirm, sign_raw(1)],
            vec!["dialog_confirm", "keys_sign_raw"],
            vec!["ops-key"],
        ),
        ("test.ungranted", vec![hash.clone()], vec![], vec![]),
    ];
    let mut plugins = Vec::new();
    for (id, calls, imports, keys) in &specs {
        let (manifest, wasm) = write_plugin(id, calls);
        let permissions = if *id == "test.ungranted" {
            vec![]
        } else {
            vec![PluginGrant {
                token: "test".into(),
                operation: "run".into(),
                imports: imports.iter().map(|s| s.to_string()).collect(),
                keys: keys.iter().map(|s| s.to_string()).collect(),
                pki_endpoints: vec![
                    format!("{}/ocsp", pki.origin),
                    format!("{}/root.crl", pki.origin),
                    format!("{}/inter.crl", pki.origin),
                ],
            }]
        };
        plugins.push(PluginConfig {
            id: id.to_string(),
            manifest,
            wasm,
            max_memory: 1 << 20,
            max_transfer: 1 << 18,
            permissions,
        });
    }
    let service = Running::start_with(|config, dir| {
        config.pki = pki.config(dir);
        named_key(config, dir, &pki, "ops-key", "user-rsa-sign");
        config.tokens[0].actions = vec![Permission::Sign];
        config.tokens[0].keys = vec!["ops-key".into()];
        config.plugins = plugins;
    })
    .await;
    let call = |plugin: &str, keys: &str, args: &str| {
        format!(
            r#"{{"items":[{{"id":"p","operation":{{"kind":"plugin","plugin":"{plugin}","operation":"run","args":{args},"keys":[{keys}]}}}}],"parts":[]}}"#
        )
    };
    let key1 = r#"{"handle":1,"name":"ops-key"}"#;
    // Granted hash plugin: independent digest check.
    let (status, _, response) = service
        .post(FORM, multipart(&call("test.hash", "", "\"{}\""), &[]))
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    assert_matches_schema("FinalEvent", &serde_json::from_slice(&response).unwrap());
    let done: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(done["results"][0]["result"]["kind"], "plugin");
    assert_eq!(done["results"][0]["result"]["applied"], "NotApplied");
    let digest = private_support::plugin::reply_bytes(
        done["results"][0]["result"]["response"].as_str().unwrap(),
    );
    assert_eq!(digest, hex(&sha256(b"abc")));
    // Granted key plugin signs through the original context + durable audit.
    let (status, _, response) = service
        .post(FORM, multipart(&call("test.sign", key1, "\"{}\""), &[]))
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let done: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["results"][0]["applied"], "Applied");
    let signature = private_support::plugin::reply_bytes(
        done["results"][0]["result"]["response"].as_str().unwrap(),
    );
    let tmp = tempfile::tempdir().unwrap();
    let pem = run_openssl(
        &["x509", "-inform", "DER", "-pubkey", "-noout", "-in"],
        &{
            use der::Encode;
            leaf.cert.to_der().unwrap()
        },
        tmp.path(),
    );
    std::fs::write(tmp.path().join("k.pub"), pem).unwrap();
    std::fs::write(tmp.path().join("s.sig"), &signature).unwrap();
    std::fs::write(tmp.path().join("m.bin"), MESSAGE).unwrap();
    let verified = std::process::Command::new("openssl")
        .args(["dgst", "-sha256", "-verify"])
        .arg(tmp.path().join("k.pub"))
        .arg("-signature")
        .arg(tmp.path().join("s.sig"))
        .arg(tmp.path().join("m.bin"))
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "OpenSSL verifies the plugin-produced RSA signature"
    );
    assert_eq!(begins(&service), 1);
    // Payload Origin/caller fields are inert data: authority comes from the token grant.
    let (status, _, _) = service
        .post(
            FORM,
            multipart(
                &call(
                    "test.hash",
                    "",
                    r#""{\"origin\":\"https://trusted.example\"}""#,
                ),
                &[],
            ),
        )
        .await;
    assert_eq!(status, 200);
    // Installed but not granted: 403 before anything runs.
    let (status, _, _) = service
        .post(FORM, multipart(&call("test.ungranted", "", "\"{}\""), &[]))
        .await;
    assert_eq!(status, 403);
    // A key not in the plugin grant is refused before the key opens.
    let (status, _, _) = service
        .post(FORM, multipart(&call("test.hash", key1, "\"{}\""), &[]))
        .await;
    assert_eq!(status, 403);
    // Forbidden nested import: sign import is not granted to test.nested.
    let (status, _, response) = service
        .post(FORM, multipart(&call("test.nested", key1, "\"{}\""), &[]))
        .await;
    assert_eq!(status, 403, "{}", String::from_utf8_lossy(&response));
    let error: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(error["code"], "PermissionDenied");
    assert_eq!(error["applied"], "NotApplied");
    assert_eq!(
        begins(&service),
        1,
        "no nested private use after the denied import"
    );
    // Mandatory dialog: typed InteractionRequired (headless never auto-answers), key never applied.
    let (status, _, response) = service
        .post(FORM, multipart(&call("test.dialog", key1, "\"{}\""), &[]))
        .await;
    assert_eq!(status, 403, "{}", String::from_utf8_lossy(&response));
    let error: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(error["code"], "InteractionRequired");
    assert_eq!(error["applied"], "NotApplied");
    assert_eq!(begins(&service), 1);
    service.stop().await;
}
fn sha256(bytes: &[u8]) -> Vec<u8> {
    let out = std::process::Command::new("openssl")
        .args(["dgst", "-sha256", "-binary"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    let mut child = out;
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    child.wait_with_output().unwrap().stdout
}
fn hex(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xades_timestamp_levels_need_a_host_tsa_policy_refused_before_the_key_opens() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let dir = tempfile::tempdir().unwrap();
    let xml = br#"<root><item Id="p">t</item><holder Id="s"></holder></root>"#;
    let shape = r#""target":"p","parent":"s","signature_id":"sig1","#;
    // With the policy OID the host TSA is acceptable to XAdES T.
    let service = Running::start_with(inline_service_config(&pki)).await;
    let (_, parts) = sign_inline(&service, &p12, "xades_t", shape, xml).await;
    assert_eq!(final_event(&parts)["status"], "completed");
    let verdict = xml_oracle(artifact(&parts, "artifact-0"), dir.path());
    assert_eq!(
        verdict["signatures"][0]["signature_valid"], true,
        "{verdict}"
    );
    service.stop().await;
    // Without it (the SDK binds the TSA policy for XAdES T/LT/LTA): typed
    // MissingConfiguration, NotApplied, and no BEGIN.
    let service = Running::start_with(|config, dir| {
        inline_service_config(&pki)(config, dir);
        config.pki.tsa.as_mut().unwrap().policy = None;
    })
    .await;
    for profile in ["xades_t", "xades_legacy_t"] {
        let extra = if profile == "xades_t" {
            shape
        } else {
            r#""element":"//item","signature_method":"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256","digest_method":"http://www.w3.org/2001/04/xmlenc#sha256","#
        };
        // A configuration refusal is decided from metadata + host config alone: a real
        // HTTP 503 before any secret/document byte is reserved (not a late failed final).
        let body = multipart(
            &sign_metadata(profile, extra),
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
                Part {
                    name: "doc",
                    filename: None,
                    bytes: xml,
                },
            ],
        );
        let (status, ct, response) = service.post(FORM, body).await;
        assert_eq!(
            status,
            503,
            "{profile}: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(ct.starts_with("application/json"), "{profile}: {ct}");
        let error: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(
            (error["code"].as_str(), error["applied"].as_str()),
            (Some("MissingConfiguration"), Some("NotApplied"))
        );
    }
    assert_eq!(begins(&service), 0);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lt_levels_need_status_material_and_the_pades_memory_profile_before_any_key_use() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let inter = {
        use der::Encode;
        pki.inter.cert.to_der().unwrap()
    };
    let pdf = include_bytes!("../../oncl-pdf/tests/fixtures/external-multipage.pdf");
    let service = Running::start_with(|config, dir| {
        inline_service_config(&pki)(config, dir);
        config.memory_per_operation = 256 << 20; // below the PAdES LT/LTA profile
        config.total_memory = 2 << 30;
    })
    .await;
    let sign = |profile: &str, evidence: bool| {
        let (ev, parts) = if evidence {
            (
                r#""evidence":[{"kind":"certificate","input":"ev0"},{"kind":"crl","input":"ev1"},{"kind":"crl","input":"ev2"}],"#,
                r#",{"name":"ev0","item_id":"s1","role":"document"},{"name":"ev1","item_id":"s1","role":"document"},{"name":"ev2","item_id":"s1","role":"document"}"#,
            )
        } else {
            ("", "")
        };
        format!(
            r#"{{"items":[{{"id":"s1","operation":{{"kind":"sign","profile":"{profile}","input":"doc",{ev}"keys":[{{"source":"inline","container":"p12","password":"pw"}}]}}}}],"parts":[{{"name":"p12","item_id":"s1","role":"secret"}},{{"name":"pw","item_id":"s1","role":"secret"}},{{"name":"doc","item_id":"s1","role":"document"}}{parts}]}}"#
        )
    };
    let request = |profile: &str, evidence: bool, doc: &[u8]| {
        let mut parts = vec![
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
            Part {
                name: "doc",
                filename: None,
                bytes: doc,
            },
        ];
        if evidence {
            parts.push(Part {
                name: "ev0",
                filename: None,
                bytes: &inter,
            });
            parts.push(Part {
                name: "ev1",
                filename: None,
                bytes: &pki.crls[0],
            });
            parts.push(Part {
                name: "ev2",
                filename: None,
                bytes: &pki.crls[1],
            });
        }
        multipart(&sign(profile, evidence), &parts)
    };
    // Missing material: 400 before any secret/key/document, never "Applied then failed".
    for profile in ["cades_lt", "cades_lta", "pades_lt", "pades_lta"] {
        let (status, _, response) = service.post(FORM, request(profile, false, pdf)).await;
        assert_eq!(
            status,
            400,
            "{profile}: {}",
            String::from_utf8_lossy(&response)
        );
    }
    // xades_lt/lta signing is not offered at all (the SDK XML sign facade takes no material).
    let (status, _, _) = service.post(FORM, request("xades_lt", true, b"<a/>")).await;
    assert_eq!(status, 400);
    // PAdES LT/LTA below the memory profile: typed 413 MemoryLimit, NotApplied, no BEGIN.
    let (status, _, response) = service.post(FORM, request("pades_lt", true, pdf)).await;
    assert_eq!(status, 413, "{}", String::from_utf8_lossy(&response));
    let error: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(
        (error["code"].as_str(), error["applied"].as_str()),
        (Some("MemoryLimit"), Some("NotApplied"))
    );
    assert_eq!(begins(&service), 0);
    // CAdES LT with material succeeds and verifies in OpenSSL.
    let (status, ct, response) = service
        .post(FORM, request("cades_lt", true, b"lt payload"))
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let parts = mixed(&ct, response).await;
    assert_eq!(final_event(&parts)["status"], "completed");
    let dir = tempfile::tempdir().unwrap();
    assert!(
        openssl_cms_verify(
            artifact(&parts, "artifact-0"),
            Some(b"lt payload"),
            dir.path()
        )
        .is_some()
    );
    assert_eq!(begins(&service), 1);
    // Extend LT without material is refused up front as well.
    let extend = r#"{"items":[{"id":"e","operation":{"kind":"extend","profile":"cades_lt","input":"sig"}}],"parts":[{"name":"sig","item_id":"e","role":"document"}]}"#;
    let (status, _, _) = service
        .post(
            FORM,
            multipart(
                extend,
                &[Part {
                    name: "sig",
                    filename: None,
                    bytes: b"x",
                }],
            ),
        )
        .await;
    assert_eq!(status, 400);
    service.stop().await;
}

/// Send `body` in two halves with `middle` executed between them (body held open).
async fn split_request(service: &Running, body: &[u8], middle: impl FnOnce()) -> (u16, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(service.address)
        .await
        .unwrap();
    let head = format!(
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {FORM}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        service.address,
        service.token.as_str(),
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let cut = body.len() - 40;
    stream.write_all(&body[..cut]).await.unwrap();
    stream.flush().await.unwrap();
    // The authorized native worker is provably inside intake, blocked on the unsent tail.
    wait_for("worker blocked on the unsent body", || {
        service.host.executor.running() == 1
    })
    .await;
    middle();
    stream.write_all(&body[cut..]).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut response),
    )
    .await;
    let text = String::from_utf8_lossy(&response).into_owned();
    let status: u16 = text[9..12].parse().unwrap();
    let end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    (status, response[end..].to_vec())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authority_revoked_during_the_upload_never_runs_the_key_or_the_plugin() {
    use oncl_pdk::abi::{self, Import};
    use oncl_server::config::{PluginConfig, PluginGrant};
    let pki = Pki::start();
    let dir = tempfile::tempdir().unwrap();
    let (manifest, wasm) = (dir.path().join("p.toml"), dir.path().join("p.wasm"));
    std::fs::write(&manifest, private_support::plugin::manifest("test.sign")).unwrap();
    std::fs::write(
        &wasm,
        private_support::plugin::wasm(&[(
            Import::KeysSignRaw,
            abi::encode(&abi::SignRawArgs {
                handle: 1,
                data: b"m".to_vec().into(),
            }),
        )]),
    )
    .unwrap();
    let plugin = PluginConfig {
        id: "test.sign".into(),
        manifest,
        wasm,
        max_memory: 1 << 20,
        max_transfer: 1 << 18,
        permissions: vec![PluginGrant {
            token: "test".into(),
            operation: "run".into(),
            imports: vec!["keys_sign_raw".into()],
            keys: vec!["ops-key".into()],
            pki_endpoints: vec![
                format!("{}/ocsp", pki.origin),
                format!("{}/root.crl", pki.origin),
                format!("{}/inter.crl", pki.origin),
            ],
        }],
    };
    for case in ["named_sign_streaming", "keyed_plugin_then_slow_document"] {
        let plugin = plugin.clone();
        let service = Running::start_with(|config, dir| {
            config.pki = pki.config(dir);
            named_key(config, dir, &pki, "ops-key", "user-rsa-sign");
            config.tokens[0].actions = vec![Permission::Sign, Permission::Hash];
            config.tokens[0].keys = vec!["ops-key".into()];
            config.plugins = vec![plugin];
        })
        .await;
        let (metadata, document) = if case == "named_sign_streaming" {
            (r#"{"items":[{"id":"s","operation":{"kind":"sign","profile":"cms","input":"doc","keys":[{"source":"named","name":"ops-key"}]}}],"parts":[{"name":"doc","item_id":"s","role":"document"}]}"#.to_string(),
             vec![b'd'; 50_000])
        } else {
            (r#"{"items":[{"id":"p","operation":{"kind":"plugin","plugin":"test.sign","operation":"run","args":"{}","keys":[{"handle":1,"name":"ops-key"}]}},{"id":"h","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"h","role":"document"}]}"#.to_string(),
             vec![b'd'; 50_000])
        };
        let body = multipart(
            &metadata,
            &[Part {
                name: "doc",
                filename: None,
                bytes: &document,
            }],
        );
        let host = service.host.clone();
        let (status, response) =
            split_request(&service, &body, || host.policy.revoke("test").unwrap()).await;
        assert_eq!(
            status,
            403,
            "{case}: {}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(begins(&service), 0, "{case}: no BEGIN after revocation");
        service.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_streaming_multi_item_failure_after_an_applied_plugin_item_keeps_its_applied_state() {
    use oncl_pdk::abi::{self, Import};
    use oncl_server::config::{PluginConfig, PluginGrant};
    let pki = Pki::start();
    let dir = tempfile::tempdir().unwrap();
    let (manifest, wasm) = (dir.path().join("p.toml"), dir.path().join("p.wasm"));
    std::fs::write(&manifest, private_support::plugin::manifest("test.sign")).unwrap();
    std::fs::write(
        &wasm,
        private_support::plugin::wasm(&[(
            Import::KeysSignRaw,
            abi::encode(&abi::SignRawArgs {
                handle: 1,
                data: b"m".to_vec().into(),
            }),
        )]),
    )
    .unwrap();
    let plugin = PluginConfig {
        id: "test.sign".into(),
        manifest,
        wasm,
        max_memory: 1 << 20,
        max_transfer: 1 << 18,
        permissions: vec![PluginGrant {
            token: "test".into(),
            operation: "run".into(),
            imports: vec!["keys_sign_raw".into()],
            keys: vec!["ops-key".into()],
            pki_endpoints: vec![
                format!("{}/ocsp", pki.origin),
                format!("{}/root.crl", pki.origin),
                format!("{}/inter.crl", pki.origin),
            ],
        }],
    };
    let service = Running::start_with(|config, dir| {
        config.pki = pki.config(dir);
        named_key(config, dir, &pki, "ops-key", "user-rsa-sign");
        config.tokens[0].actions = vec![Permission::Sign, Permission::Inspect];
        config.tokens[0].keys = vec!["ops-key".into()];
        config.plugins = vec![plugin];
    })
    .await;
    let metadata = r#"{"items":[{"id":"p","operation":{"kind":"plugin","plugin":"test.sign","operation":"run","args":"{}","keys":[{"handle":1,"name":"ops-key"}]}},{"id":"bad","operation":{"kind":"inspect","target":{"type":"certificate","input":"c"}}}],"parts":[{"name":"c","item_id":"bad","role":"document"}]}"#;
    let (status, _, response) = service
        .post(
            FORM,
            multipart(
                metadata,
                &[Part {
                    name: "c",
                    filename: None,
                    bytes: b"not a certificate",
                }],
            ),
        )
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let done: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_matches_schema("FinalEvent", &done);
    assert_eq!(done["status"], "failed", "{done}");
    assert_eq!(done["results"][0]["item_id"], "p");
    assert_eq!(
        done["results"][0]["applied"], "Applied",
        "earlier item's key use must survive: {done}"
    );
    assert_eq!(begins(&service), 1);
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_final_audit_write_after_card_use_is_applied_withholds_the_artifact_and_blocks_further_use()
 {
    let pki = Pki::start();
    let leaf = pki.leaf("user-rsa-sign");
    let alias = leaf.alias.clone();
    let (probe, _) = private_support::cards::backend(&[("reader-a", Some(leaf))], 0);
    let gate = probe.private_gate.clone();
    let when = probe.when.clone();
    let service =
        Arc::new(start_with_cards(&pki, probe, &[("card-a", "reader-a", &alias)], |_| {}).await);
    {
        let host = service.host.clone();
        *when.lock().unwrap() = Some(Arc::new(move || {
            host.audit
                .records()
                .map(|r| r.iter().any(|e| e.kind == RecordKind::Begin))
                .unwrap_or(false)
        }));
    }
    gate.hold();
    let task = {
        let service = service.clone();
        tokio::spawn(async move {
            let (metadata, doc) = named_sign("card-a", "final write fails");
            service
                .post(
                    FORM,
                    multipart(
                        &metadata,
                        &[Part {
                            name: "doc",
                            filename: None,
                            bytes: &doc,
                        }],
                    ),
                )
                .await
        })
    };
    // BEGIN is durable and the card is inside the private operation.
    wait_for("card inside the private operation", || gate.entered() == 1).await;
    assert_eq!(begins(&service), 1);
    service
        .host
        .audit
        .inject_fault(oncl_server::audit::FaultPoint::BeforeWrite);
    gate.release();
    let (status, ct, response) = task.await.unwrap();
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let parts = mixed(&ct, response).await;
    let done = final_event(&parts);
    assert_eq!(done["status"], "failed", "{done}");
    assert_ne!(
        done["error"]["applied"], "NotApplied",
        "the card signed: {done}"
    );
    assert!(
        parts.iter().all(|(n, _, _)| n != "artifact"),
        "artifact withheld"
    );
    // Health policy: a failed FINAL poisons the journal; no further private use.
    assert_ne!(
        service.host.audit.health(),
        oncl_server::audit::AuditHealth::Healthy
    );
    let (metadata, doc) = named_sign("card-a", "second");
    let (status, _, response) = service
        .post(
            FORM,
            multipart(
                &metadata,
                &[Part {
                    name: "doc",
                    filename: None,
                    bytes: &doc,
                }],
            ),
        )
        .await;
    assert_eq!(status, 503, "{}", String::from_utf8_lossy(&response));
    let service = Arc::try_unwrap(service).ok().unwrap();
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deadline_after_card_use_keeps_a_durable_applied_final_and_no_artifact() {
    let pki = Pki::start();
    let leaf = pki.leaf("user-rsa-sign");
    let alias = leaf.alias.clone();
    let (probe, _) = private_support::cards::backend(&[("reader-a", Some(leaf))], 0);
    let gate = probe.private_gate.clone();
    let when = probe.when.clone();
    probe
        .at_end
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let service = Arc::new(
        start_with_cards(&pki, probe, &[("card-a", "reader-a", &alias)], |config| {
            config.operation_timeout_ms = 3000;
            config.admission_wait_ms = 1000;
            config.header_timeout_ms = 1000;
        })
        .await,
    );
    {
        let host = service.host.clone();
        *when.lock().unwrap() = Some(Arc::new(move || {
            host.audit
                .records()
                .map(|r| r.iter().any(|e| e.kind == RecordKind::Begin))
                .unwrap_or(false)
        }));
    }
    gate.hold();
    let task = {
        let service = service.clone();
        tokio::spawn(async move {
            let (metadata, doc) = named_sign("card-a", "deadline after use");
            service
                .post(
                    FORM,
                    multipart(
                        &metadata,
                        &[Part {
                            name: "doc",
                            filename: None,
                            bytes: &doc,
                        }],
                    ),
                )
                .await
        })
    };
    wait_for("card inside the private operation", || gate.entered() == 1).await;
    // The original deadline (the semantics under test) expires while the card is busy.
    tokio::time::sleep(std::time::Duration::from_millis(3200)).await;
    gate.release();
    let (_, _, response) = task.await.unwrap();
    assert!(!String::from_utf8_lossy(&response).contains("\"status\":\"completed\""));
    wait_for("durable FINAL", || {
        service
            .host
            .audit
            .records()
            .unwrap()
            .iter()
            .any(|r| r.kind == RecordKind::Final)
    })
    .await;
    let records = service.host.audit.records().unwrap();
    let last = records
        .iter()
        .rev()
        .find(|r| r.kind == RecordKind::Final)
        .unwrap();
    assert_ne!(
        format!("{:?}", last.applied),
        "NotApplied",
        "card was used: never reported NotApplied"
    );
    wait_for("worker returned", || service.host.executor.running() == 0).await;
    assert!(
        spool_files(&service.scratch()).is_empty(),
        "no artifact survives"
    );
    assert_eq!(
        service.host.audit.health(),
        oncl_server::audit::AuditHealth::Healthy
    );
    let service = Arc::try_unwrap(service).ok().unwrap();
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_queued_behind_max_in_flight_expires_before_native_work_without_begin() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Arc::new(
        Running::start_with(running_with_tsa(&pki, |config| {
            config.max_in_flight = 2;
            config.blocking_workers = 1;
            config.queue_capacity = 1;
            // Admission wait ends well inside the first request's own deadline, so the
            // queued request is refused by capacity, not by a race with the holder.
            config.admission_wait_ms = 800;
            config.operation_timeout_ms = 8000;
            config.header_timeout_ms = 1000;
        }))
        .await,
    );
    pki.tsa_gate.hold();
    let post = |profile: &'static str, doc: &'static str| {
        let (service, p12) = (service.clone(), p12.clone());
        tokio::spawn(async move {
            let body = multipart(
                &sign_metadata(profile, ""),
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
                    Part {
                        name: "doc",
                        filename: None,
                        bytes: doc.as_bytes(),
                    },
                ],
            );
            service.post(FORM, body).await
        })
    };
    let first = post("cades_t", "holds the only native worker");
    wait_for("worker held inside the TSA", || pki.tsa_gate.entered() == 1).await;
    let queued = post("cms", "queued behind it");
    wait_for("second request queued", || {
        service.host.executor.queued() == 1
    })
    .await;
    // It waits in the queue and is refused by the admission wait, never reaching the key.
    let (status, _, response) = queued.await.unwrap();
    assert_eq!(status, 503, "{}", String::from_utf8_lossy(&response));
    let error: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(error["code"], "CapacityExceeded");
    assert_eq!(error["applied"], "NotApplied");
    assert_eq!(
        begins(&service),
        1,
        "only the running request wrote a BEGIN"
    );
    pki.tsa_gate.release();
    let _ = first.await.unwrap();
    assert_eq!(
        begins(&service),
        1,
        "the expired queued request never reached the key"
    );
    let service = Arc::try_unwrap(service).ok().unwrap();
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_missing_right_is_refused_before_intake_with_nothing_held() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    // Global inline switch OFF although the token has the inline right.
    let service = Running::start_with(|config, dir| {
        config.inline_pkcs12 = false;
        config.tokens[0].inline_pkcs12 = true;
        config.pki = pki.config(dir);
        named_key(config, dir, &pki, "ops-key", "user-rsa-sign");
        config.tokens[0].actions = vec![Permission::Sign];
        config.tokens[0].keys = vec![]; // no right to the named key either
    })
    .await;
    type Case<'a> = (&'a str, String, Vec<(&'a str, Vec<u8>)>);
    let cases: Vec<Case<'_>> = vec![
        ("global inline switch off", sign_metadata("cms", ""), vec![("p12", p12.clone()), ("pw", PASSWORD.as_bytes().to_vec()), ("doc", b"x".to_vec())]),
        ("named key without right", r#"{"items":[{"id":"n","operation":{"kind":"sign","profile":"cms","input":"doc","keys":[{"source":"named","name":"ops-key"}]}}],"parts":[{"name":"doc","item_id":"n","role":"document"}]}"#.into(), vec![("doc", b"x".to_vec())]),
        ("inspect named without right", r#"{"items":[{"id":"n","operation":{"kind":"inspect","target":{"type":"named","name":"ops-key"}}}],"parts":[]}"#.into(), vec![]),
        ("inspect container without action", r#"{"items":[{"id":"c","operation":{"kind":"inspect","target":{"type":"container","container":"p12","password":"pw"}}}],"parts":[{"name":"p12","item_id":"c","role":"secret"},{"name":"pw","item_id":"c","role":"secret"}]}"#.into(), vec![("p12", p12.clone()), ("pw", PASSWORD.as_bytes().to_vec())]),
    ];
    for (name, metadata, parts) in cases {
        let parts: Vec<Part<'_>> = parts
            .iter()
            .map(|(n, b)| Part {
                name: n,
                filename: None,
                bytes: b,
            })
            .collect();
        let (status, _, response) = service.post(FORM, multipart(&metadata, &parts)).await;
        assert_eq!(
            status,
            403,
            "{name}: {}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(begins(&service), 0, "{name}");
        assert!(spool_files(&service.scratch()).is_empty(), "{name}");
        // Nothing stays reserved by the refused request.
        assert!(
            service
                .host
                .engine
                .admit(Arc::new(oncl_server::executor::Cancellation::new()))
                .is_ok(),
            "{name}"
        );
    }
    service.stop().await;
}

/// Sweep the per-operation memory profile for one PAdES request: every profile is
/// either refused BEFORE any key use (413, NotApplied, no BEGIN) or the request does not
/// fail for memory. A request that writes a BEGIN and then fails with MemoryLimit would
/// be an under-refusal. Returns `(mib, completed)` per profile.
async fn memory_sweep(
    pki: &Pki,
    p12: &[u8],
    pdf: &[u8],
    evidence: &[Vec<u8>],
    steps: impl Iterator<Item = u64>,
    tune: &dyn Fn(&mut oncl_server::config::ServerConfig, u64),
) -> Vec<(u64, bool)> {
    let refs: String = (0..evidence.len())
        .map(|n| {
            let kind = if n == 0 { "certificate" } else { "crl" };
            format!(r#"{{"kind":"{kind}","input":"ev{n}"}}"#)
        })
        .collect::<Vec<_>>()
        .join(",");
    let ev_parts: String = (0..evidence.len())
        .map(|n| format!(r#",{{"name":"ev{n}","item_id":"s1","role":"document"}}"#))
        .collect();
    let metadata = format!(
        r#"{{"items":[{{"id":"s1","operation":{{"kind":"sign","profile":"pades_lta","input":"doc","evidence":[{refs}],"keys":[{{"source":"inline","container":"p12","password":"pw"}}]}}}}],"parts":[{{"name":"p12","item_id":"s1","role":"secret"}},{{"name":"pw","item_id":"s1","role":"secret"}},{{"name":"doc","item_id":"s1","role":"document"}}{ev_parts}]}}"#
    );
    let mut outcomes = Vec::new();
    for mib in steps {
        let service = Running::start_with(|config, dir| {
            inline_service_config(pki)(config, dir);
            tune(config, mib);
        })
        .await;
        let mut parts = vec![
            Part {
                name: "p12",
                filename: None,
                bytes: p12,
            },
            Part {
                name: "pw",
                filename: None,
                bytes: PASSWORD.as_bytes(),
            },
            Part {
                name: "doc",
                filename: None,
                bytes: pdf,
            },
        ];
        let names: Vec<String> = (0..evidence.len()).map(|n| format!("ev{n}")).collect();
        for (n, bytes) in evidence.iter().enumerate() {
            parts.push(Part {
                name: &names[n],
                filename: None,
                bytes,
            });
        }
        let (status, _, response) = service.post(FORM, multipart(&metadata, &parts)).await;
        let text = String::from_utf8_lossy(&response).into_owned();
        let completed = text.contains("\"status\":\"completed\"");
        let refused = status == 413;
        if refused {
            assert_eq!(
                begins(&service),
                0,
                "{mib} MiB: refused requests never write BEGIN"
            );
        } else {
            assert!(
                !((text.contains("MemoryLimit") || text.contains("MetadataLimit"))
                    && begins(&service) > 0)
                    && !(begins(&service) > 0 && response.is_empty()),
                "{mib} MiB: BEGIN then a resource failure (under-refusal): status {status} {}",
                text.lines()
                    .find(|l| l.contains("\"type\":\"final\""))
                    .unwrap_or("")
            );
        }
        if !completed && !refused {
            let tail = text
                .lines()
                .find(|l| l.contains("\"type\":\"final\""))
                .unwrap_or("");
            eprintln!("SWEEP {mib} MiB not completed: status {status} ...{tail}");
        }
        outcomes.push((mib, completed));
        service.stop().await;
    }
    outcomes
}
/// Coarse sweep, then a 1 MiB sweep over the whole band below the first completion:
/// under-refusal can only live between the preflight threshold and the real one.
async fn fine_sweep(
    pki: &Pki,
    p12: &[u8],
    pdf: &[u8],
    evidence: &[Vec<u8>],
    coarse: std::ops::RangeInclusive<u64>,
    step: u64,
    tune: &dyn Fn(&mut oncl_server::config::ServerConfig, u64),
) -> Vec<(u64, bool)> {
    let mut outcomes = memory_sweep(
        pki,
        p12,
        pdf,
        evidence,
        coarse.clone().step_by(step as usize),
        tune,
    )
    .await;
    let first = outcomes
        .iter()
        .find(|(_, c)| *c)
        .expect("a sufficient profile completes")
        .0;
    let lower = first.saturating_sub(step).max(*coarse.start());
    let fine = memory_sweep(pki, p12, pdf, evidence, lower..=first, tune).await;
    outcomes.extend(fine);
    outcomes.sort_by_key(|(mib, _)| *mib);
    outcomes.dedup_by_key(|(mib, _)| *mib);
    outcomes
}
fn assert_monotonic(outcomes: &[(u64, bool)]) {
    if let Some(first) = outcomes.iter().position(|(_, c)| *c) {
        let flips: Vec<_> = outcomes[first..].iter().filter(|(_, c)| !*c).collect();
        assert!(
            flips.is_empty(),
            "first complete at {:?}, later non-complete: {flips:?}",
            outcomes[first]
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pades_preflight_never_under_refuses_across_memory_profiles() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let inter = {
        use der::Encode;
        pki.inter.cert.to_der().unwrap()
    };
    let pdf = include_bytes!("../../oncl-pdf/tests/fixtures/external-multipage.pdf");
    let evidence = vec![inter, pki.crls[0].clone(), pki.crls[1].clone()];
    // Fine sweep (1 MiB) across the whole transition band.
    let outcomes = memory_sweep(&pki, &p12, pdf, &evidence, 320u64..=400, &|config, mib| {
        config.memory_per_operation = mib << 20;
        config.total_memory = 2 << 30;
    })
    .await;
    assert!(
        outcomes.iter().any(|(_, c)| *c) && outcomes.iter().any(|(_, c)| !*c),
        "{outcomes:?}"
    );
    assert_monotonic(&outcomes);
    // The METADATA budget is a predictable need too: fine sweep of metadata_bytes.
    let meta = memory_sweep(&pki, &p12, pdf, &evidence, 40u64..=75, &|config, mib| {
        config.metadata_bytes = mib << 20;
        config.memory_per_operation = 1 << 30;
        config.total_memory = 2 << 30;
    })
    .await;
    assert!(
        meta.iter().any(|(_, c)| *c) && meta.iter().any(|(_, c)| !*c),
        "{meta:?}"
    );
    assert_monotonic(&meta);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pades_preflight_accounts_for_prior_signatures_and_large_evidence() {
    let pki = Pki::start_with_revoked(20_000);
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let inter = {
        use der::Encode;
        pki.inter.cert.to_der().unwrap()
    };
    let pdf = include_bytes!("../../oncl-pdf/tests/fixtures/external-multipage.pdf");
    // Several MiB of valid evidence: the (large) CRLs repeated.
    let mut evidence = vec![inter];
    evidence.push(pki.crls[0].clone());
    for _ in 0..8 {
        evidence.push(pki.crls[1].clone());
    }
    let total: usize = evidence.iter().map(Vec::len).sum();
    assert!(total > 3 << 20, "evidence is several MiB ({total})");
    // Memory profile with ample metadata budget.
    let outcomes = fine_sweep(
        &pki,
        &p12,
        pdf,
        &evidence,
        400u64..=640,
        8,
        &|config, mib| {
            config.memory_per_operation = mib << 20;
            config.total_memory = 2 << 30;
            config.metadata_bytes = 256 << 20;
        },
    )
    .await;
    assert!(
        outcomes.iter().any(|(_, c)| *c) && outcomes.iter().any(|(_, c)| !*c),
        "{outcomes:?}"
    );
    assert_monotonic(&outcomes);
    // Metadata budget with the large evidence (the default 64 MiB is refused up front).
    let meta = memory_sweep(&pki, &p12, pdf, &evidence, 60u64..=90, &|config, mib| {
        config.metadata_bytes = mib << 20;
        config.memory_per_operation = 1 << 30;
        config.total_memory = 2 << 30;
    })
    .await;
    assert!(
        meta.iter().any(|(_, c)| *c) && meta.iter().any(|(_, c)| !*c),
        "{meta:?}"
    );
    assert_monotonic(&meta);
    // A document that already carries a signature (the real pades_b output of the SAME
    // PKI): the prior-contents accounting is exercised and LTA onto it must complete
    // (the new signature and the old signer both reach LTA).
    let plain = Pki::start();
    let plain_p12 = container(&plain.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(inline_service_config(&plain)).await;
    let (_, parts) = sign_inline(&service, &plain_p12, "pades_b", "", pdf).await;
    let signed = artifact(&parts, "artifact-0").to_vec();
    service.stop().await;
    let small = vec![
        {
            use der::Encode;
            plain.inter.cert.to_der().unwrap()
        },
        plain.crls[0].clone(),
        plain.crls[1].clone(),
    ];
    let outcomes = fine_sweep(
        &plain,
        &plain_p12,
        &signed,
        &small,
        380u64..=460,
        8,
        &|config, mib| {
            config.memory_per_operation = mib << 20;
            config.total_memory = 2 << 30;
            config.metadata_bytes = 256 << 20;
        },
    )
    .await;
    assert!(
        outcomes.iter().any(|(_, c)| *c) && outcomes.iter().any(|(_, c)| !*c),
        "{outcomes:?}"
    );
    assert_monotonic(&outcomes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreadable_pdf_for_a_pades_high_level_is_refused_before_any_key_use() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let inter = {
        use der::Encode;
        pki.inter.cert.to_der().unwrap()
    };
    let service = Running::start_with(|config, dir| {
        inline_service_config(&pki)(config, dir);
        config.memory_per_operation = 1 << 30;
        config.total_memory = 2 << 30;
        config.metadata_bytes = 256 << 20;
    })
    .await;
    for (name, bytes) in [
        ("not a pdf", b"this is not a pdf".to_vec()),
        (
            "truncated",
            include_bytes!("../../oncl-pdf/tests/fixtures/external-multipage.pdf")[..400].to_vec(),
        ),
    ] {
        let metadata = r#"{"items":[{"id":"s1","operation":{"kind":"sign","profile":"pades_lt","input":"doc","evidence":[{"kind":"certificate","input":"ev0"},{"kind":"crl","input":"ev1"}],"keys":[{"source":"inline","container":"p12","password":"pw"}]}}],"parts":[{"name":"p12","item_id":"s1","role":"secret"},{"name":"pw","item_id":"s1","role":"secret"},{"name":"doc","item_id":"s1","role":"document"},{"name":"ev0","item_id":"s1","role":"document"},{"name":"ev1","item_id":"s1","role":"document"}]}"#;
        let parts = [
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
            Part {
                name: "doc",
                filename: None,
                bytes: &bytes,
            },
            Part {
                name: "ev0",
                filename: None,
                bytes: &inter,
            },
            Part {
                name: "ev1",
                filename: None,
                bytes: &pki.crls[0],
            },
        ];
        let (status, _, response) = service.post(FORM, multipart(metadata, &parts)).await;
        assert_eq!(
            status,
            400,
            "{name}: {}",
            String::from_utf8_lossy(&response)
        );
        let error: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(
            (error["code"].as_str(), error["applied"].as_str()),
            (Some("InvalidRequest"), Some("NotApplied")),
            "{name}"
        );
        assert_eq!(begins(&service), 0, "{name}");
    }
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plugin_grant_key_must_also_be_a_token_key_and_plugin_config_is_bounded() {
    use oncl_pdk::abi::{self, Import};
    use oncl_server::{
        config::{PluginConfig, PluginGrant, ServerConfig},
        service::ServiceHost,
    };
    let pki = Pki::start();
    let dir = tempfile::tempdir().unwrap();
    let (manifest, wasm) = (dir.path().join("p.toml"), dir.path().join("p.wasm"));
    std::fs::write(&manifest, private_support::plugin::manifest("test.sign")).unwrap();
    std::fs::write(
        &wasm,
        private_support::plugin::wasm(&[(
            Import::KeysSignRaw,
            abi::encode(&abi::SignRawArgs {
                handle: 1,
                data: b"m".to_vec().into(),
            }),
        )]),
    )
    .unwrap();
    let grant = |token: &str, operation: &str| PluginGrant {
        token: token.into(),
        operation: operation.into(),
        imports: vec!["keys_sign_raw".into()],
        keys: vec!["ops-key".into()],
        pki_endpoints: vec![],
    };
    let plugin = |permissions: Vec<PluginGrant>| PluginConfig {
        id: "test.sign".into(),
        manifest: manifest.clone(),
        wasm: wasm.clone(),
        max_memory: 1 << 20,
        max_transfer: 1 << 18,
        permissions,
    };
    // A key listed in the plugin grant but NOT in the token's own key rights: 403.
    let service = Running::start_with(|config, dir| {
        config.pki = pki.config(dir);
        named_key(config, dir, &pki, "ops-key", "user-rsa-sign");
        config.tokens[0].actions = vec![Permission::Sign];
        config.tokens[0].keys = vec![]; // no right to ops-key
        config.plugins = vec![plugin(vec![grant("test", "run")])];
    })
    .await;
    let call = r#"{"items":[{"id":"p","operation":{"kind":"plugin","plugin":"test.sign","operation":"run","args":"{}","keys":[{"handle":1,"name":"ops-key"}]}}],"parts":[]}"#;
    let (status, _, _) = service.post(FORM, multipart(call, &[])).await;
    assert_eq!(status, 403);
    assert_eq!(begins(&service), 0);
    service.stop().await;
    // Configuration bounds and duplicates are refused at startup.
    let base = |mutate: &dyn Fn(&mut ServerConfig)| -> bool {
        let secret = oncl_server::auth::TokenSecret::generate().unwrap();
        let mut config = ServerConfig {
            enabled: true,
            audit_directory: dir.path().join("a"),
            scratch_directory: dir.path().join("s"),
            ..ServerConfig::default()
        };
        config.tokens.push(oncl_server::config::TokenConfig {
            id: "test".into(),
            verifier: secret.verifier().encoded(),
            actions: vec![Permission::Hash],
            keys: vec![],
            inline_pkcs12: false,
            metadata_aliases: vec![],
        });
        mutate(&mut config);
        ServiceHost::new(config).is_ok()
    };
    assert!(
        base(&|c| c.plugins = vec![plugin(vec![grant("test", "run")])]),
        "valid config starts"
    );
    assert!(
        !base(&|c| c.plugins = vec![plugin(vec![grant("test", "run"), grant("test", "run")])]),
        "duplicate (token, operation)"
    );
    assert!(
        !base(&|c| c.plugins = vec![plugin(vec![grant("nobody", "run")])]),
        "unknown token"
    );
    assert!(
        !base(&|c| {
            let mut p = plugin(vec![]);
            p.max_memory = 0;
            c.plugins = vec![p];
        }),
        "zero memory"
    );
    assert!(
        !base(&|c| {
            let mut p = plugin(vec![]);
            p.max_transfer = usize::MAX;
            c.plugins = vec![p];
        }),
        "transfer over the SDK bound"
    );
    assert!(
        !base(&|c| c.plugins = vec![plugin(vec![PluginGrant {
            imports: vec!["no_such_import".into()],
            ..grant("test", "run")
        }])]),
        "unknown import"
    );
    assert!(
        !base(&|c| c.plugins = vec![plugin(vec![PluginGrant {
            keys: (0..9).map(|n| format!("k{n}")).collect(),
            ..grant("test", "run")
        }])]),
        "too many keys"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xades_lt_and_lta_are_sign_t_then_keyless_extend_and_stay_valid_in_lxml() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let inter = {
        use der::Encode;
        pki.inter.cert.to_der().unwrap()
    };
    let service = Running::start_with(inline_service_config(&pki)).await;
    let dir = tempfile::tempdir().unwrap();
    let xml = br#"<root><item Id="p">chain</item><holder Id="s"></holder></root>"#;
    let (_, parts) = sign_inline(
        &service,
        &p12,
        "xades_t",
        r#""target":"p","parent":"s","signature_id":"sig1","#,
        xml,
    )
    .await;
    assert_eq!(final_event(&parts)["status"], "completed");
    let mut current = artifact(&parts, "artifact-0").to_vec();
    let begins_after_sign = begins(&service);
    for level in ["xades_lt", "xades_lta"] {
        let metadata = format!(
            r#"{{"items":[{{"id":"e","operation":{{"kind":"extend","profile":"{level}","input":"sig","evidence":[{{"kind":"certificate","input":"ev0"}},{{"kind":"crl","input":"ev1"}},{{"kind":"crl","input":"ev2"}}]}}}}],"parts":[{{"name":"sig","item_id":"e","role":"document"}},{{"name":"ev0","item_id":"e","role":"document"}},{{"name":"ev1","item_id":"e","role":"document"}},{{"name":"ev2","item_id":"e","role":"document"}}]}}"#
        );
        let (status, parts, response) = operate(
            &service,
            &metadata,
            &[
                Part {
                    name: "sig",
                    filename: None,
                    bytes: &current,
                },
                Part {
                    name: "ev0",
                    filename: None,
                    bytes: &inter,
                },
                Part {
                    name: "ev1",
                    filename: None,
                    bytes: &pki.crls[0],
                },
                Part {
                    name: "ev2",
                    filename: None,
                    bytes: &pki.crls[1],
                },
            ],
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
        let done = final_event(&parts);
        assert_eq!(done["status"], "completed", "{level}: {done}");
        assert_eq!(
            done["results"][0]["applied"], "NotApplied",
            "extension is keyless"
        );
        current = artifact(&parts, "artifact-0").to_vec();
        let verdict = xml_oracle(&current, dir.path());
        assert_eq!(verdict["checked"], true, "{level}: {verdict}");
        assert_eq!(
            verdict["signatures"][0]["signature_valid"], true,
            "{level}: {verdict}"
        );
        assert!(
            verdict["signatures"][0]["references"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["match"] == true),
            "{level}: {verdict}"
        );
        let text = String::from_utf8_lossy(&current).into_owned();
        assert!(
            text.contains("CertificateValues") || text.contains("RevocationValues"),
            "{level}"
        );
        if level == "xades_lta" {
            assert!(text.contains("ArchiveTimeStamp"), "{level}");
        }
    }
    assert_eq!(
        begins(&service),
        begins_after_sign,
        "extension never used a key"
    );
    service.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plugin_permission_matrix_is_per_token_and_per_operation_and_payload_origin_is_inert() {
    use oncl_server::{
        auth::TokenSecret,
        config::{PluginConfig, PluginGrant, TokenConfig},
    };
    let dir = tempfile::tempdir().unwrap();
    let (manifest, wasm) = (dir.path().join("echo.toml"), dir.path().join("echo.wasm"));
    std::fs::write(&manifest, private_support::plugin::manifest("test.echo")).unwrap();
    std::fs::write(&wasm, private_support::plugin::echo_wasm()).unwrap();
    let other = TokenSecret::generate().unwrap();
    let third = TokenSecret::generate().unwrap();
    let (other_verifier, third_verifier) = (other.verifier().encoded(), third.verifier().encoded());
    let grant = |token: &str, operation: &str| PluginGrant {
        token: token.into(),
        operation: operation.into(),
        imports: vec![],
        keys: vec![],
        pki_endpoints: vec![],
    };
    let service = Running::start_with(|config, _| {
        config.tokens[0].actions = vec![Permission::Hash];
        for (id, verifier) in [
            ("other", other_verifier.clone()),
            ("third", third_verifier.clone()),
        ] {
            config.tokens.push(TokenConfig {
                id: id.into(),
                verifier,
                actions: vec![Permission::Hash],
                keys: vec![],
                inline_pkcs12: false,
                metadata_aliases: vec![],
            });
        }
        config.plugins = vec![PluginConfig {
            id: "test.echo".into(),
            manifest: manifest.clone(),
            wasm: wasm.clone(),
            max_memory: 1 << 20,
            max_transfer: 1 << 18,
            // test: ops "alpha"+"beta"; other: only "beta"; third: nothing.
            permissions: vec![
                grant("test", "alpha"),
                grant("test", "beta"),
                grant("other", "beta"),
            ],
        }];
    })
    .await;
    let call = |operation: &str, args: &str| {
        let args = serde_json::to_string(args).unwrap();
        format!(
            r#"{{"items":[{{"id":"p","operation":{{"kind":"plugin","plugin":"test.echo","operation":"{operation}","args":{args},"keys":[]}}}}],"parts":[]}}"#
        )
    };
    let claims_origin = r#"{"origin":"https://trusted.example","caller":"test"}"#;
    let echoed = |response: &[u8]| -> Vec<u8> {
        let done: serde_json::Value = serde_json::from_slice(response).unwrap();
        private_support::plugin::reply_bytes_raw(
            done["results"][0]["result"]["response"].as_str().unwrap(),
        )
    };
    let contains =
        |haystack: &[u8], needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
    // (token, operation) -> allowed?
    let matrix: [(&str, &str, bool); 6] = [
        ("test", "alpha", true),
        ("test", "beta", true),
        ("test", "gamma", false),
        ("other", "alpha", false),
        ("other", "beta", true),
        ("third", "beta", false),
    ];
    for (who, operation, allowed) in matrix {
        let token = match who {
            "test" => service.token.to_string(),
            "other" => other.bearer().to_string(),
            _ => third.bearer().to_string(),
        };
        let (status, _, response) = service
            .post_as(
                &token,
                FORM,
                multipart(&call(operation, claims_origin), &[]),
            )
            .await;
        if allowed {
            assert_eq!(
                status,
                200,
                "{who}/{operation}: {}",
                String::from_utf8_lossy(&response)
            );
            // The guest really read the payload (origin and caller claims are visible
            // to it as data) yet authority came only from the token grant.
            let seen = echoed(&response);
            assert!(
                contains(&seen, claims_origin.as_bytes()),
                "guest sees the payload as data"
            );
            // The host-supplied `origin` field of the request is CBOR null (0xf6):
            // a service client has no browser origin, whatever the payload claims.
            assert!(
                contains(&seen, b"origin\xf6"),
                "host origin must be null: {seen:?}"
            );
        } else {
            assert_eq!(status, 403, "{who}/{operation}");
        }
    }
    service.stop().await;
}

/// Revoke the token while the upload is still in flight (worker blocked on the unsent
/// tail): plain actions are refused 403 before execution, no BEGIN. (A key-less plugin
/// has no upload to hold open; its liveness check is pinned by the dispatch unit test
/// `plugin_items_need_a_live_principal_with_and_without_keys`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_during_upload_refuses_plain_actions_with_no_execution() {
    let cases = [
        (
            "plain verify",
            r#"{"items":[{"id":"v","operation":{"kind":"verify","profile":"cms","input":"doc"}}],"parts":[{"name":"doc","item_id":"v","role":"document"}]}"#,
        ),
        (
            "plain hash",
            r#"{"items":[{"id":"h","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"h","role":"document"}]}"#,
        ),
    ];
    for (name, metadata) in cases {
        let service = Running::start_with(|config, _| {
            config.tokens[0].actions = vec![Permission::Hash, Permission::Verify];
        })
        .await;
        let body = multipart(
            metadata,
            &[Part {
                name: "doc",
                filename: None,
                bytes: &vec![b'd'; 50_000],
            }],
        );
        let host = service.host.clone();
        let (status, response) =
            split_request(&service, &body, || host.policy.revoke("test").unwrap()).await;
        assert_eq!(
            status,
            403,
            "{name}: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            !String::from_utf8_lossy(&response).contains("\"status\":\"completed\""),
            "{name}"
        );
        assert_eq!(begins(&service), 0, "{name}");
        service.stop().await;
    }
}
