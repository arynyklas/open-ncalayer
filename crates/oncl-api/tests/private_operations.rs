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
        if level == "pades_lta" {
            assert!(
                signatures.len() >= 2,
                "LTA adds a document timestamp: {report}"
            );
        }
        // Tamper control: a flipped covered byte breaks pyHanko's integrity check.
        let mut altered = signed.to_vec();
        altered[20] ^= 1;
        let broken = pyhanko(&altered, &leaf_der, dir.path());
        assert!(
            broken["signatures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["intact"] == false),
            "{level}: {broken}"
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
    pki.tsa_delay_ms
        .store(1500, std::sync::atomic::Ordering::SeqCst);
    let document = b"document bytes that DO belong in the spool".to_vec();
    let watch = SpoolWatch::start(
        service.scratch(),
        vec![
            PASSWORD.as_bytes().to_vec(),
            p12[..64].to_vec(),
            document.clone(),
        ],
    );
    let (_, parts) = sign_inline(&service, &p12, "cades_t", "", &document).await;
    assert_eq!(final_event(&parts)["status"], "completed");
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
    let metadata = r#"{"items":[{"id":"a","operation":{"kind":"sign","profile":"cms","input":"d1","attached":true,"keys":[{"source":"inline","container":"p12","password":"pw"}]}},{"id":"b","operation":{"kind":"sign","profile":"cms","input":"d2","attached":true,"keys":[{"source":"inline","container":"p12","password":"pw"}]}}],"parts":[{"name":"p12","item_id":"a","role":"secret"},{"name":"pw","item_id":"a","role":"secret"},{"name":"d1","item_id":"a","role":"document"},{"name":"d2","item_id":"b","role":"document"}]}"#;
    // Item b has no keys of its own declared parts: reuse is refused; build properly instead.
    let _ = metadata;
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
    pki.tsa_delay_ms
        .store(1500, std::sync::atomic::Ordering::SeqCst);
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
    wait_for("native worker", || service.host.executor.running() == 1).await;
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
    pki.tsa_delay_ms
        .store(1500, std::sync::atomic::Ordering::SeqCst);
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
    wait_for("both slots held", || service.host.executor.running() == 2).await;
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
    let paths: Vec<&String> = document["paths"].as_object().unwrap().keys().collect();
    for path in paths {
        for forbidden in ["batch", "plugin", "encrypt", "decrypt"] {
            assert!(!path.contains(forbidden), "{path}");
        }
    }
    let text = document.to_string().to_lowercase();
    assert!(
        !text.contains("\"kind\":{\"const\":\"encrypt\"")
            && !text.contains("\"const\":\"decrypt\"")
    );
    for route in [
        "/v1/batch",
        "/v1/plugin",
        "/v1/plugins",
        "/v1/encrypt",
        "/v1/decrypt",
    ] {
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
async fn xades_legacy_b_is_signed_over_http_and_checked_by_lxml() {
    let pki = Pki::start();
    let p12 = container(&pki.leaf("user-rsa-sign"), PASSWORD);
    let service = Running::start_with(inline_service_config(&pki)).await;
    let dir = tempfile::tempdir().unwrap();
    let xml = br#"<root><data Id="d">xades legacy</data></root>"#;
    for profile in ["xades_legacy_b"] {
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
    }
    service.stop().await;
}
