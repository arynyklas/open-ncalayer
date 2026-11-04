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
    // Never read. After the original deadline the server must have released all.
    let started = std::time::Instant::now();
    loop {
        if service
            .host
            .engine
            .admit(Arc::new(oncl_server::executor::Cancellation::new()))
            .is_ok()
            && spool_files(&service.scratch()).is_empty()
        {
            break;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(8),
            "a non-reading peer held the root/scratch past its deadline"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(started.elapsed() >= std::time::Duration::from_millis(500));
    // The peer never receives a terminal success record.
    let mut received = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut received),
    )
    .await;
    assert!(!String::from_utf8_lossy(&received).contains("\"status\":\"completed\""));
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
        assert_eq!(verdict["signature_valid"], true, "{profile}: {verdict}");
        assert!(
            verdict["references"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["match"] == true),
            "{verdict}"
        );
        assert_eq!(
            xades,
            String::from_utf8_lossy(signed).contains("QualifyingProperties")
        );
        // Altering signed content breaks the independent digest check.
        let altered = String::from_utf8_lossy(signed).replace("payload text", "payload texT");
        let broken = xml_oracle(altered.as_bytes(), dir.path());
        assert!(
            broken["references"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["match"] == false),
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
