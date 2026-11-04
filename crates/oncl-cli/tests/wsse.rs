//! WS-Security sign options observed in the produced SOAP, parsed by an
//! independent lxml script, plus exact negative exits.
mod support;
use der::Encode;
use std::{path::Path, process::Command};
use support::*;

fn python() -> Option<&'static str> {
    ["python", "python3", "py"].into_iter().find(|candidate| {
        Command::new(candidate)
            .args(["-c", "import lxml"])
            .output()
            .is_ok_and(|o| o.status.success())
    })
}
fn inspect(w: &World, signed: &Path) -> serde_json::Value {
    let python = python().expect("python with lxml is required for the WSSE structural oracle");
    let script = w.dir.path().join("wsse_inspect.py");
    std::fs::write(&script, include_str!("support/wsse_inspect.py")).unwrap();
    let out = Command::new(python)
        .args([path(&script), path(signed)])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}
const SOAP11: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const SOAP12: &str = "http://www.w3.org/2003/05/soap-envelope";
const WSU: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
fn envelope(namespace: &str, header: &str) -> Vec<u8> {
    format!(
        "<s:Envelope xmlns:s=\"{namespace}\" xmlns:wsu=\"{WSU}\" xmlns:h=\"urn:h\"><s:Header>{header}</s:Header><s:Body><a>payload</a></s:Body></s:Envelope>"
    )
    .into_bytes()
}
fn trust(w: &World) -> Vec<&str> {
    vec![
        "--root",
        path(&w.root),
        "--pki-endpoint",
        &w.origin,
        "--as-of",
        "1793620800",
    ]
}
fn sign(
    w: &World,
    name: &str,
    document: &[u8],
    extra: &[&str],
) -> (std::process::Output, std::path::PathBuf) {
    let input = w.dir.path().join(format!("{name}.in.xml"));
    let output = w.dir.path().join(format!("{name}.signed.xml"));
    std::fs::write(&input, document).unwrap();
    let mut args = vec![
        "sign",
        "--profile",
        "wsse",
        "--input",
        path(&input),
        "--output",
        path(&output),
        "--key",
        path(&w.rsa_key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ];
    args.extend(trust(w));
    args.extend(extra);
    (run(&args, b""), output)
}
fn verify(w: &World, signed: &Path, extra: &[&str]) -> std::process::Output {
    let mut args = vec![
        "verify",
        "--profile",
        "wsse",
        "--input",
        path(signed),
        "--json",
    ];
    args.extend(trust(w));
    args.extend(extra);
    run(&args, b"")
}
fn stable_code(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_owned()
}

#[test]
fn token_body_and_timestamp_options_appear_in_the_signed_soap() {
    let w = world();
    let leaf_hex: String = w
        .pki
        .rsa
        .cert
        .to_der()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    // Default: NCANode key identifier, no BinarySecurityToken.
    let (signed, out) = sign(&w, "default", &envelope(SOAP11, ""), &[]);
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    let view = inspect(&w, &out);
    assert_eq!(view["envelope_ns"], SOAP11);
    assert!(view.get("bst").is_none(), "{view}");
    assert!(
        view["key_reference"]["key_identifier_value_type"].is_string(),
        "{view}"
    );
    assert!(view["key_reference"]["reference_uri"].is_null(), "{view}");
    assert_eq!(verify(&w, &out, &[]).status.code(), Some(0));
    // BinarySecurityToken with the operator's token and body identities.
    let (signed, out) = sign(
        &w,
        "bst",
        &envelope(SOAP11, ""),
        &[
            "--wsse-token-reference",
            "binary-security-token",
            "--wsse-token-id",
            "tok-1",
            "--wsse-body-id",
            "body-1",
        ],
    );
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    let view = inspect(&w, &out);
    assert_eq!(view["bst"]["id"], "tok-1", "{view}");
    assert_eq!(
        view["bst"]["value_type"],
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
    );
    assert_eq!(
        view["bst"]["encoding_type"],
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
    );
    assert_eq!(
        view["bst"]["der_hex"], leaf_hex,
        "the token is the signer certificate"
    );
    assert_eq!(view["body_id"], "body-1");
    assert_eq!(view["key_reference"]["reference_uri"], "#tok-1", "{view}");
    assert!(
        view["references"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "#body-1"),
        "{view}"
    );
    assert_eq!(verify(&w, &out, &[]).status.code(), Some(0));
    // Timestamp identity and lifetime, signed as a reference.
    let (signed, out) = sign(
        &w,
        "timestamp",
        &envelope(SOAP11, ""),
        &[
            "--wsse-timestamp-id",
            "ts-1",
            "--wsse-timestamp-created",
            "1793620740",
            "--wsse-timestamp-expires",
            "1793620860",
        ],
    );
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    let view = inspect(&w, &out);
    assert_eq!(view["timestamp"]["id"], "ts-1", "{view}");
    let created = view["timestamp"]["created"].as_str().unwrap();
    let expires = view["timestamp"]["expires"].as_str().unwrap();
    assert!(created.starts_with("2026-11-02T11:59:00"), "{view}");
    assert!(expires.starts_with("2026-11-02T12:01:00"), "{view}");
    assert!(
        view["references"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "#ts-1"),
        "{view}"
    );
    assert_eq!(
        verify(
            &w,
            &out,
            &[
                "--wsse-timestamp-required",
                "--wsse-timestamp-max-lifetime",
                "300"
            ]
        )
        .status
        .code(),
        Some(0)
    );
    // A lifetime above the verifier's limit is refused as invalid input.
    let too_long = verify(
        &w,
        &out,
        &[
            "--wsse-timestamp-required",
            "--wsse-timestamp-max-lifetime",
            "60",
        ],
    );
    assert_eq!(too_long.status.code(), Some(1), "{too_long:?}");
    assert_eq!(
        stable_code(&too_long),
        "oncl: InvalidInput; applied=NotApplied"
    );
}
const REFUSED: &str = "oncl: InvalidInput; applied=NotApplied";
#[test]
fn soap_version_role_and_required_header_are_signed_and_enforced_with_exact_refusals() {
    let w = world();
    let header = "<h:Custom wsu:Id=\"hdr-1\">x</h:Custom>";
    let (signed, plain) = sign(&w, "plain", &envelope(SOAP11, header), &[]);
    assert_eq!(signed.status.code(), Some(0));
    let (signed, hdr) = sign(
        &w,
        "hdr",
        &envelope(SOAP11, header),
        &["--wsse-required-header", "hdr-1"],
    );
    assert_eq!(signed.status.code(), Some(0));
    let (signed, r11) = sign(
        &w,
        "r11",
        &envelope(SOAP11, header),
        &["--wsse-role", "urn:role"],
    );
    assert_eq!(signed.status.code(), Some(0));
    let (signed, r12) = sign(
        &w,
        "r12",
        &envelope(SOAP12, header),
        &["--soap-version", "soap12", "--wsse-role", "urn:role"],
    );
    assert_eq!(signed.status.code(), Some(0));
    // Observed in the produced SOAP: only the requested header is referenced;
    // the role becomes `actor` (SOAP 1.1) or `role` (SOAP 1.2), never both.
    let view = inspect(&w, &plain);
    assert_eq!(view["references"], serde_json::json!(["#oncl-body"]));
    let view = inspect(&w, &hdr);
    assert_eq!(
        view["references"],
        serde_json::json!(["#oncl-body", "#hdr-1"])
    );
    let view = inspect(&w, &r11);
    assert_eq!(view["security_actor"], "urn:role");
    assert!(view["security_role"].is_null());
    let view = inspect(&w, &r12);
    assert_eq!(view["envelope_ns"], SOAP12);
    assert_eq!(view["security_role"], "urn:role");
    assert!(view["security_actor"].is_null());
    // Positive verification with matching host options.
    for (label, file, extra) in [
        (
            "signed header required",
            &hdr,
            vec!["--wsse-required-header", "hdr-1"],
        ),
        ("role", &r11, vec!["--wsse-role", "urn:role"]),
        (
            "soap12 role",
            &r12,
            vec!["--soap-version", "soap12", "--wsse-role", "urn:role"],
        ),
        ("plain without requirements", &plain, vec![]),
    ] {
        let result = verify(&w, file, &extra);
        assert_eq!(result.status.code(), Some(0), "{label}: {result:?}");
    }
    // Exact, stable refusals (exit 1, InvalidInput) for every mismatch.
    for (label, file, extra) in [
        (
            "unsigned required header",
            &plain,
            vec!["--wsse-required-header", "hdr-1"],
        ),
        (
            "unknown required header",
            &hdr,
            vec!["--wsse-required-header", "nope"],
        ),
        ("role mismatch", &r11, vec!["--wsse-role", "urn:other"]),
        ("role missing", &r11, vec![]),
        (
            "soap12 verified as soap11",
            &r12,
            vec!["--wsse-role", "urn:role"],
        ),
        (
            "soap11 verified as soap12",
            &plain,
            vec!["--soap-version", "soap12"],
        ),
    ] {
        let result = verify(&w, file, &extra);
        assert_eq!(result.status.code(), Some(1), "{label}: {result:?}");
        assert_eq!(stable_code(&result), REFUSED, "{label}");
        assert!(result.stdout.is_empty(), "{label}");
    }
}
