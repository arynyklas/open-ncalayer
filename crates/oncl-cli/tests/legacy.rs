//! Legacy `XmlSignSpec` / `XadesSpec` host options through the real `oncl`
//! binary, strict loopback PKI and an independent lxml/cryptography oracle.
mod support;
use der::Encode;
use std::{path::Path, process::Command};
use support::*;

fn python() -> Option<&'static str> {
    ["python", "python3", "py"].into_iter().find(|candidate| {
        Command::new(candidate)
            .args(["-c", "import lxml, cryptography"])
            .output()
            .is_ok_and(|o| o.status.success())
    })
}
/// Independent XML-DSig verification of `signed` against the RSA leaf.
fn oracle(w: &World, signed: &Path) -> Option<String> {
    let python = python().or_else(|| {
        eprintln!("python with lxml+cryptography unavailable: oracle not exercised");
        None
    })?;
    let script = w.dir.path().join("xmldsig_oracle.py");
    std::fs::write(&script, include_str!("support/xmldsig_oracle.py")).unwrap();
    let leaf = w.dir.path().join("oracle-leaf.der");
    std::fs::write(&leaf, w.pki.rsa.cert.to_der().unwrap()).unwrap();
    let result = Command::new(python)
        .args([path(&script), path(signed), path(&leaf)])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "oracle rejected {}: {}",
        signed.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    Some(String::from_utf8(result.stdout).unwrap())
}
fn common(w: &World) -> Vec<&str> {
    vec!["--root", path(&w.root), "--pki-endpoint", &w.origin]
}
fn sign(
    w: &World,
    profile: &str,
    document: &[u8],
    name: &str,
    extra: &[&str],
) -> (std::process::Output, std::path::PathBuf) {
    let input = w.dir.path().join(format!("{name}.in.xml"));
    let output = w.dir.path().join(format!("{name}.signed.xml"));
    std::fs::write(&input, document).unwrap();
    let mut args = vec![
        "sign",
        "--profile",
        profile,
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
    args.extend(common(w));
    if !extra.contains(&"--as-of") {
        args.extend(["--as-of", "1793620800"]);
    }
    args.extend(extra);
    (run(&args, b""), output)
}
fn verify(w: &World, profile: &str, signed: &Path) -> std::process::Output {
    let mut args = vec![
        "verify",
        "--profile",
        profile,
        "--input",
        path(signed),
        "--json",
    ];
    args.extend(common(w));
    args.extend(["--as-of", AS_OF]);
    run(&args, b"")
}
const AS_OF: &str = "1793620800";
const DOC: &[u8] = b"<r xmlns:p=\"urn:p\"><p:data Id=\"d1\">legacy data</p:data><s/></r>";

#[test]
fn kalkan_default_and_selector_placement_namespace_c14n_options_verify_valid() {
    let w = world();
    // Whole document, Kalkan defaults.
    let (signed, out) = sign(&w, "xml", DOC, "default", &["--legacy"]);
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    assert!(String::from_utf8_lossy(&signed.stderr).contains("applied=Applied succeeded=true"));
    let result = verify(&w, "xml-kalkan", &out);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.contains("URI=\"\""), "{text}");
    if let Some(proof) = oracle(&w, &out) {
        assert!(proof.starts_with("OK 1 "), "{proof}");
    }
    // Selector, parent, namespace binding, SignedInfo C14N and reference transform.
    let (signed, out) = sign(
        &w,
        "xml",
        DOC,
        "selected",
        &[
            "--legacy",
            "--legacy-element",
            "//p:data",
            "--legacy-parent",
            "/r/s",
            "--legacy-namespace",
            "p=urn:p",
            "--legacy-signed-info-c14n",
            "inclusive",
            "--legacy-transform",
            "exclusive-with-comments",
        ],
    );
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.contains("URI=\"#d1\""), "{text}");
    // The signature is inside <s>, not at the document element.
    let start = text.find("<s>").expect("signature parent");
    assert!(text[start..].contains("Signature"), "{text}");
    assert!(
        text.contains("Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\""),
        "SignedInfo canonicalization requested: {text}"
    );
    assert!(
        text.contains("Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\""),
        "reference transform requested: {text}"
    );
    let result = verify(&w, "xml-kalkan", &out);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    if let Some(proof) = oracle(&w, &out) {
        assert!(proof.contains("REC-xml-c14n-20010315"), "{proof}");
    }
}
#[test]
fn legacy_algorithms_signing_time_layout_and_as_is_output_are_typed_and_verified() {
    let w = world();
    let (signed, out) = sign(
        &w,
        "xml",
        b"<r><x Id=\"d\">a</x></r>",
        "layout",
        &[
            "--legacy",
            "--legacy-element",
            "/r/x",
            "--legacy-signature-method",
            "rsa-sha256",
            "--legacy-digest-method",
            "rsa-sha256",
            "--signature-id",
            "sig-1",
            "--legacy-signing-time-id",
            "time-1",
            "--legacy-signing-time",
            "2026-11-03T12:00:00Z",
            "--legacy-signing-time-reference",
            "--legacy-line-breaks",
            "--legacy-base64-line-breaks",
            "on",
            "--legacy-output",
            "as-is",
        ],
    );
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.contains("Id=\"sig-1\""), "{text}");
    assert!(
        text.contains("Id=\"time-1\"") && text.contains("2026-11-03T12:00:00Z"),
        "{text}"
    );
    assert!(text.contains("URI=\"#time-1\""), "second reference: {text}");
    assert!(text.contains('\n'), "Santuario line breaks requested");
    assert!(
        text.starts_with("<r>"),
        "as-is keeps the input bytes: {text}"
    );
    assert_eq!(verify(&w, "xml-kalkan", &out).status.code(), Some(0));
    if let Some(proof) = oracle(&w, &out) {
        assert!(proof.starts_with("OK 2 "), "{proof}");
    }
    // Serialize form with a declaration is a different, requested output shape.
    let (signed, out) = sign(
        &w,
        "xml",
        b"<r><x Id=\"d\">a</x></r>",
        "declared",
        &[
            "--legacy",
            "--legacy-xml-declaration",
            "--legacy-standalone-no",
        ],
    );
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    assert!(
        std::fs::read_to_string(&out)
            .unwrap()
            .starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>")
    );
}
#[test]
fn legacy_selector_or_algorithm_the_sdk_refuses_never_reaches_private_use_or_output() {
    let w = world();
    let document: &[u8] = b"<r><x Id=\"d\">a</x></r>";
    // Controls: the same invocation shapes with valid values do sign, so the
    // refusals below come from the SDK facade and not from option parsing.
    let (control, _) = sign(
        &w,
        "xml",
        document,
        "ctl-a",
        &["--legacy", "--legacy-element", "/r/x"],
    );
    assert_eq!(control.status.code(), Some(0), "{control:?}");
    let (control, _) = sign(
        &w,
        "xml",
        document,
        "ctl-b",
        &["--legacy", "--legacy-signature-method", "rsa-sha256"],
    );
    assert_eq!(control.status.code(), Some(0), "{control:?}");
    for (label, extra) in [
        (
            "missing selector target",
            vec!["--legacy", "--legacy-element", "/r/missing"],
        ),
        (
            "GOST method for an RSA key",
            vec!["--legacy", "--legacy-signature-method", "gost2015-512"],
        ),
    ] {
        let (result, out) = sign(&w, "xml", document, "refused", &extra);
        assert_eq!(result.status.code(), Some(1), "{label}: {result:?}");
        let text = String::from_utf8_lossy(&result.stderr);
        assert!(
            !text.contains("private_use") && !text.contains("UsageError"),
            "{label}: {text}"
        );
        assert!(text.contains("applied=NotApplied"), "{label}: {text}");
        assert!(!out.exists(), "{label}");
        let _ = std::fs::remove_file(w.dir.path().join("refused.in.xml"));
    }
}
#[test]
fn legacy_xades_b_t_lt_use_the_host_tsa_and_chain_and_verify_at_their_level() {
    let w = world();
    let tsa = format!("{}/tsa", w.origin);
    let chain = w.dir.path().join("chain.cer");
    std::fs::write(&chain, w.pki.root.cert.to_der().unwrap()).unwrap();
    let document: &[u8] = b"<r><p>legacy xades</p></r>";
    for (profile, verify_profile, level) in [
        ("xades-b", "xades-b", "B"),
        ("xades-t", "xades-t", "T"),
        ("xades-lt", "xades-lt", "Lt"),
    ] {
        let mut extra = vec![
            "--legacy",
            "--legacy-signature-method",
            "rsa-sha256",
            "--legacy-chain",
            path(&chain),
        ];
        if profile != "xades-b" {
            extra.extend(["--tsa-url", &tsa, "--tsa-policy", "1.2.398.3.3.2.6.2"]);
        }
        let (signed, out) = sign(&w, profile, document, profile, &extra);
        assert_eq!(signed.status.code(), Some(0), "{profile}: {signed:?}");
        let result = verify(&w, verify_profile, &out);
        assert_eq!(result.status.code(), Some(0), "{profile}: {result:?}");
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["ades_level"], level, "{profile}");
        if let Some(proof) = oracle(&w, &out) {
            assert!(proof.starts_with("OK 2 "), "{profile}: {proof}");
        }
    }
    // XAdES evidence requires an explicit TSA policy: absent it, the host
    // configuration is refused before private use; a malformed OID is typed.
    let (refused, out) = sign(
        &w,
        "xades-t",
        document,
        "no-policy",
        &["--legacy", "--tsa-url", &tsa],
    );
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    assert!(!String::from_utf8_lossy(&refused.stderr).contains("private_use"));
    assert!(!out.exists());
    let (bad, _) = sign(
        &w,
        "xades-t",
        document,
        "bad-policy",
        &["--legacy", "--tsa-url", &tsa, "--tsa-policy", "not.an.oid"],
    );
    assert_eq!(bad.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("InvalidCombination"));
}

#[test]
fn unsupported_legacy_combinations_fail_before_any_io() {
    let cases: &[(&str, &[&str], &str)] = &[
        (
            "option without --legacy",
            &["--profile", "xml", "--legacy-element", "/r"],
            "InvalidCombination",
        ),
        (
            "legacy CMS",
            &["--profile", "cms", "--legacy"],
            "InvalidCombination",
        ),
        (
            "legacy PDF",
            &["--profile", "pdf", "--legacy"],
            "InvalidCombination",
        ),
        (
            "legacy WSSE",
            &["--profile", "wsse", "--legacy"],
            "InvalidCombination",
        ),
        (
            "legacy XAdES-LTA",
            &[
                "--profile",
                "xades-lta",
                "--legacy",
                "--tsa-url",
                "http://127.0.0.1:1/tsa",
            ],
            "InvalidCombination",
        ),
        (
            "legacy add",
            &["--profile", "xml", "--legacy", "--add"],
            "InvalidCombination",
        ),
        (
            "legacy target id",
            &["--profile", "xml", "--legacy", "--target-id", "x"],
            "InvalidCombination",
        ),
        (
            "XML selector on XAdES",
            &["--profile", "xades-b", "--legacy", "--legacy-element", "/r"],
            "InvalidCombination",
        ),
        (
            "signature id on XAdES",
            &["--profile", "xades-b", "--legacy", "--signature-id", "s"],
            "InvalidCombination",
        ),
        (
            "chain on plain XML",
            &["--profile", "xml", "--legacy", "--legacy-chain", "c.cer"],
            "InvalidCombination",
        ),
        (
            "XAdES-T without TSA",
            &["--profile", "xades-t", "--legacy"],
            "TsaRequired",
        ),
        (
            "parent and placement",
            &[
                "--profile",
                "xml",
                "--legacy",
                "--legacy-parent",
                "/r",
                "--legacy-placement",
                "first-child",
            ],
            "InvalidCombination",
        ),
        (
            "bad namespace binding",
            &[
                "--profile",
                "xml",
                "--legacy",
                "--legacy-namespace",
                "no-equals",
            ],
            "InvalidCombination",
        ),
        (
            "empty namespace prefix",
            &[
                "--profile",
                "xml",
                "--legacy",
                "--legacy-namespace",
                "=urn:x",
            ],
            "InvalidCombination",
        ),
        (
            "two canonicalizations",
            &[
                "--profile",
                "xml",
                "--legacy",
                "--legacy-transform",
                "inclusive",
                "--legacy-transform",
                "exclusive",
            ],
            "InvalidCombination",
        ),
        (
            "enveloped not first",
            &[
                "--profile",
                "xml",
                "--legacy",
                "--legacy-transform",
                "inclusive",
                "--legacy-transform",
                "enveloped",
            ],
            "InvalidCombination",
        ),
        (
            "enveloped twice",
            &[
                "--profile",
                "xml",
                "--legacy",
                "--legacy-transform",
                "enveloped",
                "--legacy-transform",
                "enveloped",
            ],
            "InvalidCombination",
        ),
        (
            "signing time text only",
            &[
                "--profile",
                "xml",
                "--legacy",
                "--legacy-signing-time",
                "t",
                "--signature-id",
                "s",
            ],
            "InvalidCombination",
        ),
        (
            "signing time without signature id",
            &[
                "--profile",
                "xml",
                "--legacy",
                "--legacy-signing-time-id",
                "i",
                "--legacy-signing-time",
                "t",
            ],
            "InvalidCombination",
        ),
        (
            "time reference without object",
            &[
                "--profile",
                "xml",
                "--legacy",
                "--legacy-signing-time-reference",
            ],
            "InvalidCombination",
        ),
        (
            "declaration with as-is",
            &[
                "--profile",
                "xml",
                "--legacy",
                "--legacy-output",
                "as-is",
                "--legacy-xml-declaration",
            ],
            "InvalidCombination",
        ),
        (
            "standalone without declaration",
            &["--profile", "xml", "--legacy", "--legacy-standalone-no"],
            "InvalidCombination",
        ),
        (
            "control character in selector",
            &["--profile", "xml", "--legacy", "--legacy-element", "/r\n"],
            "InvalidCombination",
        ),
    ];
    for (label, extra, code) in cases {
        let mut args = vec![
            "sign",
            "--input",
            "missing-document",
            "--output",
            "-",
            "--key",
            "missing-key",
            "--authorize",
        ];
        args.extend(*extra);
        let result = run(&args, b"");
        assert_eq!(result.status.code(), Some(1), "{label}: {result:?}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(code),
            "{label}: {result:?}"
        );
        assert!(result.stdout.is_empty(), "{label}");
    }
    // No raw key path or free-form algorithm/transform option exists.
    for flag in [
        "--legacy-key",
        "--legacy-signature-uri",
        "--legacy-transform-uri",
    ] {
        let result = run(
            &[
                "sign",
                "--profile",
                "xml",
                "--legacy",
                flag,
                "x",
                "--input",
                "-",
                "--output",
                "-",
            ],
            b"",
        );
        assert_eq!(result.status.code(), Some(1), "{flag}");
        assert!(!String::from_utf8_lossy(&result.stderr).contains(flag));
    }
}
#[test]
fn baseline_xades_levels_need_and_use_the_operator_tsa_policy() {
    let w = world();
    let tsa = format!("{}/tsa", w.origin);
    let document: &[u8] = b"<r><p>baseline xades</p></r>";
    for (profile, level) in [("xades-t", "T"), ("xades-lt", "Lt"), ("xades-lta", "Lta")] {
        let (refused, out) = sign(
            &w,
            profile,
            document,
            &format!("{profile}-nopolicy"),
            &["--tsa-url", &tsa],
        );
        assert_eq!(refused.status.code(), Some(1), "{profile}: {refused:?}");
        assert!(!String::from_utf8_lossy(&refused.stderr).contains("private_use"));
        assert!(!out.exists());
        let (signed, out) = sign(
            &w,
            profile,
            document,
            profile,
            &[
                "--tsa-url",
                &tsa,
                "--tsa-policy",
                "1.2.398.3.3.2.6.2",
                "--signature-id",
                "baseline-sig",
            ],
        );
        assert_eq!(signed.status.code(), Some(0), "{profile}: {signed:?}");
        let result = verify(&w, profile, &out);
        assert_eq!(result.status.code(), Some(0), "{profile}: {result:?}");
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["ades_level"], level, "{profile}");
        if let Some(proof) = oracle(&w, &out) {
            assert!(proof.starts_with("OK "), "{profile}: {proof}");
        }
    }
}
