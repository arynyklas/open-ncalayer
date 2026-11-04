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
    oracle_mode(w, signed, None)
}
/// The oracle is mandatory: its absence fails the test unless the operator
/// explicitly opts out with `ONCL_ALLOW_NO_ORACLE=1`, which is then logged.
fn oracle_mode(w: &World, signed: &Path, mode: Option<&str>) -> Option<String> {
    let python = python().or_else(|| {
        assert!(
            std::env::var_os("ONCL_ALLOW_NO_ORACLE").is_some(),
            "python with lxml+cryptography is required (set ONCL_ALLOW_NO_ORACLE=1 to skip explicitly)"
        );
        eprintln!("ORACLE SKIPPED (explicit ONCL_ALLOW_NO_ORACLE)");
        None
    })?;
    let script = w.dir.path().join("xmldsig_oracle.py");
    std::fs::write(&script, include_str!("support/xmldsig_oracle.py")).unwrap();
    let leaf = w.dir.path().join("oracle-leaf.der");
    std::fs::write(&leaf, w.pki.rsa.cert.to_der().unwrap()).unwrap();
    let mut command = Command::new(python);
    command.args([path(&script), path(signed), path(&leaf)]);
    command.args(mode);
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "oracle rejected {}: {}",
        signed.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    let proof = String::from_utf8(result.stdout).unwrap();
    assert!(proof.contains("SIGNATURES=1"), "{proof}");
    eprintln!("ORACLE RAN {proof}");
    Some(proof)
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
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr).trim(),
        "oncl: TsaPolicyRequired"
    );
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
                "--tsa-policy",
                "1.2.398.3.3.2.6.2",
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
        assert_eq!(
            String::from_utf8_lossy(&refused.stderr).trim(),
            "oncl: TsaPolicyRequired",
            "{profile}"
        );
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
fn normalized(bytes: &[u8]) -> String {
    // Certificate and RSA signature bytes depend on the per-run issuing key; every
    // other byte (digest, SignedInfo, layout, declaration, whitespace) is pinned.
    let mut text = String::from_utf8(bytes.to_vec()).unwrap();
    for tag in [
        "ds:X509Certificate",
        "ds:SignatureValue",
        "X509Certificate",
        "SignatureValue",
    ] {
        let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
        while let Some(start) = text.find(&open) {
            let end = text[start..].find(&close).unwrap() + start;
            text.replace_range(start + open.len()..end, "{VOLATILE}");
            // continue after this element
            let marker = format!("{open}{{VOLATILE}}");
            text = text.replacen(&marker, &format!("<{tag}-pinned>{{VOLATILE}}"), 1);
        }
        text = text.replace(&format!("<{tag}-pinned>"), &open);
    }
    text
}
#[test]
fn legacy_output_bytes_are_pinned_for_a_fixed_input() {
    let w = world();
    let document = b"<r><p Id=\"d1\">data</p></r>";
    let mut results = Vec::new();
    for (name, extra) in [
        ("kalkan", vec!["--legacy", "--legacy-element", "/r/p"]),
        (
            "santuario",
            vec![
                "--legacy",
                "--legacy-element",
                "/r/p",
                "--legacy-line-breaks",
                "--legacy-base64-line-breaks",
                "on",
                "--legacy-output",
                "as-is",
            ],
        ),
        (
            "declared",
            vec![
                "--legacy",
                "--legacy-xml-declaration",
                "--legacy-standalone-no",
            ],
        ),
    ] {
        let (signed, out) = sign(&w, "xml", document, name, &extra);
        assert_eq!(signed.status.code(), Some(0), "{name}: {signed:?}");
        let bytes = std::fs::read(&out).unwrap();
        results.push((name, normalized(&bytes)));
    }
    let golden = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    for (name, text) in &results {
        let file = golden.join(format!("legacy_{name}.xml"));
        if std::env::var_os("ONCL_WRITE_GOLDEN").is_some() {
            std::fs::create_dir_all(&golden).unwrap();
            std::fs::write(&file, text).unwrap();
        }
        let expected = std::fs::read_to_string(&file)
            .unwrap_or_else(|_| panic!("missing golden {}", file.display()))
            .replace("\r\n", "\n");
        assert_eq!(
            &text.replace("\r\n", "\n"),
            &expected,
            "{name}: legacy wire drifted"
        );
    }
    // Independent digests: Python hashlib over the canonical bytes of the signed
    // element / the document without its signature.
    assert!(
        results[0].1.contains(
            "<ds:DigestValue>6e7Z69I++CmaGim1DbiK3WN4VIuPVyTgC7QIetHT+20=</ds:DigestValue>"
        )
    );
    assert!(
        results[2].1.contains(
            "<ds:DigestValue>xrH6qCO/dCfbAgRNEKjuB2eFf50jxcVI90CPQwxNz7E=</ds:DigestValue>"
        )
    );
}

#[test]
fn a_tsa_token_with_another_policy_than_requested_is_rejected() {
    let w = world();
    let good = format!("{}/tsa", w.origin);
    // This responder drops the requested policy, so the token carries its own
    // (basics) policy, which differs from the operator's `--tsa-policy`.
    let other = format!("{}/tsa-other-policy", w.origin);
    let document: &[u8] = b"<r><p>policy</p></r>";
    let (accepted, _) = sign(
        &w,
        "xades-t",
        document,
        "policy-ok",
        &[
            "--tsa-url",
            &good,
            "--tsa-policy",
            "1.2.398.3.3.2.6.2",
            "--signature-id",
            "s1",
        ],
    );
    assert_eq!(accepted.status.code(), Some(0), "control: {accepted:?}");
    let (rejected, out) = sign(
        &w,
        "xades-t",
        document,
        "policy-mismatch",
        &[
            "--tsa-url",
            &other,
            "--tsa-policy",
            "1.2.398.3.3.2.6.2",
            "--signature-id",
            "s1",
        ],
    );
    assert_eq!(rejected.status.code(), Some(1), "{rejected:?}");
    assert!(!out.exists());
    let text = String::from_utf8_lossy(&rejected.stderr);
    eprintln!("POLICY MISMATCH: {}", text.trim());
    // Honest bound: acquisition happens after key use, so the refusal is reported
    // with the truthful private-use state and nothing is published.
    assert!(text.contains("private_use"), "{text}");
    assert!(text.contains("applied=Applied"), "{text}");
    assert!(
        text.trim_end()
            .ends_with("oncl: ValidationRequired; applied=Applied"),
        "{text}"
    );
}
#[test]
fn gost_xml_is_structurally_checked_not_independently_verified_and_legacy_gost_is_refused() {
    let w = world();
    let input = w.dir.path().join("gost.in.xml");
    std::fs::write(&input, b"<r><p Id=\"d1\">gost</p></r>").unwrap();
    let run_sign = |name: &str, extra: &[&str]| {
        let out = w.dir.path().join(format!("{name}.xml"));
        let mut args = vec![
            "sign",
            "--input",
            path(&input),
            "--output",
            path(&out),
            "--key",
            path(&w.gost_key),
            "--secret-file",
            path(&w.secret),
            "--authorize",
        ];
        args.extend(extra);
        args.extend(common(&w));
        args.extend(["--as-of", AS_OF]);
        (run(&args, b""), out)
    };
    // Baseline XML with a GOST-2015 key signs and verifies Valid.
    let (signed, out) = run_sign("baseline", &["--profile", "xml"]);
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.contains("gostr34102015-gostr34112015-512"), "{text}");
    assert_eq!(verify(&w, "xml", &out).status.code(), Some(0));
    // Honest bound: the Python oracle has no GOST R 34.10/34.11, so only structure
    // (references, digest length, algorithm URIs, SignatureValue) is checked
    // independently; the GOST math is verified by the SDK alone.
    if let Some(proof) = oracle_mode(&w, &out, Some("gost")) {
        assert!(proof.contains("MODE=structural-gost"), "{proof}");
    }
    let tampered = w.dir.path().join("gost.tampered.xml");
    std::fs::write(&tampered, text.replace(">gost<", ">g0st<")).unwrap();
    assert_eq!(verify(&w, "xml", &tampered).status.code(), Some(2));
    // Observed limitation: the guarded legacy facade refuses a GOST-2015 signer
    // before any private use (it is exercised with RSA and baseline GOST instead).
    let (refused, out) = run_sign("legacy", &["--profile", "xml", "--legacy"]);
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    let text = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !text.contains("private_use") && text.contains("applied=NotApplied"),
        "{text}"
    );
    assert!(!out.exists());
}
#[test]
fn the_oracle_rejects_a_signature_without_references() {
    let w = world();
    let Some(_) = python() else {
        panic!("python with lxml+cryptography is required");
    };
    let file = w.dir.path().join("empty.xml");
    std::fs::write(
        &file,
        b"<r><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature></r>",
    )
    .unwrap();
    let script = w.dir.path().join("o.py");
    std::fs::write(&script, include_str!("support/xmldsig_oracle.py")).unwrap();
    let leaf = w.dir.path().join("leaf.der");
    std::fs::write(&leaf, w.pki.rsa.cert.to_der().unwrap()).unwrap();
    let r = Command::new(python().unwrap())
        .args([path(&script), path(&file), path(&leaf)])
        .output()
        .unwrap();
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("no Reference"));
}

#[test]
fn legacy_base64_line_break_option_changes_the_signature_layout() {
    let w = world();
    for (flag, wrapped) in [("on", true), ("off", false)] {
        let (signed, out) = sign(
            &w,
            "xml",
            b"<r><p Id=\"d1\">x</p></r>",
            &format!("b64-{flag}"),
            &[
                "--legacy",
                "--legacy-line-breaks",
                "--legacy-base64-line-breaks",
                flag,
            ],
        );
        assert_eq!(signed.status.code(), Some(0));
        let text = std::fs::read_to_string(&out).unwrap().replace("\r\n", "\n");
        let start = text.find("<ds:SignatureValue>").unwrap() + "<ds:SignatureValue>".len();
        let value = &text[start..text[start..].find("</ds:SignatureValue>").unwrap() + start];
        let lines: Vec<&str> = value.split('\n').collect();
        if wrapped {
            assert!(lines.len() > 1, "{value}");
            assert!(
                lines[..lines.len() - 1].iter().all(|l| l.len() == 76),
                "{value}"
            );
        } else {
            assert_eq!(lines.len(), 1, "{value}");
        }
    }
}
