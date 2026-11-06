//! Regressions for the XML/XAdES interop defects D2, D3 and D4 found by the independent
//! interop matrix (NCANode, lxml, OpenSSL). Each runs the real `oncl` binary.
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
fn sign_args<'a>(
    w: &'a World,
    profile: &'a str,
    input: &'a Path,
    output: &'a Path,
) -> Vec<&'a str> {
    let mut args = vec![
        "sign",
        "--profile",
        profile,
        "--input",
        path(input),
        "--output",
        path(output),
        "--key",
        path(&w.rsa_key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ];
    args.extend(trust(w));
    args
}
fn verify_json(w: &World, profile: &str, signed: &Path) -> (Option<i32>, serde_json::Value) {
    let mut args = vec![
        "verify",
        "--profile",
        profile,
        "--input",
        path(signed),
        "--json",
    ];
    args.extend(trust(w));
    let result = run(&args, b"");
    let report = serde_json::from_slice(&result.stdout).unwrap_or(serde_json::Value::Null);
    (result.status.code(), report)
}
/// Independent lxml+cryptography re-derivation of every reference digest and every
/// SignedInfo signature (RSA-SHA256), no oncl code involved.
fn lxml_oracle(w: &World, signed: &Path) -> Option<String> {
    let Some(python) = python() else {
        assert!(
            std::env::var_os("ONCL_ALLOW_NO_ORACLE").is_some(),
            "python with lxml+cryptography is required (set ONCL_ALLOW_NO_ORACLE=1 to skip explicitly)"
        );
        return None;
    };
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

/// D2: `--add` over a whole-document signature can never verify (the new signature is
/// inside the covered bytes). It must be refused before the key is used
/// (`applied=NotApplied`), while an Add over element-reference signatures still works.
#[test]
fn add_over_a_whole_document_signature_is_refused_before_the_key_is_used() {
    let w = world();
    let doc = w.dir.path().join("doc.xml");
    std::fs::write(&doc, b"<r><p Id=\"a\">one</p><q Id=\"b\">two</q></r>").unwrap();

    // Whole-document first signature.
    let first = w.dir.path().join("first.xml");
    let created = run(&sign_args(&w, "xml", &doc, &first), b"");
    assert_eq!(created.status.code(), Some(0), "{created:?}");
    let first_text = std::fs::read_to_string(&first).unwrap();
    assert!(first_text.contains("URI=\"\""), "{first_text}");

    let refused_out = w.dir.path().join("refused.xml");
    let mut add = sign_args(&w, "xml", &first, &refused_out);
    add.push("--add");
    let refused = run(&add, b"");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    assert!(stderr.contains("InvalidInput"), "{stderr}");
    assert!(
        stderr.contains("applied=NotApplied"),
        "the key must not have been used: {stderr}"
    );
    assert!(!refused_out.exists());

    // Element-reference signatures survive an Add and verify (lxml oracle, two signatures).
    let one = w.dir.path().join("one.xml");
    let mut by_id = sign_args(&w, "xml", &doc, &one);
    by_id.extend(["--target-id", "a"]);
    let created = run(&by_id, b"");
    assert_eq!(created.status.code(), Some(0), "{created:?}");
    let two = w.dir.path().join("two.xml");
    let mut add = sign_args(&w, "xml", &one, &two);
    add.extend(["--add", "--target-id", "b"]);
    let added = run(&add, b"");
    assert_eq!(added.status.code(), Some(0), "{added:?}");
    let (code, report) = verify_json(&w, "xml", &two);
    assert_eq!(code, Some(0), "{report}");
    if let Some(proof) = lxml_oracle(&w, &two) {
        assert!(proof.contains("SIGNATURES=2"), "{proof}");
    }
}

/// D3: NCANode's own GOST 2015 XAdES (certificate digest GOST R 34.11-2015) was refused
/// with `InvalidInput` and no report at every level, while its RSA shape verified.
/// The pinned fixtures are fetched, never committed (`cargo xtask fetch-fixtures`).
#[test]
fn ncanode_gost_xades_is_read_not_refused() {
    let w = world();
    for level in ["b", "t", "lt", "lta"] {
        let fixture = oncl_testkit::ncanode(&format!("xades-test-signed-{level}.xml"));
        for profile in ["xml", "xades-b"] {
            let (code, report) = verify_json(&w, profile, &fixture);
            // The test CA is not a configured anchor: Invalid for the chain (exit 2)
            // with a full report, never a refusal of the structure (exit 1, no report).
            assert_eq!(code, Some(2), "{level}/{profile}: {report}");
            let signer = &report["signers"][0];
            assert_eq!(signer["signature"], "Passed", "{level}/{profile}: {report}");
            assert_eq!(signer["chain"], "Failed", "{level}/{profile}: {report}");
        }
    }
}

/// D4: an LT signature must carry `CertificateValues` with the signing path's CA
/// certificates and the trust anchor (EN 319 132-1 §5.4.2), or NCANode reads it as T.
/// Our verifier must not claim LT for a document without them either.
#[test]
fn xades_lt_carries_the_trust_anchor_and_the_verifier_does_not_claim_lt_without_it() {
    let w = world();
    let tsa = format!("{}/tsa", w.origin);
    let doc = w.dir.path().join("doc.xml");
    std::fs::write(&doc, b"<r><p>lt</p></r>").unwrap();
    let signed = w.dir.path().join("lt.xml");
    let mut args = sign_args(&w, "xades-lt", &doc, &signed);
    args.extend([
        "--tsa-url",
        &tsa,
        "--tsa-policy",
        "1.2.398.3.3.2.6.2",
        "--signature-id",
        "sig-1",
    ]);
    let result = run(&args, b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let text = std::fs::read_to_string(&signed).unwrap();

    // Independent structure oracle (Python ElementTree, no oncl code): the carried
    // certificates, compared with the root DER the loopback PKI really uses.
    let python = ["python", "python3", "py"]
        .into_iter()
        .find(|c| Command::new(c).arg("--version").output().is_ok())
        .expect("python");
    let script = w.dir.path().join("lt_values.py");
    std::fs::write(
        &script,
        "import sys,base64,xml.etree.ElementTree as E\n\
         X='{http://uri.etsi.org/01903/v1.3.2#}'\n\
         t=E.parse(sys.argv[1])\n\
         root=open(sys.argv[2],'rb').read()\n\
         certs=[base64.b64decode(e.text) for cv in t.iter(X+'CertificateValues') for e in cv.iter(X+'EncapsulatedX509Certificate')]\n\
         ocsp=[1 for e in t.iter(X+'EncapsulatedOCSPValue')]\n\
         ts=[1 for e in t.iter(X+'EncapsulatedTimeStamp')]\n\
         print('CERTS=%d OCSP=%d TS=%d ROOT=%s'%(len(certs),len(ocsp),len(ts),root in certs))\n",
    )
    .unwrap();
    let root_der = w.dir.path().join("root.der");
    std::fs::write(&root_der, w.pki.root.cert.to_der().unwrap()).unwrap();
    let structure = |file: &Path| {
        let out = Command::new(python)
            .args([path(&script), path(file), path(&root_der)])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    let facts = structure(&signed);
    assert!(facts.contains("ROOT=True"), "{facts}");
    assert!(!facts.contains("CERTS=0"), "{facts}");
    assert!(facts.contains("TS=1"), "{facts}");

    let (code, report) = verify_json(&w, "xades-lt", &signed);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(report["ades_level"], "Lt", "{report}");

    // The same document without CertificateValues is T material, not LT.
    let start = text
        .find("<xades:CertificateValues")
        .expect("CertificateValues");
    let end = start
        + text[start..].find("</xades:CertificateValues>").unwrap()
        + "</xades:CertificateValues>".len();
    let stripped_text = format!("{}{}", &text[..start], &text[end..]);
    let stripped = w.dir.path().join("lt-stripped.xml");
    std::fs::write(&stripped, stripped_text).unwrap();
    assert!(structure(&stripped).contains("CERTS=0"));
    let (code, report) = verify_json(&w, "xades-lt", &stripped);
    assert_ne!(
        code,
        Some(0),
        "stripped LT must not satisfy xades-lt: {report}"
    );
    let (_, report) = verify_json(&w, "xades-t", &stripped);
    assert_eq!(report["ades_level"], "T", "{report}");
}

/// D1: NCANode/Kalkan XAdES-LT carries the complete CA CRL (about 20 MB) as base64 in
/// `EncapsulatedCRLValue`; `oncl verify` refused it with `MetadataLimit` and no report.
/// The metadata cap bounds markup only; the text is decoded as it streams into the
/// evidence quotas. A genuine oncl XAdES-LT gets a multi-megabyte CRL spliced over its
/// signer's OCSP answer (revocation data lies outside every signed byte), then goes
/// through the real binary: a good CRL verifies, a CRL listing the signer revokes it,
/// a CRL not issued by the root gives no status at all. Independent oracle: lxml +
/// cryptography parse the embedded CRL and check its signature and the listed serial.
#[test]
fn xades_lt_with_a_multi_megabyte_crl_is_verified_not_refused() {
    use base64::Engine as _;
    let w = world();
    let tsa = format!("{}/tsa", w.origin);
    let doc = w.dir.path().join("doc.xml");
    std::fs::write(&doc, b"<r><p>lt</p></r>").unwrap();
    let signed = w.dir.path().join("lt.xml");
    let mut args = sign_args(&w, "xades-lt", &doc, &signed);
    args.extend([
        "--tsa-url",
        &tsa,
        "--tsa-policy",
        "1.2.398.3.3.2.6.2",
        "--signature-id",
        "sig-1",
    ]);
    let result = run(&args, b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let text = std::fs::read_to_string(&signed).unwrap();
    let signer_serial = w
        .pki
        .rsa
        .cert
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .to_vec();

    let crl = |entries: u32, list_signer: bool, wrong_key: bool| {
        let mut crl = oncl_pki::crl::MockCrl::new(w.pki.root.clone())
            .with_this_update(now() - time::Duration::MINUTE)
            .next_update(Some(now() + time::Duration::HOUR));
        if wrong_key {
            crl = crl.wrong_key();
        }
        for index in 0..entries {
            if list_signer && index == entries / 2 {
                crl = crl.revoke_with_reason(&signer_serial, now() - time::Duration::DAY, 1);
            }
            crl = crl.revoke(
                &(0x0200_0000_u32 + index).to_be_bytes(),
                now() - time::Duration::DAY,
            );
        }
        crl.der()
    };
    // The signer's own OCSP answer is the last one: the TSA's precedes it.
    let with_crl = |der: &[u8]| {
        let start = text
            .rfind("<xades:OCSPValues>")
            .expect("signer OCSP values");
        let end = start
            + text[start..].find("</xades:OCSPValues>").unwrap()
            + "</xades:OCSPValues>".len();
        let lines = base64::engine::general_purpose::STANDARD
            .encode(der)
            .as_bytes()
            .chunks(76)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect::<Vec<_>>()
            .join("&#13;\n");
        format!(
            "{}<xades:CRLValues><xades:EncapsulatedCRLValue>{lines}</xades:EncapsulatedCRLValue></xades:CRLValues>{}",
            &text[..start],
            &text[end..]
        )
    };
    let python = python();
    let root_der = w.dir.path().join("oracle-root.der");
    std::fs::write(&root_der, w.pki.root.cert.to_der().unwrap()).unwrap();
    let serial_hex = signer_serial
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let oracle = |file: &Path| -> Option<String> {
        let python = python?;
        let script = w.dir.path().join("crl_oracle.py");
        std::fs::write(
            &script,
            "import sys,base64\n\
             from lxml import etree\n\
             from cryptography import x509\n\
             X='{http://uri.etsi.org/01903/v1.3.2#}'\n\
             root=x509.load_der_x509_certificate(open(sys.argv[2],'rb').read())\n\
             serial=int(sys.argv[3],16)\n\
             for e in etree.parse(sys.argv[1]).iter(X+'EncapsulatedCRLValue'):\n\
             \tcrl=x509.load_der_x509_crl(base64.b64decode(e.text))\n\
             \tlisted=crl.get_revoked_certificate_by_serial_number(serial) is not None\n\
             \tprint('SIGNED_BY_ROOT=%s LISTED=%s ENTRIES=%d'%(crl.is_signature_valid(root.public_key()),listed,len(crl)))\n",
        )
        .unwrap();
        let out = Command::new(python)
            .args([path(&script), path(file), path(&root_der), &serial_hex])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "oracle: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Some(String::from_utf8(out.stdout).unwrap())
    };

    let cases = [
        (
            "good",
            crl(150_000, false, false),
            Some(0),
            "Passed",
            "SIGNED_BY_ROOT=True LISTED=False",
        ),
        (
            "revoked signer",
            crl(150_000, true, false),
            Some(2),
            "Failed",
            "SIGNED_BY_ROOT=True LISTED=True",
        ),
        (
            "wrong key",
            crl(20_000, true, true),
            None,
            "",
            "SIGNED_BY_ROOT=False LISTED=True",
        ),
    ];
    for (name, der, exit, revocation, facts) in cases {
        assert!(
            name == "wrong key" || der.len() > 2 << 20,
            "{name}: {}",
            der.len()
        );
        let file = w
            .dir
            .path()
            .join(format!("lt-crl-{}.xml", name.replace(' ', "-")));
        std::fs::write(&file, with_crl(&der)).unwrap();
        if let Some(proof) = oracle(&file) {
            assert!(proof.contains(facts), "{name}: oracle says {proof}");
        }
        let (code, report) = verify_json(&w, "xades-lt", &file);
        let signer = &report["signers"][0];
        assert_eq!(signer["signature"], "Passed", "{name}: {report}");
        match exit {
            Some(exit) => {
                assert_eq!(code, Some(exit), "{name}: {report}");
                assert_eq!(signer["revocation"], revocation, "{name}: {report}");
                if exit == 0 {
                    assert_eq!(report["ades_level"], "Lt", "{name}: {report}");
                }
            }
            None => {
                // A CRL its issuer did not sign says nothing, even about a listed serial.
                assert_ne!(code, Some(0), "{name}: {report}");
                assert_ne!(signer["revocation"], "Passed", "{name}: {report}");
                assert_ne!(signer["revocation"], "Failed", "{name}: {report}");
            }
        }
    }
}

/// D3 negative controls: the certificate digest is really compared and only known
/// digest algorithms are admitted. A flipped digest value, a SHA-1 digest URI and an
/// unknown URI in an otherwise genuine oncl XAdES-B each get a typed refusal
/// (`InvalidInput`, exit 1), never a verdict that passes them.
#[test]
fn a_wrong_or_weak_signing_certificate_digest_is_refused_with_a_typed_error() {
    let w = world();
    let doc = w.dir.path().join("doc.xml");
    std::fs::write(&doc, b"<r><p>b</p></r>").unwrap();
    let signed = w.dir.path().join("b.xml");
    let mut args = sign_args(&w, "xades-b", &doc, &signed);
    args.extend(["--signature-id", "sig-1"]);
    let created = run(&args, b"");
    assert_eq!(created.status.code(), Some(0), "{created:?}");
    let text = std::fs::read_to_string(&signed).unwrap();
    let (code, _) = verify_json(&w, "xades-b", &signed);
    assert_eq!(code, Some(0), "untouched document verifies");

    let marker = "<xades:CertDigest>";
    let at = text.find(marker).expect("CertDigest");
    let value_at = at + text[at..].find("<ds:DigestValue>").unwrap() + "<ds:DigestValue>".len();
    let first = text.as_bytes()[value_at];
    let flipped_char = if first == b'A' { 'B' } else { 'A' };
    let flipped = format!(
        "{}{}{}",
        &text[..value_at],
        flipped_char,
        &text[value_at + 1..]
    );
    let method_at = at + text[at..].find("Algorithm=\"").unwrap() + "Algorithm=\"".len();
    let method_end = method_at + text[method_at..].find('"').unwrap();
    let with_method = |uri: &str| format!("{}{}{}", &text[..method_at], uri, &text[method_end..]);
    for (name, mutated) in [
        ("flipped digest value", flipped),
        (
            "sha1 digest uri",
            with_method("http://www.w3.org/2000/09/xmldsig#sha1"),
        ),
        (
            "unknown digest uri",
            with_method("urn:example:unknown-digest"),
        ),
    ] {
        let file = w.dir.path().join("mutated.xml");
        std::fs::write(&file, mutated).unwrap();
        let mut args = vec![
            "verify",
            "--profile",
            "xades-b",
            "--input",
            path(&file),
            "--json",
        ];
        args.extend(trust(&w));
        let result = run(&args, b"");
        assert_eq!(result.status.code(), Some(1), "{name}: {result:?}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("InvalidInput"),
            "{name}: {result:?}"
        );
    }
}
