//! `oncl verify --profile cms --pem`: bounded, explicit PEM intake (the daemon's demo page
//! used to hand out PEM and the removed `openncalayer cms-verify` read it). The PEM is
//! decoded before parsing; nothing is inferred from the file's content.
mod support;
use std::path::Path;
use support::*;

fn common(w: &World) -> Vec<&str> {
    vec![
        "--root",
        path(&w.root),
        "--pki-endpoint",
        &w.origin,
        "--as-of",
        "1793620800",
    ]
}

/// A detached strict RSA CMS of `document` and its DER bytes.
fn signed(w: &World, document: &Path) -> Vec<u8> {
    let signature = w.dir.path().join("signature.der");
    let mut args = vec![
        "sign",
        "--profile",
        "cms",
        "--detached",
        "--input",
        path(document),
        "--output",
        path(&signature),
        "--key",
        path(&w.rsa_key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ];
    args.extend(common(w));
    let result = run(&args, b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    std::fs::read(&signature).unwrap()
}

fn verify(w: &World, file: &Path, document: &Path, extra: &[&str]) -> std::process::Output {
    let mut args = vec![
        "verify",
        "--profile",
        "cms",
        "--input",
        path(file),
        "--detached",
        path(document),
    ];
    args.extend(extra);
    args.extend(common(w));
    run(&args, b"")
}

fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[test]
fn pem_cms_is_decoded_only_when_asked_for_and_verifies_like_its_der() {
    let w = world();
    let document = w.dir.path().join("document.bin");
    std::fs::write(&document, b"abc").unwrap();
    let der = signed(&w, &document);
    let file = w.dir.path().join("signature.pem");

    for label in ["CMS", "PKCS7"] {
        std::fs::write(&file, pem(label, &der)).unwrap();
        let valid = verify(&w, &file, &document, &["--pem"]);
        assert_eq!(valid.status.code(), Some(0), "{label}: {valid:?}");
    }

    // Never inferred: without the flag the PEM text is not a CMS.
    std::fs::write(&file, pem("CMS", &der)).unwrap();
    let plain = verify(&w, &file, &document, &[]);
    assert_ne!(plain.status.code(), Some(0), "{plain:?}");

    // The decoded signature is judged: altered data is `Invalid` (2), as for the DER.
    let altered = w.dir.path().join("altered.bin");
    std::fs::write(&altered, b"abd").unwrap();
    let invalid = verify(&w, &file, &altered, &["--pem"]);
    assert_eq!(invalid.status.code(), Some(2), "{invalid:?}");
}

#[test]
fn pem_intake_is_strict_and_bounded() {
    let w = world();
    let document = w.dir.path().join("document.bin");
    std::fs::write(&document, b"abc").unwrap();
    let der = signed(&w, &document);
    let file = w.dir.path().join("signature.pem");
    // The same file, well-formed, verifies: the refusals below are about the text only.
    std::fs::write(&file, pem("CMS", &der)).unwrap();
    let valid = verify(&w, &file, &document, &["--pem"]);
    assert_eq!(valid.status.code(), Some(0), "{valid:?}");
    let refused = |text: &str| {
        std::fs::write(&file, text).unwrap();
        let out = verify(&w, &file, &document, &["--pem"]);
        assert_eq!(out.status.code(), Some(1), "{text:.80}: {out:?}");
    };
    // Another object, a second block, text around the block, a damaged body, nothing.
    refused(&pem("CERTIFICATE", &der));
    refused(&format!("{}{}", pem("CMS", &der), pem("CMS", &der)));
    refused(&format!("{}trailing", pem("CMS", &der)));
    refused(&format!("leading\n{}", pem("CMS", &der)));
    refused(&pem("CMS", &der).replace("A", "*"));
    refused("");
    refused("-----BEGIN CMS-----\n");

    // Larger than the cap (16 MiB of PEM text) is refused without decoding it.
    let mut huge = String::from("-----BEGIN CMS-----\n");
    let line = "A".repeat(64) + "\n";
    huge.push_str(&line.repeat((16 << 20) / 65 + 1));
    huge.push_str("-----END CMS-----\n");
    std::fs::write(&file, &huge).unwrap();
    let out = verify(&w, &file, &document, &["--pem"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");

    // Only for the CMS profile.
    std::fs::write(&file, pem("CMS", &der)).unwrap();
    let mut args = vec![
        "verify",
        "--profile",
        "xml",
        "--input",
        path(&file),
        "--pem",
    ];
    args.extend(common(&w));
    let out = run(&args, b"");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
}
