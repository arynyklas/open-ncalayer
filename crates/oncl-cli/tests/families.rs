//! Keyless/standalone families and PDF through the real binary: RFC 3161
//! timestamp acquire/verify, CAdES evidence extension, PDF and PAdES sign +
//! verify with an independent ByteRange/OpenSSL oracle.
mod support;
use std::{path::Path, process::Command};
use support::*;

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
fn openssl() -> String {
    openssl_command()
}
fn python() -> &'static str {
    ["python", "python3", "py"]
        .into_iter()
        .find(|c| Command::new(c).arg("--version").output().is_ok())
        .expect("python")
}
#[test]
fn timestamp_acquire_then_verify_is_valid_and_altered_data_is_not() {
    let w = world();
    let tsa = format!("{}/tsa", w.origin);
    let doc = w.dir.path().join("doc.bin");
    let altered = w.dir.path().join("altered.bin");
    std::fs::write(&doc, b"stamp me").unwrap();
    std::fs::write(&altered, b"stamp mf").unwrap();
    let token = w.dir.path().join("doc.tst");
    let mut acquire = vec![
        "timestamp",
        "acquire",
        "--input",
        path(&doc),
        "--output",
        path(&token),
        "--tsa",
        &tsa,
        "--json",
    ];
    acquire.extend(trust(&w));
    let result = run(&acquire, b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        (report["verdict"].as_str(), report["policy"].as_str()),
        (Some("Valid"), Some("StrictOnline"))
    );
    // Independent oracle: the token is a DER CMS and its TSTInfo imprint is SHA-256("stamp me").
    let bytes = std::fs::read(&token).unwrap();
    // sha256("stamp me") computed with Python hashlib.
    let imprint: Vec<u8> = (0..32)
        .map(|i| {
            u8::from_str_radix(
                &"9b2991a8c40f07495278544db1d4c4e762c00f690a27c69ce1e9c2e0b2d375e8"
                    [i * 2..i * 2 + 2],
                16,
            )
            .unwrap()
        })
        .collect();
    assert!(
        bytes.windows(32).any(|w| w == imprint.as_slice()),
        "imprint not in token"
    );
    let verify = |data: &Path, offline: bool| {
        let mut args = vec![
            "timestamp",
            "verify",
            "--input",
            path(&token),
            "--data",
            path(data),
            "--json",
        ];
        args.extend(trust(&w));
        if offline {
            args.push("--offline");
        }
        run(&args, b"").status.code()
    };
    assert_eq!(verify(&doc, false), Some(0));
    assert_eq!(verify(&altered, false), Some(2));
}
#[test]
fn pdf_pades_b_and_t_sign_verify_with_an_independent_byterange_openssl_oracle() {
    let w = world();
    let tsa = format!("{}/tsa", w.origin);
    let pdf = oncl_testkit::workspace_root()
        .join("crates/oncl-pdf/tests/fixtures/external-multipage.pdf");
    let original = std::fs::read(&pdf).unwrap();
    let script = w.dir.path().join("pdf_signature.py");
    std::fs::write(&script, include_str!("support/pdf_signature.py")).unwrap();
    for (profile, evidence) in [("pdf", false), ("pades-b", false), ("pades-t", true)] {
        let out = w.dir.path().join(format!("{profile}.pdf"));
        let mut args = vec![
            "sign",
            "--profile",
            profile,
            "--input",
            path(&pdf),
            "--output",
            path(&out),
            "--key",
            path(&w.rsa_key),
            "--secret-file",
            path(&w.secret),
            "--authorize",
        ];
        if evidence {
            args.extend(["--tsa-url", &tsa, "--tsa-policy", "1.2.398.3.3.2.6.2"]);
        }
        args.extend(trust(&w));
        let signed = run(&args, b"");
        assert_eq!(signed.status.code(), Some(0), "{profile}: {signed:?}");
        let mut verify = vec![
            "verify",
            "--profile",
            profile,
            "--input",
            path(&out),
            "--json",
        ];
        verify.extend(trust(&w));
        let valid = run(&verify, b"");
        assert_eq!(valid.status.code(), Some(0), "{profile}: {valid:?}");
        // The source revision is preserved byte-for-byte (incremental update).
        let signed_bytes = std::fs::read(&out).unwrap();
        assert_eq!(&signed_bytes[..original.len()], &original[..], "{profile}");
        // Independent oracle: ByteRange covers the whole file except /Contents, and
        // the embedded CMS verifies over exactly those bytes with OpenSSL.
        let (covered, cms) = (
            w.dir.path().join(format!("{profile}.covered")),
            w.dir.path().join(format!("{profile}.cms")),
        );
        let extract = Command::new(python())
            .args([path(&script), path(&out), path(&covered), path(&cms)])
            .output()
            .unwrap();
        assert!(
            extract.status.success(),
            "{}",
            String::from_utf8_lossy(&extract.stderr)
        );
        let root_pem = w.dir.path().join("root.pem");
        assert!(
            Command::new(openssl())
                .args([
                    "x509",
                    "-inform",
                    "DER",
                    "-in",
                    path(&w.root),
                    "-out",
                    path(&root_pem)
                ])
                .status()
                .unwrap()
                .success()
        );
        let check = |content: &Path| {
            Command::new(openssl())
                .args([
                    "cms",
                    "-verify",
                    "-binary",
                    "-inform",
                    "DER",
                    "-in",
                    path(&cms),
                    "-content",
                    path(content),
                    "-CAfile",
                    path(&root_pem),
                    "-purpose",
                    "any",
                    "-no_check_time",
                    "-out",
                ])
                .arg(w.dir.path().join("oracle.out"))
                .output()
                .unwrap()
        };
        let good = check(&covered);
        assert!(
            good.status.success(),
            "{profile}: {}",
            String::from_utf8_lossy(&good.stderr)
        );
        // Flip one covered byte: OpenSSL and the CLI both reject (CLI: Invalid, 2).
        let mut tampered_bytes = signed_bytes.clone();
        tampered_bytes[200] ^= 0x01;
        let tampered = w.dir.path().join(format!("{profile}.tampered.pdf"));
        std::fs::write(&tampered, &tampered_bytes).unwrap();
        let (covered2, cms2) = (w.dir.path().join("t.covered"), w.dir.path().join("t.cms"));
        assert!(
            Command::new(python())
                .args([path(&script), path(&tampered), path(&covered2), path(&cms2)])
                .status()
                .unwrap()
                .success()
        );
        assert!(!check(&covered2).status.success(), "{profile}");
        let mut bad = vec![
            "verify",
            "--profile",
            profile,
            "--input",
            path(&tampered),
            "--json",
        ];
        bad.extend(trust(&w));
        assert_eq!(run(&bad, b"").status.code(), Some(2), "{profile}");
    }
}
