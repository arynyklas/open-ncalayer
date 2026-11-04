//! CAdES LT/LTA signing and keyless evidence extension through the real binary,
//! with operator-supplied public validation material (certificates, OCSP
//! responses) and loopback TSA. Independent oracle: `openssl cms -verify`.
mod support;
use der::Encode;
use oncl_pki::{
    http::{GetOptions, HttpRequest, HttpTransport},
    ocsp::{MockOcsp, request_der},
};
use std::{
    path::{Path, PathBuf},
    process::Command,
};
use support::*;

const POLICY: &str = "1.2.398.3.3.2.6.2";

fn ocsp_for(w: &World, cert: &x509_cert::Certificate) -> Vec<u8> {
    let responder =
        MockOcsp::new(w.pki.responder.clone()).with_now(now() + time::Duration::seconds(60));
    let request = request_der(cert, &w.pki.root.cert);
    responder
        .send(&HttpRequest::post(
            &format!("{}/ocsp", w.origin),
            Some("application/ocsp-request"),
            &request,
            GetOptions::default(),
        ))
        .unwrap()
        .body
}
struct Material {
    files: Vec<PathBuf>,
}
fn material(w: &World) -> Material {
    let dir = w.dir.path();
    let files = vec![
        (
            "root.der",
            w.pki.root.cert.to_der().unwrap(),
            "--evidence-certificate",
        ),
        (
            "tsa.der",
            w.pki.tsa.cert.to_der().unwrap(),
            "--evidence-certificate",
        ),
        ("leaf.ocsp", ocsp_for(w, &w.pki.rsa.cert), "--evidence-ocsp"),
        ("tsa.ocsp", ocsp_for(w, &w.pki.tsa.cert), "--evidence-ocsp"),
    ];
    let mut out = Vec::new();
    for (name, bytes, _) in &files {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        out.push(p);
    }
    Material { files: out }
}
impl Material {
    fn args(&self) -> Vec<&str> {
        let flags = [
            "--evidence-certificate",
            "--evidence-certificate",
            "--evidence-ocsp",
            "--evidence-ocsp",
        ];
        let mut args = Vec::new();
        for (flag, file) in flags.iter().zip(&self.files) {
            args.extend([*flag, path(file)]);
        }
        args
    }
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
fn tsa_args(tsa: &str) -> Vec<&str> {
    vec!["--tsa-url", tsa, "--tsa-policy", POLICY]
}
fn openssl_verify(w: &World, signature: &Path, content: &Path) -> bool {
    let openssl = ["openssl", r"drive_C:\Program Files\Git\usr\bin\openssl.exe"]
        .into_iter()
        .find(|c| {
            Command::new(c)
                .arg("version")
                .output()
                .is_ok_and(|o| o.status.success())
        })
        .expect("OpenSSL oracle");
    let root_pem = w.dir.path().join("root.pem");
    assert!(
        Command::new(openssl)
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
    Command::new(openssl)
        .args([
            "cms",
            "-verify",
            "-binary",
            "-inform",
            "DER",
            "-in",
            path(signature),
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
        .status
        .success()
}
fn level_of(
    w: &World,
    profile: &str,
    signature: &Path,
    content: &Path,
) -> (Option<i32>, serde_json::Value) {
    let mut args = vec![
        "verify",
        "--profile",
        profile,
        "--input",
        path(signature),
        "--detached",
        path(content),
        "--json",
    ];
    args.extend(trust(w));
    let result = run(&args, b"");
    let report = serde_json::from_slice(&result.stdout).unwrap_or(serde_json::Value::Null);
    (result.status.code(), report)
}
#[test]
fn cades_lt_and_lta_sign_from_operator_material_verify_at_level_and_with_openssl() {
    let w = world();
    let tsa = format!("{}/tsa", w.origin);
    let m = material(&w);
    let doc = w.dir.path().join("doc.bin");
    std::fs::write(&doc, b"evidence document").unwrap();
    for (profile, level) in [("cades-lt", "Lt"), ("cades-lta", "Lta")] {
        let out = w.dir.path().join(format!("{profile}.der"));
        let mut args = vec![
            "sign",
            "--profile",
            profile,
            "--detached",
            "--input",
            path(&doc),
            "--output",
            path(&out),
            "--key",
            path(&w.rsa_key),
            "--secret-file",
            path(&w.secret),
            "--authorize",
        ];
        args.extend(tsa_args(&tsa));
        args.extend(m.args());
        args.extend(trust(&w));
        let signed = run(&args, b"");
        assert_eq!(signed.status.code(), Some(0), "{profile}: {signed:?}");
        let (code, report) = level_of(&w, profile, &out, &doc);
        assert_eq!(code, Some(0), "{profile}: {report}");
        assert_eq!(report["ades_level"], level);
        assert!(
            openssl_verify(&w, &out, &doc),
            "{profile}: independent OpenSSL verification"
        );
        // The operator's OCSP response is embedded (independent byte oracle).
        let bytes = std::fs::read(&out).unwrap();
        let ocsp = std::fs::read(&m.files[2]).unwrap();
        let basic = &ocsp[ocsp.len().saturating_sub(64)..];
        assert!(
            bytes.windows(basic.len()).any(|w| w == basic),
            "{profile}: OCSP not embedded"
        );
        // Altered content is Invalid (2).
        let altered = w.dir.path().join("altered.bin");
        std::fs::write(&altered, b"evidence docuMent").unwrap();
        assert_eq!(
            level_of(&w, profile, &out, &altered).0,
            Some(2),
            "{profile}"
        );
        assert!(!openssl_verify(&w, &out, &altered));
    }
    // Missing required material fails before private use with a typed refusal.
    let out = w.dir.path().join("refused.der");
    let mut args = vec![
        "sign",
        "--profile",
        "cades-lt",
        "--detached",
        "--input",
        path(&doc),
        "--output",
        path(&out),
        "--key",
        path(&w.rsa_key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ];
    args.extend(tsa_args(&tsa));
    args.extend(trust(&w));
    let refused = run(&args, b"");
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    let text = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !text.contains("private_use") && text.contains("EvidenceMaterialRequired"),
        "{text}"
    );
    assert!(!out.exists());
    // Evidence options on commands that cannot use them are rejected before I/O.
    let misplaced = run(
        &[
            "hash",
            "--algorithm",
            "sha256",
            "--input",
            "-",
            "--evidence-crl",
            "x.crl",
        ],
        b"abc",
    );
    assert_eq!(misplaced.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&misplaced.stderr).contains("InvalidCombination"));
}
#[test]
fn keyless_extend_b_to_t_to_lt_to_lta_with_no_key_provider_and_tampered_evidence_is_rejected() {
    let w = world();
    let tsa = format!("{}/tsa", w.origin);
    let m = material(&w);
    let doc = w.dir.path().join("doc.bin");
    std::fs::write(&doc, b"extend me").unwrap();
    let mut current = w.dir.path().join("b.der");
    let mut args = vec![
        "sign",
        "--profile",
        "cades-b",
        "--detached",
        "--input",
        path(&doc),
        "--output",
        path(&current),
        "--key",
        path(&w.rsa_key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ];
    args.extend(trust(&w));
    assert_eq!(run(&args, b"").status.code(), Some(0));
    assert_eq!(level_of(&w, "cades-b", &current, &doc).1["ades_level"], "B");
    for (level, verify_as, label) in [
        ("t", "cades-t", "T"),
        ("lt", "cades-lt", "Lt"),
        ("lta", "cades-lta", "Lta"),
    ] {
        let next = w.dir.path().join(format!("extended-{level}.der"));
        let mut extend = vec![
            "extend",
            "--profile",
            "cms",
            "--level",
            level,
            "--input",
            path(&current),
            "--detached",
            path(&doc),
            "--output",
            path(&next),
        ];
        extend.extend(tsa_args(&tsa));
        if level != "t" {
            extend.extend(m.args());
        }
        extend.extend(trust(&w));
        let result = run(&extend, b"");
        assert_eq!(result.status.code(), Some(0), "{level}: {result:?}");
        // Keyless: no key source exists on the command line and no private use happens.
        let text = String::from_utf8_lossy(&result.stderr);
        assert!(!text.contains("private_use"), "{level}: {text}");
        let (code, report) = level_of(&w, verify_as, &next, &doc);
        assert_eq!(code, Some(0), "{level}: {report}");
        assert_eq!(report["ades_level"], label);
        assert!(openssl_verify(&w, &next, &doc), "{level}: OpenSSL");
        current = next;
    }
    // A key option on `extend` does not exist at all.
    let with_key = run(
        &[
            "extend",
            "--profile",
            "cms",
            "--level",
            "t",
            "--input",
            "x",
            "--output",
            "-",
            "--key",
            "k",
        ],
        b"",
    );
    assert_eq!(with_key.status.code(), Some(1));
    // Renewal: extending an LTA again with a fresh archive timestamp stays Lta.
    let renewed = w.dir.path().join("renewed.der");
    let mut renew = vec![
        "extend",
        "--profile",
        "cms",
        "--level",
        "lta",
        "--input",
        path(&current),
        "--detached",
        path(&doc),
        "--output",
        path(&renewed),
    ];
    renew.extend(tsa_args(&tsa));
    renew.extend(m.args());
    renew.extend(trust(&w));
    let result = run(&renew, b"");
    assert_eq!(result.status.code(), Some(0), "renewal: {result:?}");
    assert_eq!(level_of(&w, "cades-lta", &renewed, &doc).0, Some(0));
    // Tampered evidence (one flipped byte of the leaf OCSP response) is refused, no output.
    let mut bad = std::fs::read(&m.files[2]).unwrap();
    let at = bad.len() / 2;
    bad[at] ^= 0x55;
    let bad_ocsp = w.dir.path().join("bad.ocsp");
    std::fs::write(&bad_ocsp, bad).unwrap();
    let out = w.dir.path().join("tampered-lt.der");
    let t = w.dir.path().join("extended-t.der");
    let mut tampered = vec![
        "extend",
        "--profile",
        "cms",
        "--level",
        "lt",
        "--input",
        path(&t),
        "--detached",
        path(&doc),
        "--output",
        path(&out),
        "--evidence-certificate",
        path(&m.files[0]),
        "--evidence-certificate",
        path(&m.files[1]),
        "--evidence-ocsp",
        path(&bad_ocsp),
        "--evidence-ocsp",
        path(&m.files[3]),
    ];
    tampered.extend(tsa_args(&tsa));
    tampered.extend(trust(&w));
    let result = run(&tampered, b"");
    assert_ne!(result.status.code(), Some(0), "{result:?}");
    assert!(!out.exists());
    // Tampered content under the LTA signature is Invalid (2).
    let altered = w.dir.path().join("altered.bin");
    std::fs::write(&altered, b"extend mf").unwrap();
    assert_eq!(level_of(&w, "cades-lta", &current, &altered).0, Some(2));
}
