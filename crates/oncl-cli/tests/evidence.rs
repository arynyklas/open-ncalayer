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
    let openssl = openssl_command();
    let root_pem = w.dir.path().join("root.pem");
    assert!(
        Command::new(&openssl)
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
    Command::new(&openssl)
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
fn pdf_fixture() -> PathBuf {
    oncl_testkit::workspace_root().join("crates/oncl-pdf/tests/fixtures/external-multipage.pdf")
}
fn pyhanko(w: &World, pdf: &Path) -> (bool, serde_json::Value, String) {
    // ONCL_PYHANKO_PYTHON must name a Python with pyHanko installed (see
    // docs/user/cli.md, "Oracle environments"); there is no default.
    let python = std::env::var("ONCL_PYHANKO_PYTHON").unwrap_or_default();
    let python = python.as_str();
    assert!(
        !python.is_empty() && Path::new(python).exists(),
        "pyHanko oracle interpreter unavailable (ONCL_PYHANKO_PYTHON={python:?}): create a virtualenv with `python -m venv <dir>` and `<dir>/bin/pip install pyhanko pyhanko-certvalidator` (Scripts/ on Windows), then set ONCL_PYHANKO_PYTHON to its python executable"
    );
    let script = w.dir.path().join("pyhanko_oracle.py");
    std::fs::write(&script, include_str!("support/pyhanko_oracle.py")).unwrap();
    let out = Command::new(python)
        .args([path(&script), path(pdf), path(&w.root), "1793620920"])
        .output()
        .unwrap();
    let json = serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    eprintln!("PYHANKO {}", String::from_utf8_lossy(&out.stdout).trim());
    (out.status.success(), json, err)
}
fn cli_pdf_level(w: &World, level: &str, pdf: &Path) -> (Option<i32>, serde_json::Value) {
    let mut v = vec!["verify", "--profile", level, "--input", path(pdf), "--json"];
    v.extend(trust(w));
    let result = run(&v, b"");
    (
        result.status.code(),
        serde_json::from_slice(&result.stdout).unwrap_or(serde_json::Value::Null),
    )
}
fn tampered_copy(w: &World, pdf: &Path, name: &str) -> PathBuf {
    let mut bytes = std::fs::read(pdf).unwrap();
    bytes[300] ^= 0x01; // inside the original, signed revision
    let out = w.dir.path().join(name);
    std::fs::write(&out, bytes).unwrap();
    out
}
#[test]
fn pades_lt_and_lta_sign_and_keyless_extend_verify_with_pyhanko_dss_and_doctimestamp() {
    let w = world();
    let tsa = format!("{}/tsa", w.origin);
    let m = material(&w);
    let pdf = pdf_fixture();
    let check = |file: &Path, label: &str, doc_timestamps: u64| {
        let (ok, json, err) = pyhanko(&w, file);
        assert!(ok, "{label}: pyHanko rejected: {json} {err}");
        assert_eq!(json["signatures"], 1, "{label}");
        assert_eq!(json["doc_timestamps"], doc_timestamps, "{label}");
        // Validation material is in the DSS (the oracle validates from it alone, with
        // revocation required and fetching disabled).
        assert!(
            json["dss"]["certs"].as_u64().unwrap() >= 2,
            "{label}: {json}"
        );
        assert!(
            json["dss"]["ocsps"].as_u64().unwrap() >= 1,
            "{label}: {json}"
        );
        for item in json["results"].as_array().unwrap() {
            assert_eq!(item["bottom_line"], true, "{label}: {json}");
        }
    };
    for (profile, level, timestamps) in [("pades-lt", "Lt", 0u64), ("pades-lta", "Lta", 1)] {
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
        args.extend(tsa_args(&tsa));
        args.extend(m.args());
        args.extend(trust(&w));
        let signed = run(&args, b"");
        assert_eq!(signed.status.code(), Some(0), "{profile}: {signed:?}");
        let (code, report) = cli_pdf_level(&w, profile, &out);
        assert_eq!(code, Some(0), "{profile}: {report}");
        assert_eq!(report["ades_level"], level);
        check(&out, profile, timestamps);
        // Tamper negative: CLI Invalid (2), pyHanko no longer intact.
        let bad = tampered_copy(&w, &out, &format!("{profile}-tampered.pdf"));
        assert_eq!(cli_pdf_level(&w, profile, &bad).0, Some(2), "{profile}");
        let (ok, json, _) = pyhanko(&w, &bad);
        assert!(!ok, "{profile}: pyHanko accepted a tampered PDF: {json}");
    }
    // Keyless extend PAdES-T -> LT -> LTA with no key provider.
    let t = w.dir.path().join("t.pdf");
    let mut sign = vec![
        "sign",
        "--profile",
        "pades-t",
        "--input",
        path(&pdf),
        "--output",
        path(&t),
        "--key",
        path(&w.rsa_key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ];
    sign.extend(tsa_args(&tsa));
    sign.extend(trust(&w));
    assert_eq!(run(&sign, b"").status.code(), Some(0));
    let mut current = t;
    for (level, profile, label, timestamps) in [
        ("lt", "pades-lt", "Lt", 0u64),
        ("lta", "pades-lta", "Lta", 1),
    ] {
        let next = w.dir.path().join(format!("extended-{level}.pdf"));
        let mut ext = vec![
            "extend",
            "--profile",
            "pdf",
            "--level",
            level,
            "--input",
            path(&current),
            "--output",
            path(&next),
        ];
        ext.extend(tsa_args(&tsa));
        ext.extend(m.args());
        ext.extend(trust(&w));
        let result = run(&ext, b"");
        assert_eq!(result.status.code(), Some(0), "{level}: {result:?}");
        assert!(!String::from_utf8_lossy(&result.stderr).contains("private_use"));
        let (code, report) = cli_pdf_level(&w, profile, &next);
        assert_eq!(code, Some(0), "{level}: {report}");
        assert_eq!(report["ades_level"], label);
        check(&next, &format!("extend-{level}"), timestamps);
        current = next;
    }
    // Tampered evidence is refused by `extend` with no output.
    let mut bad = std::fs::read(&m.files[2]).unwrap();
    let at = bad.len() / 2;
    bad[at] ^= 0x55;
    let bad_ocsp = w.dir.path().join("bad-pdf.ocsp");
    std::fs::write(&bad_ocsp, bad).unwrap();
    let out = w.dir.path().join("tampered-evidence.pdf");
    let t = w.dir.path().join("t.pdf");
    let mut ext = vec![
        "extend",
        "--profile",
        "pdf",
        "--level",
        "lt",
        "--input",
        path(&t),
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
    ext.extend(tsa_args(&tsa));
    ext.extend(trust(&w));
    let refused = run(&ext, b"");
    assert_ne!(refused.status.code(), Some(0), "{refused:?}");
    assert!(!out.exists());
}
fn big_file(w: &World, name: &str, len: usize) -> PathBuf {
    let p = w.dir.path().join(name);
    std::fs::write(&p, vec![0x30u8; len]).unwrap();
    p
}
/// Evidence admission happens before any document or key I/O: the input and key
/// are deliberately missing in every case.
fn lt_args<'a>(profile: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut a = vec![
        "sign",
        "--profile",
        profile,
        "--input",
        "missing-document",
        "--output",
        "-",
        "--key",
        "missing-key",
        "--authorize",
    ];
    a.extend(extra);
    a
}
fn stderr_of(r: &std::process::Output) -> String {
    String::from_utf8_lossy(&r.stderr).into_owned()
}
#[test]
fn evidence_bounds_and_ordering_are_enforced_before_document_and_key_io() {
    let w = world();
    let root = w.dir.path().join("root.der");
    std::fs::write(&root, w.pki.root.cert.to_der().unwrap()).unwrap();
    let cert = path(&root);
    // Per-file cap: 256 KiB accepted (fails later on the missing input), +1 refused first.
    let ok = big_file(&w, "ok.ocsp", 262_144);
    let over = big_file(&w, "over.ocsp", 262_145);
    let r = run(
        &lt_args(
            "cades-lt",
            &["--evidence-certificate", cert, "--evidence-ocsp", path(&ok)],
        ),
        b"",
    );
    assert!(
        !stderr_of(&r).contains("MetadataLimit"),
        "{}",
        stderr_of(&r)
    );
    let r = run(
        &lt_args(
            "cades-lt",
            &[
                "--evidence-certificate",
                cert,
                "--evidence-ocsp",
                path(&over),
            ],
        ),
        b"",
    );
    assert_eq!(r.status.code(), Some(1));
    assert!(stderr_of(&r).contains("MetadataLimit"), "{}", stderr_of(&r));
    // Total cap: 32 x 256 KiB = 8 MiB exactly is admitted, one more byte is not.
    let mut exact = vec!["--evidence-certificate", cert];
    let files: Vec<PathBuf> = (0..31).map(|_| ok.clone()).collect();
    for f in &files {
        exact.extend(["--evidence-ocsp", path(f)]);
    }
    // 1 root cert (~900 B) + 31 x 262144 + 262144 - 1 stays under 8 MiB; add the 32nd full file to cross it.
    let mut under = exact.clone();
    let almost = big_file(&w, "almost.ocsp", 262_144 - 2_048);
    under.extend(["--evidence-ocsp", path(&almost)]);
    let r = run(&lt_args("cades-lt", &under), b"");
    assert!(
        !stderr_of(&r).contains("MetadataLimit"),
        "N: {}",
        stderr_of(&r)
    );
    let mut crossing = exact.clone();
    crossing.extend(["--evidence-ocsp", path(&ok)]);
    let r = run(&lt_args("cades-lt", &crossing), b"");
    assert!(
        stderr_of(&r).contains("MetadataLimit"),
        "N+1: {}",
        stderr_of(&r)
    );
    // Item cap: 64 admitted, 65 refused by preflight.
    let mut many = vec!["--evidence-certificate", cert];
    let small = big_file(&w, "tiny.ocsp", 8);
    for _ in 0..64 {
        many.extend(["--evidence-ocsp", path(&small)]);
    }
    let r = run(&lt_args("cades-lt", &many), b"");
    assert!(
        !stderr_of(&r).contains("ConfigurationLimit"),
        "{}",
        stderr_of(&r)
    );
    many.extend(["--evidence-ocsp", path(&small)]);
    let r = run(&lt_args("cades-lt", &many), b"");
    assert!(
        stderr_of(&r).contains("ConfigurationLimit"),
        "{}",
        stderr_of(&r)
    );
    // EvidenceMaterialRequired for every LT/LTA profile, with a missing input (pre-I/O).
    for profile in ["cades-lt", "cades-lta", "pades-lt", "pades-lta"] {
        let r = run(&lt_args(profile, &[]), b"");
        assert_eq!(r.status.code(), Some(1), "{profile}");
        assert!(
            stderr_of(&r).contains("EvidenceMaterialRequired"),
            "{profile}: {}",
            stderr_of(&r)
        );
    }
    // Evidence options are InvalidCombination outside CAdES/PAdES sign and extend.
    for args in [
        lt_args("xml", &["--evidence-crl", "x.crl"]),
        lt_args("wsse", &["--evidence-crl", "x.crl"]),
        vec![
            "jws",
            "sign",
            "--serialization",
            "compact",
            "--input",
            "m",
            "--output",
            "-",
            "--key",
            "k",
            "--authorize",
            "--evidence-crl",
            "x.crl",
        ],
        vec![
            "verify",
            "--profile",
            "cms",
            "--input",
            "m",
            "--evidence-crl",
            "x.crl",
        ],
    ] {
        let r = run(&args, b"");
        assert_eq!(r.status.code(), Some(1), "{args:?}");
        assert!(
            stderr_of(&r).contains("InvalidCombination"),
            "{args:?}: {}",
            stderr_of(&r)
        );
    }
}
