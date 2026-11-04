//! Operator-configured named key sources through the real `oncl` binary.
mod support;
use der::Encode;
use serde_json::json;
use std::path::{Path, PathBuf};
use support::*;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
/// The key configuration lives in an owner-only directory, like a secret file.
fn config(w: &World, value: serde_json::Value) -> PathBuf {
    let directory = w.dir.path().join("cfg-private");
    let namespace = oncl_pki::private_fs::PrivateDirectory::open(&directory)
        .or_else(|_| oncl_pki::private_fs::PrivateDirectory::create(&directory))
        .unwrap();
    let path = directory.join("keys.json");
    let _ = std::fs::remove_file(&path);
    std::io::Write::write_all(
        &mut namespace.create_file("keys.json").unwrap(),
        &serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    path
}
fn raw_config(w: &World, bytes: &[u8]) -> PathBuf {
    let directory = w.dir.path().join("cfg-private");
    let namespace = oncl_pki::private_fs::PrivateDirectory::open(&directory)
        .or_else(|_| oncl_pki::private_fs::PrivateDirectory::create(&directory))
        .unwrap();
    let _ = std::fs::remove_file(directory.join("raw.json"));
    std::io::Write::write_all(&mut namespace.create_file("raw.json").unwrap(), bytes).unwrap();
    directory.join("raw.json")
}
fn standard(w: &World) -> PathBuf {
    // Relative paths resolve against the config's directory, not the cwd.
    config(
        w,
        json!({"keys":[
            {"source":"file","name":"rsa-main","path":w.rsa_key},
            {"source":"file","name":"gost-main","path":w.gost_key},
            {"source":"file","name":"missing","path":w.dir.path().join("absent.p12")}
        ]}),
    )
}
fn sign<'a>(
    w: &'a World,
    cfg: &'a Path,
    name: &'a str,
    input: &'a Path,
    out: &'a Path,
) -> Vec<&'a str> {
    vec![
        "sign",
        "--profile",
        "cms",
        "--detached",
        "--input",
        path(input),
        "--output",
        path(out),
        "--key-name",
        name,
        "--key-config",
        path(cfg),
        "--secret-file",
        path(&w.secret),
        "--authorize",
        "--root",
        path(&w.root),
        "--pki-endpoint",
        &w.origin,
        "--as-of",
        "1793620800",
    ]
}
fn verify(w: &World, signature: &Path, document: &Path) -> std::process::Output {
    run(
        &[
            "verify",
            "--profile",
            "cms",
            "--input",
            path(signature),
            "--detached",
            path(document),
            "--json",
            "--root",
            path(&w.root),
            "--pki-endpoint",
            &w.origin,
            "--as-of",
            "1793620800",
        ],
        b"",
    )
}
#[test]
fn named_keys_select_the_configured_source_and_verify_valid() {
    let w = world();
    let cfg = standard(&w);
    let document = w.dir.path().join("document.bin");
    std::fs::write(&document, b"named key document").unwrap();
    for (name, expected, other) in [
        ("rsa-main", &w.pki.rsa, &w.pki.gost),
        ("gost-main", &w.pki.gost, &w.pki.rsa),
    ] {
        let signature = w.dir.path().join(format!("{name}.der"));
        let signed = run(&sign(&w, &cfg, name, &document, &signature), b"");
        assert_eq!(signed.status.code(), Some(0), "{name}: {signed:?}");
        let text = String::from_utf8_lossy(&signed.stderr);
        assert!(text.contains("applied=Applied succeeded=true"), "{text}");
        assert!(
            !text.contains(PASSWORD) && !text.contains("rsa.p12") && !text.contains("gost.p12")
        );
        let bytes = std::fs::read(&signature).unwrap();
        // Independent selection oracle: the embedded signer certificate DER.
        assert!(contains(&bytes, &expected.cert.to_der().unwrap()), "{name}");
        assert!(!contains(&bytes, &other.cert.to_der().unwrap()), "{name}");
        let result = verify(&w, &signature, &document);
        assert_eq!(result.status.code(), Some(0), "{name}: {result:?}");
    }
}
#[test]
fn unknown_missing_or_malformed_named_keys_fail_closed_before_private_use() {
    let w = world();
    let cfg = standard(&w);
    let document = w.dir.path().join("document.bin");
    std::fs::write(&document, b"abc").unwrap();
    let out = w.dir.path().join("out.der");
    let refuse = |args: Vec<&str>, label: &str, code: &str| {
        let result = run(&args, b"");
        assert_eq!(result.status.code(), Some(1), "{label}: {result:?}");
        let text = String::from_utf8_lossy(&result.stderr);
        assert!(
            !text.contains("private_use") && !text.contains(PASSWORD),
            "{label}: {text}"
        );
        assert!(text.contains(code), "{label}: {text}");
        assert!(!out.exists(), "{label}");
    };
    refuse(
        sign(&w, &cfg, "no-such-name", &document, &out),
        "unknown name",
        "KeyNotFound",
    );
    refuse(
        sign(&w, &cfg, "missing", &document, &out),
        "configured source absent",
        "Io",
    );
    refuse(
        sign(&w, &cfg, "bad/name", &document, &out),
        "name syntax",
        "InvalidInput",
    );
    for (label, value) in [
        (
            "duplicate",
            json!({"keys":[
            {"source":"file","name":"a","path":w.rsa_key},
            {"source":"file","name":"a","path":w.gost_key}]}),
        ),
        (
            "unknown field",
            json!({"keys":[{"source":"file","name":"rsa-main","path":w.rsa_key,"password":"x"}]}),
        ),
        (
            "unknown source",
            json!({"keys":[{"source":"pkcs11","name":"rsa-main","path":w.rsa_key}]}),
        ),
        (
            "bad token kind",
            json!({"keys":[{"source":"token","name":"rsa-main","reader":"r","kind":"nope","alias":"a"}]}),
        ),
    ] {
        let cfg = config(&w, value);
        refuse(
            sign(&w, &cfg, "rsa-main", &document, &out),
            label,
            "InvalidInput",
        );
    }
    // Oversize configuration is bounded before parsing.
    let big = raw_config(&w, &vec![b' '; 70_000]);
    refuse(
        sign(&w, &big, "rsa-main", &document, &out),
        "oversize config",
        "MetadataLimit",
    );
    // A name cannot be mixed with a client path, a token, or without its config.
    let mut both = sign(&w, &cfg, "rsa-main", &document, &out);
    both.extend(["--key", path(&w.rsa_key)]);
    assert_eq!(run(&both, b"").status.code(), Some(1));
    let mut no_config = sign(&w, &cfg, "rsa-main", &document, &out);
    let at = no_config.iter().position(|a| *a == "--key-config").unwrap();
    no_config.drain(at..at + 2);
    assert_eq!(run(&no_config, b"").status.code(), Some(1));
    assert!(!out.exists());
}
#[test]
fn named_jks_and_pkcs12_metadata_without_private_use_and_wrong_password_refused() {
    let w = world();
    let jks = oncl_testkit::fixture("jks/rsa.jks");
    let private = w.dir.path().join("private");
    let namespace = oncl_pki::private_fs::PrivateDirectory::open(&private).unwrap();
    std::io::Write::write_all(
        &mut namespace.create_file("jks.secret").unwrap(),
        b"Qwerty12",
    )
    .unwrap();
    let cfg = config(
        &w,
        json!({"keys":[
            {"source":"file","name":"jks-key","path":jks,"alias":"openncalayer-rsa"},
            {"source":"file","name":"p12-key","path":w.rsa_key}]}),
    );
    let secret = private.join("jks.secret");
    let inspect = |name: &str, secret: &Path| {
        run(
            &[
                "inspect",
                "--profile",
                "named-key",
                "--key-name",
                name,
                "--key-config",
                path(&cfg),
                "--secret-file",
                path(secret),
                "--alias",
                &w.pki.rsa.alias,
                "--json",
            ],
            b"",
        )
    };
    let result = inspect("jks-key", &secret);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["applied"], "NotApplied");
    assert_eq!(report["entries"].as_array().unwrap().len(), 1);
    assert_eq!(report["entries"][0]["alias"], "openncalayer-rsa");
    assert!(!String::from_utf8_lossy(&result.stdout).contains("Qwerty12"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("private_use"));
    // The PKCS#12 entry with the world's password (alias from the CLI grant).
    let p12 = inspect("p12-key", &w.secret);
    assert_eq!(p12.status.code(), Some(0), "{p12:?}");
    let report: serde_json::Value = serde_json::from_slice(&p12.stdout).unwrap();
    assert_eq!(report["entries"].as_array().unwrap().len(), 1);
    // Wrong password for the JKS entry fails closed.
    let wrong = inspect("jks-key", &w.secret);
    assert_eq!(wrong.status.code(), Some(1), "{wrong:?}");
    assert!(wrong.stdout.is_empty());
    // named-key needs a name and forbids --input; other profiles forbid a name.
    for args in [
        vec!["inspect", "--profile", "named-key"],
        vec![
            "inspect",
            "--profile",
            "named-key",
            "--key-name",
            "x",
            "--key-config",
            "c.json",
            "--input",
            "f",
        ],
        vec![
            "inspect",
            "--profile",
            "certificate",
            "--input",
            "f",
            "--key-name",
            "x",
            "--key-config",
            "c.json",
        ],
        vec!["inspect", "--profile", "certificate"],
    ] {
        let rejected = run(&args, b"");
        assert_eq!(rejected.status.code(), Some(1), "{args:?}");
    }
}
#[test]
fn batch_signs_with_a_named_key_and_rejects_a_name_with_a_path() {
    let w = world();
    let cfg = standard(&w);
    let document = w.dir.path().join("a.bin");
    std::fs::write(&document, b"batch named").unwrap();
    let signature = w.dir.path().join("a.der");
    let manifest = w.dir.path().join("batch.json");
    std::fs::write(
        &manifest,
        serde_json::to_vec(&json!({"items":[
            {"op":"sign","id":"s","profile":"cms-detached","input":document,"output":signature}
        ]}))
        .unwrap(),
    )
    .unwrap();
    let args = vec![
        "batch",
        "run",
        "--manifest",
        path(&manifest),
        "--key-name",
        "rsa-main",
        "--key-config",
        path(&cfg),
        "--secret-file",
        path(&w.secret),
        "--authorize",
        "--json",
        "--root",
        path(&w.root),
        "--pki-endpoint",
        &w.origin,
        "--as-of",
        "1793620800",
    ];
    let result = run(&args, b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert!(contains(
        &std::fs::read(&signature).unwrap(),
        &w.pki.rsa.cert.to_der().unwrap()
    ));
    assert_eq!(verify(&w, &signature, &document).status.code(), Some(0));
    let mut mixed = args.clone();
    mixed.extend(["--key", path(&w.rsa_key)]);
    assert_eq!(run(&mixed, b"").status.code(), Some(1));
    // Secrets without any key are a typed refusal, not ignored.
    let result = run(
        &[
            "batch",
            "run",
            "--manifest",
            path(&manifest),
            "--authorize",
            "--secret-file",
            path(&w.secret),
        ],
        b"",
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("InvalidCombination"));
}

#[test]
fn key_configuration_is_an_owner_only_regular_file_with_an_exact_size_cap() {
    let w = world();
    let document = w.dir.path().join("document.bin");
    std::fs::write(&document, b"abc").unwrap();
    let out = w.dir.path().join("out.der");
    let valid = serde_json::to_vec(&json!({"keys":[
        {"source":"file","name":"rsa-main","path":w.rsa_key}]}))
    .unwrap();
    // Exactly 65536 bytes (valid JSON padded with spaces) is accepted; 65537 is not.
    let mut exact = valid.clone();
    exact.resize(65_536, b' ');
    let cfg = raw_config(&w, &exact);
    let signed = run(&sign(&w, &cfg, "rsa-main", &document, &out), b"");
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    let mut over = valid.clone();
    over.resize(65_537, b' ');
    let cfg = raw_config(&w, &over);
    let out2 = w.dir.path().join("out2.der");
    let refused = run(&sign(&w, &cfg, "rsa-main", &document, &out2), b"");
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("MetadataLimit"));
    assert!(!out2.exists());
    // An ordinary (not owner-only) directory is refused: the file selects which
    // container a granted named key reaches, so it is held to the secret-file policy.
    let open = w.dir.path().join("open-keys.json");
    std::fs::write(&open, &valid).unwrap();
    let out3 = w.dir.path().join("out3.der");
    let refused = run(&sign(&w, &open, "rsa-main", &document, &out3), b"");
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    assert!(!String::from_utf8_lossy(&refused.stderr).contains("private_use"));
    assert!(!out3.exists());
    // A directory (or any non-regular file) in its place is refused. FIFOs and
    // devices are not creatable by this unprivileged Windows test user; the
    // regular-file check (`is_file`) covers them on every platform.
    let out4 = w.dir.path().join("out4.der");
    let dir_cfg = w.dir.path().join("cfg-private");
    let refused = run(&sign(&w, &dir_cfg, "rsa-main", &document, &out4), b"");
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    assert!(!out4.exists());
}
#[test]
fn a_container_whose_certificate_does_not_match_its_key_is_refused_before_private_use() {
    use der::Encode as _;
    let w = world();
    // The RSA key paired with the GOST leaf certificate: a PKCS#12 that is
    // internally inconsistent.
    let bytes = oncl_pki::pkcs12::write(
        &[oncl_pki::pkcs12::WriteEntry {
            alias: "mismatch".into(),
            pkcs8_der: w.pki.rsa.key.to_pkcs8_der().unwrap().to_vec(),
            cert_der: Some(w.pki.gost.cert.to_der().unwrap()),
        }],
        &[],
        PASSWORD,
        &oncl_pki::pkcs12::WriteOptions::default(),
        &mut |b| b.fill(0x5a),
    )
    .unwrap();
    let mismatched = w.dir.path().join("mismatch.p12");
    std::fs::write(&mismatched, bytes).unwrap();
    let document = w.dir.path().join("document.bin");
    std::fs::write(&document, b"abc").unwrap();
    let cfg = config(
        &w,
        json!({"keys":[{"source":"file","name":"bad","path":mismatched}]}),
    );
    let direct = w.dir.path().join("direct.der");
    let named = w.dir.path().join("named.der");
    let mut by_path = vec![
        "sign",
        "--profile",
        "cms",
        "--detached",
        "--input",
        path(&document),
        "--output",
        path(&direct),
        "--key",
        path(&mismatched),
        "--secret-file",
        path(&w.secret),
        "--authorize",
        "--root",
        path(&w.root),
        "--pki-endpoint",
        &w.origin,
        "--as-of",
        "1793620800",
    ];
    let first = run(&by_path, b"");
    by_path.clear();
    let second = run(&sign(&w, &cfg, "bad", &document, &named), b"");
    for (label, result, out) in [("direct", &first, &direct), ("named", &second, &named)] {
        assert_eq!(result.status.code(), Some(1), "{label}: {result:?}");
        let text = String::from_utf8_lossy(&result.stderr);
        eprintln!("MISMATCH {label}: {}", text.trim());
        assert!(!text.contains("private_use"), "{label}: {text}");
        assert!(text.contains("applied=NotApplied"), "{label}: {text}");
        assert!(!out.exists(), "{label}");
    }
}
