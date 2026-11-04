//! Strict signing with a JKS container. The JKS is built by an independent,
//! test-only Python writer (`support/jks_write.py`, hashlib only) around a leaf
//! issued by the loopback CA, and by Java's own `keytool` (an independent JKS
//! writer AND reader): the Python-written JKS must be listed and converted by
//! keytool, and a keytool-written JKS must sign strictly through the CLI.
mod support;
use der::Encode;
use std::{path::PathBuf, process::Command};
use support::*;

fn python() -> &'static str {
    ["python", "python3", "py"]
        .into_iter()
        .find(|c| Command::new(c).arg("--version").output().is_ok())
        .expect("python is required for the JKS writer")
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
fn keytool(args: &[&str]) -> std::process::Output {
    Command::new("keytool")
        .args(args)
        .output()
        .expect("Java keytool")
}
fn jks(w: &World, alias: &str) -> PathBuf {
    let script = w.dir.path().join("jks_write.py");
    std::fs::write(&script, include_str!("support/jks_write.py")).unwrap();
    let (pkcs8, leaf, root) = (
        w.dir.path().join("leaf.pk8"),
        w.dir.path().join("leaf.der"),
        w.dir.path().join("root.der"),
    );
    std::fs::write(&pkcs8, w.pki.rsa.key.to_pkcs8_der().unwrap()).unwrap();
    std::fs::write(&leaf, w.pki.rsa.cert.to_der().unwrap()).unwrap();
    std::fs::write(&root, w.pki.root.cert.to_der().unwrap()).unwrap();
    let out = w.dir.path().join("signer.jks");
    let status = Command::new(python())
        .args([
            path(&script),
            path(&out),
            alias,
            PASSWORD,
            path(&pkcs8),
            path(&leaf),
            path(&root),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    out
}
#[test]
fn strict_jks_sign_then_valid_zero_with_openssl_and_wrong_password_refused() {
    let w = world();
    let container = jks(&w, "jks-signer");
    // The writer's output is a JKS the SDK reader accepts, with the right entry.
    let bytes = std::fs::read(&container).unwrap();
    assert!(oncl_pki::jks::is_jks(&bytes));
    let entries = oncl_pki::jks::load(&bytes, PASSWORD).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].alias, "jks-signer");
    assert_eq!(
        entries[0].cert.to_der().unwrap(),
        w.pki.rsa.cert.to_der().unwrap()
    );
    assert!(oncl_pki::jks::load(&bytes, "wrong").is_err());
    let document = w.dir.path().join("document.bin");
    std::fs::write(&document, b"jks signed document").unwrap();
    let signature = w.dir.path().join("jks.der");
    let mut sign = vec![
        "sign",
        "--profile",
        "cms",
        "--detached",
        "--input",
        path(&document),
        "--output",
        path(&signature),
        "--key",
        path(&container),
        "--alias",
        "jks-signer",
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ];
    sign.extend(trust(&w));
    let signed = run(&sign, b"");
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    assert!(String::from_utf8_lossy(&signed.stderr).contains("applied=Applied succeeded=true"));
    let mut verify = vec![
        "verify",
        "--profile",
        "cms",
        "--input",
        path(&signature),
        "--detached",
        path(&document),
        "--json",
    ];
    verify.extend(trust(&w));
    let valid = run(&verify, b"");
    assert_eq!(valid.status.code(), Some(0), "{valid:?}");
    let report: serde_json::Value = serde_json::from_slice(&valid.stdout).unwrap();
    assert_eq!(
        (report["verdict"].as_str(), report["policy"].as_str()),
        (Some("Valid"), Some("StrictOnline"))
    );
    // Independent oracle: OpenSSL verifies the produced CMS against the loopback root.
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
    let check = |content: &std::path::Path| {
        Command::new(&openssl)
            .args([
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-in",
                path(&signature),
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
    };
    assert!(check(&document));
    let altered = w.dir.path().join("altered.bin");
    std::fs::write(&altered, b"jks signed documenT").unwrap();
    assert!(!check(&altered));
    let mut changed = verify.clone();
    let at = changed.iter().position(|a| *a == path(&document)).unwrap();
    changed[at] = path(&altered);
    assert_eq!(run(&changed, b"").status.code(), Some(2));
    // A wrong JKS password (another protected secret file) is refused before private use.
    let wrong = w.secret.parent().unwrap().join("wrong.secret");
    std::io::Write::write_all(
        &mut oncl_pki::private_fs::PrivateDirectory::open(w.secret.parent().unwrap())
            .unwrap()
            .create_file("wrong.secret")
            .unwrap(),
        b"not the password",
    )
    .unwrap();
    let refused_out = w.dir.path().join("refused.der");
    let mut refused = vec![
        "sign",
        "--profile",
        "cms",
        "--detached",
        "--input",
        path(&document),
        "--output",
        path(&refused_out),
        "--key",
        path(&container),
        "--alias",
        "jks-signer",
        "--secret-file",
        path(&wrong),
        "--authorize",
    ];
    refused.extend(trust(&w));
    let result = run(&refused, b"");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(!String::from_utf8_lossy(&result.stderr).contains("private_use"));
    assert!(!refused_out.exists());
    // An unknown alias is a typed refusal too.
    let mut unknown = sign.clone();
    let at = unknown.iter().position(|a| *a == "jks-signer").unwrap();
    unknown[at] = "no-such-alias";
    let out2 = w.dir.path().join("unknown.der");
    let at = unknown.iter().position(|a| *a == path(&signature)).unwrap();
    unknown[at] = path(&out2);
    let result = run(&unknown, b"");
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("KeyNotFound"));
}

#[test]
fn java_keytool_reads_the_test_writer_output_and_its_own_jks_signs_strictly() {
    let w = world();
    let written = jks(&w, "jks-signer");
    // Independent reader: keytool lists one private-key entry with the issued chain
    // and can decrypt the protected key (it converts it to PKCS#12).
    let listing = keytool(&[
        "-list",
        "-v",
        "-keystore",
        path(&written),
        "-storepass",
        PASSWORD,
    ]);
    let text = String::from_utf8_lossy(&listing.stdout);
    assert!(
        listing.status.success(),
        "{text} {}",
        String::from_utf8_lossy(&listing.stderr)
    );
    assert!(
        text.contains("PrivateKeyEntry") && text.contains("Certificate chain length: 2"),
        "{text}"
    );
    let converted = w.dir.path().join("converted.p12");
    let import = keytool(&[
        "-importkeystore",
        "-srckeystore",
        path(&written),
        "-srcstoretype",
        "JKS",
        "-srcstorepass",
        PASSWORD,
        "-destkeystore",
        path(&converted),
        "-deststoretype",
        "PKCS12",
        "-deststorepass",
        PASSWORD,
        "-noprompt",
    ]);
    assert!(
        import.status.success(),
        "{} {}",
        String::from_utf8_lossy(&import.stdout),
        String::from_utf8_lossy(&import.stderr)
    );
    assert_eq!(
        oncl_pki::pkcs12::load(&std::fs::read(&converted).unwrap(), PASSWORD)
            .unwrap()
            .len(),
        1
    );
    // A JKS written by keytool itself (from the world's PKCS#12) signs strictly.
    let java_jks = w.dir.path().join("java.jks");
    let made = keytool(&[
        "-importkeystore",
        "-srckeystore",
        path(&w.rsa_key),
        "-srcstoretype",
        "PKCS12",
        "-srcstorepass",
        PASSWORD,
        "-destkeystore",
        path(&java_jks),
        "-deststoretype",
        "JKS",
        "-deststorepass",
        PASSWORD,
        "-noprompt",
    ]);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let document = w.dir.path().join("document.bin");
    std::fs::write(&document, b"keytool jks document").unwrap();
    let signature = w.dir.path().join("java.der");
    let mut sign = vec![
        "sign",
        "--profile",
        "cms",
        "--detached",
        "--input",
        path(&document),
        "--output",
        path(&signature),
        "--key",
        path(&java_jks),
        "--alias",
        &w.pki.rsa.alias,
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ];
    sign.extend(trust(&w));
    let signed = run(&sign, b"");
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    let mut verify = vec![
        "verify",
        "--profile",
        "cms",
        "--input",
        path(&signature),
        "--detached",
        path(&document),
    ];
    verify.extend(trust(&w));
    assert_eq!(run(&verify, b"").status.code(), Some(0));
}
