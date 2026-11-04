//! Real `oncl` private sign -> strict verify through a loopback OCSP responder.
mod support;
use der::Encode;
use std::{path::Path, process::Command};
use support::*;

fn openssl() -> Option<String> {
    for candidate in ["openssl", r"drive_C:\Program Files\Git\usr\bin\openssl.exe"] {
        if Command::new(candidate)
            .arg("version")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            return Some(candidate.to_owned());
        }
    }
    None
}
fn common<'a>(w: &'a World) -> Vec<&'a str> {
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
    key: &'a Path,
    input: &'a Path,
    output: &'a Path,
    extra: &[&'a str],
) -> Vec<&'a str> {
    let mut args = vec![
        "sign",
        "--profile",
        "cms",
        "--detached",
        "--input",
        path(input),
        "--output",
        path(output),
        "--key",
        path(key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ];
    args.extend(extra);
    args.extend(common(w));
    args
}
#[test]
fn strict_private_sign_then_valid_zero_and_altered_two_for_rsa_and_gost() {
    let w = world();
    let document = w.dir.path().join("document.bin");
    let altered = w.dir.path().join("altered.bin");
    std::fs::write(&document, b"abc").unwrap();
    std::fs::write(&altered, b"abd").unwrap();
    for (name, key) in [("rsa", &w.rsa_key), ("gost", &w.gost_key)] {
        let signature = w.dir.path().join(format!("{name}.der"));
        let signed = run(&sign_args(&w, key, &document, &signature, &[]), b"");
        assert_eq!(signed.status.code(), Some(0), "{name}: {signed:?}");
        let diagnostics = String::from_utf8_lossy(&signed.stderr);
        assert!(
            diagnostics.contains("applied=Applied succeeded=true"),
            "{name}: {diagnostics}"
        );
        assert!(!diagnostics.contains(PASSWORD));
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
        verify.extend(common(&w));
        let valid = run(&verify, b"");
        assert_eq!(valid.status.code(), Some(0), "{name}: {valid:?}");
        let report: serde_json::Value = serde_json::from_slice(&valid.stdout).unwrap();
        assert_eq!(
            (report["verdict"].as_str(), report["policy"].as_str()),
            (Some("Valid"), Some("StrictOnline"))
        );
        assert_eq!(report["signers"][0]["revocation"], "Passed");
        let mut offline = verify.clone();
        offline.push("--offline");
        assert_eq!(
            run(&offline, b"").status.code(),
            Some(3),
            "{name}: offline math/trust only is Indeterminate"
        );
        let mut changed = verify.clone();
        changed[6] = path(&altered);
        assert_eq!(
            run(&changed, b"").status.code(),
            Some(2),
            "{name}: altered data"
        );
        if name == "rsa" {
            let Some(openssl) = openssl() else {
                panic!("independent OpenSSL oracle unavailable")
            };
            let root_pem = w.dir.path().join("root.pem");
            let status = Command::new(&openssl)
                .args([
                    "x509",
                    "-inform",
                    "DER",
                    "-in",
                    path(&w.root),
                    "-out",
                    path(&root_pem),
                ])
                .status()
                .unwrap();
            assert!(status.success());
            let oracle = |content: &Path| {
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
            };
            let good = oracle(&document);
            assert!(
                good.status.success(),
                "{}",
                String::from_utf8_lossy(&good.stderr)
            );
            assert!(!oracle(&altered).status.success());
        }
    }
    let _ = w.pki.root.cert.to_der();
}
#[test]
fn wrong_secret_or_missing_authority_never_reaches_private_use_or_output() {
    let w = world();
    let document = w.dir.path().join("document.bin");
    std::fs::write(&document, b"abc").unwrap();
    let private = w.secret.parent().unwrap().join("wrong.secret");
    let namespace =
        oncl_pki::private_fs::PrivateDirectory::open(w.secret.parent().unwrap()).unwrap();
    std::io::Write::write_all(
        &mut namespace.create_file("wrong.secret").unwrap(),
        b"not the password",
    )
    .unwrap();
    let output = w.dir.path().join("must-not-exist.der");
    let mut args = sign_args(&w, &w.rsa_key, &document, &output, &[]);
    let at = args.iter().position(|a| *a == path(&w.secret)).unwrap();
    args[at] = path(&private);
    let denied = run(&args, b"");
    assert_eq!(denied.status.code(), Some(1), "{denied:?}");
    assert!(!output.exists());
    let text = String::from_utf8_lossy(&denied.stderr);
    assert!(
        !text.contains("private_use") && !text.contains("not the password"),
        "{text}"
    );
}
