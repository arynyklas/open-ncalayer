use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_oncl"))
        .args(args)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("standalone oncl process");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input);
    }
    child.wait_with_output().unwrap()
}

#[test]
fn hash_stdin_known_sha256() {
    let result = run(&["hash", "--algorithm", "sha256", "--input", "-"], b"abc");
    assert_eq!(result.status.code(), Some(0), "{:?}", result);
    assert_eq!(
        result.stdout,
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
    );
}

#[test]
fn duplicate_stdin_roles_are_rejected_before_io() {
    let result = run(
        &[
            "verify",
            "--profile",
            "cms",
            "--input",
            "-",
            "--detached",
            "-",
        ],
        b"not read",
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    // Duplicate stream roles are rejected at admission, not parsed as a CMS.
    assert!(String::from_utf8_lossy(&result.stderr).contains("StdinConflict"));
}

#[test]
fn stdout_binary_not_json_mix() {
    let result = run(
        &[
            "extract",
            "--input",
            "missing-document",
            "--output",
            "-",
            "--json",
        ],
        b"",
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("OutputConflict"));
}

#[test]
fn secret_not_in_diagnostics() {
    for args in [
        vec!["sign", "--password", "secret-sentinel-93"],
        vec!["hash", "--algorithm", "secret-sentinel-93"],
        vec!["--pin=secret-sentinel-93"],
    ] {
        let result = run(&args, b"");
        assert_eq!(result.status.code(), Some(1));
        assert!(!String::from_utf8_lossy(&result.stdout).contains("secret-sentinel-93"));
        assert!(!String::from_utf8_lossy(&result.stderr).contains("secret-sentinel-93"));
    }
}

#[test]
fn protected_secret_and_private_authority_are_separate() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("must-not-exist.cms");
    let result = run(
        &[
            "sign",
            "--profile",
            "cms",
            "--input",
            "-",
            "--output",
            output.to_str().unwrap(),
            "--key",
            "missing-key",
        ],
        b"abc",
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("AuthorityRequired"));
    assert!(!output.exists());
}

#[test]
fn existing_output_is_rejected_before_document_or_key_io() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("existing.cms");
    std::fs::write(&output, b"keep").unwrap();
    let result = run(
        &[
            "sign",
            "--profile",
            "cms",
            "--input",
            "missing-document",
            "--output",
            output.to_str().unwrap(),
            "--key",
            "missing-key",
            "--authorize",
        ],
        b"",
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("DestinationExists"));
    assert_eq!(std::fs::read(output).unwrap(), b"keep");
}

fn cms_fixture(attached: bool) -> Vec<u8> {
    use oncl_pki::cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec};
    let fixture = oncl_testkit::synthetic("user-rsa-sign");
    let entry = oncl_pki::pkcs12::load(&oncl_testkit::read(fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let intermediate =
        oncl_pki::cert::parse(&oncl_testkit::synthetic_cert("inter-gost2015")).unwrap();
    cms::sign_spec(
        &entry,
        &[intermediate],
        &SignSpec {
            content: Content::Data(b"abc"),
            encapsulate: attached,
            cosign: CoSign::Never,
            econtent_type: None,
            digest: None,
            attrs: AttrSpec::cades(
                time::OffsetDateTime::from_unix_timestamp(1_793_620_800).unwrap(),
            ),
            certificates: CertSpec::Chain,
        },
    )
    .unwrap()
}

#[test]
fn detached_verify_exit_states() {
    let temp = tempfile::tempdir().unwrap();
    let signature = temp.path().join("detached.der");
    let document = temp.path().join("document");
    let roots = ["root-rsa", "root-gost2004", "root-gost2015"].map(|name| {
        let path = temp.path().join(format!("{name}.cer"));
        std::fs::write(&path, oncl_testkit::synthetic_cert(name)).unwrap();
        path
    });
    std::fs::write(&signature, cms_fixture(false)).unwrap();
    std::fs::write(&document, b"abc").unwrap();
    let args = [
        "verify",
        "--profile",
        "cms",
        "--input",
        signature.to_str().unwrap(),
        "--detached",
        document.to_str().unwrap(),
        "--offline",
        "--json",
        "--root",
        roots[0].to_str().unwrap(),
        "--root",
        roots[1].to_str().unwrap(),
        "--root",
        roots[2].to_str().unwrap(),
    ];
    let good = run(&args, b"");
    assert_eq!(good.status.code(), Some(3), "{good:?}");
    let report: serde_json::Value = serde_json::from_slice(&good.stdout).unwrap();
    assert_eq!(report["verdict"], "Indeterminate");
    assert_eq!(report["policy"], "OfflineReport");
    assert_eq!(report["signers"][0]["signature"], "Passed");
    std::fs::write(&document, b"abd").unwrap();
    let bad = run(&args, b"");
    assert_eq!(bad.status.code(), Some(2), "{bad:?}");
    let report: serde_json::Value = serde_json::from_slice(&bad.stdout).unwrap();
    assert_eq!(report["verdict"], "Invalid");
    assert_eq!(report["signers"][0]["signature"], "Failed");
    let execution = run(
        &["verify", "--profile", "cms", "--input", "-", "--offline"],
        b"malformed",
    );
    assert_eq!(execution.status.code(), Some(1));
}

#[test]
fn extraction_binary_stdout_and_noclobber() {
    let encoded = cms_fixture(true);
    let good = run(&["extract", "--input", "-", "--output", "-"], &encoded);
    assert_eq!(good.status.code(), Some(0), "{good:?}");
    assert_eq!(good.stdout, b"abc");
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("existing");
    std::fs::write(&destination, b"keep").unwrap();
    let denied = run(
        &[
            "extract",
            "--input",
            "-",
            "--output",
            destination.to_str().unwrap(),
        ],
        &encoded,
    );
    assert_eq!(denied.status.code(), Some(1));
    assert_eq!(std::fs::read(destination).unwrap(), b"keep");
}

#[test]
fn certificate_inspection_is_structural_without_key_provider() {
    let encoded = oncl_testkit::synthetic_cert("root-rsa");
    let result = run(
        &[
            "inspect",
            "--profile",
            "certificate",
            "--input",
            "-",
            "--json",
        ],
        &encoded,
    );
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["kind"], "Certificate");
    assert_eq!(report["entries"].as_array().unwrap().len(), 1);
    assert!(report.get("verdict").is_none());
}

#[test]
fn incompatible_signing_flags_are_not_silently_ignored() {
    for flags in [
        vec!["--profile", "raw", "--add"],
        vec!["--profile", "raw", "--detached"],
        vec!["--profile", "cms", "--target-id", "document"],
        vec!["--profile", "cms", "--add", "--detached"],
        vec!["--profile", "cades-b", "--add", "--detached"],
    ] {
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
        args.extend(flags);
        let result = run(&args, b"");
        assert_eq!(result.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&result.stderr).contains("InvalidCombination"));
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn closed_stderr_does_not_replace_usage_exit_with_a_panic() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_oncl"))
        .arg("--unsupported-option")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stderr.take());
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
}

#[test]
fn aggregate_document_and_report_quota_is_admitted_before_publication() {
    let encoded = cms_fixture(true);
    let temp = tempfile::tempdir().unwrap();
    for mode in ["human", "json", "file"] {
        let baseline = temp.path().join(format!("{mode}-baseline"));
        let report_path = temp.path().join(format!("{mode}-baseline-report"));
        let mut args = vec![
            "extract",
            "--input",
            "-",
            "--output",
            baseline.to_str().unwrap(),
        ];
        if mode == "json" {
            args.push("--json");
        }
        if mode == "file" {
            args.extend(["--report", report_path.to_str().unwrap()]);
        }
        let result = run(&args, &encoded);
        assert_eq!(result.status.code(), Some(0), "{result:?}");
        assert_eq!(std::fs::read(&baseline).unwrap(), b"abc");
        let report = if mode == "file" {
            std::fs::read(&report_path).unwrap()
        } else if mode == "json" {
            result.stdout
        } else {
            result.stderr
        };
        let exact = 3 + report.len();
        for cap in [exact, exact - 1] {
            let output = temp.path().join(format!("{mode}-{cap}"));
            let report_output = temp.path().join(format!("{mode}-{cap}-report"));
            let cap_string = cap.to_string();
            let mut args = vec![
                "extract",
                "--input",
                "-",
                "--output",
                output.to_str().unwrap(),
                "--output-limit",
                &cap_string,
            ];
            if mode == "json" {
                args.push("--json");
            }
            if mode == "file" {
                args.extend(["--report", report_output.to_str().unwrap()]);
            }
            let result = run(&args, &encoded);
            assert_eq!(
                result.status.code(),
                Some(if cap == exact { 0 } else { 1 }),
                "mode={mode},cap={cap}: {result:?}"
            );
            if cap == exact {
                assert_eq!(std::fs::read(output).unwrap(), b"abc");
                if mode == "file" {
                    assert_eq!(std::fs::read(report_output).unwrap(), report);
                }
            } else {
                assert!(
                    !output.exists(),
                    "known report quota failure published the document"
                );
                assert!(!report_output.exists());
                assert!(String::from_utf8_lossy(&result.stderr).contains("OutputLimit"));
            }
        }
    }
}

#[test]
fn duplicate_host_roots_obey_aggregate_encoded_admission_before_document_io() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root.cer");
    let certificate = oncl_testkit::synthetic_cert("root-rsa");
    std::fs::write(&root, &certificate).unwrap();
    let encoded = cms_fixture(true);
    for copies in [1, 2] {
        let exact = certificate.len() * copies;
        for limit in [exact, exact - 1] {
            let limit = limit.to_string();
            let mut args = vec![
                "verify",
                "--profile",
                "cms",
                "--input",
                "-",
                "--offline",
                "--json",
                "--configuration-bytes",
                &limit,
            ];
            for _ in 0..copies {
                args.extend(["--root", root.to_str().unwrap()]);
            }
            let result = run(&args, &encoded);
            assert_eq!(
                result.status.code(),
                Some(if limit == exact.to_string() { 3 } else { 1 }),
                "copies={copies}: {result:?}"
            );
            if limit != exact.to_string() {
                assert!(String::from_utf8_lossy(&result.stderr).contains("MetadataLimit"));
                assert!(result.stdout.is_empty());
            }
        }
        let insufficient = (exact - 1).to_string();
        let mut args = vec![
            "verify",
            "--profile",
            "cms",
            "--input",
            "missing-document",
            "--offline",
            "--configuration-bytes",
            &insufficient,
        ];
        for _ in 0..copies {
            args.extend(["--root", root.to_str().unwrap()]);
        }
        let result = run(&args, b"");
        assert_eq!(result.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("MetadataLimit"),
            "{result:?}"
        );
    }
}

#[test]
fn excessive_configuration_item_count_precedes_provider_and_file_io() {
    let mut args = vec![
        "sign",
        "--profile",
        "cms",
        "--input",
        "missing-document",
        "--output",
        "-",
        "--key",
        "missing-key",
        "--authorize",
    ];
    for _ in 0..1025 {
        args.extend(["--root", "missing-ca"]);
    }
    let result = run(&args, b"");
    assert_eq!(result.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("ConfigurationLimit"),
        "{result:?}"
    );
    assert!(result.stdout.is_empty());
}
