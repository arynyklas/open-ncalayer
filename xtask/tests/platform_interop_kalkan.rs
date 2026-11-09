//! The parts of the Kalkan oracle that need neither the jars nor a JDK: how the descriptor in
//! `coverage.toml` pins them, why a row is BLOCKED without them, and how the verifier's JSON is
//! read. The oracle itself (`xtask/assets/platform-interop/KalkanOracle.java`) runs only in
//! `cargo xtask platform-interop` on a machine that has the operator's Kalkan jars.

use std::collections::BTreeSet;
use std::ffi::OsString;

use serde_json::json;
use xtask::platform_interop::kalkan::{
    Artifact, java_major, locate_jars, parse_answer, verdict, wsse_summary,
};
use xtask::platform_interop::tools::{Out, sha256_hex};
use xtask::platform_interop::{Coverage, OracleDescriptor, oracle_labels};

/// The rows the Kalkan oracle exists for: signatures of ours that no other verifier could judge.
const KALKAN_ROWS: [&str; 12] = [
    "wsse-sign-gost2015",
    "wsse-tamper-gost2015-body",
    "wsse-tamper-gost2015-signature",
    "wsse-sign-gost2004",
    "wsse-tamper-gost2004-body",
    "wsse-tamper-gost2004-signature",
    "jws-gost2015-independent-signature",
    "x509-sign-ours-gost2015",
    "x509-sign-ncanode-gost2015",
    "x509-sign-ours-gost2004",
    "x509-sign-ncanode-gost2004",
    "plugin-sign-raw-gost2015",
];

fn descriptor(artifacts: Vec<Artifact>) -> OracleDescriptor {
    OracleDescriptor {
        id: "kalkan".to_owned(),
        tool: "Kalkan (test)".to_owned(),
        version: "1".to_owned(),
        match_version: "exact".to_owned(),
        pin: String::new(),
        role: String::new(),
        artifact: artifacts,
        local_only: true,
    }
}

fn out(code: Option<i32>, stdout: &str) -> Out {
    Out {
        code,
        stdout: stdout.as_bytes().to_vec(),
        stderr: String::new(),
    }
}

#[test]
fn the_descriptor_pins_both_jars_by_sha256_and_is_local_only() {
    let coverage = Coverage::load().unwrap();
    let kalkan = coverage.descriptor("kalkan").expect("kalkan descriptor");
    assert!(kalkan.local_only);
    let envs: Vec<&str> = kalkan.artifact.iter().map(|a| a.env.as_str()).collect();
    assert_eq!(envs, ["ONCL_KALKAN_JAR", "ONCL_KALKAN_XMLDSIG_JAR"]);
    for artifact in &kalkan.artifact {
        assert!(
            artifact.sha256.len() == 64 && artifact.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "{}: not a sha256: {}",
            artifact.env,
            artifact.sha256
        );
    }
    // No other oracle is local-only or needs an operator-supplied file.
    for other in coverage.oracle.iter().filter(|o| o.id != "kalkan") {
        assert!(
            !other.local_only && other.artifact.is_empty(),
            "{}",
            other.id
        );
    }
}

#[test]
fn exactly_the_twelve_rows_that_had_no_independent_gost_judge_use_the_kalkan_oracle() {
    let coverage = Coverage::load().unwrap();
    let using: BTreeSet<&str> = coverage
        .case
        .iter()
        .filter(|row| row.oracles.iter().any(|o| o == "kalkan"))
        .map(|row| row.id.as_str())
        .collect();
    assert_eq!(using, BTreeSet::from(KALKAN_ROWS));
    for row in &coverage.case {
        assert!(
            !row.expected.contains("requires independent"),
            "row {} still waits for an independent verifier: {}",
            row.id,
            row.expected
        );
    }
}

#[test]
fn a_row_judged_by_kalkan_is_marked_local_only_in_the_report() {
    let coverage = Coverage::load().unwrap();
    let labels = oracle_labels(&coverage, &["ncanode".to_owned(), "kalkan".to_owned()]);
    assert_eq!(
        labels,
        ["ncanode", "kalkan (local-only, not reproducible in CI)"]
    );
}

#[test]
fn without_the_environment_variable_the_reason_names_it_and_the_pinned_hash() {
    let coverage = Coverage::load().unwrap();
    let kalkan = coverage.descriptor("kalkan").unwrap();
    let reason = locate_jars(kalkan, |_| None).unwrap_err();
    assert!(reason.contains("ONCL_KALKAN_JAR is not set"), "{reason}");
    assert!(reason.contains(&kalkan.artifact[0].sha256), "{reason}");
    assert!(reason.contains("local-only"), "{reason}");
    // An empty variable is not a path.
    let empty = locate_jars(kalkan, |_| Some(OsString::new())).unwrap_err();
    assert!(empty.contains("ONCL_KALKAN_JAR is not set"), "{empty}");
}

#[test]
fn a_missing_second_jar_is_named_after_the_first_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("kalkancrypt.jar");
    std::fs::write(&first, b"first jar").unwrap();
    let kalkan = descriptor(vec![
        Artifact {
            env: "ONCL_KALKAN_JAR".to_owned(),
            name: "jce".to_owned(),
            sha256: sha256_hex(b"first jar"),
        },
        Artifact {
            env: "ONCL_KALKAN_XMLDSIG_JAR".to_owned(),
            name: "xmldsig".to_owned(),
            sha256: sha256_hex(b"second jar"),
        },
    ]);
    let reason = locate_jars(&kalkan, |name| {
        (name == "ONCL_KALKAN_JAR").then(|| first.clone().into_os_string())
    })
    .unwrap_err();
    assert!(
        reason.contains("ONCL_KALKAN_XMLDSIG_JAR is not set"),
        "{reason}"
    );
}

#[test]
fn a_jar_with_other_bytes_is_refused_with_both_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let jar = dir.path().join("kalkancrypt.jar");
    std::fs::write(&jar, b"not the pinned jar").unwrap();
    let pinned = sha256_hex(b"the pinned jar");
    let kalkan = descriptor(vec![Artifact {
        env: "ONCL_KALKAN_JAR".to_owned(),
        name: "jce".to_owned(),
        sha256: pinned.clone(),
    }]);
    let reason = locate_jars(&kalkan, |_| Some(jar.clone().into_os_string())).unwrap_err();
    assert!(
        reason.contains(&sha256_hex(b"not the pinned jar")),
        "{reason}"
    );
    assert!(reason.contains(&pinned), "{reason}");
    assert!(reason.contains("ONCL_KALKAN_JAR"), "{reason}");

    // A path that is not a file.
    let missing = dir.path().join("absent.jar");
    let reason = locate_jars(&kalkan, |_| Some(missing.clone().into_os_string())).unwrap_err();
    assert!(reason.contains("is not a file"), "{reason}");
}

#[test]
fn jars_with_the_pinned_bytes_make_a_classpath_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("a.jar");
    let second = dir.path().join("b.jar");
    std::fs::write(&first, b"first jar").unwrap();
    std::fs::write(&second, b"second jar").unwrap();
    let kalkan = descriptor(vec![
        Artifact {
            env: "A".to_owned(),
            name: "a".to_owned(),
            sha256: sha256_hex(b"first jar"),
        },
        Artifact {
            env: "B".to_owned(),
            name: "b".to_owned(),
            // The descriptor's hash is hex either way.
            sha256: sha256_hex(b"second jar").to_uppercase(),
        },
    ]);
    let classpath = locate_jars(&kalkan, |name| match name {
        "A" => Some(first.clone().into_os_string()),
        "B" => Some(second.clone().into_os_string()),
        _ => None,
    })
    .unwrap();
    let parts: Vec<_> = std::env::split_paths(&classpath).collect();
    assert_eq!(parts, [first, second]);
}

#[test]
fn no_jar_is_shipped_in_the_repository_assets() {
    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets");
    let mut stack = vec![assets];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let name = path.file_name().unwrap().to_string_lossy().to_lowercase();
                assert!(
                    !name.ends_with(".jar") && !name.ends_with(".class"),
                    "{} must not be committed (the Kalkan jar is local-only)",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn the_java_version_is_read_from_both_styles() {
    assert_eq!(
        java_major("openjdk version \"17.0.20.1\" 2026-08-18\nOpenJDK Runtime Environment"),
        Some(17)
    );
    assert_eq!(
        java_major("openjdk version \"25.0.2\" 2026-01-20 LTS"),
        Some(25)
    );
    assert_eq!(java_major("openjdk version \"21\" 2023-09-19"), Some(21));
    assert_eq!(java_major("java version \"1.8.0_391\""), Some(8));
    assert_eq!(java_major("not java"), None);
}

#[test]
fn a_verdict_is_read_from_the_answer() {
    let accepted = parse_answer(&out(Some(0), "{\"ok\":true,\"mode\":\"raw\"}\n")).unwrap();
    assert!(verdict(&accepted));
    let rejected = parse_answer(&out(Some(0), "{\"ok\":false,\"mode\":\"raw\"}")).unwrap();
    assert!(!verdict(&rejected));
}

#[test]
fn an_oracle_that_could_not_run_is_an_error_never_a_verdict() {
    // The verifier's own failure (exit 2, `error`): a tamper row must not read it as "rejected".
    let error = parse_answer(&out(
        Some(2),
        "{\"error\":\"InvalidKeyException: key too weak\"}",
    ))
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("could not run") && error.contains("key too weak"),
        "{error}"
    );
    // Even with exit 0.
    assert!(parse_answer(&out(Some(0), "{\"error\":\"x\"}")).is_err());
    // No JSON at all (a JVM crash, a compile error of the source).
    let error = parse_answer(&Out {
        code: Some(1),
        stdout: Vec::new(),
        stderr: "error: compilation failed".to_owned(),
    })
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("no JSON") && error.contains("compilation failed"),
        "{error}"
    );
    // An answer without a verdict, or a verdict with a failing exit code.
    assert!(parse_answer(&out(Some(0), "{\"mode\":\"raw\"}")).is_err());
    assert!(parse_answer(&out(Some(1), "{\"ok\":true}")).is_err());
    assert!(parse_answer(&out(Some(0), "{\"ok\":\"yes\"}")).is_err());
}

#[test]
fn the_wsse_summary_tells_which_part_failed() {
    let reference = |digest| json!({"uri": "#b", "node": "Body", "digest_ok": digest});
    let signature = |value, digest| {
        json!({"ok": value && digest, "signatures": [
            {"signature_value_ok": value, "references": [reference(digest)]}
        ]})
    };
    assert_eq!(wsse_summary(&signature(true, true)), "verified/Body");
    assert_eq!(wsse_summary(&signature(true, false)), "rejected/digest");
    assert_eq!(
        wsse_summary(&signature(false, true)),
        "rejected/signature-value"
    );
    assert_eq!(
        wsse_summary(&signature(false, false)),
        "rejected/signature-value+digest"
    );
    // A signature that references nothing is not a verified message.
    let empty = json!({"ok": false, "signatures": [
        {"signature_value_ok": true, "references": []}
    ]});
    assert_eq!(wsse_summary(&empty), "rejected/digest");
    assert_eq!(wsse_summary(&json!({"ok": false})), "rejected/no-signature");
}
