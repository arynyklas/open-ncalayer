use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use der::Encode;
use std::{
    io::Write,
    process::{Command, Output, Stdio},
};
fn run(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_oncl"))
        .args(args)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input);
    }
    child.wait_with_output().unwrap()
}
fn compact(payload: &[u8], jwt: bool) -> Vec<u8> {
    let fixture = oncl_testkit::synthetic("user-rsa-sign");
    let entry = oncl_pki::pkcs12::load(&oncl_testkit::read(fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let mut header =
        serde_json::json!({"alg":"RS256","x5c":[STANDARD.encode(entry.cert.to_der().unwrap())]});
    if jwt {
        header["typ"] = "JWT".into();
    }
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = entry
        .key
        .sign(oncl_pki::key::SigAlg::RsaSha256, input.as_bytes())
        .unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)).into_bytes()
}
fn trust(temp: &tempfile::TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    let root = temp.path().join("root.cer");
    let intermediate = temp.path().join("intermediate.cer");
    std::fs::write(&root, oncl_testkit::synthetic_cert("root-rsa")).unwrap();
    std::fs::write(
        &intermediate,
        oncl_testkit::synthetic_cert("inter-gost2015"),
    )
    .unwrap();
    (root, intermediate)
}
#[test]
fn jws_all_serializations_and_detached_are_real_process_verification() {
    let temp = tempfile::tempdir().unwrap();
    let (root, intermediate) = trust(&temp);
    let wire = compact(b"abc", false);
    let parts: Vec<_> = std::str::from_utf8(&wire).unwrap().split('.').collect();
    let forms=[("compact",wire.clone()),("flattened",serde_json::to_vec(&serde_json::json!({"protected":parts[0],"payload":parts[1],"signature":parts[2]})).unwrap()),("general",serde_json::to_vec(&serde_json::json!({"payload":parts[1],"signatures":[{"protected":parts[0],"signature":parts[2]}]})).unwrap())];
    for (serialization, wire) in forms {
        let result = run(
            &[
                "jws",
                "verify",
                "--serialization",
                serialization,
                "--input",
                "-",
                "--root",
                root.to_str().unwrap(),
                "--intermediate",
                intermediate.to_str().unwrap(),
                "--offline",
                "--json",
            ],
            &wire,
        );
        assert_eq!(result.status.code(), Some(3), "{result:?}");
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["signers"][0]["crypto"], "Passed");
        assert_eq!(report["verdict"], "Indeterminate");
    }
    let data = temp.path().join("data");
    std::fs::write(&data, b"abd").unwrap();
    let detached = format!("{}..{}", parts[0], parts[2]);
    let result = run(
        &[
            "jws",
            "verify",
            "--serialization",
            "compact",
            "--input",
            "-",
            "--detached-input",
            data.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--intermediate",
            intermediate.to_str().unwrap(),
            "--offline",
            "--json",
        ],
        detached.as_bytes(),
    );
    assert_eq!(result.status.code(), Some(2), "{result:?}");
}
#[test]
fn jwt_claim_policy_and_unverified_decode_do_not_claim_crypto_success() {
    let temp = tempfile::tempdir().unwrap();
    let (root, intermediate) = trust(&temp);
    let claims=br#"{"iss":"operator-issuer","aud":["operator-audience"],"exp":1793624400,"nbf":1793620800}"#;
    let wire = compact(claims, true);
    let result = run(
        &[
            "jwt",
            "verify",
            "--input",
            "-",
            "--root",
            root.to_str().unwrap(),
            "--intermediate",
            intermediate.to_str().unwrap(),
            "--issuer",
            "operator-issuer",
            "--audience",
            "operator-audience",
            "--as-of",
            "1793624400",
            "--offline",
            "--json",
        ],
        &wire,
    );
    assert_eq!(result.status.code(), Some(2), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["claims"]["verdict"], "Invalid");
    assert_eq!(report["jws"]["signers"][0]["crypto"], "Passed");
    let decoded = run(&["jwt", "decode", "--input", "-", "--output", "-"], &wire);
    assert_eq!(decoded.status.code(), Some(0), "{decoded:?}");
    assert_eq!(decoded.stdout, claims);
    assert!(String::from_utf8_lossy(&decoded.stderr).contains("unverified"));
}
#[test]
fn jose_binary_report_conflict_and_nested_algorithm_fail_before_key_io() {
    let denied = run(
        &[
            "jwt",
            "encode",
            "--input",
            "missing",
            "--output",
            "-",
            "--json",
            "--key",
            "missing-key",
            "--authorize",
        ],
        b"",
    );
    assert_eq!(denied.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&denied.stderr).contains("OutputConflict"));
    let none = run(
        &["jwt", "verify", "--input", "-", "--offline", "--json"],
        b"eyJhbGciOiJub25lIn0.eyJleHAiOjE4MDAwMDAwMDB9.",
    );
    assert_eq!(none.status.code(), Some(1));
    assert!(none.stdout.is_empty());
}
