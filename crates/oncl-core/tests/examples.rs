//! The embedding examples are consumer-visible documentation: they must keep running, not only
//! compiling. Each is run as a real process (`cargo run --example`), the way a reader runs it:
//! sign a file, verify it, see an altered file refused, and see strict signing fail closed
//! when a host transport cannot establish revocation status.
use std::{
    path::Path,
    process::{Command, Output},
};

fn example(name: &str, args: &[&Path]) -> Output {
    Command::new(env!("CARGO"))
        .args(["run", "--quiet", "--manifest-path"])
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .args(["--example", name, "--"])
        .args(args)
        .output()
        .expect("cargo runs")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn sign_then_verify_accepts_the_document_and_refuses_an_altered_one() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("contract.txt");
    std::fs::write(&file, b"pay 100 to Aigerim").unwrap();

    let signed = example("sign_file", &[dir.path(), &file]);
    assert!(signed.status.success(), "{}", text(&signed));
    assert!(file.with_extension("txt.p7s").is_file());

    let verified = example("verify_file", &[dir.path(), &file]);
    assert!(verified.status.success(), "{}", text(&verified));
    assert!(
        text(&verified).contains("verdict: Valid"),
        "{}",
        text(&verified)
    );

    std::fs::write(&file, b"pay 900 to Aigerim").unwrap();
    let altered = example("verify_file", &[dir.path(), &file]);
    assert_eq!(altered.status.code(), Some(1), "{}", text(&altered));
    assert!(
        text(&altered).contains("verdict: Invalid"),
        "{}",
        text(&altered)
    );
}

#[test]
fn custom_transport_is_used_and_strict_signing_fails_closed_without_status() {
    let run = example("custom_transport", &[]);
    assert!(run.status.success(), "{}", text(&run));
    let out = text(&run);
    assert!(out.contains("online: signed"), "{out}");
    assert!(out.contains("offline: refused"), "{out}");
}
