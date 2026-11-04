//! Output delivery faults through the real binary: fragmented stdout reads,
//! failed stdout writes (read-only handle, pipe closed mid-stream) and a real
//! OS refusal to publish after private use (directory ACL denies new files while
//! the loopback OCSP responder holds the signer's status). A genuinely full
//! volume cannot be created without elevation on the test machine; these inject
//! the same `io::Error` on the same write/publish paths.
mod support;
use std::{
    io::Read,
    process::{Command, Stdio},
    time::Duration,
};
use support::*;

fn common(w: &World) -> Vec<&str> {
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
    key: &'a std::path::Path,
    input: &'a std::path::Path,
    output: &'a str,
    attached: bool,
) -> Vec<&'a str> {
    let mut args = vec!["sign", "--profile", "cms"];
    if !attached {
        args.push("--detached");
    }
    args.extend([
        "--input",
        path(input),
        "--output",
        output,
        "--key",
        path(key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ]);
    args.extend(common(w));
    args
}
fn big_attached(w: &World) -> (std::path::PathBuf, Vec<u8>) {
    let document: Vec<u8> = (0..3 * 1024 * 1024u32)
        .map(|n| (n.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let input = w.dir.path().join("big.bin");
    std::fs::write(&input, &document).unwrap();
    let attached = w.dir.path().join("big.der");
    let signed = run(
        &sign_args(w, &w.rsa_key, &input, path(&attached), true),
        b"",
    );
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    (attached, document)
}
#[test]
fn fragmented_slow_stdout_reads_deliver_every_byte_exactly() {
    let w = world();
    let (attached, document) = big_attached(&w);
    let mut child = Command::new(env!("CARGO_BIN_EXE_oncl"))
        .args(["extract", "--input", path(&attached), "--output", "-"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    // Tiny, odd-sized reads with periodic stalls force partial pipe writes.
    let mut stdout = child.stdout.take().unwrap();
    let mut received = Vec::new();
    let sizes = [1usize, 3, 7, 61, 509, 4093, 65537];
    let mut buffer = vec![0u8; 65537];
    let mut turn = 0usize;
    loop {
        let size = sizes[turn % sizes.len()];
        turn += 1;
        let n = stdout.read(&mut buffer[..size]).unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buffer[..n]);
        if turn.is_multiple_of(97) {
            std::thread::sleep(Duration::from_millis(3));
        }
    }
    let status = child.wait().unwrap();
    let text = errors.join().unwrap();
    assert_eq!(status.code(), Some(0), "{text}");
    assert_eq!(received.len(), document.len());
    assert!(
        received == document,
        "stdout bytes differ from the signed content"
    );
    assert!(text.contains("Completed (unverified extraction)"), "{text}");
}
#[test]
fn stdout_closed_midstream_is_failure_without_a_completed_report() {
    let w = world();
    let (attached, document) = big_attached(&w);
    let mut child = Command::new(env!("CARGO_BIN_EXE_oncl"))
        .args(["extract", "--input", path(&attached), "--output", "-"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut first = vec![0u8; 64 * 1024];
    stdout.read_exact(&mut first).unwrap();
    assert!(first == document[..first.len()]);
    drop(stdout);
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let text = String::from_utf8_lossy(&result.stderr);
    assert!(!text.contains("Completed"), "no success report: {text}");
    assert!(text.contains("applied=NotApplied"), "{text}");
}
#[test]
fn unwritable_stdout_after_private_use_is_a_truthful_applied_failure_not_success() {
    let w = world();
    let input = w.dir.path().join("doc.bin");
    std::fs::write(&input, b"abc").unwrap();
    // stdout is a file opened read-only: every write fails (an injected write error).
    let readonly = w.dir.path().join("readonly.out");
    std::fs::write(&readonly, b"").unwrap();
    let args = sign_args(&w, &w.rsa_key, &input, "-", true);
    let result = Command::new(env!("CARGO_BIN_EXE_oncl"))
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::fs::File::open(&readonly).unwrap()))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let text = String::from_utf8_lossy(&result.stderr);
    assert!(
        text.contains("applied=Applied succeeded=true"),
        "private use is reported: {text}"
    );
    assert!(
        text.contains("; applied=Applied"),
        "failure keeps Applied: {text}"
    );
    assert!(!text.contains("Completed"), "no success report: {text}");
    assert_eq!(
        std::fs::read(&readonly).unwrap(),
        b"",
        "nothing was written"
    );
}
#[cfg(windows)]
mod acl {
    use super::*;
    use std::os::windows::process::CommandExt;

    fn user() -> String {
        std::env::var("USERNAME").unwrap()
    }
    fn deny_new_files(dir: &std::path::Path) {
        let status = Command::new("icacls")
            .arg(dir)
            .args(["/deny", &format!("{}:(WD)", user())])
            .stdout(Stdio::null())
            .creation_flags(0x0800_0000)
            .status()
            .unwrap();
        assert!(status.success(), "icacls deny failed");
    }
    fn allow_again(dir: &std::path::Path) {
        let status = Command::new("icacls")
            .arg(dir)
            .args(["/remove:d", &user()])
            .stdout(Stdio::null())
            .creation_flags(0x0800_0000)
            .status()
            .unwrap();
        assert!(status.success(), "icacls restore failed");
    }
    fn spawn(args: &[&str]) -> std::process::Child {
        Command::new(env!("CARGO_BIN_EXE_oncl"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }
    /// Restores the ACL even if an assertion fails, so the tempdir can be removed.
    struct Restore(std::path::PathBuf);
    impl Drop for Restore {
        /// Never panics (a panic in Drop during unwinding aborts the process).
        fn drop(&mut self) {
            for _ in 0..2 {
                let restored = Command::new("icacls")
                    .arg(&self.0)
                    .args(["/remove:d", &user()])
                    .stdout(Stdio::null())
                    .creation_flags(0x0800_0000)
                    .status()
                    .is_ok_and(|s| s.success());
                if restored {
                    break;
                }
            }
        }
    }
    #[test]
    fn publication_refused_by_the_filesystem_after_private_use_publishes_nothing() {
        let w = world();
        let input = w.dir.path().join("doc.bin");
        std::fs::write(&input, b"abc").unwrap();
        let sealed = w.dir.path().join("sealed");
        std::fs::create_dir(&sealed).unwrap();
        let destination = sealed.join("out.der");
        // The GOST signer's OCSP status is held, so the process sits before its
        // private use while the directory stops accepting new files.
        w.server.hold(&[0x71, 4, 11]);
        let args = sign_args(&w, &w.gost_key, &input, path(&destination), false);
        let child = spawn(&args);
        // The stage exists beside the destination before any wait for validation.
        let start = std::time::Instant::now();
        while std::fs::read_dir(&sealed).unwrap().next().is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "stage never appeared"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let _restore = Restore(sealed.clone());
        deny_new_files(&sealed);
        w.server.release();
        let result = child.wait_with_output().unwrap();
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        let text = String::from_utf8_lossy(&result.stderr);
        assert!(text.contains("applied=Applied succeeded=true"), "{text}");
        assert!(text.contains("; applied=Applied"), "{text}");
        assert!(!text.contains("Completed"), "{text}");
        assert!(
            !destination.exists(),
            "a refused publication leaves no destination"
        );
        allow_again(&sealed);
        let leftovers: Vec<_> = std::fs::read_dir(&sealed).unwrap().collect();
        assert!(
            leftovers.is_empty(),
            "staged bytes were not published or left behind: {leftovers:?}"
        );
    }
    #[test]
    fn batch_keeps_earlier_outputs_when_a_later_publication_is_refused() {
        let w = world();
        let (doc_a, doc_b, doc_c) = (
            w.dir.path().join("a.bin"),
            w.dir.path().join("b.bin"),
            w.dir.path().join("c.bin"),
        );
        for (p, bytes) in [(&doc_a, "first"), (&doc_b, "second"), (&doc_c, "gate")] {
            std::fs::write(p, bytes).unwrap();
        }
        let sealed = w.dir.path().join("sealed");
        std::fs::create_dir(&sealed).unwrap();
        let (out_a, out_b) = (w.dir.path().join("a.der"), sealed.join("b.der"));
        // Item 2 (verification of a GOST signature) holds on OCSP while the
        // directory of item 3's output is sealed.
        let sig_c = w.dir.path().join("c.der");
        let pre = run(
            &sign_args(&w, &w.gost_key, &doc_c, path(&sig_c), false),
            b"",
        );
        assert_eq!(pre.status.code(), Some(0), "{pre:?}");
        w.server.hold(&[0x71, 4, 11]);
        let manifest = w.dir.path().join("batch.json");
        std::fs::write(
            &manifest,
            serde_json::to_vec(&serde_json::json!({"items":[
                {"op":"sign","id":"one","profile":"cms-detached","input":doc_a,"output":out_a},
                {"op":"verify","id":"hold","input":sig_c,"detached":doc_c},
                {"op":"sign","id":"three","profile":"cms-detached","input":doc_b,"output":out_b},
            ]}))
            .unwrap(),
        )
        .unwrap();
        let mut args = vec![
            "batch",
            "run",
            "--manifest",
            path(&manifest),
            "--key",
            path(&w.rsa_key),
            "--secret-file",
            path(&w.secret),
            "--authorize",
            "--json",
        ];
        args.extend(common(&w));
        let child = spawn(&args);
        let start = std::time::Instant::now();
        while !out_a.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "item one never published"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let _restore = Restore(sealed.clone());
        deny_new_files(&sealed);
        w.server.release();
        let result = child.wait_with_output().unwrap();
        assert_eq!(result.status.code(), Some(4), "{result:?}");
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        let row = |id: &str| {
            report["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|i| i["id"] == id)
                .unwrap()
                .clone()
        };
        assert_eq!(row("one")["status"], "Completed", "{report}");
        assert_eq!(row("one")["published"], true);
        assert_eq!(row("three")["status"], "Failed", "{report}");
        assert_eq!(row("three")["applied"], "Applied", "{report}");
        assert_eq!(row("three")["published"], false);
        assert!(!out_b.exists());
        // Item one's file is intact and independently verifiable.
        let verify = run(
            &[
                "verify",
                "--profile",
                "cms",
                "--input",
                path(&out_a),
                "--detached",
                path(&doc_a),
                "--root",
                path(&w.root),
                "--pki-endpoint",
                &w.origin,
                "--as-of",
                "1793620800",
            ],
            b"",
        );
        assert_eq!(verify.status.code(), Some(0), "{verify:?}");
    }
}
