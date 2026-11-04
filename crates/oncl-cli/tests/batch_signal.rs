//! Real batch cancellation and deadline. The Core freezes every batch source
//! before approval, so the second item stalls where a real batch can: a strict
//! verification whose OCSP request (for the GOST signer only) the loopback
//! responder holds until the test releases it, after item 1 is signed and
//! published. Isolated binary: console events are delivered only to the owned
//! child's process group.
#![cfg(windows)]
mod support;
use serde_json::json;
use std::{
    os::windows::process::CommandExt,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use support::*;
fn wait_for(child: &mut std::process::Child, path: &std::path::Path) {
    let start = Instant::now();
    while !path.exists() {
        if start.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut pipe, &mut stderr);
            }
            panic!("item 1 never published; child stderr: {stderr}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
struct Scenario {
    output: std::process::Output,
    report: serde_json::Value,
    a: std::path::PathBuf,
    b: std::path::PathBuf,
    document: std::path::PathBuf,
    world: World,
}
fn run_stalled(
    extra: &[&str],
    readonly_stdout: bool,
    stop: impl FnOnce(&mut std::process::Child, &World, Instant),
) -> Scenario {
    let w = world();
    let doc_a = w.dir.path().join("a.bin");
    let doc_b = w.dir.path().join("b.bin");
    let doc_c = w.dir.path().join("c.bin");
    for (path, bytes) in [
        (&doc_a, "first document"),
        (&doc_b, "third document"),
        (&doc_c, "stalled document"),
    ] {
        std::fs::write(path, bytes).unwrap();
    }
    let (sig_a, sig_b, sig_c) = (
        w.dir.path().join("a.der"),
        w.dir.path().join("b.der"),
        w.dir.path().join("c.der"),
    );
    // Item 2's signature is made beforehand by the GOST signer through the
    // real binary; verifying it later needs that signer's OCSP status.
    let pre = run(
        &[
            "sign",
            "--profile",
            "cms",
            "--detached",
            "--input",
            path(&doc_c),
            "--output",
            path(&sig_c),
            "--key",
            path(&w.gost_key),
            "--secret-file",
            path(&w.secret),
            "--authorize",
            "--root",
            path(&w.root),
            "--pki-endpoint",
            &w.origin,
            "--as-of",
            "1793620800",
        ],
        b"",
    );
    assert_eq!(pre.status.code(), Some(0), "{pre:?}");
    w.server.hold(&[0x71, 4, 11]);
    let m = w.dir.path().join("batch.json");
    std::fs::write(
        &m,
        serde_json::to_vec(&json!({"items":[
            {"op":"sign","id":"first","profile":"cms-detached","input":doc_a,"output":sig_a},
            {"op":"verify","id":"stalled","input":sig_c,"detached":doc_c},
            {"op":"sign","id":"third","profile":"cms-detached","input":doc_b,"output":sig_b},
        ]}))
        .unwrap(),
    )
    .unwrap();
    let mut args = vec![
        "batch",
        "run",
        "--manifest",
        path(&m),
        "--key",
        path(&w.rsa_key),
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
    args.extend(extra);
    let start = Instant::now();
    let readonly = w.dir.path().join("readonly.out");
    std::fs::write(&readonly, b"").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_oncl"));
    command
        .args(&args)
        .creation_flags(0x0000_0200) // CREATE_NEW_PROCESS_GROUP: owned child group only
        .env_remove("DISPLAY")
        .stdin(Stdio::null())
        .stderr(Stdio::piped());
    if readonly_stdout {
        // Every stdout write fails: an injected report-delivery failure.
        command.stdout(Stdio::from(std::fs::File::open(&readonly).unwrap()));
    } else {
        command.stdout(Stdio::piped());
    }
    let mut child = command.spawn().unwrap();
    wait_for(&mut child, &sig_a);
    // Barrier, not a sleep: the held OCSP request of item 2 has reached the
    // responder, so the batch is provably inside item 2 and item 3 cannot run.
    w.server.wait_arrival(30);
    stop(&mut child, &w, start);
    let output = child.wait_with_output().unwrap();
    let report = serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
    Scenario {
        output,
        report,
        a: sig_a,
        b: sig_b,
        document: doc_a,
        world: w,
    }
}
fn assert_terminal_report(s: &Scenario, interrupted_code: &str, top_code: &str) {
    let items = s.report["items"]
        .as_array()
        .unwrap_or_else(|| panic!("no terminal batch report: {:?}", s.output));
    let by = |id: &str| items.iter().find(|i| i["id"] == id).unwrap().clone();
    assert_eq!(by("first")["status"], "Completed", "{}", s.report);
    assert_eq!(by("first")["applied"], "Applied");
    assert_eq!(by("first")["published"], true);
    let stalled = by("stalled");
    assert_eq!(stalled["status"], "Failed", "{}", s.report);
    assert_eq!(stalled["code"], interrupted_code, "{}", s.report);
    assert_eq!(stalled["applied"], "NotApplied", "{}", s.report);
    assert_eq!(by("third")["status"], "NotRun", "{}", s.report);
    assert_eq!(by("third")["applied"], "NotApplied");
    assert_eq!(by("third")["published"], false);
    assert_eq!(s.report["attempted"], 2);
    assert_eq!(s.report["completed"], 1);
    assert_eq!(s.report["total"], 3);
    assert_eq!(s.report["code"], top_code, "{}", s.report);
    assert_eq!(
        s.report["stop"],
        format!("item 1: {interrupted_code}: NotApplied"),
        "{}",
        s.report
    );
    // Item 1's file is intact and independently verifiable; item 3 never ran.
    let verify = run(
        &[
            "verify",
            "--profile",
            "cms",
            "--input",
            path(&s.a),
            "--detached",
            path(&s.document),
            "--root",
            path(&s.world.root),
            "--pki-endpoint",
            &s.world.origin,
            "--as-of",
            "1793620800",
        ],
        b"",
    );
    assert_eq!(verify.status.code(), Some(0), "{verify:?}");
    assert!(!s.b.exists());
    let stderr = String::from_utf8_lossy(&s.output.stderr);
    assert_eq!(
        stderr.matches("applied=Applied succeeded=true").count(),
        1,
        "{stderr}"
    );
    assert!(!stderr.contains(PASSWORD));
}
fn ctrl_break(child: &std::process::Child) {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
    }
    // SAFETY: targets only the owned child's fresh process group id (its pid).
    let sent = unsafe { GenerateConsoleCtrlEvent(1, child.id()) };
    assert_ne!(
        sent, 0,
        "CTRL_BREAK delivery failed (no console in this harness?)"
    );
}
// The held OCSP response is released only after the process has ended on its
// own: item 2's request cannot complete, so the batch can only stop through the
// real cancellation or the real deadline (no sleep decides the semantics).
#[test]
fn real_ctrl_break_after_item_one_exits_130_with_a_terminal_report_and_kept_output() {
    let s = run_stalled(&[], false, |child, _, _| ctrl_break(child));
    assert_eq!(s.output.status.code(), Some(130), "{:?}", s.output);
    assert_terminal_report(&s, "Cancelled", "Cancelled");
}
#[test]
fn deadline_after_item_one_exits_4_with_a_terminal_report_and_kept_output() {
    let s = run_stalled(&["--timeout-seconds", "4"], false, |_, _, _| {});
    assert_eq!(s.output.status.code(), Some(4), "{:?}", s.output);
    assert_terminal_report(&s, "DeadlineExceeded", "DeadlineExceeded");
}
#[test]
fn a_failed_terminal_report_never_changes_the_stop_exit_code() {
    // stdout is unwritable: the report cannot be delivered, the stop still wins.
    let s = run_stalled(&[], true, |child, _, _| ctrl_break(child));
    assert_eq!(s.output.status.code(), Some(130), "{:?}", s.output);
    let stderr = String::from_utf8_lossy(&s.output.stderr);
    assert!(
        stderr.contains("report_delivery_failed_after_stop"),
        "{stderr}"
    );
    assert!(!s.b.exists());
    // The unwritable report destination (missing directory) after a deadline.
    let missing = std::env::temp_dir()
        .join("oncl-no-such-dir")
        .join("report.json");
    let missing = missing.to_str().unwrap().to_owned();
    let s = run_stalled(
        &["--timeout-seconds", "4", "--report", &missing],
        false,
        |_, _, _| {},
    );
    assert_eq!(s.output.status.code(), Some(4), "{:?}", s.output);
    let stderr = String::from_utf8_lossy(&s.output.stderr);
    assert!(
        stderr.contains("report_delivery_failed_after_stop"),
        "{stderr}"
    );
    assert!(!std::path::Path::new(&missing).exists());
}
