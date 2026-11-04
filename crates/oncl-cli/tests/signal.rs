//! Real owned-child signal cancellation of a streaming `hash` (batch cancellation
//! with later items NotRun is `batch_signal.rs`). Isolated in its own test binary so no
//! other process in the suite can share its console event delivery.
use std::{
    io::Write,
    process::{Command, Stdio},
};

#[cfg(windows)]
#[test]
fn real_ctrl_break_reaches_the_owned_hash_child_as_exit_130_with_no_stdout() {
    use std::os::windows::process::CommandExt;
    // The blocking read is cooperative: after the signal latches, closing the
    // pipe lets the original control observe cancellation. No forced termination.
    let mut child = Command::new(env!("CARGO_BIN_EXE_oncl"))
        .args(["hash", "--algorithm", "sha256", "--input", "-"])
        .creation_flags(0x0000_0200) // CREATE_NEW_PROCESS_GROUP: owned child group only
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
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
    std::thread::sleep(std::time::Duration::from_millis(300));
    child.stdin.take().unwrap().write_all(b"x").unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(130), "{result:?}");
    assert!(result.stdout.is_empty());
}
