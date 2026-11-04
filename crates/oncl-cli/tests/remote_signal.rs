//! Ctrl-Break against a remote call whose server accepts and never answers: the real `oncl`
//! exits 130 within seconds (the wait is polled, not a blocking read), commits nothing and
//! never retries. Own test binary so no other process shares its console event delivery.
#[cfg(windows)]
#[test]
fn ctrl_break_ends_a_remote_call_to_a_silent_server_promptly() {
    use std::{
        io::{Read, Write},
        os::windows::process::CommandExt,
        process::{Command, Stdio},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let (count, stop) = (
        accepted.clone(),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );
    let stopping = stop.clone();
    let silent = std::thread::spawn(move || {
        let mut held = Vec::new();
        while !stopping.load(Ordering::SeqCst) {
            if let Ok((mut stream, _)) = listener.accept() {
                count.fetch_add(1, Ordering::SeqCst);
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_millis(50)))
                    .unwrap();
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer);
                held.push(stream); // accepted, read, never answered
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let private = oncl_pki::private_fs::PrivateDirectory::create(&dir.path().join("t")).unwrap();
    private
        .create_file("token")
        .unwrap()
        .write_all(b"abcdefabcdefabcdefabcdefabcdefab")
        .unwrap();
    let document = dir.path().join("doc.bin");
    std::fs::write(&document, b"abc").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_oncl"))
        .args([
            "--endpoint",
            &format!("http://{address}"),
            "--token-file",
            dir.path().join("t").join("token").to_str().unwrap(),
            "hash",
            "--algorithm",
            "sha256",
            "--input",
            document.to_str().unwrap(),
        ])
        .creation_flags(0x0000_0200) // CREATE_NEW_PROCESS_GROUP: only the owned child group
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while accepted.load(Ordering::SeqCst) == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the client never connected"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // Past the 1 s `Expect: 100-continue` wait: the body is sent and the client is waiting for
    // a response that never comes (the case a polled upload alone cannot cover).
    std::thread::sleep(Duration::from_millis(2500));
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
    }
    // SAFETY: targets only the owned child's fresh process group id (its pid).
    assert_ne!(
        unsafe { GenerateConsoleCtrlEvent(1, child.id()) },
        0,
        "CTRL_BREAK delivery failed"
    );
    let signalled = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            signalled.elapsed() < Duration::from_secs(10),
            "no prompt exit after Ctrl-Break"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    silent.join().unwrap();
    assert_eq!(
        status.code(),
        Some(130),
        "{}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(stdout.is_empty());
    assert!(signalled.elapsed() < Duration::from_secs(10));
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "the call was retried");
    assert!(String::from_utf8_lossy(&stderr).contains("applied=NotApplied"));
}
