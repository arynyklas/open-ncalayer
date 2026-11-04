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

#[cfg(windows)]
mod ctrl_break {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        os::windows::process::CommandExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    pub struct Run {
        pub code: Option<i32>,
        pub stderr: String,
        pub stdout: Vec<u8>,
        pub dir: tempfile::TempDir,
    }

    /// Runs `oncl <args>` against a stub server, delivers a real Ctrl-Break `after` the stub
    /// accepted the connection, and waits (at most 10 s) for the exit.
    pub fn run(
        serve: fn(TcpStream),
        after: Duration,
        args: impl FnOnce(&str, &std::path::Path) -> Vec<String>,
    ) -> Run {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                tx.send(()).unwrap();
                serve(stream);
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let private =
            oncl_pki::private_fs::PrivateDirectory::create(&dir.path().join("t")).unwrap();
        private
            .create_file("token")
            .unwrap()
            .write_all(b"abcdefabcdefabcdefabcdefabcdefab")
            .unwrap();
        std::fs::write(dir.path().join("doc.bin"), b"abc").unwrap();
        let mut command_args = vec![
            "--endpoint".to_owned(),
            format!("http://{address}"),
            "--token-file".to_owned(),
            dir.path()
                .join("t")
                .join("token")
                .to_str()
                .unwrap()
                .to_owned(),
        ];
        command_args.extend(args(&address.to_string(), dir.path()));
        let mut child = Command::new(env!("CARGO_BIN_EXE_oncl"))
            .args(&command_args)
            .current_dir(dir.path())
            .creation_flags(0x0000_0200)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        rx.recv_timeout(Duration::from_secs(20))
            .expect("never connected");
        std::thread::sleep(after);
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
        }
        // SAFETY: targets only the owned child's fresh process group id (its pid).
        assert_ne!(unsafe { GenerateConsoleCtrlEvent(1, child.id()) }, 0);
        let signalled = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(
                signalled.elapsed() < Duration::from_secs(10),
                "no prompt exit"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        Run {
            code: status.code(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            stdout,
            dir,
        }
    }

    pub fn silent(mut stream: TcpStream) {
        let mut buffer = [0u8; 8192];
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let end = Instant::now() + Duration::from_secs(30);
        while Instant::now() < end {
            let _ = stream.read(&mut buffer);
        }
    }

    /// Accepts the whole request, then streams the first bytes of a huge artifact forever.
    pub fn streaming(mut stream: TcpStream) {
        let mut buffer = [0u8; 8192];
        stream
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let _ = stream.read(&mut buffer);
        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        while matches!(stream.read(&mut buffer), Ok(n) if n > 0) {}
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; boundary=B\r\nTransfer-Encoding: chunked\r\n\r\n");
        let head = "--B\r\nContent-Type: application/octet-stream\r\nContent-Disposition: form-data; name=\"artifact\"\r\nContent-ID: artifact-0\r\nContent-Length: 4000000000\r\n\r\n";
        let _ = write!(stream, "{:x}\r\n{head}\r\n", head.len());
        let zeros = vec![0u8; 16 * 1024];
        let end = Instant::now() + Duration::from_secs(30);
        while Instant::now() < end {
            if write!(stream, "{:x}\r\n", zeros.len()).is_err()
                || stream.write_all(&zeros).is_err()
                || stream.write_all(b"\r\n").is_err()
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// A key-capable request whose whole body was handed over and that is then cancelled: the
/// key may have been applied, so the honest state is `Unknown` (never `NotApplied`).
#[cfg(windows)]
#[test]
fn ctrl_break_after_a_full_sign_upload_is_130_with_applied_unknown() {
    let run = ctrl_break::run(
        ctrl_break::silent,
        std::time::Duration::from_millis(2500),
        |_, dir| {
            [
                "sign",
                "--profile",
                "cms",
                "--key-name",
                "ops-key",
                "--authorize",
                "--input",
                dir.join("doc.bin").to_str().unwrap(),
                "--output",
                dir.join("out.p7s").to_str().unwrap(),
            ]
            .iter()
            .map(ToString::to_string)
            .collect()
        },
    );
    assert_eq!(run.code, Some(130), "{}", run.stderr);
    assert!(run.stderr.contains("applied=Unknown"), "{}", run.stderr);
    assert!(!run.dir.path().join("out.p7s").exists());
}

/// Ctrl-C while an artifact is being downloaded and staged exits 130 (the staging failure it
/// causes must not turn the user's cancellation into exit 1); nothing is published.
#[cfg(windows)]
#[test]
fn ctrl_break_during_an_artifact_download_is_130_and_publishes_nothing() {
    let run = ctrl_break::run(
        ctrl_break::streaming,
        std::time::Duration::from_millis(2000),
        |_, dir| {
            [
                "extract",
                "--input",
                dir.join("doc.bin").to_str().unwrap(),
                "--output",
                dir.join("out.bin").to_str().unwrap(),
            ]
            .iter()
            .map(ToString::to_string)
            .collect()
        },
    );
    assert_eq!(run.code, Some(130), "{}", run.stderr);
    assert!(run.stderr.contains("applied=NotApplied"), "{}", run.stderr);
    assert!(run.stdout.is_empty());
    let left: Vec<_> = std::fs::read_dir(run.dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !left.iter().any(|n| n == "out.bin" || n.starts_with("oncl")),
        "{left:?}"
    );
}
