#[path = "server_support/mod.rs"]
mod support;

use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};

const DOCUMENT: u64 = 256 * 1024 * 1024;

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// Real server + real socket: a long streaming hash must not turn each native checkpoint into a
/// response frame. Progress is latest-state and paced by wall time, the terminal record is
/// still delivered, and the whole response stays far below the operation output cap.
#[test]
fn streaming_progress_is_paced_by_time_not_by_checkpoints() {
    let process = support::Process::configured("127.0.0.1:0", |root| {
        format!(
            "scratch_directory = {}\nmax_in_flight = 1\nblocking_workers = 1\nqueue_capacity = 1",
            support::toml_path(&root.join("scratch"))
        )
    });
    let metadata = r#"{"items":[{"id":"big","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"big","role":"document"}]}"#;
    let prefix = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"d.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    );
    let suffix = "\r\n--b--\r\n";
    let length = prefix.len() as u64 + DOCUMENT + suffix.len() as u64;
    let mut stream = std::net::TcpStream::connect(process.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .unwrap();
    let mut reader = stream.try_clone().unwrap();
    let started = Instant::now();
    let collector = std::thread::spawn(move || {
        let mut response = Vec::new();
        let _ = reader.read_to_end(&mut response);
        response
    });
    stream
        .write_all(
            format!(
                "POST /v1/batch HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n",
                process.address,
                process.token.as_str()
            )
            .as_bytes(),
        )
        .unwrap();
    stream.write_all(prefix.as_bytes()).unwrap();
    let chunk = vec![0u8; 1 << 20];
    let mut sent = Ok(());
    for _ in 0..DOCUMENT / chunk.len() as u64 {
        sent = stream.write_all(&chunk);
        if sent.is_err() {
            break;
        }
    }
    if sent.is_ok() {
        sent = stream.write_all(suffix.as_bytes());
    }
    let response = collector.join().unwrap();
    assert!(
        sent.is_ok(),
        "upload refused: {sent:?}: {}",
        String::from_utf8_lossy(&response[..response.len().min(600)])
    );
    let elapsed = started.elapsed();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let progress = count(&response, b"name=\"progress\"");
    let finals = count(&response, b"name=\"final\"");
    eprintln!(
        "elapsed={elapsed:?} response_bytes={} progress_frames={progress}",
        response.len()
    );
    assert_eq!(finals, 1, "terminal record is delivered exactly once");
    assert!(
        response.ends_with(b"--\r\n\r\n0\r\n\r\n"),
        "multipart closed: {:?}",
        String::from_utf8_lossy(&response[response.len() - 60..])
    );
    // One immediate frame plus at most one per 500 ms (a 250 ms spacing fails).
    assert!(
        progress <= 2 + (elapsed.as_millis() / 500) as usize,
        "{progress} progress frames in {elapsed:?}"
    );
    assert!(count(&response, b"\"status\":\"completed\"") == 1);
    process.stop();
}
