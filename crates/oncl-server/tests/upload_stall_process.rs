//! D7: a stalled (slow-loris) upload must not hold an admission slot until the whole
//! operation deadline. Real `oncl-server` process, real sockets, scaled timings.
#[path = "server_support/mod.rs"]
mod support;

use std::{
    io::{Read, Write},
    net::TcpStream,
    thread::sleep,
    time::{Duration, Instant},
};

const METADATA: &str = r#"{"items":[{"id":"h","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"h","role":"document"}]}"#;

fn config(root: &std::path::Path, extra: &str) -> String {
    format!(
        "scratch_directory = {}\nmax_in_flight = 2\nblocking_workers = 2\nqueue_capacity = 2\n{extra}",
        support::toml_path(&root.join("scratch"))
    )
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Route {
    /// `POST /v1/hash`, the raw body is read by the native hashing worker.
    Hash,
    /// `POST /v1/operations`, multipart read through the bounded intake.
    Multipart,
}

struct Reply {
    status: u16,
    body: String,
    elapsed: Duration,
}
impl Reply {
    fn code(&self) -> &str {
        self.body
            .split("\"code\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or("")
    }
}

/// One upload on its own socket. Headers + first bytes are written by `open`; the rest by
/// the caller. A collector thread reads the reply from the start, as a real client does: the
/// server may answer (and close) while request bytes are still in flight.
struct Upload {
    stream: TcpStream,
    route: Route,
    collector: std::thread::JoinHandle<(Vec<u8>, Duration)>,
}
impl Upload {
    fn open(process: &support::Process, route: Route, length: Option<u64>) -> Self {
        let mut stream = TcpStream::connect(process.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let (path, content_type) = match route {
            Route::Hash => ("/v1/hash", "application/octet-stream"),
            Route::Multipart => ("/v1/operations", "multipart/form-data; boundary=b"),
        };
        let framing = match length {
            Some(n) => format!("Content-Length: {n}"),
            None => "Transfer-Encoding: chunked".to_owned(),
        };
        write!(
            stream,
            "POST {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {content_type}\r\n{framing}\r\nConnection: close\r\n\r\n",
            process.address,
            process.token.as_str()
        )
        .unwrap();
        let started = Instant::now();
        let mut reader = stream.try_clone().unwrap();
        let collector = std::thread::spawn(move || {
            let mut raw = Vec::new();
            let _ = reader.read_to_end(&mut raw);
            (raw, started.elapsed())
        });
        Self {
            stream,
            route,
            collector,
        }
    }
    fn prefix(route: Route) -> Vec<u8> {
        match route {
            Route::Hash => Vec::new(),
            Route::Multipart => format!(
                "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{METADATA}\r\n--b\r\nContent-Disposition: form-data; name=\"doc\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .into_bytes(),
        }
    }
    fn suffix(route: Route) -> &'static [u8] {
        match route {
            Route::Hash => b"",
            Route::Multipart => b"\r\n--b--\r\n",
        }
    }
    /// Raw bytes of the HTTP entity, as one chunk when the upload is chunked.
    fn send(&mut self, chunked: bool, bytes: &[u8]) -> std::io::Result<()> {
        if chunked {
            write!(self.stream, "{:x}\r\n", bytes.len())?;
            self.stream.write_all(bytes)?;
            self.stream.write_all(b"\r\n")
        } else {
            self.stream.write_all(bytes)
        }
    }
    fn finish(self) -> Reply {
        let (raw, elapsed) = self.collector.join().unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        let status = text
            .strip_prefix("HTTP/1.1 ")
            .and_then(|rest| rest.get(..3))
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        Reply {
            status,
            body: text,
            elapsed,
        }
    }
}

/// An upload that sends one block of document bytes and then goes silent.
fn stalled(process: &support::Process, route: Route) -> Upload {
    let chunked = route == Route::Multipart;
    let mut upload = Upload::open(process, route, (!chunked).then_some(1 << 20));
    let mut first = Upload::prefix(route);
    first.extend_from_slice(&[7u8; 4096]);
    upload.send(chunked, &first).unwrap();
    upload
}

fn small_hash(process: &support::Process) -> Reply {
    let mut upload = Upload::open(process, Route::Hash, Some(3));
    upload.send(false, b"abc").unwrap();
    upload.finish()
}

fn assert_typed_refusal(reply: &Reply, status: u16, code: &str) {
    assert_eq!(reply.status, status, "{}", reply.body);
    assert_eq!(reply.code(), code, "{}", reply.body);
    assert!(
        reply.body.contains("\"applied\":\"NotApplied\""),
        "{}",
        reply.body
    );
}

/// The scaled D7 reproduction: both slots taken by stalled uploads (one per read path),
/// then more clients. Operation deadline 8 s, idle timeout 1.5 s, admission wait 0.6 s.
#[test]
fn stalled_uploads_release_their_slots_at_the_idle_timeout_not_the_operation_deadline() {
    let process = support::Process::configured("127.0.0.1:0", |root| {
        config(
            root,
            "admission_wait_ms = 600\noperation_timeout_ms = 8000\nheader_timeout_ms = 2000\nupload_idle_timeout_ms = 1500\n",
        )
    });
    let hold_hash = stalled(&process, Route::Hash);
    let hold_multipart = stalled(&process, Route::Multipart);
    sleep(Duration::from_millis(300));

    // Both slots are held: an honest, typed refusal, but only AFTER waiting admission_wait.
    let refused = small_hash(&process);
    assert_typed_refusal(&refused, 503, "CapacityExceeded");
    assert!(
        refused.elapsed >= Duration::from_millis(500),
        "a refusal must follow the admission wait, took {:?}",
        refused.elapsed
    );

    for held in [hold_hash, hold_multipart] {
        let route = held.route;
        let reply = held.finish();
        assert_typed_refusal(&reply, 504, "DeadlineExceeded");
        assert!(
            reply.elapsed >= Duration::from_millis(1400)
                && reply.elapsed < Duration::from_millis(4500),
            "{route:?}: the idle timeout (1.5 s), not the 8 s operation deadline, ends a stall; took {:?}",
            reply.elapsed
        );
    }

    // The slots and the spool are free again: a CPU/hash client completes at once.
    let reply = small_hash(&process);
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(reply.body.contains(
        "\"digest\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\""
    ));
    let scratch = process.directory.path().join("scratch");
    assert!(
        walk(&scratch).is_empty(),
        "stalled multipart spool must be released: {:?}",
        walk(&scratch)
    );
    process.stop();
}

fn walk(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(walk(&path));
            } else {
                files.push(path);
            }
        }
    }
    files
}

/// admission_wait_ms queues a client that arrives while max_in_flight operations run, and
/// admits it as soon as a slot frees.
#[test]
fn a_client_arriving_at_the_in_flight_cap_waits_for_a_slot_within_admission_wait() {
    let process = support::Process::configured("127.0.0.1:0", |root| {
        config(
            root,
            "admission_wait_ms = 6000\noperation_timeout_ms = 10000\nheader_timeout_ms = 2000\nupload_idle_timeout_ms = 1500\n",
        )
    });
    let hold_a = stalled(&process, Route::Hash);
    let hold_b = stalled(&process, Route::Hash);
    sleep(Duration::from_millis(300));
    let waited = small_hash(&process);
    assert_eq!(waited.status, 200, "{}", waited.body);
    assert!(
        waited.elapsed >= Duration::from_millis(900)
            && waited.elapsed < Duration::from_millis(5000),
        "queued until the stalls ended at the idle timeout, took {:?}",
        waited.elapsed
    );
    for held in [hold_a, hold_b] {
        assert_typed_refusal(&held.finish(), 504, "DeadlineExceeded");
    }
    process.stop();
}

/// A slow client that keeps sending (4 KiB every 400 ms = 10 KiB/s, 4 s in total, far
/// beyond the 1.5 s idle timeout) is governed by the operation deadline only.
#[test]
fn a_slow_but_steady_upload_is_not_killed_by_the_idle_timeout() {
    let process = support::Process::configured("127.0.0.1:0", |root| {
        config(
            root,
            "admission_wait_ms = 600\noperation_timeout_ms = 8000\nheader_timeout_ms = 2000\nupload_idle_timeout_ms = 1500\n",
        )
    });
    for route in [Route::Hash, Route::Multipart] {
        let block = [9u8; 4096];
        let mut upload = Upload::open(&process, route, None);
        let mut first = Upload::prefix(route);
        first.extend_from_slice(&block);
        upload.send(true, &first).unwrap();
        for _ in 0..9 {
            sleep(Duration::from_millis(400));
            upload.send(true, &block).unwrap();
        }
        upload.send(true, Upload::suffix(route)).unwrap();
        upload.stream.write_all(b"0\r\n\r\n").unwrap();
        let reply = upload.finish();
        assert_eq!(reply.status, 200, "{route:?}: {}", reply.body);
        assert!(
            reply.elapsed >= Duration::from_millis(3500),
            "{:?}",
            reply.elapsed
        );
        assert!(
            reply.body.contains("\"bytes_in\":40960"),
            "{route:?}: {}",
            reply.body
        );
    }
    process.stop();
}

/// One byte every 400 ms never trips the 1.5 s idle timeout but is far below the minimum
/// throughput (1 KiB/s): it is ended at the end of the first rate window, not at 8 s.
#[test]
fn a_trickle_below_the_minimum_rate_is_refused_long_before_the_operation_deadline() {
    let process = support::Process::configured("127.0.0.1:0", |root| {
        config(
            root,
            "admission_wait_ms = 600\noperation_timeout_ms = 8000\nheader_timeout_ms = 2000\nupload_idle_timeout_ms = 1500\n",
        )
    });
    for route in [Route::Hash, Route::Multipart] {
        let mut upload = Upload::open(&process, route, None);
        let mut first = Upload::prefix(route);
        first.push(1);
        upload.send(true, &first).unwrap();
        let started = Instant::now();
        while started.elapsed() < Duration::from_millis(7000) {
            sleep(Duration::from_millis(400));
            if upload.send(true, &[1]).is_err() {
                break;
            }
        }
        let reply = upload.finish();
        assert_typed_refusal(&reply, 504, "DeadlineExceeded");
        assert!(
            reply.elapsed < Duration::from_millis(4500),
            "{route:?}: the minimum-rate rule must end a 1 B/0.4 s trickle early, took {:?}",
            reply.elapsed
        );
    }
    process.stop();
}

#[test]
fn the_upload_knobs_have_safe_defaults_and_bounded_ranges() {
    let defaults = oncl_server::config::ServerConfig::default();
    assert_eq!(defaults.upload_idle_timeout_ms, 30_000);
    assert_eq!(defaults.upload_min_bytes_per_second, 1024);
    defaults.validate().expect("the defaults are valid");
    for (idle, rate) in [(999, 1024), (86_400_001, 1024), (30_000, (1 << 30) + 1)] {
        let config = oncl_server::config::ServerConfig {
            upload_idle_timeout_ms: idle,
            upload_min_bytes_per_second: rate,
            ..Default::default()
        };
        assert!(config.validate().is_err(), "{idle} ms / {rate} B/s");
    }
    let off = oncl_server::config::ServerConfig {
        upload_min_bytes_per_second: 0,
        ..Default::default()
    };
    off.validate().expect("0 switches the rate rule off");
}
