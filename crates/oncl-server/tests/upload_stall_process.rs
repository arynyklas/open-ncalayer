//! D7: a stalled (slow-loris) upload must not hold an admission slot, a native worker or the
//! capacity of other clients until the whole operation deadline. The body is captured in its
//! own phase with its own limit (`max_uploads`). Real `oncl-server` process, real sockets,
//! scaled timings.
#[path = "server_support/mod.rs"]
mod support;

use std::{
    io::{Read, Write},
    net::TcpStream,
    thread::sleep,
    time::{Duration, Instant},
};

const METADATA: &str = r#"{"items":[{"id":"h","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"h","role":"document"}]}"#;

/// Plenty of slots and workers: only the upload phase can be the limit.
fn config_wide(root: &std::path::Path, extra: &str) -> String {
    format!(
        "scratch_directory = {}\nmax_in_flight = 16\nblocking_workers = 16\nqueue_capacity = 16\n{extra}",
        support::toml_path(&root.join("scratch"))
    )
}

/// The default executor shape is `max_in_flight = 2`, `blocking_workers = 2`.
fn config(root: &std::path::Path, extra: &str) -> String {
    format!(
        "scratch_directory = {}\nmax_in_flight = 2\nblocking_workers = 2\nqueue_capacity = 2\n{extra}",
        support::toml_path(&root.join("scratch"))
    )
}

/// One slot and one worker only: a single stalled upload would have been enough to starve
/// every other request before the upload phase had its own limit.
fn config_one(root: &std::path::Path, extra: &str) -> String {
    format!(
        "scratch_directory = {}\nmax_in_flight = 1\nblocking_workers = 1\nqueue_capacity = 1\n{extra}",
        support::toml_path(&root.join("scratch"))
    )
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Route {
    /// `POST /v1/hash`, the raw body is hashed while it is read.
    Hash,
    /// `POST /v1/operations`, multipart captured by the bounded intake.
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

/// The starvation this design removes: ONE admission slot and ONE native worker, and two
/// stalled uploads (one per read path). Before the upload phase had its own limit a single
/// stalled upload took the slot or the worker and every other client got `503` until the
/// stall ended. Now other requests complete at once while both stalls are pending, and the
/// stalls end at the idle timeout (4 s), not at the operation deadline (12 s).
#[test]
fn stalled_uploads_take_neither_an_admission_slot_nor_a_native_worker() {
    let process = support::Process::configured("127.0.0.1:0", |root| {
        config_one(
            root,
            "admission_wait_ms = 600\noperation_timeout_ms = 12000\nheader_timeout_ms = 2000\nupload_idle_timeout_ms = 4000\n",
        )
    });
    let hold_hash = stalled(&process, Route::Hash);
    let hold_multipart = stalled(&process, Route::Multipart);
    sleep(Duration::from_millis(300));

    let pending = Instant::now();
    for round in 0..3 {
        let reply = small_hash(&process);
        assert_eq!(reply.status, 200, "hash round {round}: {}", reply.body);
        assert!(reply.body.contains(
            "\"digest\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\""
        ));
        assert!(
            reply.elapsed < Duration::from_millis(550),
            "round {round}: a hash must not wait behind a stalled upload (admission wait is 600 ms), took {:?}",
            reply.elapsed
        );
        let reply = small_operation(&process, "/v1/operations");
        assert_eq!(
            reply.status, 200,
            "operations round {round}: {}",
            reply.body
        );
        assert!(
            reply.elapsed < Duration::from_millis(550),
            "round {round}: an operation must not wait behind a stalled upload, took {:?}",
            reply.elapsed
        );
    }
    assert!(
        pending.elapsed() < Duration::from_millis(3000),
        "the small requests must have run while both stalls were still pending, took {:?}",
        pending.elapsed()
    );

    for held in [hold_hash, hold_multipart] {
        let route = held.route;
        let reply = held.finish();
        assert_typed_refusal(&reply, 504, "DeadlineExceeded");
        assert!(
            reply.elapsed >= Duration::from_millis(3900)
                && reply.elapsed < Duration::from_millis(9000),
            "{route:?}: the idle timeout (4 s), not the 12 s operation deadline, ends a stall; took {:?}",
            reply.elapsed
        );
    }

    // The spool of the stalled multipart upload is released with its request.
    let reply = small_hash(&process);
    assert_eq!(reply.status, 200, "{}", reply.body);
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

/// `max_uploads` is the limit of the upload phase: with every upload slot taken by a stalled
/// body (one per read path) a further client waits `admission_wait_ms` and gets the typed
/// `503 CapacityExceeded`/`NotApplied` on every body route; the refusal comes before its body
/// is read, and the slots are free again when the stalls have ended.
#[test]
fn upload_cap_exhaustion_is_a_typed_503_after_the_admission_wait_and_frees_when_uploads_end() {
    let process = support::Process::configured("127.0.0.1:0", |root| {
        config_wide(
            root,
            "max_uploads = 2\nadmission_wait_ms = 500\noperation_timeout_ms = 8000\nheader_timeout_ms = 2000\nupload_idle_timeout_ms = 3000\n",
        )
    });
    let hold_hash = stalled(&process, Route::Hash);
    let hold_multipart = stalled(&process, Route::Multipart);
    sleep(Duration::from_millis(300));

    let refused = small_hash(&process);
    assert_typed_refusal(&refused, 503, "CapacityExceeded");
    assert!(
        refused.elapsed >= Duration::from_millis(450)
            && refused.elapsed < Duration::from_millis(2500),
        "a refusal must follow the admission wait, took {:?}",
        refused.elapsed
    );
    for path in ["/v1/operations", "/v1/batch"] {
        let refused = small_operation(&process, path);
        assert_typed_refusal(&refused, 503, "CapacityExceeded");
        assert!(
            refused.elapsed >= Duration::from_millis(450),
            "{path}: {:?}",
            refused.elapsed
        );
    }

    for held in [hold_hash, hold_multipart] {
        assert_typed_refusal(&held.finish(), 504, "DeadlineExceeded");
    }
    let reply = small_hash(&process);
    assert_eq!(reply.status, 200, "{}", reply.body);
    for path in ["/v1/operations", "/v1/batch"] {
        let reply = small_operation(&process, path);
        assert_eq!(reply.status, 200, "{path}: {}", reply.body);
    }
    process.stop();
}

/// A client that arrives while every upload slot is taken waits for one within
/// `admission_wait_ms` and is served as soon as a stalled upload ends.
#[test]
fn a_client_at_the_upload_cap_waits_for_a_slot_within_admission_wait() {
    let process = support::Process::configured("127.0.0.1:0", |root| {
        config_wide(
            root,
            "max_uploads = 2\nadmission_wait_ms = 6000\noperation_timeout_ms = 10000\nheader_timeout_ms = 2000\nupload_idle_timeout_ms = 1500\n",
        )
    });
    for path in ["/v1/hash", "/v1/operations", "/v1/batch"] {
        let hold_a = stalled(&process, Route::Hash);
        let hold_b = stalled(&process, Route::Multipart);
        sleep(Duration::from_millis(300));
        let waited = if path == "/v1/hash" {
            small_hash(&process)
        } else {
            small_operation(&process, path)
        };
        assert_eq!(waited.status, 200, "{path}: {}", waited.body);
        assert!(
            waited.elapsed >= Duration::from_millis(900)
                && waited.elapsed < Duration::from_millis(5000),
            "{path}: queued until the stalls ended at the idle timeout, took {:?}",
            waited.elapsed
        );
        for held in [hold_a, hold_b] {
            assert_typed_refusal(&held.finish(), 504, "DeadlineExceeded");
        }
    }
    process.stop();
}

/// A client that disconnects in the middle of its upload releases the upload slot, the
/// spool and the temp reservation: with room for exactly one full-size upload, a client that
/// sent most of a document and hung up does not stop the next full-size operation.
#[test]
fn a_disconnect_during_the_upload_releases_slot_spool_and_temp() {
    const LIMIT: usize = 1 << 20;
    let process = support::Process::configured("127.0.0.1:0", |root| {
        config_wide(
            root,
            &format!(
                "max_uploads = 1\ninput_bytes = {LIMIT}\ncontainer_bytes = {LIMIT}\ntotal_temp = {}\ntemp_per_operation = {}\nadmission_wait_ms = 600\noperation_timeout_ms = 20000\nheader_timeout_ms = 2000\nupload_idle_timeout_ms = 15000\n",
                2 * LIMIT,
                2 * LIMIT
            ),
        )
    });
    let scratch = process.directory.path().join("scratch");
    for round in 0..3 {
        let mut upload = Upload::open(&process, Route::Multipart, None);
        let mut first = Upload::prefix(Route::Multipart);
        first.extend_from_slice(&vec![5u8; LIMIT - 4096]);
        upload.send(true, &first).unwrap();
        // The spool exists while the upload is in progress.
        let started = Instant::now();
        while walk(&scratch).is_empty() && started.elapsed() < Duration::from_secs(5) {
            sleep(Duration::from_millis(20));
        }
        assert!(
            !walk(&scratch).is_empty(),
            "round {round}: the upload spools to scratch"
        );
        // Hang up in the middle of the document.
        upload.stream.shutdown(std::net::Shutdown::Both).unwrap();
        drop(upload.stream);
        let _ = upload.collector.join();

        // The one upload slot is free at once (no idle timeout, no admission wait elapsed).
        let reply = full_size_operation(&process, LIMIT);
        assert_eq!(reply.status, 200, "round {round}: {}", reply.body);
        assert!(
            reply.elapsed < Duration::from_millis(550),
            "round {round}: the slot must be free right after the disconnect, took {:?}",
            reply.elapsed
        );
        let started = Instant::now();
        while !walk(&scratch).is_empty() && started.elapsed() < Duration::from_secs(5) {
            sleep(Duration::from_millis(20));
        }
        assert!(
            walk(&scratch).is_empty(),
            "round {round}: the spool must be gone: {:?}",
            walk(&scratch)
        );
    }
    process.stop();
}

/// A `hash` operation over a document of exactly `size` bytes.
fn full_size_operation(process: &support::Process, size: usize) -> Reply {
    let mut body = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{METADATA}\r\n--b\r\nContent-Disposition: form-data; name=\"doc\"\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(&vec![3u8; size]);
    body.extend_from_slice(b"\r\n--b--\r\n");
    let mut stream = TcpStream::connect(process.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let started = Instant::now();
    write!(
        stream,
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        process.address,
        process.token.as_str(),
        body.len()
    )
    .unwrap();
    stream.write_all(&body).unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    Reply {
        status: text
            .strip_prefix("HTTP/1.1 ")
            .and_then(|r| r.get(..3))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0),
        body: text,
        elapsed: started.elapsed(),
    }
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

/// `max_uploads` unset: the effective default is `min(8, max(1, total_temp /
/// (input_bytes + container_bytes)))` and every config that validated before still validates.
/// An explicit value is 1 ..= 256 and at most that bound; the refusal names the key.
#[test]
fn max_uploads_defaults_to_what_the_temp_budget_holds_and_an_explicit_value_is_bounded() {
    use oncl_server::config::{MaxUploadsError, ServerConfig};
    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;
    let defaults = ServerConfig::default();
    assert_eq!(defaults.max_uploads, None, "the key is unset by default");
    assert_eq!(defaults.effective_max_uploads(), 8);
    assert_eq!(defaults.lowered_max_uploads(), None, "nothing to log at 8");
    defaults.validate().expect("the default config validates");

    // (total_temp, temp_per_operation, effective default): the configs the proof harness and
    // the operators use, all with the key unset and the default 1 GiB + 1 GiB allowances.
    let table = [
        (16 * GIB, 8 * GIB, 8),
        (8 * GIB, 8 * GIB, 4),
        (4 * GIB, 4 * GIB, 2),
        (3 * GIB, 2 * GIB, 1),
        (2 * GIB, GIB, 1),
        (4 * GIB, GIB, 2),
        (8 * GIB, 4 * GIB, 4),
        (512 * MIB, 512 * MIB, 1),
        (MIB, MIB, 1),
    ];
    for (total_temp, temp_per_operation, effective) in table {
        let config = ServerConfig {
            total_temp,
            temp_per_operation,
            ..Default::default()
        };
        config
            .validate()
            .unwrap_or_else(|e| panic!("{total_temp}/{temp_per_operation}: {e}"));
        assert_eq!(
            config.effective_max_uploads(),
            effective,
            "{total_temp}/{temp_per_operation}"
        );
        assert_eq!(config.lowered_max_uploads().is_some(), effective < 8);
    }
    let lowered = ServerConfig {
        total_temp: 4 * GIB,
        temp_per_operation: 4 * GIB,
        ..Default::default()
    };
    assert_eq!(lowered.lowered_max_uploads(), Some((2, 2)));

    // Explicit values: the bound is accepted, one more is refused with the key named.
    let with = |max_uploads: usize, tweak: &dyn Fn(&mut ServerConfig)| {
        let mut config = ServerConfig {
            max_uploads: Some(max_uploads),
            ..Default::default()
        };
        tweak(&mut config);
        config.validate()
    };
    let nothing = |_: &mut ServerConfig| {};
    let named = |result: std::io::Result<()>, bound: u64| {
        let error = result.expect_err("refused");
        let refusal = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<MaxUploadsError>())
            .expect("a typed max_uploads refusal, not the generic one");
        assert_eq!(refusal.bound, bound);
        let text = error.to_string();
        assert!(text.contains("`max_uploads`"), "{text}");
        assert!(text.contains(&bound.to_string()), "{text}");
    };
    named(with(0, &nothing), 8);
    named(with(9, &nothing), 8);
    assert!(with(8, &nothing).is_ok());
    assert!(with(1, &nothing).is_ok());
    let large = |config: &mut ServerConfig| {
        config.total_temp = 1024 * GIB;
    };
    assert!(with(256, &large).is_ok(), "1024 GiB / 2 GiB = 512 >= 256");
    named(with(257, &large), 512);
    let small_documents = |config: &mut ServerConfig| {
        config.input_bytes = GIB / 4;
        config.container_bytes = GIB / 4;
    };
    assert!(with(32, &small_documents).is_ok(), "16 GiB / 0.5 GiB = 32");
    named(with(33, &small_documents), 32);
    // An explicit value above a bound of 0 is refused (the default would be 1 there).
    let tiny = |config: &mut ServerConfig| {
        config.total_temp = GIB;
        config.temp_per_operation = GIB;
    };
    named(with(1, &tiny), 0);
    // The key is part of the documented TOML surface.
    let parsed: ServerConfig = toml::from_str("max_uploads = 3").expect("max_uploads is a key");
    assert_eq!(parsed.max_uploads, Some(3));
    assert_eq!(parsed.effective_max_uploads(), 3);
}

/// One helper sizes the runtime's blocking pool for every runtime builder (the server binary
/// and the proof harness's token host): the executor's workers plus one spool write per
/// upload in progress. Workers only would queue the spool writes behind long operations.
#[test]
fn the_blocking_pool_holds_the_workers_and_the_effective_uploads() {
    use oncl_server::config::ServerConfig;
    const GIB: u64 = 1 << 30;
    let defaults = ServerConfig::default();
    assert_eq!(defaults.blocking_threads(), defaults.blocking_workers + 8);
    let explicit = ServerConfig {
        blocking_workers: 5,
        max_uploads: Some(3),
        ..Default::default()
    };
    assert_eq!(explicit.blocking_threads(), 8);
    let lowered = ServerConfig {
        blocking_workers: 4,
        total_temp: 3 * GIB,
        temp_per_operation: 2 * GIB,
        ..Default::default()
    };
    assert_eq!(lowered.blocking_threads(), 5, "4 workers + the default 1");
}

/// A small `hash` request of the given body kind for `/v1/operations` or `/v1/batch`.
fn small_operation(process: &support::Process, path: &str) -> Reply {
    let body = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{METADATA}\r\n--b\r\nContent-Disposition: form-data; name=\"doc\"\r\n\r\nabc\r\n--b--\r\n"
    );
    let mut stream = TcpStream::connect(process.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let started = Instant::now();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        process.address,
        process.token.as_str(),
        body.len()
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    Reply {
        status: text
            .strip_prefix("HTTP/1.1 ")
            .and_then(|r| r.get(..3))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0),
        body: text,
        elapsed: started.elapsed(),
    }
}

/// The JSON body path is paced as well: a stalled `application/json` upload is ended at
/// the idle timeout, not at the operation deadline.
#[test]
fn a_stalled_json_body_is_ended_by_the_idle_timeout() {
    let process = support::Process::configured("127.0.0.1:0", |root| {
        config(
            root,
            "admission_wait_ms = 600\noperation_timeout_ms = 8000\nheader_timeout_ms = 2000\nupload_idle_timeout_ms = 1500\n",
        )
    });
    let mut stream = TcpStream::connect(process.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let started = Instant::now();
    write!(
        stream,
        "POST /v1/operations HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n{{\"metadata\":",
        process.address,
        process.token.as_str()
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw);
    assert!(text.starts_with("HTTP/1.1 504"), "{text}");
    assert!(text.contains("\"code\":\"DeadlineExceeded\""), "{text}");
    assert!(
        started.elapsed() >= Duration::from_millis(1400)
            && started.elapsed() < Duration::from_millis(4500),
        "{:?}",
        started.elapsed()
    );
    process.stop();
}
