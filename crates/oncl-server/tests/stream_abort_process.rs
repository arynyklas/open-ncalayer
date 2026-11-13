//! A response stream the server aborts after it started (a first-fatal resource failure:
//! the client sees only a lost response) must still leave the typed cause in the server's
//! own log. Real `oncl-server` binary, real socket, real stderr.
#[path = "server_support/mod.rs"]
mod support;

use std::{
    io::{Read, Write},
    sync::LazyLock,
    time::Duration,
};

const ITEM: &str = "CANARY-ITEM-ID";
const PART: &str = "CANARY-PART-NAME";
const FILE: &str = "CANARY-file-name.pdf";
const CONTENT: &str = "CANARY citizen IIN 900101300123 signs contract";

fn batch_body() -> String {
    let metadata = format!(
        r#"{{"items":[{{"id":"{ITEM}","operation":{{"kind":"hash","algorithm":"sha256","input":"{PART}"}}}}],"parts":[{{"name":"{PART}","item_id":"{ITEM}","role":"document"}}]}}"#
    );
    format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n--b\r\nContent-Disposition: form-data; name=\"{PART}\"; filename=\"{FILE}\"\r\nContent-Type: application/pdf\r\n\r\n{CONTENT}\r\n--b--\r\n"
    )
}

/// One streamed `/v1/batch` request against a server whose `metadata_bytes` is
/// `metadata_bytes`: the raw response bytes and the server's stderr after a graceful stop.
fn run(metadata_bytes: u64) -> (Vec<u8>, String) {
    let mut process = support::Process::configured("127.0.0.1:0", |root| {
        format!(
            "scratch_directory = {}\nmetadata_bytes = {metadata_bytes}",
            support::toml_path(&root.join("scratch")),
        )
    });
    let body = batch_body();
    let mut stream = std::net::TcpStream::connect(process.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .write_all(
            format!(
                "POST /v1/batch HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                process.address,
                process.token.as_str(),
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
    stream.write_all(body.as_bytes()).unwrap();
    let mut response = Vec::new();
    // A cut-short chunked body ends in an error: the bytes read so far are the evidence.
    let _ = stream.read_to_end(&mut response);
    process
        .child
        .stdin
        .take()
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    process.child.wait().unwrap();
    let mut stderr = String::new();
    process
        .child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (response, stderr)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Seen {
    /// A typed HTTP refusal before any stream.
    Refused,
    /// The stream ended without a terminal record.
    Aborted,
    /// The stream ended with its terminal record.
    Completed,
}
fn seen(response: &[u8]) -> Seen {
    if response.starts_with(b"HTTP/1.1 413") {
        Seen::Refused
    } else if String::from_utf8_lossy(response).contains("name=\"final\"") {
        Seen::Completed
    } else {
        Seen::Aborted
    }
}

/// A `metadata_bytes` value at which the hash batch is admitted and then aborted by the
/// metadata budget (the D10 cause). The window is narrow and its place moves with every
/// fixed reservation of the service, so it is found, not hard-coded: bisect the smallest
/// value that completes, then stand `MARGIN` bytes below it.
///
/// Not the value next to the edge, and not the middle of the window. The frames of the
/// stream hold metadata until the socket has taken them, so how much of the budget is
/// held at a given moment depends on how fast the client and the server run:
/// - the smallest budget that completes moves by some tens of bytes under load, in both
///   directions, so a value a few bytes below the edge found by one run completes in
///   the next;
/// - the budget can also run out earlier, before the first item (`item=none`), and under
///   load that was seen across the lower part of the window, down to ~450 bytes below
///   the edge. The window is over a thousand bytes wide, but the band that is free of
///   both is about 350 bytes wide, from ~70 to ~420 bytes below the edge.
/// `MARGIN` is the middle of that band.
///
/// The bisect has the same jitter: one stray abort of a value above the edge (seen under
/// load, about one run in forty a few dozen bytes above it) would send it up to the next
/// value that completes, hundreds of bytes too high. A value therefore completes if any
/// of `TRIES` runs completes; the runs that complete are cheap, as the first one ends it.
const MARGIN: u64 = 224;
const TRIES: usize = 3;
fn completes(metadata_bytes: u64) -> bool {
    (0..TRIES).any(|_| seen(&run(metadata_bytes).0) == Seen::Completed)
}
static ABORTING: LazyLock<u64> = LazyLock::new(|| {
    let (mut refused, mut completed) = (1_000_000u64, 4_000_000u64);
    assert!(completes(completed));
    while completed - refused > 64 {
        let middle = refused + (completed - refused) / 2;
        if completes(middle) {
            completed = middle;
        } else {
            refused = middle;
        }
    }
    completed - MARGIN
});

/// One request at the aborting budget: its response and the server's stderr.
///
/// The budget is aimed at a band, not at a point (see `MARGIN`), and some runs under load
/// still land on the other side of the moving edge: the stream then completed, with its
/// terminal record, and there is no abort to look at. That run is not an answer to the
/// question of these tests and is made again, a few times. Any other outcome is the
/// answer: an abort is judged by what it logged, a refusal or a lost log line is a
/// failure, never made again.
fn aborted_run() -> (Vec<u8>, String) {
    let mut last = run(*ABORTING);
    for _ in 1..ATTEMPTS {
        if seen(&last.0) != Seen::Completed {
            break;
        }
        last = run(*ABORTING);
    }
    last
}
const ATTEMPTS: usize = 5;

fn fields(line: &str) -> std::collections::BTreeMap<&str, &str> {
    line.split(' ')
        .skip(3)
        .map(|pair| pair.split_once('=').expect("key=value"))
        .collect()
}

/// RED before the change: the server wrote nothing, so the operator saw a lost response
/// and no cause.
#[test]
fn an_aborted_stream_is_logged_with_its_typed_cause() {
    let (response, stderr) = aborted_run();
    assert_eq!(seen(&response), Seen::Aborted, "{response:?}");
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "exactly one line per aborted stream: {stderr:?}"
    );
    let line = lines[0];
    assert!(line.starts_with("oncl-server: stream aborted: "), "{line}");
    let fields = fields(line);
    assert_eq!(fields["route"], "batch", "{line}");
    assert_eq!(fields["item"], "0", "{line}");
    assert_eq!(fields["kind"], "hash", "{line}");
    assert_eq!(fields["code"], "metadata_limit", "{line}");
    assert_eq!(fields["cause"], "MetadataLimit", "{line}");
    assert_eq!(fields["applied"], "not_applied", "{line}");
    for numeric in ["operation", "elapsed_ms", "bytes_in", "bytes_out"] {
        fields[numeric]
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("{numeric} is not a number: {line}"));
    }
    assert_eq!(
        fields.len(),
        10,
        "no field beyond the documented ones: {line}"
    );
}

/// The line is built from numbers and closed names only: whatever the request carried
/// (item id, part name, file name, document text, the bearer token, the operator's paths)
/// never reaches the log.
#[test]
fn the_abort_log_line_carries_no_user_data() {
    let (response, stderr) = aborted_run();
    assert_eq!(seen(&response), Seen::Aborted, "{response:?}");
    assert!(!stderr.is_empty(), "the abort must be logged at all");
    for canary in [
        ITEM,
        PART,
        FILE,
        "CANARY",
        "citizen",
        "900101300123",
        "contract",
        "synthetic-actor",
        "scratch",
        "audit",
        "127.0.0.1",
        "target-task23",
    ] {
        assert!(
            !stderr.contains(canary),
            "{canary:?} leaked into {stderr:?}"
        );
    }
    assert!(
        stderr.trim_end().bytes().all(|b| b == b' '
            || b == b':'
            || b == b'-'
            || b == b'='
            || b == b'_'
            || b.is_ascii_alphanumeric()),
        "only closed names and numbers: {stderr:?}"
    );
}

/// A healthy stream writes nothing: the line is the abort's alone.
#[test]
fn a_completed_stream_logs_nothing() {
    let (response, stderr) = run(64 << 20);
    assert_eq!(seen(&response), Seen::Completed, "{response:?}");
    assert!(stderr.is_empty(), "{stderr:?}");
}
