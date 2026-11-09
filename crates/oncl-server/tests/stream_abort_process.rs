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
/// value that completes, then step down until the stream is aborted.
static ABORTING: LazyLock<u64> = LazyLock::new(|| {
    let (mut refused, mut completed) = (1_000_000u64, 4_000_000u64);
    assert_eq!(seen(&run(completed).0), Seen::Completed);
    while completed - refused > 64 {
        let middle = refused + (completed - refused) / 2;
        if seen(&run(middle).0) == Seen::Completed {
            completed = middle;
        } else {
            refused = middle;
        }
    }
    (1..=64)
        .map(|step| completed - 64 * step)
        .find(|bytes| seen(&run(*bytes).0) == Seen::Aborted)
        .expect("no metadata budget aborts the stream after it started")
});

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
    let (response, stderr) = run(*ABORTING);
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
    let (response, stderr) = run(*ABORTING);
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
