//! Bounded incremental parser of the service's `multipart/mixed` response.
//!
//! Wire shape (docs/user/http-api.md): `--B CRLF headers CRLF CRLF body CRLF` repeated for
//! `progress*`, `artifact*`, `final`, then `--B-- CRLF`. Every part carries an exact
//! `Content-Length`, so the reader frames by length (an artifact may contain any byte
//! sequence, including the boundary) and verifies every delimiter byte-for-byte. Artifact
//! bytes go to the caller's sink chunk by chunk and are never accumulated; JSON parts are
//! capped. A response is a result only when the `final` part, the closing delimiter and the
//! end of the HTTP entity were all received intact.
use super::{
    ArtifactSink, ReceivedArtifact, Stop,
    wire::FinalRecord,
};
use std::io::{self, Read};

/// A single header line, all header lines of one part, and one JSON part.
const MAX_LINE: usize = 1024;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_HEADERS: usize = 16;
pub(super) const MAX_PROGRESS_BYTES: u64 = 64 * 1024;
pub(super) const MAX_FINAL_BYTES: u64 = 16 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;

/// How reading the stream ended unsuccessfully.
#[derive(Debug)]
pub(super) enum StreamError {
    /// The transport ended or failed before the `final` part and closing delimiter.
    Lost,
    /// Well-formed bytes that violate the documented framing or record shape.
    Protocol(&'static str),
    /// The artifact sink refused or failed (local staging error).
    Sink,
    Stop(Stop),
}

pub(super) struct Parsed {
    pub record: FinalRecord,
    pub artifacts: Vec<ReceivedArtifact>,
    pub progress_frames: u64,
}

struct Wire<'a, R: Read> {
    inner: R,
    buffer: Box<[u8; CHUNK]>,
    start: usize,
    end: usize,
    control: &'a (dyn Fn() -> Result<(), Stop> + 'a),
}

impl<R: Read> Wire<'_, R> {
    fn refill(&mut self) -> Result<(), StreamError> {
        (self.control)().map_err(StreamError::Stop)?;
        loop {
            match self.inner.read(&mut self.buffer[..]) {
                Ok(0) => return Err(StreamError::Lost),
                Ok(n) => {
                    self.start = 0;
                    self.end = n;
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    (self.control)().map_err(StreamError::Stop)?;
                }
                Err(_) => return Err(StreamError::Lost),
            }
        }
    }
    fn available(&mut self) -> Result<&[u8], StreamError> {
        if self.start == self.end {
            self.refill()?;
        }
        Ok(&self.buffer[self.start..self.end])
    }
    fn consume(&mut self, count: usize) {
        self.start += count;
    }
    /// One CRLF-terminated line (without the CRLF), at most `limit` bytes before it.
    fn line(&mut self, limit: usize) -> Result<Vec<u8>, StreamError> {
        let mut line = Vec::new();
        loop {
            let (found, used) = {
                let available = self.available()?;
                match available.iter().position(|b| *b == b'\n') {
                    Some(at) => {
                        line.extend_from_slice(&available[..at]);
                        (true, at + 1)
                    }
                    None => {
                        line.extend_from_slice(available);
                        (false, available.len())
                    }
                }
            };
            self.consume(used);
            if line.len() > limit + 1 {
                return Err(StreamError::Protocol("header line too long"));
            }
            if found {
                return match line.pop() {
                    Some(b'\r') if line.len() <= limit => Ok(line),
                    _ => Err(StreamError::Protocol("line is not CRLF terminated")),
                };
            }
        }
    }
    fn expect(&mut self, text: &[u8]) -> Result<(), StreamError> {
        let line = self.line(text.len() + 2)?;
        if line == text {
            Ok(())
        } else {
            Err(StreamError::Protocol("unexpected delimiter"))
        }
    }
    /// Exactly `length` body bytes into `to`.
    fn body(
        &mut self,
        mut length: u64,
        to: &mut dyn FnMut(&[u8]) -> Result<(), StreamError>,
    ) -> Result<(), StreamError> {
        while length > 0 {
            let available = self.available()?;
            let count = usize::try_from(length).unwrap_or(usize::MAX).min(available.len());
            to(&available[..count])?;
            self.consume(count);
            length -= count as u64;
        }
        Ok(())
    }
    /// The HTTP entity must end exactly here.
    fn end(&mut self) -> Result<(), StreamError> {
        if self.start != self.end {
            return Err(StreamError::Protocol("bytes after the closing delimiter"));
        }
        (self.control)().map_err(StreamError::Stop)?;
        loop {
            match self.inner.read(&mut self.buffer[..1]) {
                Ok(0) => return Ok(()),
                Ok(_) => return Err(StreamError::Protocol("bytes after the closing delimiter")),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(StreamError::Lost),
            }
        }
    }
}

struct Head {
    name: String,
    length: u64,
    content_id: Option<String>,
}

fn head<R: Read>(wire: &mut Wire<'_, R>) -> Result<Head, StreamError> {
    let mut name = None;
    let mut length = None;
    let mut content_id = None;
    let mut total = 0usize;
    for count in 0.. {
        let line = wire.line(MAX_LINE)?;
        if line.is_empty() {
            break;
        }
        total += line.len() + 2;
        if count >= MAX_HEADERS || total > MAX_HEADER_BYTES {
            return Err(StreamError::Protocol("part header too large"));
        }
        let text = std::str::from_utf8(&line)
            .map_err(|_| StreamError::Protocol("non-UTF-8 part header"))?;
        let (field, value) = text
            .split_once(':')
            .ok_or(StreamError::Protocol("malformed part header"))?;
        let value = value.trim();
        match field.to_ascii_lowercase().as_str() {
            "content-disposition" => {
                let found = value
                    .strip_prefix("form-data; name=\"")
                    .and_then(|rest| rest.strip_suffix('"'))
                    .ok_or(StreamError::Protocol("malformed Content-Disposition"))?;
                if name.replace(found.to_owned()).is_some() {
                    return Err(StreamError::Protocol("duplicate Content-Disposition"));
                }
            }
            "content-length" => {
                let parsed = value
                    .parse::<u64>()
                    .ok()
                    .filter(|_| value.bytes().all(|b| b.is_ascii_digit()))
                    .ok_or(StreamError::Protocol("malformed Content-Length"))?;
                if length.replace(parsed).is_some() {
                    return Err(StreamError::Protocol("duplicate Content-Length"));
                }
            }
            "content-id" => {
                let valid = !value.is_empty()
                    && value.len() <= 128
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
                if !valid || content_id.replace(value.to_owned()).is_some() {
                    return Err(StreamError::Protocol("malformed Content-ID"));
                }
            }
            "content-type" => {}
            _ => return Err(StreamError::Protocol("unexpected part header")),
        }
    }
    Ok(Head {
        name: name.ok_or(StreamError::Protocol("part without Content-Disposition"))?,
        length: length.ok_or(StreamError::Protocol("part without Content-Length"))?,
        content_id,
    })
}

fn json_part<R: Read>(
    wire: &mut Wire<'_, R>,
    length: u64,
    limit: u64,
) -> Result<Vec<u8>, StreamError> {
    if length > limit {
        return Err(StreamError::Protocol("JSON part too large"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length as usize)
        .map_err(|_| StreamError::Protocol("JSON part too large"))?;
    wire.body(length, &mut |chunk| {
        bytes.extend_from_slice(chunk);
        Ok(())
    })?;
    Ok(bytes)
}

/// Parse the whole response. `sink` receives artifact bytes as they arrive; the caller
/// publishes nothing until this returns `Ok`.
pub(super) fn parse<R: Read>(
    reader: R,
    boundary: &str,
    sink: &mut dyn ArtifactSink,
    control: &(dyn Fn() -> Result<(), Stop> + '_),
) -> Result<Parsed, StreamError> {
    let mut wire = Wire {
        inner: reader,
        buffer: Box::new([0; CHUNK]),
        start: 0,
        end: 0,
        control,
    };
    let delimiter = format!("--{boundary}");
    let closing = format!("--{boundary}--");
    wire.expect(delimiter.as_bytes())?;
    let mut artifacts: Vec<ReceivedArtifact> = Vec::new();
    let mut record = None;
    let mut progress_frames = 0u64;
    loop {
        if record.is_some() {
            // Nothing may follow the terminal record except the closing delimiter.
            return Err(StreamError::Protocol("part after the final record"));
        }
        let head = head(&mut wire)?;
        match head.name.as_str() {
            "progress" => {
                let bytes = json_part(&mut wire, head.length, MAX_PROGRESS_BYTES)?;
                let value: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|_| StreamError::Protocol("malformed progress part"))?;
                if value.get("type").and_then(serde_json::Value::as_str) != Some("progress") {
                    return Err(StreamError::Protocol("malformed progress part"));
                }
                progress_frames += 1;
            }
            "artifact" => {
                let id = head
                    .content_id
                    .ok_or(StreamError::Protocol("artifact without Content-ID"))?;
                if artifacts.iter().any(|known| known.content_id == id) {
                    return Err(StreamError::Protocol("duplicate artifact Content-ID"));
                }
                sink.begin(&id, head.length).map_err(|_| StreamError::Sink)?;
                wire.body(head.length, &mut |chunk| {
                    sink.write(chunk).map_err(|_| StreamError::Sink)
                })?;
                artifacts.push(ReceivedArtifact {
                    content_id: id,
                    length: head.length,
                });
            }
            "final" => {
                let bytes = json_part(&mut wire, head.length, MAX_FINAL_BYTES)?;
                record = Some(
                    serde_json::from_slice::<FinalRecord>(&bytes)
                        .map_err(|_| StreamError::Protocol("malformed final record"))?,
                );
            }
            _ => return Err(StreamError::Protocol("unknown part name")),
        }
        // Every part body ends with its own CRLF, then the next delimiter line.
        wire.expect(b"")?;
        let line = wire.line(closing.len() + 2)?;
        if line == delimiter.as_bytes() {
            continue;
        }
        if line == closing.as_bytes() {
            break;
        }
        return Err(StreamError::Protocol("unexpected delimiter"));
    }
    wire.end()?;
    let record = record.ok_or(StreamError::Lost)?;
    Ok(Parsed {
        record,
        artifacts,
        progress_frames,
    })
}

/// A buffered JSON entity (`application/json` final record or typed error), at most `limit`.
pub(super) fn bounded_body<R: Read>(
    mut reader: R,
    limit: u64,
    control: &(dyn Fn() -> Result<(), Stop> + '_),
) -> Result<Vec<u8>, StreamError> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        control().map_err(StreamError::Stop)?;
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(bytes),
            Ok(n) => {
                if bytes.len() as u64 + n as u64 > limit {
                    return Err(StreamError::Protocol("response entity too large"));
                }
                bytes.extend_from_slice(&chunk[..n]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(StreamError::Lost),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINAL: &str = r#"{"type":"final","operation_id":1,"status":"completed","results":[{"item_id":"s","applied":"Applied","result":{"kind":"extraction","artifact":"artifact-0","bytes_written":9}}]}"#;

    /// The artifact deliberately contains the delimiter text and CRLFs: framing is by length.
    fn artifact_bytes() -> Vec<u8> {
        b"--B\r\n--B--\r\nbinary\x00\xff".to_vec()
    }
    fn part(name: &str, id: Option<&str>, body: &[u8]) -> Vec<u8> {
        let mut out = format!("--B\r\nContent-Type: application/octet-stream\r\nContent-Disposition: form-data; name=\"{name}\"\r\n").into_bytes();
        if let Some(id) = id {
            out.extend_from_slice(format!("Content-ID: {id}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\r\n");
        out
    }
    fn good() -> Vec<u8> {
        let mut out = part(
            "progress",
            None,
            br#"{"type":"progress","operation_id":1,"bytes_in":3,"bytes_out":0}"#,
        );
        out.extend(part("artifact", Some("artifact-0"), &artifact_bytes()));
        out.extend(part("final", None, FINAL.as_bytes()));
        out.extend_from_slice(b"--B--\r\n");
        out
    }
    /// Delivers at most `size` bytes per read, like arbitrary TCP segmentation.
    struct Segments {
        bytes: Vec<u8>,
        at: usize,
        size: usize,
    }
    impl Read for Segments {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let count = self.size.min(out.len()).min(self.bytes.len() - self.at);
            out[..count].copy_from_slice(&self.bytes[self.at..self.at + count]);
            self.at += count;
            Ok(count)
        }
    }
    #[derive(Default)]
    struct Collect {
        artifacts: Vec<(String, Vec<u8>)>,
        refuse: bool,
    }
    impl ArtifactSink for Collect {
        fn begin(&mut self, id: &str, _: u64) -> io::Result<()> {
            if self.refuse {
                return Err(io::Error::other("full"));
            }
            self.artifacts.push((id.to_owned(), Vec::new()));
            Ok(())
        }
        fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.artifacts.last_mut().unwrap().1.extend_from_slice(bytes);
            Ok(())
        }
    }
    fn run(bytes: Vec<u8>, size: usize, sink: &mut Collect) -> Result<Parsed, StreamError> {
        parse(Segments { bytes, at: 0, size }, "B", sink, &|| Ok(()))
    }

    #[test]
    fn a_well_formed_stream_parses_at_every_segmentation() {
        for size in [1, 2, 3, 5, 7, 64, 1000, usize::MAX] {
            let mut sink = Collect::default();
            let parsed = run(good(), size, &mut sink).unwrap_or_else(|e| panic!("{size}: {e:?}"));
            assert_eq!(parsed.progress_frames, 1);
            assert_eq!(parsed.artifacts.len(), 1);
            assert_eq!(sink.artifacts, vec![("artifact-0".to_owned(), artifact_bytes())]);
            assert!(matches!(parsed.record, FinalRecord::Final { .. }));
        }
    }

    #[test]
    fn every_truncation_of_a_real_shaped_stream_is_an_error_never_a_result() {
        let full = good();
        for cut in 0..full.len() {
            let mut sink = Collect::default();
            let result = run(full[..cut].to_vec(), 5, &mut sink);
            assert!(result.is_err(), "a {cut}-byte prefix of {} parsed", full.len());
        }
    }

    #[test]
    fn missing_final_before_a_closing_delimiter_is_a_lost_response() {
        let mut bytes = part("artifact", Some("artifact-0"), b"abc");
        bytes.extend_from_slice(b"--B--\r\n");
        let mut sink = Collect::default();
        assert!(matches!(run(bytes, 8, &mut sink), Err(StreamError::Lost)));
    }

    #[test]
    fn framing_violations_are_refused() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("bytes after the closing delimiter", {
                let mut b = good();
                b.extend_from_slice(b"x");
                b
            }),
            ("a part after the final record", {
                let mut b = part("final", None, FINAL.as_bytes());
                b.extend(part("final", None, FINAL.as_bytes()));
                b.extend_from_slice(b"--B--\r\n");
                b
            }),
            ("no Content-Length", {
                let mut b = b"--B\r\nContent-Disposition: form-data; name=\"final\"\r\n\r\n".to_vec();
                b.extend_from_slice(FINAL.as_bytes());
                b.extend_from_slice(b"\r\n--B--\r\n");
                b
            }),
            ("wrong delimiter after a body", {
                let mut b = part("final", None, FINAL.as_bytes());
                b.extend_from_slice(b"--C--\r\n");
                b
            }),
            ("body longer than declared", {
                let mut b = b"--B\r\nContent-Disposition: form-data; name=\"final\"\r\nContent-Length: 4\r\n\r\n".to_vec();
                b.extend_from_slice(FINAL.as_bytes());
                b.extend_from_slice(b"\r\n--B--\r\n");
                b
            }),
            ("unknown part", part("surprise", None, b"x")),
            ("artifact without id", part("artifact", None, b"x")),
            ("duplicate artifact id", {
                let mut b = part("artifact", Some("a"), b"x");
                b.extend(part("artifact", Some("a"), b"y"));
                b
            }),
            ("malformed progress", part("progress", None, b"{\"type\":\"final\"}")),
            ("malformed final", part("final", None, b"{\"type\":\"nope\"}")),
            ("LF only line ending", b"--B\nContent-Disposition: x\n\n".to_vec()),
            ("oversized JSON part", {
                let mut b = format!("--B\r\nContent-Disposition: form-data; name=\"final\"\r\nContent-Length: {}\r\n\r\n", MAX_FINAL_BYTES + 1).into_bytes();
                b.extend_from_slice(b"{}");
                b
            }),
            ("header line too long", {
                let mut b = b"--B\r\nX-Pad: ".to_vec();
                b.extend(std::iter::repeat_n(b'a', MAX_LINE + 10));
                b
            }),
        ];
        for (name, bytes) in cases {
            let mut sink = Collect::default();
            let result = run(bytes, 11, &mut sink);
            assert!(
                matches!(result, Err(StreamError::Protocol(_)) | Err(StreamError::Lost)),
                "{name}: accepted or wrongly classified: {:?}",
                result.map(|p| p.progress_frames)
            );
        }
    }

    #[test]
    fn a_sink_failure_and_a_stop_are_reported_as_such() {
        let mut sink = Collect {
            refuse: true,
            ..Collect::default()
        };
        assert!(matches!(run(good(), 64, &mut sink), Err(StreamError::Sink)));
        let mut sink = Collect::default();
        let stop = parse(
            Segments {
                bytes: good(),
                at: 0,
                size: 64,
            },
            "B",
            &mut sink,
            &|| Err(Stop::Cancelled),
        );
        assert!(matches!(stop, Err(StreamError::Stop(Stop::Cancelled))));
    }

    #[test]
    fn an_endless_stream_of_frames_is_stopped_by_the_deadline_and_never_buffered() {
        // Progress frames are coalesced by the service and a long operation may emit very
        // many: the reader keeps one frame at a time and ends only by the caller's control.
        let frame = part("progress", None, br#"{"type":"progress"}"#);
        struct Endless {
            frame: Vec<u8>,
            at: usize,
        }
        impl Read for Endless {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                let count = out.len().min(self.frame.len() - self.at);
                out[..count].copy_from_slice(&self.frame[self.at..self.at + count]);
                self.at = (self.at + count) % self.frame.len();
                Ok(count)
            }
        }
        let reads = std::cell::Cell::new(0u32);
        let control = || {
            reads.set(reads.get() + 1);
            if reads.get() > 2000 {
                Err(Stop::DeadlineExceeded)
            } else {
                Ok(())
            }
        };
        let mut sink = Collect::default();
        let result = parse(Endless { frame, at: 0 }, "B", &mut sink, &control);
        assert!(matches!(result, Err(StreamError::Stop(Stop::DeadlineExceeded))));
        assert!(sink.artifacts.is_empty());
    }
}
