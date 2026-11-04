//! A minimal HTTP/1.1 client for the cases the reference client cannot express: unknown
//! length with a held or aborted upload, paced uploads, stalls past the deadline, and the
//! typed refusals before the body (`Expect: 100-continue`). Plain std sockets: the server
//! is loopback HTTP in these cases.

use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub enum Source {
    Bytes(Vec<u8>),
    Pattern { byte: u8, len: u64 },
    File(PathBuf),
}

impl Source {
    pub fn len(&self) -> u64 {
        match self {
            Source::Bytes(b) => b.len() as u64,
            Source::Pattern { len, .. } => *len,
            Source::File(p) => std::fs::metadata(p).map_or(0, |m| m.len()),
        }
    }

    fn reader(&self) -> std::io::Result<Box<dyn Read + Send>> {
        Ok(match self {
            Source::Bytes(b) => Box::new(std::io::Cursor::new(b.clone())),
            Source::Pattern { byte, len } => Box::new(PatternReader {
                byte: *byte,
                left: *len,
            }),
            Source::File(p) => Box::new(std::fs::File::open(p)?),
        })
    }
}

struct PatternReader {
    byte: u8,
    left: u64,
}

impl Read for PatternReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = (buf.len() as u64).min(self.left) as usize;
        buf[..n].fill(self.byte);
        self.left -= n as u64;
        Ok(n)
    }
}

#[derive(Clone, Debug)]
pub struct Upload {
    pub path: String,
    pub metadata: String,
    pub document: Source,
    pub chunked: bool,
    pub expect_continue: bool,
    /// Pace of the document bytes, per second.
    pub bytes_per_second: Option<u64>,
    /// After this many document bytes stop sending and wait (up to the second value) for the
    /// server to answer or close.
    pub stall_after: Option<(u64, Duration)>,
    /// After this many document bytes close the connection (a disconnect).
    pub abort_after: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct Reply {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    pub body_len: u64,
    pub sent_document_bytes: u64,
    pub elapsed: Duration,
    pub refused_before_body: bool,
    pub transport_error: Option<String>,
}

impl Reply {
    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

const BOUNDARY: &str = "oncl-proof-7d1f3b9a";
const CAPTURE: usize = 512 << 20;

fn prelude(up: &Upload) -> Vec<u8> {
    format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{}\r\n--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"source\"; filename=\"document.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n",
        up.metadata
    )
    .into_bytes()
}

fn epilogue() -> Vec<u8> {
    format!("\r\n--{BOUNDARY}--\r\n").into_bytes()
}

struct Wire<'a> {
    stream: &'a mut TcpStream,
    chunked: bool,
}

impl Wire<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if self.chunked {
            write!(self.stream, "{:x}\r\n", data.len())?;
            self.stream.write_all(data)?;
            self.stream.write_all(b"\r\n")
        } else {
            self.stream.write_all(data)
        }
    }

    fn end(&mut self) -> std::io::Result<()> {
        if self.chunked {
            self.stream.write_all(b"0\r\n\r\n")?;
        }
        self.stream.flush()
    }
}

fn read_head(stream: &mut TcpStream) -> std::io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(std::io::Error::other("response head too large"));
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = text.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Ok((status, headers, buf))
}

fn read_body(
    stream: &mut TcpStream,
    headers: &[(String, String)],
    reply: &mut Reply,
) -> std::io::Result<()> {
    let header = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    let push = |data: &[u8], reply: &mut Reply| {
        reply.body_len += data.len() as u64;
        let room = CAPTURE.saturating_sub(reply.body.len());
        reply.body.extend_from_slice(&data[..data.len().min(room)]);
    };
    let mut buf = vec![0u8; 1 << 16];
    if header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        loop {
            let mut line = Vec::new();
            loop {
                let mut b = [0u8; 1];
                if stream.read(&mut b)? == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                line.push(b[0]);
                if line.ends_with(b"\r\n") {
                    break;
                }
            }
            let size = usize::from_str_radix(
                String::from_utf8_lossy(&line).trim().split(';').next().unwrap_or("0"),
                16,
            )
            .map_err(std::io::Error::other)?;
            if size == 0 {
                let mut tail = [0u8; 2];
                let _ = stream.read_exact(&mut tail);
                return Ok(());
            }
            let mut left = size;
            while left > 0 {
                let want = left.min(buf.len());
                let n = stream.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                push(&buf[..n], reply);
                left -= n;
            }
            let mut crlf = [0u8; 2];
            stream.read_exact(&mut crlf)?;
        }
    }
    if let Some(length) = header("content-length").and_then(|v| v.parse::<u64>().ok()) {
        let mut left = length;
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            let n = stream.read(&mut buf[..want])?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            push(&buf[..n], reply);
            left -= n as u64;
        }
        return Ok(());
    }
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        push(&buf[..n], reply);
    }
}

pub fn send(address: &str, token: &str, up: &Upload) -> Reply {
    let started = Instant::now();
    let mut reply = Reply::default();
    let result = send_inner(address, token, up, &mut reply);
    if let Err(e) = result {
        reply.transport_error = Some(e.to_string());
    }
    reply.elapsed = started.elapsed();
    reply
}

fn send_inner(address: &str, token: &str, up: &Upload, reply: &mut Reply) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(3600)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3600)))?;
    let head = prelude(up);
    let tail = epilogue();
    let total = head.len() as u64 + up.document.len() + tail.len() as u64;
    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nContent-Type: multipart/form-data; boundary={BOUNDARY}\r\nConnection: close\r\n",
        up.path
    );
    if up.chunked {
        request.push_str("Transfer-Encoding: chunked\r\n");
    } else {
        request.push_str(&format!("Content-Length: {total}\r\n"));
    }
    if up.expect_continue {
        request.push_str("Expect: 100-continue\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;
    if up.expect_continue {
        let (status, headers, _) = read_head(&mut stream)?;
        if status != 100 {
            reply.status = status;
            reply.refused_before_body = true;
            reply.content_type = headers
                .iter()
                .find(|(k, _)| k == "content-type")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let _ = read_body(&mut stream, &headers, reply);
            return Ok(());
        }
    }
    let mut writer = stream.try_clone()?;
    let mut wire = Wire {
        stream: &mut writer,
        chunked: up.chunked,
    };
    let sent = (|| -> std::io::Result<bool> {
        wire.write(&head)?;
        let mut document = up.document.reader()?;
        let mut buf = vec![0u8; 256 * 1024];
        let mut sent = 0u64;
        let paced = Instant::now();
        loop {
            let want = match (up.abort_after, up.stall_after) {
                (Some(limit), _) | (None, Some((limit, _))) => (limit.saturating_sub(sent)).min(buf.len() as u64) as usize,
                _ => buf.len(),
            };
            if want == 0 {
                break;
            }
            let n = document.read(&mut buf[..want])?;
            if n == 0 {
                break;
            }
            wire.write(&buf[..n])?;
            sent += n as u64;
            reply.sent_document_bytes = sent;
            if let Some(rate) = up.bytes_per_second {
                let due = Duration::from_secs_f64(sent as f64 / rate as f64);
                if let Some(wait) = due.checked_sub(paced.elapsed()) {
                    std::thread::sleep(wait);
                }
            }
        }
        if let Some(limit) = up.abort_after
            && sent >= limit
        {
            return Ok(false);
        }
        if let Some((limit, hold)) = up.stall_after
            && sent >= limit
        {
            // stop sending; wait for the server to answer or close
            let until = Instant::now() + hold;
            wire.stream.set_nodelay(true)?;
            let peek = stream.try_clone()?;
            peek.set_read_timeout(Some(Duration::from_millis(500)))?;
            let mut one = [0u8; 1];
            while Instant::now() < until {
                match peek.peek(&mut one) {
                    Ok(_) => return Ok(true),
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                    Err(_) => return Ok(true),
                }
            }
            return Ok(true);
        }
        wire.write(&tail)?;
        wire.end()?;
        Ok(true)
    })();
    match sent {
        Ok(false) => {
            let _ = stream.shutdown(Shutdown::Both);
            reply.transport_error = Some("disconnected by the client on purpose".into());
            return Ok(());
        }
        Ok(true) => {}
        Err(e) => {
            // The server may have answered and closed while we were still sending.
            reply.transport_error = Some(format!("write: {e}"));
        }
    }
    stream.set_read_timeout(Some(Duration::from_secs(3600)))?;
    let (status, headers, _) = read_head(&mut stream)?;
    reply.status = status;
    reply.content_type = headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    read_body(&mut stream, &headers, reply)?;
    Ok(())
}

/// `GET path`; returns the status and the time the answer took.
pub fn get(address: &str, token: &str, path: &str) -> (u16, Duration) {
    let started = Instant::now();
    let result = (|| -> std::io::Result<u16> {
        let mut stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        )?;
        let (status, headers, _) = read_head(&mut stream)?;
        let mut sink = Reply::default();
        let _ = read_body(&mut stream, &headers, &mut sink);
        Ok(status)
    })();
    (result.unwrap_or(0), started.elapsed())
}

/// The `final` JSON record of a streamed `multipart/mixed` answer, and the artifact bytes.
pub fn multipart_final(reply: &Reply) -> Option<(serde_json::Value, Vec<u8>)> {
    let boundary = reply
        .content_type
        .split("boundary=")
        .nth(1)?
        .trim_matches('"')
        .to_owned();
    let delimiter = format!("--{boundary}");
    let body = &reply.body;
    let mut artifact = Vec::new();
    let mut final_record = None;
    let mut at = 0usize;
    while let Some(found) = find(body, delimiter.as_bytes(), at) {
        let part_start = found + delimiter.len();
        if body[part_start..].starts_with(b"--") {
            break;
        }
        let head_start = part_start + 2;
        let head_end = find(body, b"\r\n\r\n", head_start)?;
        let head = String::from_utf8_lossy(&body[head_start..head_end]).into_owned();
        let length = head
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok())?
            });
        let data_start = head_end + 4;
        let data_end = match length {
            Some(len) => data_start + len,
            None => find(body, delimiter.as_bytes(), data_start)?.saturating_sub(2),
        };
        let data = &body[data_start..data_end.min(body.len())];
        if head.to_ascii_lowercase().contains("application/json") {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data)
                && matches!(v["type"].as_str(), Some("final" | "batch_final"))
            {
                final_record = Some(v);
            }
        } else {
            artifact = data.to_vec();
        }
        at = data_end;
    }
    Some((final_record?, artifact))
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack.get(from..)?.windows(needle.len()).position(|w| w == needle).map(|p| p + from)
}
