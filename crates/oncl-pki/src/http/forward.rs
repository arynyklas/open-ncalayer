//! Plain HTTP through an HTTP proxy: the request goes to the proxy in absolute form
//! (`GET http://host:port/path HTTP/1.1`, RFC 9112 §3.2.2), which `ureq` cannot send (it
//! asks every proxy for a `CONNECT` tunnel, and proxies refuse `CONNECT` to port 80).
//!
//! One request per connection (`Connection: close`). The whole exchange, resolving the
//! proxy's name and connecting included, ends at a deadline, and each connection attempt
//! after the connect timeout; a body longer than the limit is refused. The body may be
//! framed by `Content-Length`, chunked, or end with the connection. Memory stays bounded
//! whatever the proxy sends: the response head, the interim (1xx) responses, chunk lines
//! and the trailer each have a limit.

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ureq::Proxy;
use ureq::http::Uri;

use super::{HttpError, HttpReply};

/// The most bytes of all response heads (interim ones included) of one exchange.
const MAX_HEAD: usize = 64 * 1024;
/// The most headers of a response head.
const MAX_HEADERS: usize = 64;
/// The most interim (1xx) responses before the final one.
const MAX_INTERIM: usize = 8;
/// The longest line of chunked framing (a chunk size with extensions).
const MAX_CHUNK_LINE: usize = 4096;
/// The most bytes of the trailer of a chunked body.
const MAX_TRAILER: usize = 8 * 1024;
/// How much one read asks for.
const READ_SIZE: usize = 8192;

/// A response through the proxy, with its `Location` for redirects.
pub(super) struct Forwarded {
    pub(super) reply: HttpReply,
    pub(super) location: Option<String>,
}

/// Sends `url` (an `http://` URL) to `proxy`: GET, or POST of `post` (content type and
/// body), with a response body of at most `max_len` bytes. Any status is a reply, the
/// proxy's own (e.g. 407 or 502) and redirects included.
///
/// # Errors
///
/// [`HttpError`] if no complete response arrived by `deadline`, or no connection to the
/// proxy within `connect_timeout` per address. Messages name the proxy by host and port
/// only, never with its credentials.
pub(super) fn send(
    proxy: &Proxy,
    url: &str,
    post: Option<(&str, &[u8])>,
    deadline: Instant,
    connect_timeout: Duration,
    max_len: u64,
) -> Result<Forwarded, HttpError> {
    let at = format!("proxy {}:{}", proxy.host(), proxy.port());
    let fail = |e: io::Error| HttpError(format!("{at}: {e}"));
    let head = request_head(proxy, url, post)?;
    let mut stream = connect(proxy, deadline, connect_timeout).map_err(fail)?;
    stream.write_all(head.as_bytes()).map_err(fail)?;
    if let Some((_, body)) = post {
        stream.write_all(body).map_err(fail)?;
    }
    stream.flush().map_err(fail)?;
    read_reply(&mut Input::new(stream), max_len).map_err(fail)
}

/// The request line and headers of `url` for `proxy`.
fn request_head(
    proxy: &Proxy,
    url: &str,
    post: Option<(&str, &[u8])>,
) -> Result<String, HttpError> {
    let uri: Uri = url
        .parse()
        .map_err(|e| HttpError(format!("invalid URL {url}: {e}")))?;
    let host = match (uri.scheme_str(), uri.host()) {
        (Some("http"), Some(host)) if !host.is_empty() => host,
        _ => return Err(HttpError(format!("not an http:// URL: {url}"))),
    };
    // Host and port only: any user information of the URL is not sent.
    let authority = match uri.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let path = if path.is_empty() { "/" } else { path };
    let method = if post.is_some() { "POST" } else { "GET" };
    let mut head = format!("{method} http://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(user) = proxy.username() {
        let credentials = format!("{user}:{}", proxy.password().unwrap_or_default());
        // Writing to a `String` cannot fail.
        let _ = write!(
            head,
            "Proxy-Authorization: Basic {}\r\n",
            STANDARD.encode(credentials)
        );
    }
    if let Some((content_type, body)) = post {
        if content_type.chars().any(char::is_control) {
            return Err(HttpError("invalid Content-Type".to_owned()));
        }
        let _ = write!(
            head,
            "Content-Type: {content_type}\r\nContent-Length: {}\r\n",
            body.len()
        );
    }
    head.push_str("Connection: close\r\n\r\n");
    Ok(head)
}

/// A connection to `proxy`, resolving its name and trying each of its addresses, each for
/// at most `connect_timeout`, until `deadline`.
fn connect(proxy: &Proxy, deadline: Instant, connect_timeout: Duration) -> io::Result<Deadlined> {
    // An IPv6 address is bracketed in a URL.
    let host = proxy.host().trim_start_matches('[').trim_end_matches(']');
    let port = proxy.port();
    let addresses = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => {
            let host = host.to_owned();
            resolve_within(
                move || Ok((host.as_str(), port).to_socket_addrs()?.collect()),
                deadline,
            )?
        }
    };
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
    for address in addresses {
        match TcpStream::connect_timeout(&address, remaining(deadline)?.min(connect_timeout)) {
            Ok(stream) => return Ok(Deadlined { stream, deadline }),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// The addresses of `resolve`, which blocks in the system resolver: it runs on a thread of
/// its own, and is given up (left to finish alone) at `deadline`, as `ureq` does.
fn resolve_within(
    resolve: impl FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static,
    deadline: Instant,
) -> io::Result<Vec<SocketAddr>> {
    let (tx, rx) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("proxy-resolver".to_owned())
        .spawn(move || {
            // The receiver may have given up.
            let _ = tx.send(resolve());
        })?;
    match rx.recv_timeout(remaining(deadline)?) {
        Ok(addresses) => addresses,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out resolving the proxy's name",
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("the resolver thread failed"))
        }
    }
}

/// The time left until `deadline`; a timeout error if none.
fn remaining(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"))
    } else {
        Ok(left)
    }
}

/// A connection whose reads and writes end at `deadline`.
struct Deadlined {
    stream: TcpStream,
    deadline: Instant,
}

impl Read for Deadlined {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        self.stream.read(buf).map_err(timed_out)
    }
}

impl Write for Deadlined {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.stream.write(buf).map_err(timed_out)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// A socket timeout as [`io::ErrorKind::TimedOut`] with one message (Unix reports
/// `WouldBlock`, Windows `TimedOut` with its own text).
fn timed_out(e: io::Error) -> io::Error {
    if matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) {
        io::Error::new(io::ErrorKind::TimedOut, "timed out")
    } else {
        e
    }
}

/// The response bytes: those received but not consumed yet, then the connection.
struct Input<R> {
    stream: R,
    buf: Vec<u8>,
    pos: usize,
}

impl<R: Read> Input<R> {
    fn new(stream: R) -> Self {
        Input {
            stream,
            buf: Vec::new(),
            pos: 0,
        }
    }

    /// The bytes received but not consumed.
    fn pending(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// Receives more bytes; `false` at the end of the connection. The consumed bytes are
    /// dropped first, so the buffer holds only what is pending plus one read.
    fn fill(&mut self) -> io::Result<bool> {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let mut chunk = [0; READ_SIZE];
        let n = self.stream.read(&mut chunk)?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n > 0)
    }

    /// A line up to `\n` (a `\r` before it dropped), at most `max` bytes long.
    fn line(&mut self, max: usize, what: &str) -> io::Result<Vec<u8>> {
        loop {
            if let Some(end) = self.pending().iter().position(|&b| b == b'\n') {
                if end > max {
                    return Err(invalid(&format!("{what} too long")));
                }
                let mut line = self.pending()[..end].to_vec();
                self.pos += end + 1;
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(line);
            }
            if self.pending().len() > max {
                return Err(invalid(&format!("{what} too long")));
            }
            if !self.fill()? {
                return Err(truncated());
            }
        }
    }

    /// Appends exactly `n` bytes to `out`.
    fn take(&mut self, mut n: usize, out: &mut Vec<u8>) -> io::Result<()> {
        while n > 0 {
            if self.pending().is_empty() && !self.fill()? {
                return Err(truncated());
            }
            let k = n.min(self.pending().len());
            out.extend_from_slice(&self.pending()[..k]);
            self.pos += k;
            n -= k;
        }
        Ok(())
    }

    /// Appends everything up to the end of the connection to `out`, refusing more than
    /// `max` bytes in `out`.
    fn rest(&mut self, out: &mut Vec<u8>, max: u64) -> io::Result<()> {
        loop {
            out.extend_from_slice(self.pending());
            self.pos = self.buf.len();
            if out.len() as u64 > max {
                return Err(too_long(max));
            }
            if !self.fill()? {
                return Ok(());
            }
        }
    }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_owned())
}

fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "the connection closed before the response ended",
    )
}

fn too_long(max: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("response body longer than {max} bytes"),
    )
}

/// How a response body ends.
#[derive(Debug, PartialEq, Eq)]
enum Framing {
    Empty,
    Length(u64),
    Chunked,
    Close,
}

/// What a response head says.
struct Head {
    status: u16,
    content_type: Option<String>,
    location: Option<String>,
    framing: Framing,
}

/// Reads one response (after at most [`MAX_INTERIM`] interim ones) with a body of at most
/// `max_len` bytes.
fn read_reply<R: Read>(input: &mut Input<R>, max_len: u64) -> io::Result<Forwarded> {
    let mut head_budget = MAX_HEAD;
    let mut interim = 0;
    let head = loop {
        let head = read_head(input, &mut head_budget)?;
        if !(100..200).contains(&head.status) {
            break head;
        }
        interim += 1;
        if interim > MAX_INTERIM {
            return Err(invalid("too many interim (1xx) responses"));
        }
    };
    let mut body = Vec::new();
    match head.framing {
        Framing::Empty => {}
        Framing::Length(len) if len > max_len => return Err(too_long(max_len)),
        // Within `max_len`, which a `Vec` of the received bytes holds.
        Framing::Length(len) => input.take(len as usize, &mut body)?,
        Framing::Chunked => read_chunked(input, &mut body, max_len)?,
        Framing::Close => input.rest(&mut body, max_len)?,
    }
    Ok(Forwarded {
        reply: HttpReply {
            status: head.status,
            content_type: head.content_type,
            body,
        },
        location: head.location,
    })
}

/// Parses the next response head, consuming it and its size from `budget`.
fn read_head<R: Read>(input: &mut Input<R>, budget: &mut usize) -> io::Result<Head> {
    loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(input.pending()) {
            Ok(httparse::Status::Complete(len)) if len <= *budget => {
                let head = head_of(&response)?;
                input.pos += len;
                *budget -= len;
                return Ok(head);
            }
            // Over the budget: refused below.
            Ok(httparse::Status::Complete(_) | httparse::Status::Partial) => {}
            Err(e) => return Err(invalid(&format!("invalid response head: {e}"))),
        }
        if input.pending().len() > *budget {
            return Err(invalid("response head too long"));
        }
        if !input.fill()? {
            return Err(truncated());
        }
    }
}

/// The status, content type and body framing of `response` (RFC 9112 §6.3; the request is
/// never HEAD).
fn head_of(response: &httparse::Response<'_, '_>) -> io::Result<Head> {
    let status = response.code.ok_or_else(|| invalid("no status"))?;
    let values = |name: &str| -> Vec<String> {
        response
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(h.value).trim().to_owned())
            .collect()
    };
    let content_type = values("content-type").into_iter().next();
    let location = values("location").into_iter().next();
    let codings = values("transfer-encoding");
    let lengths = values("content-length");
    let framing = if (100..200).contains(&status) || status == 204 || status == 304 {
        Framing::Empty
    } else if !codings.is_empty() {
        let last = codings
            .last()
            .and_then(|c| c.rsplit(',').next())
            .map(str::trim);
        if last.is_some_and(|c| c.eq_ignore_ascii_case("chunked")) {
            Framing::Chunked
        } else {
            Framing::Close
        }
    } else if let Some(first) = lengths.first() {
        // Repeated values must agree (RFC 9110 §8.6).
        let mut all = lengths.iter().flat_map(|v| v.split(',')).map(str::trim);
        let len: u64 = first
            .split(',')
            .next()
            .unwrap_or_default()
            .trim()
            .parse()
            .map_err(|_| invalid("invalid Content-Length"))?;
        if !all.all(|v| v.parse() == Ok(len)) {
            return Err(invalid("conflicting Content-Length"));
        }
        Framing::Length(len)
    } else {
        Framing::Close
    };
    Ok(Head {
        status,
        content_type,
        location,
        framing,
    })
}

/// Decodes a chunked body into `out`, refusing more than `max` bytes; the trailer (at most
/// [`MAX_TRAILER`] bytes) is skipped.
fn read_chunked<R: Read>(input: &mut Input<R>, out: &mut Vec<u8>, max: u64) -> io::Result<()> {
    loop {
        let line = input.line(MAX_CHUNK_LINE, "chunk size line")?;
        let size = line.split(|&b| b == b';').next().unwrap_or_default();
        let size = std::str::from_utf8(size)
            .ok()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .ok_or_else(|| invalid("invalid chunk size"))?;
        if size == 0 {
            // The trailer fields, up to an empty line.
            let mut left = MAX_TRAILER;
            loop {
                let field = input.line(left, "trailer")?;
                if field.is_empty() {
                    return Ok(());
                }
                // With its line end: an endless run of empty-looking lines still counts.
                left = left.saturating_sub(field.len() + 2);
            }
        }
        // `out` never holds more than `max`, so the subtraction cannot overflow.
        if size > max - out.len() as u64 {
            return Err(too_long(max));
        }
        // Within `max`, which a `Vec` of the received bytes holds.
        input.take(size as usize, out)?;
        if !input.line(MAX_CHUNK_LINE, "chunk end")?.is_empty() {
            return Err(invalid("chunk not followed by CRLF"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::CONNECT_TIMEOUT;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    /// Ten seconds from now.
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }

    /// A one-connection stub proxy: sends the request it received (head and body) on the
    /// channel, then answers with `reply`. Returns the proxy URL with `userinfo`.
    fn stub(userinfo: &str, reply: Vec<u8>) -> (String, mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{userinfo}{}", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut input = Input::new(&mut stream);
            let mut request = Vec::new();
            loop {
                let line = input.line(MAX_HEAD, "request").unwrap();
                request.extend_from_slice(&line);
                request.extend_from_slice(b"\n");
                if line.is_empty() {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&request).to_ascii_lowercase();
            let len = text
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map_or(0, |n| n.trim().parse().unwrap());
            input.take(len, &mut request).unwrap();
            // The client may hang up once a limit is exceeded.
            let _ = stream.write_all(&reply);
            // The test may not wait for the request.
            let _ = tx.send(request);
        });
        (url, rx)
    }

    fn send_to(
        proxy: &str,
        url: &str,
        post: Option<(&str, &[u8])>,
    ) -> Result<HttpReply, HttpError> {
        send(
            &Proxy::new(proxy).unwrap(),
            url,
            post,
            deadline(),
            CONNECT_TIMEOUT,
            100,
        )
        .map(|f| f.reply)
    }

    #[test]
    fn get_is_sent_in_absolute_form_with_basic_credentials() {
        let (proxy, request) = stub(
            "us%40er:p%3Ass@",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\n\
              Content-Length: 3\r\n\r\nabcIGNORED"
                .to_vec(),
        );
        let reply = send_to(&proxy, "http://ocsp.pki.gov.kz:8080/a%2Fb?x=1#frag", None).unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(
            reply.content_type.as_deref(),
            Some("application/ocsp-response")
        );
        assert_eq!(reply.body, b"abc");
        let request = String::from_utf8(request.recv().unwrap()).unwrap();
        assert_eq!(
            request,
            format!(
                "GET http://ocsp.pki.gov.kz:8080/a%2Fb?x=1 HTTP/1.1\nHost: ocsp.pki.gov.kz:8080\n\
                 Proxy-Authorization: Basic {}\nConnection: close\n\n",
                STANDARD.encode("us@er:p:ss")
            )
        );
    }

    #[test]
    fn post_carries_its_body_and_chunked_replies_are_decoded() {
        let (proxy, request) = stub(
            "",
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n\
              3;ext=1\r\nabc\r\n0A\r\n0123456789\r\n0\r\nX-Trailer: 1\r\n\r\n"
                .to_vec(),
        );
        let reply = send_to(
            &proxy,
            "http://tsp",
            Some(("application/timestamp-query", b"req")),
        )
        .unwrap();
        assert_eq!((reply.status, reply.content_type), (200, None));
        assert_eq!(reply.body, b"abc0123456789");
        let request = String::from_utf8(request.recv().unwrap()).unwrap();
        assert_eq!(
            request,
            "POST http://tsp/ HTTP/1.1\nHost: tsp\nContent-Type: application/timestamp-query\n\
             Content-Length: 3\nConnection: close\n\nreq"
        );
    }

    #[test]
    fn close_delimited_and_empty_bodies() {
        let (proxy, _) = stub("", b"HTTP/1.0 502 Bad Gateway\r\n\r\nno route".to_vec());
        let reply = send_to(&proxy, "http://x/", None).unwrap();
        assert_eq!((reply.status, &reply.body[..]), (502, &b"no route"[..]));
        let (proxy, _) = stub(
            "",
            b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n".to_vec(),
        );
        let reply = send_to(&proxy, "http://x/", None).unwrap();
        assert_eq!((reply.status, reply.body.len()), (204, 0));
        // The proxy's own refusal is a reply too.
        let (proxy, _) = stub(
            "",
            b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n".to_vec(),
        );
        assert_eq!(send_to(&proxy, "http://x/", None).unwrap().status, 407);
    }

    #[test]
    fn limits_and_broken_responses_are_errors() {
        let cases: [(&[u8], &str); 10] = [
            // The size would overflow the sum with the bytes already decoded.
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\nffffffffffffffff\r\n",
                "longer than 100",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000\r\n",
                "chunk size",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 101\r\n\r\n",
                "longer than 100",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n64\r\n",
                "the connection closed",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n65\r\n",
                "longer than 100",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
                "chunk size",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na",
                "the connection closed",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
                "conflicting",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
                "Content-Length",
            ),
            (b"garbage\r\n\r\n", "invalid response head"),
        ];
        for (reply, expected) in cases {
            let (proxy, _) = stub("", reply.to_vec());
            let e = send_to(&proxy, "http://x/", None).unwrap_err();
            assert!(
                e.0.contains(expected),
                "{e} for {:?}",
                String::from_utf8_lossy(reply)
            );
            assert!(e.0.starts_with("proxy 127.0.0.1:"), "{e}");
        }
        let mut long = b"HTTP/1.1 200 OK\r\n".to_vec();
        long.extend(std::iter::repeat_n(b'a', MAX_HEAD + 1));
        let (proxy, _) = stub("", long);
        let e = send_to(&proxy, "http://x/", None).unwrap_err();
        assert!(e.0.contains("head too long"), "{e}");
        // Close-delimited past the limit.
        let mut big = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        big.extend([0; 101]);
        let (proxy, _) = stub("", big);
        assert!(
            send_to(&proxy, "http://x/", None)
                .unwrap_err()
                .0
                .contains("longer than 100")
        );
    }

    #[test]
    fn the_deadline_covers_the_whole_exchange() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = Proxy::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // A head that never ends, a byte at a time.
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nX-Slow: ");
            for _ in 0..50 {
                if stream.write_all(b"a").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
        });
        let start = Instant::now();
        let quick = Instant::now() + Duration::from_millis(300);
        let e = send(&proxy, "http://x/", None, quick, CONNECT_TIMEOUT, 100)
            .map(|f| f.reply)
            .unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(2), "{e}");
        assert!(e.0.contains("timed out"), "{e}");
    }

    #[test]
    fn only_http_urls_with_plain_content_types() {
        let proxy = Proxy::new("http://127.0.0.1:1").unwrap();
        for url in ["https://x/", "ftp://x/", "x/y", "http:///y"] {
            let e = send(&proxy, url, None, deadline(), CONNECT_TIMEOUT, 100)
                .map(|f| f.reply)
                .unwrap_err();
            assert!(
                e.0.contains(url) || e.0.contains("invalid URL"),
                "{url}: {e}"
            );
        }
        let e = send(
            &proxy,
            "http://x/",
            Some(("a\r\nX-Evil: 1", b"")),
            deadline(),
            CONNECT_TIMEOUT,
            100,
        )
        .map(|f| f.reply)
        .unwrap_err();
        assert_eq!(e.0, "invalid Content-Type");
    }

    /// A response of `prefix`, then `repeated` without end, handed out `piece` bytes per
    /// read so that reads end in the middle of lines.
    struct Endless {
        bytes: Vec<u8>,
        repeated: usize,
        pos: usize,
        piece: usize,
    }

    impl Endless {
        fn new(prefix: &[u8], repeated: &[u8], piece: usize) -> Self {
            Endless {
                bytes: [prefix, repeated].concat(),
                repeated: repeated.len(),
                pos: 0,
                piece,
            }
        }
    }

    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut n = 0;
            while n < self.piece.min(buf.len()) {
                if self.pos == self.bytes.len() {
                    if self.repeated == 0 {
                        break;
                    }
                    self.pos -= self.repeated;
                }
                buf[n] = self.bytes[self.pos];
                self.pos += 1;
                n += 1;
            }
            Ok(n)
        }
    }

    /// The error of reading a reply from `stream`, and the largest the buffer ever was.
    fn endless_error(stream: Endless) -> (String, usize) {
        let mut input = Input::new(stream);
        let e = match read_reply(&mut input, u64::MAX) {
            Ok(_) => panic!("an endless response was accepted"),
            Err(e) => e.to_string(),
        };
        (e, input.buf.capacity())
    }

    #[test]
    fn endless_interim_responses_and_trailers_are_refused_with_bounded_memory() {
        let pad = "a".repeat(1000);
        let interim = format!("HTTP/1.1 100 Continue\r\nX-Pad: {pad}\r\n\r\n");
        let (e, peak) = endless_error(Endless::new(b"", interim.as_bytes(), 7));
        assert_eq!(e, "too many interim (1xx) responses");
        assert!(peak <= 2 * (interim.len() + READ_SIZE), "{peak}");

        // Interim heads under the count limit but over the head budget together.
        let pad = "a".repeat(MAX_HEAD / 4);
        let big = format!("HTTP/1.1 100 Continue\r\nX-Pad: {pad}\r\n\r\n");
        let (e, peak) = endless_error(Endless::new(b"", big.as_bytes(), 1000));
        assert_eq!(e, "response head too long");
        assert!(peak <= 2 * (MAX_HEAD + READ_SIZE), "{peak}");

        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n";
        for trailer in [&b"X-Trailer: 1\r\n"[..], b"x\n", b"x\r\n"] {
            let (e, peak) = endless_error(Endless::new(head, trailer, 5));
            assert_eq!(e, "trailer too long", "{trailer:?}");
            assert!(peak <= 2 * (MAX_TRAILER + READ_SIZE), "{peak}");
        }

        // An endless chunk size line.
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let (e, peak) = endless_error(Endless::new(head, b"0", 3));
        assert_eq!(e, "chunk size line too long");
        assert!(peak <= 2 * (MAX_CHUNK_LINE + READ_SIZE), "{peak}");
    }

    #[test]
    fn many_small_chunks_keep_the_buffer_small() {
        // 100 000 one-byte chunks read 5 bytes at a time: no read ends at a line end
        // that empties the buffer, so without compaction it would hold all 600 000 bytes.
        let chunks = 100_000;
        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..chunks {
            response.extend_from_slice(b"1\r\na\r\n");
        }
        response.extend_from_slice(b"0\r\n\r\n");
        let mut input = Input::new(Endless::new(&response, b"", 5));
        let reply = read_reply(&mut input, u64::MAX).unwrap().reply;
        assert_eq!(reply.body.len(), chunks);
        assert!(
            input.buf.capacity() <= 2 * READ_SIZE,
            "{}",
            input.buf.capacity()
        );
    }

    #[test]
    fn a_responder_looping_interim_heads_is_refused_before_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = Proxy::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Each write ends mid-line; the client hangs up when it has had enough.
            let interim = b"HTTP/1.1 102 Processing\r\nX-Pad: aaaaaaaaaa\r\n\r\n";
            for _ in 0..10_000 {
                let (first, second) = interim.split_at(20);
                if stream.write_all(first).is_err() || stream.write_all(second).is_err() {
                    break;
                }
            }
        });
        let start = Instant::now();
        let e = send(&proxy, "http://x/", None, deadline(), CONNECT_TIMEOUT, 100)
            .map(|f| f.reply)
            .unwrap_err();
        assert!(e.0.ends_with("too many interim (1xx) responses"), "{e}");
        assert!(start.elapsed() < Duration::from_secs(5), "{e}");
    }

    #[test]
    fn resolving_the_proxy_name_ends_at_the_deadline() {
        let start = Instant::now();
        let slow = || {
            thread::sleep(Duration::from_secs(3));
            Ok(Vec::new())
        };
        let e = resolve_within(slow, Instant::now() + Duration::from_millis(200)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(2), "{e}");

        let address: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let quick = move || Ok(vec![address]);
        assert_eq!(resolve_within(quick, deadline()).unwrap(), [address]);
        let failing = || Err(io::Error::new(io::ErrorKind::NotFound, "no such host"));
        assert_eq!(
            resolve_within(failing, deadline()).unwrap_err().to_string(),
            "no such host"
        );
        // A name is resolved; an address is not looked up at all. (Windows refuses a
        // closed port only after about 2 s, so the connect timeout is the deadline's.)
        let proxy = Proxy::new("http://localhost:1").unwrap();
        let e = connect(&proxy, deadline(), Duration::from_secs(10))
            .map(drop)
            .unwrap_err();
        assert_ne!(e.kind(), io::ErrorKind::TimedOut, "{e}");
    }
}
