//! The wss/https server: TLS, then either the NCALayer WebSocket protocol or a plain HTTP
//! response, on one port. Its TLS configuration is [`LiveTls`]: a re-issued certificate
//! serves the next connection, without a restart.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, PoisonError, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use oncl_accessory::{Accessory, UiCallback};
use oncl_applet::Applet;
use oncl_basics::{Basics, Prompter, RecentPathStore};
use oncl_commonutils::CommonUtils;
use oncl_pki::http::HttpTransport;
use oncl_protocol::{HEARTBEAT, Registry, greeting};
use oncl_tls::SelftestReports;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{self, Message, Utf8Bytes};
use tracing::{debug, info, warn};

use crate::http::{self, Response};
use crate::session::{Session, process};

/// The NCALayer port.
pub const DEFAULT_PORT: u16 = 13579;
/// The highest port `NCALAYERPORT` may select.
pub const MAX_PORT: u16 = 13679;
/// Environment variable choosing another port in `DEFAULT_PORT..=MAX_PORT`.
pub const PORT_VAR: &str = "NCALAYERPORT";
/// A connection that sends nothing for this long is closed.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(20 * 60);
/// Largest WebSocket message (and frame) accepted: documents of tens of megabytes travel
/// base64-encoded in a single message.
pub const MAX_MESSAGE: usize = 256 << 20;
/// Largest HTTP request head read before deciding between WebSocket and plain HTTP.
const MAX_HEAD: usize = 8 << 10;
/// Most header lines parsed in a request head.
const MAX_HEADERS: usize = 64;

/// The port in `value` if it is a number in `13579..=13679`, otherwise 13579.
pub fn listen_port_from(value: Option<&str>) -> u16 {
    value
        .and_then(|v| v.parse::<u16>().ok())
        .filter(|port| (DEFAULT_PORT..=MAX_PORT).contains(port))
        .unwrap_or(DEFAULT_PORT)
}

/// The port to listen on: [`listen_port_from`] the `NCALAYERPORT` environment variable.
pub fn listen_port() -> u16 {
    listen_port_from(std::env::var(PORT_VAR).ok().as_deref())
}

/// The TLS configuration the server accepts new connections with. [`LiveTls::replace`]
/// takes effect at the next connection; connections already accepted keep theirs.
pub struct LiveTls {
    config: RwLock<Arc<rustls::ServerConfig>>,
}

impl LiveTls {
    pub fn new(config: Arc<rustls::ServerConfig>) -> Self {
        LiveTls {
            config: RwLock::new(config),
        }
    }

    /// The configuration for the next connection.
    pub fn current(&self) -> Arc<rustls::ServerConfig> {
        Arc::clone(&self.config.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Serves the next connections with `config` (a re-issued certificate).
    pub fn replace(&self, config: Arc<rustls::ServerConfig>) {
        *self.config.write().unwrap_or_else(PoisonError::into_inner) = config;
    }
}

/// What [`serve`] needs.
pub struct ServerConfig {
    pub tls: Arc<LiveTls>,
    pub registry: Arc<Registry>,
    /// Where the self-test page's reports go (the TLS wizard shows them).
    pub selftest: Arc<SelftestReports>,
    /// Read timeout of a connection (TLS handshake, request head, WebSocket messages).
    pub idle_timeout: Duration,
    /// Largest WebSocket message and frame.
    pub max_message: usize,
}

impl ServerConfig {
    /// `tls` and `registry` with reports of their own, [`IDLE_TIMEOUT`] and
    /// [`MAX_MESSAGE`].
    pub fn new(tls: Arc<LiveTls>, registry: Arc<Registry>) -> Self {
        ServerConfig {
            tls,
            registry,
            selftest: Arc::new(SelftestReports::new()),
            idle_timeout: IDLE_TIMEOUT,
            max_message: MAX_MESSAGE,
        }
    }
}

/// The module registry of the daemon: `kz.gov.pki.knca.basics`,
/// `kz.gov.pki.knca.commonUtils` and `kz.gov.pki.knca.applet.Applet` (the default module),
/// which share the dialogs of `prompter` and reach the NCA time-stamping and OCSP services
/// through `http`, and `kz.gov.pki.ncalayerservices.accessory`, which asks `ui` to open the
/// daemon's windows.
pub fn build_registry(
    prompter: Arc<dyn Prompter>,
    recent: Arc<dyn RecentPathStore>,
    http: Arc<dyn HttpTransport>,
    ui: UiCallback,
) -> Registry {
    let mut registry = Registry::default();
    let common_utils = CommonUtils::new(Arc::clone(&prompter), Arc::clone(&http));
    let applet = Applet::new(Arc::clone(&prompter));
    registry.register(
        oncl_basics::MODULE_NAME,
        Arc::new(Basics::new(prompter, recent, http)),
    );
    registry.register(oncl_commonutils::MODULE_NAME, Arc::new(common_utils));
    registry.register(oncl_applet::MODULE_NAME, Arc::new(applet));
    // Registered last: its `getServices` snapshot must see every other module.
    let mut services = registry.names();
    services.push(oncl_accessory::MODULE_NAME.to_owned());
    services.sort_unstable();
    registry.register(
        oncl_accessory::MODULE_NAME,
        Arc::new(Accessory::new(services, ui)),
    );
    registry
}

/// Serves connections accepted on `listener`, each in its own task, until the process exits.
/// Each connection takes the TLS configuration [`LiveTls`] has when it is accepted. Failed
/// accepts (for example, out of file descriptors) are logged and retried.
///
/// # Errors
///
/// The listener's address is unknown.
pub async fn serve(listener: TcpListener, cfg: ServerConfig) -> io::Result<()> {
    // The self-test page's own origin: the only one that may report.
    let origin = format!("https://127.0.0.1:{}", listener.local_addr()?.port());
    let cfg = Arc::new(Served { cfg, origin });
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let acceptor = TlsAcceptor::from(cfg.cfg.tls.current());
        let cfg = Arc::clone(&cfg);
        tokio::spawn(async move {
            match connection(tcp, peer, acceptor, &cfg).await {
                Ok(()) => debug!(%peer, "connection closed"),
                Err(e) => debug!(%peer, error = %e, "connection ended"),
            }
        });
    }
}

/// A [`ServerConfig`] being served on the listener of `origin`.
struct Served {
    cfg: ServerConfig,
    origin: String,
}

fn timed_out(_: tokio::time::error::Elapsed) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "idle timeout")
}

fn ws_error(e: tungstenite::Error) -> io::Error {
    match e {
        tungstenite::Error::Io(e) => e,
        e => io::Error::other(e),
    }
}

/// One connection: TLS, the request head, then WebSocket or plain HTTP. TLS and WebSocket
/// handshake failures (an untrusted certificate shows up here) are logged as warnings;
/// the returned error is a failure after the handshakes.
async fn connection(
    tcp: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    served: &Served,
) -> io::Result<()> {
    let cfg = &served.cfg;
    // Small replies (heartbeat) should not wait for Nagle.
    tcp.set_nodelay(true)?;
    let accepted = timeout(cfg.idle_timeout, acceptor.accept(tcp))
        .await
        .map_err(timed_out)
        .flatten();
    let mut tls = match accepted {
        Ok(tls) => tls,
        Err(e) => {
            warn!(%peer, error = %e, "TLS handshake failed");
            return Ok(());
        }
    };
    let head = timeout(cfg.idle_timeout, read_head(&mut tls))
        .await
        .map_err(timed_out)??;
    let (head, head_len) = match head {
        Head::Complete { bytes, len } => (bytes, len),
        Head::Eof => return Ok(()),
        Head::TooLarge => return reply(&mut tls, &Response::header_too_large()).await,
    };
    let Some(request) = Request::parse(&head[..head_len]) else {
        return reply(&mut tls, &Response::bad_request()).await;
    };
    if !request.websocket {
        let response = if request.method == "POST" && request.path() == http::SELFTEST_REPORT {
            let body = &head[head_len..];
            selftest_report(&mut tls, &request, body, served).await?
        } else {
            http::respond(&request.method, &request.target)
        };
        info!(%peer, method = %request.method, target = %request.target, status = response.status(), "http");
        return reply(&mut tls, &response).await;
    }

    let config = WebSocketConfig::default()
        .max_message_size(Some(cfg.max_message))
        .max_frame_size(Some(cfg.max_message));
    // tungstenite reads the handshake itself: give it back the bytes already read.
    let stream = Replay::new(head, tls);
    let accepted = timeout(
        cfg.idle_timeout,
        tokio_tungstenite::accept_async_with_config(stream, Some(config)),
    )
    .await
    .map_err(timed_out)
    .and_then(|r| r.map_err(ws_error));
    let ws = match accepted {
        Ok(ws) => ws,
        Err(e) => {
            warn!(%peer, error = %e, "WebSocket handshake failed");
            return Ok(());
        }
    };
    info!(%peer, origin = request.origin.as_deref().unwrap_or("-"), "websocket connected");
    // Closed once the connection has ended and its last call returned.
    let session = Session::new(&cfg.registry, request.origin);
    websocket(ws, &session, cfg).await
}

/// `POST /openncalayer/selftest/report`: reads the body (`read` holds what came with the
/// head) within the idle timeout, then records it ([`http::selftest_report`]).
async fn selftest_report<S: AsyncRead + Unpin>(
    stream: &mut S,
    request: &Request,
    read: &[u8],
    served: &Served,
) -> io::Result<Response> {
    let len = match request.content_length {
        ContentLength::Absent => return Ok(Response::length_required()),
        ContentLength::Invalid => return Ok(Response::bad_request()),
        ContentLength::Bytes(len) if len > http::MAX_REPORT_BODY => {
            return Ok(Response::payload_too_large());
        }
        ContentLength::Bytes(len) => len,
    };
    let mut body = read[..read.len().min(len)].to_vec();
    if body.len() < len {
        let mut rest = vec![0; len - body.len()];
        timeout(served.cfg.idle_timeout, stream.read_exact(&mut rest))
            .await
            .map_err(timed_out)??;
        body.extend_from_slice(&rest);
    }
    Ok(http::selftest_report(
        request.origin.as_deref(),
        &served.origin,
        &body,
        &served.cfg.selftest,
    ))
}

/// Writes `response` and closes the TLS session.
async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, response: &Response) -> io::Result<()> {
    stream.write_all(&response.to_bytes()).await?;
    stream.shutdown().await
}

/// The NCALayer protocol on an upgraded connection. Messages are handled one at a time;
/// module calls run on the blocking pool so that other connections are not held up.
async fn websocket<S>(
    mut ws: WebSocketStream<S>,
    session: &Arc<Session>,
    cfg: &ServerConfig,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ws.send(Message::text(greeting())).await.map_err(ws_error)?;
    loop {
        let message = match timeout(cfg.idle_timeout, ws.next()).await {
            Err(_) => {
                debug!("idle timeout");
                return Ok(());
            }
            Ok(None) => return Ok(()),
            Ok(Some(message)) => message.map_err(ws_error)?,
        };
        let text = match message {
            Message::Text(text) => text,
            // The original decodes binary messages as UTF-8 too (invalid sequences replaced).
            Message::Binary(bytes) => Utf8Bytes::from(String::from_utf8_lossy(&bytes).into_owned()),
            // Pings are answered and closes completed by tungstenite while it reads on.
            Message::Ping(_) | Message::Pong(_) | Message::Close(_) | Message::Frame(_) => {
                continue;
            }
        };
        // The heartbeat is answered right here: never queued behind a module or a dialog.
        if text.as_str() == HEARTBEAT {
            ws.send(Message::Text(text)).await.map_err(ws_error)?;
            continue;
        }
        let len = text.len();
        match process(session, text).await? {
            Some(reply) => ws.send(Message::text(reply)).await.map_err(ws_error)?,
            None => {
                // As the original: drop the TCP connection, no close frame.
                info!(
                    request_len = len,
                    "request is not a JSON object; dropping the connection"
                );
                return Ok(());
            }
        }
    }
}

enum Head {
    /// `bytes[..len]` is the head through its empty line; `bytes` may hold more.
    Complete { bytes: Vec<u8>, len: usize },
    /// The peer closed the connection first.
    Eof,
    /// No empty line within [`MAX_HEAD`] bytes.
    TooLarge,
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Head> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(Head::Eof);
        }
        // Look for the end of the head only in the region the new bytes could complete.
        let from = bytes.len().saturating_sub(3);
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(at) = bytes[from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let len = from + at + 4;
            if len > MAX_HEAD {
                return Ok(Head::TooLarge);
            }
            return Ok(Head::Complete { bytes, len });
        }
        if bytes.len() > MAX_HEAD {
            return Ok(Head::TooLarge);
        }
    }
}

/// What the server needs from a request head.
struct Request {
    method: String,
    target: String,
    /// `Upgrade: websocket`.
    websocket: bool,
    /// The `Origin` header.
    origin: Option<String>,
    content_length: ContentLength,
}

/// The `Content-Length` header of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentLength {
    Absent,
    /// Not a number, or given twice.
    Invalid,
    Bytes(usize),
}

impl Request {
    /// The target without its query.
    fn path(&self) -> &str {
        self.target
            .split_once('?')
            .map_or(self.target.as_str(), |(path, _)| path)
    }

    fn parse(head: &[u8]) -> Option<Request> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut request = httparse::Request::new(&mut headers);
        if !matches!(request.parse(head), Ok(httparse::Status::Complete(_))) {
            return None;
        }
        let mut websocket = false;
        let mut origin = None;
        let mut content_length = ContentLength::Absent;
        for header in request.headers.iter() {
            if header.name.eq_ignore_ascii_case("upgrade") {
                websocket |= header
                    .value
                    .split(|&b| b == b',')
                    .any(|v| v.trim_ascii().eq_ignore_ascii_case(b"websocket"));
            } else if header.name.eq_ignore_ascii_case("origin") {
                origin = Some(String::from_utf8_lossy(header.value).into_owned());
            } else if header.name.eq_ignore_ascii_case("content-length") {
                let value = std::str::from_utf8(header.value)
                    .ok()
                    .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|v| v.parse().ok());
                content_length = match (content_length, value) {
                    (ContentLength::Absent, Some(len)) => ContentLength::Bytes(len),
                    _ => ContentLength::Invalid,
                };
            }
        }
        Some(Request {
            method: request.method?.to_owned(),
            target: request.path?.to_owned(),
            websocket,
            origin,
            content_length,
        })
    }
}

/// A stream that first yields `head` (bytes already read from `inner`), then reads `inner`.
struct Replay<S> {
    head: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Replay<S> {
    fn new(head: Vec<u8>, inner: S) -> Self {
        Replay {
            head,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.pos < this.head.len() {
            let n = (this.head.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.head[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.head.len() {
                this.head = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn head_is_split_from_the_rest_and_replayed() {
        let input: &[u8] =
            b"GET / HTTP/1.1\r\nUpgrade: WebSocket\r\nOrigin: https://x.kz\r\n\r\nrest";
        let mut reader = input;
        let Head::Complete { bytes, len } = read_head(&mut reader).await.unwrap() else {
            panic!("incomplete head");
        };
        let request = Request::parse(&bytes[..len]).unwrap();
        assert!(request.websocket);
        assert_eq!(request.origin.as_deref(), Some("https://x.kz"));
        assert_eq!(
            (request.method.as_str(), request.target.as_str()),
            ("GET", "/")
        );

        let mut replay = Replay::new(bytes, tokio::io::empty());
        let mut all = Vec::new();
        replay.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, input);
    }

    #[tokio::test]
    async fn head_limits() {
        let mut big = b"GET / HTTP/1.1\r\nX: ".to_vec();
        big.resize(MAX_HEAD + 10, b'a');
        big.extend_from_slice(b"\r\n\r\n");
        assert!(matches!(
            read_head(&mut big.as_slice()).await.unwrap(),
            Head::TooLarge
        ));
        assert!(matches!(
            read_head(&mut &b"GET / HT"[..]).await.unwrap(),
            Head::Eof
        ));
        assert!(Request::parse(b"\x01\x02\r\n\r\n").is_none());
    }

    #[test]
    fn content_length_is_read_strictly() {
        let length = |headers: &str| {
            let head = format!("POST /x?y HTTP/1.1\r\n{headers}\r\n");
            let request = Request::parse(head.as_bytes()).unwrap();
            assert_eq!(request.path(), "/x");
            request.content_length
        };
        assert_eq!(length(""), ContentLength::Absent);
        assert_eq!(length("Content-Length: 12\r\n"), ContentLength::Bytes(12));
        assert_eq!(length("content-length: 0\r\n"), ContentLength::Bytes(0));
        for bad in ["-1", "+1", "1 2", "", "0x10", "99999999999999999999999"] {
            assert_eq!(
                length(&format!("Content-Length: {bad}\r\n")),
                ContentLength::Invalid,
                "{bad:?}"
            );
        }
        assert_eq!(
            length("Content-Length: 1\r\nContent-Length: 1\r\n"),
            ContentLength::Invalid
        );
    }
}
