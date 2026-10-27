//! HTTP transport shared by the network clients: time-stamping, OCSP and CRL downloads, and
//! the GET binding of the NCA services.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::fmt::{self, Write};
use std::time::{Duration, Instant};
use ureq::http::Uri;
use ureq::{Proxy, ProxyProtocol};

mod forward;
mod system_proxy;

/// Default limit of a response body: 1 MiB. A time-stamp reply or an OCSP response is a few
/// kilobytes; the NCA services are reached over plain HTTP, so anything on the path can
/// answer, and a bigger body is refused instead of buffered.
pub const MAX_RESPONSE_LEN: u64 = 1 << 20;

/// Default timeout of a whole request, connecting to reading the body.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout of connecting to a server (or proxy), for every request: time-stamping,
/// OCSP and CRL. A host whose connection never completes (it drops the SYN) fails after
/// this instead of holding the request to its whole timeout; a server that does connect
/// answers well within it on any working network.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// An HTTP response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpReply {
    /// Status code.
    pub status: u16,
    /// `Content-Type` header, if present.
    pub content_type: Option<String>,
    /// Body.
    pub body: Vec<u8>,
}

/// No HTTP response arrived: connection, timeout, size-limit or protocol failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct HttpError(pub String);

/// Limits of a GET request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetOptions {
    /// Timeout of the whole request, connecting to reading the body.
    pub timeout: Duration,
    /// Timeout of each connection attempt (to an address of the server or of its proxy),
    /// within `timeout`.
    pub connect_timeout: Duration,
    /// Largest accepted body; a bigger one is an [`HttpError`].
    pub max_len: u64,
}

impl Default for GetOptions {
    /// 10 seconds, [`CONNECT_TIMEOUT`] and [`MAX_RESPONSE_LEN`].
    fn default() -> Self {
        GetOptions {
            timeout: TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
            max_len: MAX_RESPONSE_LEN,
        }
    }
}

/// Sends HTTP requests. Any status code is a reply, not an error.
pub trait HttpTransport: Send + Sync {
    /// `GET url` with the default [`GetOptions`].
    ///
    /// # Errors
    ///
    /// [`HttpError`] if no response arrived.
    fn get(&self, url: &str) -> Result<HttpReply, HttpError>;

    /// `GET url` within `opts`. The default implementation ignores `opts` and calls
    /// [`HttpTransport::get`].
    ///
    /// # Errors
    ///
    /// [`HttpError`] if no response arrived.
    fn get_with(&self, url: &str, opts: GetOptions) -> Result<HttpReply, HttpError> {
        let _ = opts;
        self.get(url)
    }

    /// `POST url` with `body` of type `content_type`, with the default [`GetOptions`] limits.
    ///
    /// # Errors
    ///
    /// [`HttpError`] if no response arrived.
    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<HttpReply, HttpError>;
}

/// The proxy [`UreqTransport`] connects through. Only HTTP proxies are supported: plain
/// HTTP goes to them in absolute form (`GET http://host/path`), HTTPS through a
/// `CONNECT` tunnel. SOCKS proxies and proxies reached over TLS (`https://` proxy URLs)
/// are not.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum ProxySetting {
    /// Direct connections, whatever the system's settings.
    #[default]
    None,
    /// The system's proxy: `ALL_PROXY`, `HTTPS_PROXY` or `HTTP_PROXY` (with `NO_PROXY`), on
    /// Windows otherwise the manual proxy of the Internet Options (`ProxyServer` with its
    /// per-scheme entries, `ProxyOverride`, the per-machine policy). Automatic
    /// configuration (PAC, WPAD) is not followed.
    System,
    /// This proxy URL, e.g. `http://proxy.example:3128`; `user:password@` before the host
    /// for Basic authentication.
    Manual(String),
}

impl ProxySetting {
    /// Checks that a [`ProxySetting::Manual`] URL names a usable proxy.
    ///
    /// # Errors
    ///
    /// [`HttpError`] if the URL is not one or the proxy is not an HTTP proxy. The message
    /// does not repeat the URL, which may hold a password.
    pub fn validate(&self) -> Result<(), HttpError> {
        match self {
            ProxySetting::Manual(url) => parse_proxy(url).map(drop),
            ProxySetting::None | ProxySetting::System => Ok(()),
        }
    }
}

/// The password of a manual proxy URL is not shown.
impl fmt::Debug for ProxySetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxySetting::None => f.write_str("None"),
            ProxySetting::System => f.write_str("System"),
            ProxySetting::Manual(url) => f
                .debug_tuple("Manual")
                .field(&without_userinfo(url))
                .finish(),
        }
    }
}

/// `url` with everything between its scheme and its last `@` (the user name and password,
/// which may hold an unencoded `/`, `?`, `#` or `@`) replaced by `***`.
fn without_userinfo(url: &str) -> String {
    let start = url.find("://").map_or(0, |i| i + 3);
    match url[start..].rfind('@') {
        Some(at) => format!("{}***{}", &url[..start], &url[start + at..]),
        None => url.to_owned(),
    }
}

/// The proxy of the URL `url`, if it is an HTTP proxy.
fn parse_proxy(url: &str) -> Result<Proxy, HttpError> {
    // The URL may hold a password: it is not repeated in the errors.
    let proxy = Proxy::new(url).map_err(|_| HttpError("invalid proxy URL".to_owned()))?;
    usable(proxy)
}

/// `proxy` if it is an HTTP proxy.
fn usable(proxy: Proxy) -> Result<Proxy, HttpError> {
    if proxy.protocol() == ProxyProtocol::Http {
        Ok(proxy)
    } else {
        Err(HttpError(format!(
            "unsupported proxy type {}: only http:// proxies are supported",
            proxy.protocol()
        )))
    }
}

/// [`HttpTransport`] over `ureq`: plain HTTP (the NCA services have no TLS) or HTTPS on
/// rustls, directly or through the proxy of its [`ProxySetting`] (directly by default).
/// The timeout (for the whole request, redirects included), the connect timeout and the
/// body limit of [`GetOptions`] are enforced.
///
/// Through a proxy, HTTPS goes in a `CONNECT` tunnel (`ureq`), and plain HTTP as an
/// absolute-form request to the proxy (`GET http://host/path HTTP/1.1`, see `forward`),
/// which `ureq` cannot send.
///
/// Redirects are followed as `ureq` follows them, at most [`MAX_REDIRECTS`]: 301, 302 and
/// 303 as a GET; 307 and 308 of a GET as a GET, of a POST not at all (the 3xx is the
/// reply). Each step takes its own route, so a redirect from `https://` to `http://` goes
/// through the proxy in absolute form too.
#[derive(Clone, Debug, Default)]
pub struct UreqTransport {
    proxy: ProxySetting,
}

/// The most redirects one request follows, as `ureq` by default.
pub const MAX_REDIRECTS: usize = 10;

/// How a request reaches its server.
enum Route {
    /// Directly.
    Direct,
    /// Through a `CONNECT` tunnel of this proxy.
    Tunnel(Proxy),
    /// As an absolute-form request to this proxy.
    Forward(Proxy),
}

impl UreqTransport {
    /// A transport through `proxy`. A [`ProxySetting::Manual`] proxy that fails
    /// [`ProxySetting::validate`] fails every request with an [`HttpError`] instead of
    /// connecting directly.
    pub fn with_proxy(proxy: ProxySetting) -> Self {
        UreqTransport { proxy }
    }

    /// The route of a request to `url`. The system's proxy is looked up for each request,
    /// so a change takes effect without a restart.
    fn route(&self, url: &str) -> Result<Route, HttpError> {
        let proxy = match &self.proxy {
            ProxySetting::None => return Ok(Route::Direct),
            ProxySetting::System => match system_proxy::for_url(url) {
                Some(proxy) => usable(proxy)?,
                None => return Ok(Route::Direct),
            },
            ProxySetting::Manual(proxy) => parse_proxy(proxy)?,
        };
        let uri: Uri = url
            .parse()
            .map_err(|e| HttpError(format!("invalid URL {url}: {e}")))?;
        Ok(if proxy.is_no_proxy(&uri) {
            Route::Direct
        } else if uri.scheme_str() == Some("http") {
            Route::Forward(proxy)
        } else {
            Route::Tunnel(proxy)
        })
    }

    /// A `ureq` agent connecting directly or through the tunnel of `proxy` within
    /// `connect_timeout`, the whole request ending after `timeout`, following no redirects
    /// (`send` does).
    fn agent(proxy: Option<Proxy>, timeout: Duration, connect_timeout: Duration) -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .timeout_connect(Some(connect_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(proxy)
            .build()
            .into()
    }

    /// `url` with `post` (content type and body) or GET, within `opts`, following
    /// redirects.
    fn send(
        &self,
        url: &str,
        mut post: Option<(&str, &[u8])>,
        opts: GetOptions,
    ) -> Result<HttpReply, HttpError> {
        let deadline = Instant::now() + opts.timeout;
        let mut url = url.to_owned();
        for _ in 0..=MAX_REDIRECTS {
            let (reply, location) = self.send_once(&url, post, deadline, opts)?;
            match redirect(&url, &reply, location.as_deref(), post.is_some())? {
                Some(next) => {
                    url = next;
                    post = None;
                }
                None => return Ok(reply),
            }
        }
        Err(HttpError(format!(
            "too many redirects (more than {MAX_REDIRECTS})"
        )))
    }

    /// One request without following redirects: the reply and its `Location`.
    fn send_once(
        &self,
        url: &str,
        post: Option<(&str, &[u8])>,
        deadline: Instant,
        opts: GetOptions,
    ) -> Result<(HttpReply, Option<String>), HttpError> {
        let proxy = match self.route(url)? {
            Route::Forward(proxy) => {
                let forwarded = forward::send(
                    &proxy,
                    url,
                    post,
                    deadline,
                    opts.connect_timeout,
                    opts.max_len,
                )?;
                return Ok((forwarded.reply, forwarded.location));
            }
            Route::Tunnel(proxy) => Some(proxy),
            Route::Direct => None,
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(HttpError("timed out".to_owned()));
        }
        let agent = Self::agent(proxy, left, opts.connect_timeout);
        let response = match post {
            Some((content_type, body)) => agent
                .post(url)
                .header("Content-Type", content_type)
                .send(body),
            None => agent.get(url).call(),
        };
        reply(response, opts.max_len)
    }
}

/// The URL a reply to `url` redirects to, if it is followed (see [`UreqTransport`]).
///
/// # Errors
///
/// A redirect to be followed without a usable `Location`.
fn redirect(
    url: &str,
    reply: &HttpReply,
    location: Option<&str>,
    post: bool,
) -> Result<Option<String>, HttpError> {
    match reply.status {
        301..=303 => {}
        307 | 308 if !post => {}
        _ => return Ok(None),
    }
    let location =
        location.ok_or_else(|| HttpError(format!("redirect {} without Location", reply.status)))?;
    join_url(url, location).map(Some)
}

/// `location` (absolute, scheme-relative, absolute-path or relative) resolved against
/// `base`; only `http://` and `https://` results.
fn join_url(base: &str, location: &str) -> Result<String, HttpError> {
    let bad = || HttpError(format!("unusable redirect to {location}"));
    let location = location.trim();
    let base: Uri = base.parse().map_err(|_| bad())?;
    let (scheme, authority) = match (base.scheme_str(), base.authority()) {
        (Some(scheme), Some(authority)) => (scheme, authority.as_str()),
        _ => return Err(bad()),
    };
    let has_scheme = location
        .split_once(':')
        .is_some_and(|(s, _)| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphabetic()));
    let joined = if has_scheme {
        location.to_owned()
    } else if let Some(rest) = location.strip_prefix("//") {
        format!("{scheme}://{rest}")
    } else if location.starts_with('/') {
        format!("{scheme}://{authority}{location}")
    } else {
        let path = base.path();
        let dir = &path[..path.rfind('/').map_or(0, |i| i + 1)];
        let dir = if dir.is_empty() { "/" } else { dir };
        format!("{scheme}://{authority}{dir}{location}")
    };
    // The fragment stays with the client.
    let joined = joined.split('#').next().unwrap_or_default().to_owned();
    let uri: Uri = joined.parse().map_err(|_| bad())?;
    match uri.scheme_str() {
        Some(s) if s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https") => Ok(joined),
        _ => Err(bad()),
    }
}

impl HttpTransport for UreqTransport {
    fn get(&self, url: &str) -> Result<HttpReply, HttpError> {
        self.get_with(url, GetOptions::default())
    }

    fn get_with(&self, url: &str, opts: GetOptions) -> Result<HttpReply, HttpError> {
        self.send(url, None, opts)
    }

    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<HttpReply, HttpError> {
        self.send(url, Some((content_type, body)), GetOptions::default())
    }
}

/// The reply of a `ureq` response, with at most `max_len` bytes of body, and its
/// `Location`.
fn reply(
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    max_len: u64,
) -> Result<(HttpReply, Option<String>), HttpError> {
    let http_error = |e: ureq::Error| HttpError(e.to_string());
    let mut response = response.map_err(http_error)?;
    let header = |name| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let content_type = header(ureq::http::header::CONTENT_TYPE);
    let location = header(ureq::http::header::LOCATION);
    let body = response
        .body_mut()
        .with_config()
        .limit(max_len)
        .read_to_vec()
        .map_err(http_error)?;
    let reply = HttpReply {
        status: response.status().as_u16(),
        content_type,
        body,
    };
    Ok((reply, location))
}

/// URL of the NCA GET binding (OCSP and time-stamping): `base`, a `/` unless `base` already
/// ends with one, and the base64 of the DER `request` percent-encoded like
/// `java.net.URLEncoder` (`+` → `%2B`, `/` → `%2F`, `=` → `%3D`; every character but the
/// unreserved ones of RFC 3986 is escaped, which on the base64 alphabet is the same).
pub fn nca_get_url(base: &str, request: &[u8]) -> String {
    let encoded = STANDARD.encode(request);
    let base = base.strip_suffix('/').unwrap_or(base);
    let mut url = String::with_capacity(base.len() + 1 + encoded.len() + encoded.len() / 8);
    url.push_str(base);
    url.push('/');
    for b in encoded.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            url.push(char::from(b));
        } else {
            // Writing to a `String` cannot fail.
            let _ = write!(url, "%{b:02X}");
        }
    }
    url
}

#[cfg(feature = "testing")]
pub use route::RouteTransport;
#[cfg(feature = "testing")]
pub(crate) use route::{percent_decode, text_reply};

#[cfg(feature = "testing")]
mod route {
    use super::{GetOptions, HttpError, HttpReply, HttpTransport};
    use std::sync::Arc;

    /// An [`HttpTransport`] that hands each request to the first transport whose URL prefix
    /// the request URL starts with; a URL no prefix matches gets `HttpError("no route")`.
    pub struct RouteTransport {
        routes: Vec<(String, Arc<dyn HttpTransport>)>,
    }

    impl RouteTransport {
        /// Routes `(URL prefix, transport)`, tried in order.
        pub fn new(routes: Vec<(String, Arc<dyn HttpTransport>)>) -> Self {
            RouteTransport { routes }
        }

        fn route(&self, url: &str) -> Result<&dyn HttpTransport, HttpError> {
            self.routes
                .iter()
                .find(|(prefix, _)| url.starts_with(prefix.as_str()))
                .map(|(_, transport)| transport.as_ref())
                .ok_or_else(|| HttpError("no route".to_owned()))
        }
    }

    impl HttpTransport for RouteTransport {
        fn get(&self, url: &str) -> Result<HttpReply, HttpError> {
            self.route(url)?.get(url)
        }

        fn get_with(&self, url: &str, opts: GetOptions) -> Result<HttpReply, HttpError> {
            self.route(url)?.get_with(url, opts)
        }

        fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<HttpReply, HttpError> {
            self.route(url)?.post(url, content_type, body)
        }
    }

    /// A reply of `status` with a `text/plain` body.
    pub(crate) fn text_reply(status: u16, text: &str) -> HttpReply {
        HttpReply {
            status,
            content_type: Some("text/plain".to_owned()),
            body: text.as_bytes().to_vec(),
        }
    }

    /// Decodes `%XX` escapes; `None` for a broken one.
    pub(crate) fn percent_decode(s: &str) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(s.len());
        let mut bytes = s.bytes();
        while let Some(b) = bytes.next() {
            if b == b'%' {
                let hex = |b: Option<u8>| char::from(b?).to_digit(16);
                let (high, low) = (hex(bytes.next())?, hex(bytes.next())?);
                out.push(u8::try_from(high * 16 + low).ok()?);
            } else {
                out.push(b);
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    /// A one-connection HTTP server on a free local port: reads the request head and hands
    /// the stream to `serve`. Returns the URL.
    fn serve_once(serve: impl FnOnce(TcpStream) + Send + 'static) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/x", listener.local_addr().unwrap());
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            let mut byte = [0];
            while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                head.push(byte[0]);
            }
            serve(stream);
        });
        url
    }

    fn body_of(len: usize) -> impl FnOnce(TcpStream) + Send + 'static {
        move |mut stream| {
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                 Content-Length: {len}\r\nConnection: close\r\n\r\n"
            );
            // The client may hang up once the limit is exceeded.
            let _ = stream
                .write_all(head.as_bytes())
                .and_then(|()| stream.write_all(&vec![0x5a; len]));
        }
    }

    /// Direct connections, as by default.
    fn direct() -> UreqTransport {
        UreqTransport::default()
    }

    #[test]
    fn ureq_transport_honours_timeout_and_size() {
        let silent = serve_once(|stream| {
            thread::sleep(Duration::from_secs(5));
            drop(stream);
        });
        let start = Instant::now();
        let opts = GetOptions {
            timeout: Duration::from_millis(200),
            ..GetOptions::default()
        };
        let err = direct().get_with(&silent, opts).unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(2), "{err}");

        let limit = GetOptions {
            timeout: Duration::from_secs(10),
            ..GetOptions::default()
        };
        let big = serve_once(body_of(2 << 20));
        direct().get_with(&big, limit).unwrap_err();

        let small = serve_once(body_of(1 << 10));
        let reply = direct().get_with(&small, limit).unwrap();
        assert_eq!((reply.status, reply.body.len()), (200, 1 << 10));
        assert_eq!(
            reply.content_type.as_deref(),
            Some("application/octet-stream")
        );
    }

    #[test]
    fn agent_connects_within_the_connect_timeout() {
        let agent = UreqTransport::agent(None, Duration::from_secs(5), CONNECT_TIMEOUT);
        let timeouts = agent.config().timeouts();
        assert_eq!(
            (timeouts.global, timeouts.connect),
            (Some(Duration::from_secs(5)), Some(CONNECT_TIMEOUT))
        );
    }

    /// A local address whose connections never complete: a listener with a backlog of 0
    /// and its accept queue filled by connections it never accepts, so the system drops
    /// further SYNs, as a dead host does. Windows refuses them instead (after its own SYN
    /// retries, about 2 s), so this needs a Unix system.
    #[cfg(unix)]
    fn unconnectable() -> (std::net::SocketAddr, TcpListener, Vec<TcpStream>) {
        use std::os::fd::AsRawFd;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        // SAFETY: `listen` on the listener's own open socket only changes its backlog.
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let address = listener.local_addr().unwrap();
        let mut held = Vec::new();
        for _ in 0..64 {
            match TcpStream::connect_timeout(&address, Duration::from_millis(300)) {
                Ok(stream) => held.push(stream),
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    return (address, listener, held);
                }
                Err(e) => panic!("{e}"),
            }
        }
        panic!("the accept queue of {address} never filled");
    }

    /// Connect timeout 2 s, whole request 5 s.
    #[cfg(unix)]
    const DEAD_HOST: GetOptions = GetOptions {
        timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(2),
        max_len: MAX_RESPONSE_LEN,
    };

    /// Whether a request that cannot connect failed after the connect timeout, not the
    /// whole request timeout.
    #[cfg(unix)]
    fn fails_at_the_connect_timeout(request: impl FnOnce() -> Result<HttpReply, HttpError>) {
        let start = Instant::now();
        let err = request().unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(1900) && elapsed < Duration::from_millis(2500),
            "{elapsed:?}: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unconnectable_server_fails_at_the_connect_timeout() {
        let (address, _listener, _held) = unconnectable();
        fails_at_the_connect_timeout(|| {
            direct().get_with(&format!("http://{address}/x"), DEAD_HOST)
        });
    }

    #[cfg(unix)]
    #[test]
    fn unconnectable_proxy_fails_at_the_connect_timeout() {
        let (address, _listener, _held) = unconnectable();
        // Plain HTTP goes through `forward`.
        let through = UreqTransport::with_proxy(ProxySetting::Manual(format!("http://{address}")));
        fails_at_the_connect_timeout(|| through.get_with("http://nca.invalid/ocsp", DEAD_HOST));
    }

    /// A one-connection stub proxy: sends the request head it received on the channel and
    /// answers `reply`. Returns the proxy URL.
    fn stub_proxy(reply: &'static [u8]) -> (String, std::sync::mpsc::Receiver<String>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            let mut byte = [0];
            while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                head.push(byte[0]);
            }
            let _ = stream.write_all(reply);
            tx.send(String::from_utf8(head).unwrap()).unwrap();
        });
        (proxy, rx)
    }

    #[test]
    fn plain_http_is_forwarded_and_https_tunnelled() {
        let (proxy, head) = stub_proxy(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let through = UreqTransport::with_proxy(ProxySetting::Manual(proxy));
        let reply = through.get("http://nca.invalid:8080/ocsp").unwrap();
        assert_eq!((reply.status, &reply.body[..]), (200, &b"ok"[..]));
        let head = head.recv().unwrap();
        assert!(
            head.starts_with("GET http://nca.invalid:8080/ocsp HTTP/1.1\r\n"),
            "{head}"
        );

        let (proxy, head) = stub_proxy(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        let through = UreqTransport::with_proxy(ProxySetting::Manual(proxy));
        through.get("https://nca.invalid:8443/ocsp").unwrap_err();
        let head = head.recv().unwrap();
        assert!(
            head.starts_with("CONNECT nca.invalid:8443 HTTP/1.1\r\n"),
            "{head}"
        );
    }

    #[test]
    fn unusable_proxies_fail_without_connecting_or_panicking() {
        let unsupported = |url: &str| {
            let setting = ProxySetting::Manual(url.to_owned());
            let validated = setting.validate();
            let through = UreqTransport::with_proxy(setting);
            for target in ["http://127.0.0.1:1/", "https://127.0.0.1:1/"] {
                let got = through.post(target, "t", b"");
                assert_eq!(
                    got.as_ref().err(),
                    validated.as_ref().err(),
                    "{url} {target}"
                );
                assert!(got.is_err(), "{url} {target}");
            }
            validated.unwrap_err().0
        };
        assert_eq!(unsupported("http://u:p@[x"), "invalid proxy URL");
        assert_eq!(unsupported(""), "invalid proxy URL");
        for url in [
            "socks5://127.0.0.1:1",
            "socks4://h",
            "socks://h:1",
            "https://u:p@h:443",
        ] {
            let e = unsupported(url);
            assert!(e.starts_with("unsupported proxy type"), "{url}: {e}");
            assert!(!e.contains("u:p"), "{e}");
        }
        assert_eq!(
            ProxySetting::Manual("http://h:1".to_owned()).validate(),
            Ok(())
        );
        assert_eq!(ProxySetting::Manual("h:1".to_owned()).validate(), Ok(()));
        assert_eq!(ProxySetting::None.validate(), Ok(()));
        assert_eq!(ProxySetting::System.validate(), Ok(()));
    }

    #[test]
    fn default_is_direct_and_debug_hides_passwords() {
        assert_eq!(UreqTransport::default().proxy, ProxySetting::None);
        assert_eq!(ProxySetting::default(), ProxySetting::None);
        let shown = |url: &str| format!("{:?}", ProxySetting::Manual(url.to_owned()));
        // Everything up to the last `@` goes, an `@` after the host too (over-masking is
        // harmless here).
        assert_eq!(
            shown("http://user:secret@h:1/x@y"),
            r#"Manual("http://***@y")"#
        );
        assert_eq!(shown("a:b@c@h:1"), r#"Manual("***@h:1")"#);
        // Unencoded `/`, `?` and `#` in the password.
        for password in ["p/ss", "p?ss", "p#ss", "p/?#ss"] {
            assert_eq!(
                shown(&format!("http://user:{password}@h:1")),
                r#"Manual("http://***@h:1")"#,
                "{password}"
            );
        }
        assert_eq!(shown("http://h:1"), r#"Manual("http://h:1")"#);
        let transport = UreqTransport::with_proxy(ProxySetting::Manual("http://u:pw@h".to_owned()));
        assert!(!format!("{transport:?}").contains("pw"));
        assert_eq!(format!("{:?}", ProxySetting::System), "System");
    }

    /// A stub HTTP server (a proxy or the origin) answering its connections in turn with
    /// `replies`; returns its URL and, once joined, the request heads it got.
    fn serve_in_turn(replies: Vec<String>) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut heads = Vec::new();
            for reply in replies {
                let (mut stream, _) = listener.accept().unwrap();
                let mut head = Vec::new();
                let mut byte = [0];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                let head = String::from_utf8(head).unwrap();
                let len = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|n| n.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                let mut body = vec![0; len];
                stream.read_exact(&mut body).unwrap();
                let _ = stream.write_all(reply.as_bytes());
                heads.push(head);
            }
            heads
        });
        (url, server)
    }

    fn redirect_to(status: u16, location: &str) -> String {
        format!("HTTP/1.1 {status} R\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n")
    }

    fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    /// The request lines of `heads`.
    fn request_lines(heads: &[String]) -> Vec<&str> {
        heads.iter().map(|h| h.lines().next().unwrap()).collect()
    }

    #[test]
    fn redirects_are_followed_through_the_proxy_as_ureq_follows_them() {
        let replies = vec![
            redirect_to(302, "/b?x=1"),
            redirect_to(307, "c"),
            redirect_to(301, "http://other.invalid/d#frag"),
            ok("done"),
        ];
        let (proxy, heads) = serve_in_turn(replies);
        let through = UreqTransport::with_proxy(ProxySetting::Manual(proxy));
        let reply = through.get("http://nca.invalid:8080/a/start").unwrap();
        assert_eq!((reply.status, &reply.body[..]), (200, &b"done"[..]));
        assert_eq!(
            request_lines(&heads.join().unwrap()),
            [
                "GET http://nca.invalid:8080/a/start HTTP/1.1",
                "GET http://nca.invalid:8080/b?x=1 HTTP/1.1",
                "GET http://nca.invalid:8080/c HTTP/1.1",
                "GET http://other.invalid/d HTTP/1.1",
            ]
        );

        // A POST: 303 continues as a GET without the body; 307 and 308 are the reply.
        let (proxy, heads) = serve_in_turn(vec![redirect_to(303, "/r"), ok("got")]);
        let through = UreqTransport::with_proxy(ProxySetting::Manual(proxy));
        let reply = through
            .post("http://nca.invalid/q", "t/q", b"body")
            .unwrap();
        assert_eq!(reply.body, b"got");
        let heads = heads.join().unwrap();
        assert!(
            heads[0].starts_with("POST http://nca.invalid/q "),
            "{heads:?}"
        );
        assert!(
            heads[1].starts_with("GET http://nca.invalid/r "),
            "{heads:?}"
        );
        assert!(
            !heads[1].to_ascii_lowercase().contains("content-length"),
            "{heads:?}"
        );
        for status in [307, 308] {
            let (proxy, heads) = serve_in_turn(vec![redirect_to(status, "/r")]);
            let through = UreqTransport::with_proxy(ProxySetting::Manual(proxy));
            let reply = through
                .post("http://nca.invalid/q", "t/q", b"body")
                .unwrap();
            assert_eq!(reply.status, status);
            assert_eq!(heads.join().unwrap().len(), 1);
        }
    }

    #[test]
    fn direct_redirects_take_the_same_rules() {
        let (origin, heads) = serve_in_turn(vec![redirect_to(302, "/next"), ok("direct")]);
        let reply = direct().get(&format!("{origin}/first")).unwrap();
        assert_eq!(reply.body, b"direct");
        assert_eq!(
            request_lines(&heads.join().unwrap()),
            ["GET /first HTTP/1.1", "GET /next HTTP/1.1"]
        );
        let (origin, heads) = serve_in_turn(vec![redirect_to(308, "/next")]);
        let reply = direct().post(&format!("{origin}/q"), "t/q", b"x").unwrap();
        assert_eq!(reply.status, 308);
        heads.join().unwrap();
    }

    #[test]
    fn redirect_limits_and_broken_redirects() {
        let loops = vec![redirect_to(302, "/again"); MAX_REDIRECTS + 1];
        let (proxy, heads) = serve_in_turn(loops);
        let through = UreqTransport::with_proxy(ProxySetting::Manual(proxy));
        let e = through.get("http://nca.invalid/").unwrap_err();
        assert_eq!(e.0, "too many redirects (more than 10)");
        assert_eq!(heads.join().unwrap().len(), MAX_REDIRECTS + 1);

        let no_location = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n".to_owned();
        let (proxy, _) = serve_in_turn(vec![no_location]);
        let through = UreqTransport::with_proxy(ProxySetting::Manual(proxy));
        let e = through.get("http://nca.invalid/").unwrap_err();
        assert_eq!(e.0, "redirect 302 without Location");

        let (proxy, _) = serve_in_turn(vec![redirect_to(302, "ftp://x/")]);
        let through = UreqTransport::with_proxy(ProxySetting::Manual(proxy));
        let e = through.get("http://nca.invalid/").unwrap_err();
        assert_eq!(e.0, "unusable redirect to ftp://x/");
    }

    #[test]
    fn locations_are_resolved_against_the_request() {
        let base = "https://h:8443/a/b/c?q=1";
        let joined = |l| join_url(base, l).unwrap();
        assert_eq!(joined("http://x/y"), "http://x/y");
        assert_eq!(joined("//x/y"), "https://x/y");
        assert_eq!(joined("/y"), "https://h:8443/y");
        assert_eq!(joined("y?z"), "https://h:8443/a/b/y?z");
        assert_eq!(joined("/y#f"), "https://h:8443/y");
        assert_eq!(join_url("http://h", "y").unwrap(), "http://h/y");
        assert!(join_url(base, "mailto:x@y").is_err());
    }

    #[test]
    fn nca_get_url_encodes_all_but_unreserved() {
        // base64 "+/8=" for [0xfb, 0xff].
        assert_eq!(
            nca_get_url("http://h/tsp", &[0xfb, 0xff]),
            "http://h/tsp/%2B%2F8%3D"
        );
        assert_eq!(
            nca_get_url("http://h/", &[0xfb, 0xff]),
            "http://h/%2B%2F8%3D"
        );
    }

    #[cfg(feature = "testing")]
    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%2Bb%2f").as_deref(), Some(&b"a+b/"[..]));
        assert_eq!(percent_decode("%2"), None);
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_decode("%+1"), None);
    }

    #[test]
    fn default_options_are_ten_seconds_two_to_connect_and_one_mib() {
        assert_eq!(
            GetOptions::default(),
            GetOptions {
                timeout: Duration::from_secs(10),
                connect_timeout: Duration::from_secs(2),
                max_len: 1 << 20,
            }
        );
    }

    #[cfg(feature = "testing")]
    #[test]
    fn route_transport_picks_the_first_matching_prefix() {
        use std::sync::Arc;

        struct Fixed(u16);
        impl HttpTransport for Fixed {
            fn get(&self, _: &str) -> Result<HttpReply, HttpError> {
                Ok(HttpReply {
                    status: self.0,
                    content_type: None,
                    body: Vec::new(),
                })
            }
            fn post(&self, url: &str, _: &str, _: &[u8]) -> Result<HttpReply, HttpError> {
                self.get(url)
            }
        }

        let routes = RouteTransport::new(vec![
            ("http://a.test/x".to_owned(), Arc::new(Fixed(201)) as _),
            ("http://a.test".to_owned(), Arc::new(Fixed(202)) as _),
        ]);
        let status = |url| routes.get(url).map(|r| r.status);
        assert_eq!(status("http://a.test/x/1"), Ok(201));
        assert_eq!(status("http://a.test/y"), Ok(202));
        assert_eq!(
            routes
                .get_with("http://a.test/y", GetOptions::default())
                .map(|r| r.status),
            Ok(202)
        );
        assert_eq!(
            routes.post("http://a.test/x", "t", b"").map(|r| r.status),
            Ok(201)
        );
        assert_eq!(
            status("http://b.test"),
            Err(HttpError("no route".to_owned()))
        );
    }
}
