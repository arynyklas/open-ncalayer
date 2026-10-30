//! HTTP transport shared by the network clients: time-stamping, OCSP and CRL downloads, and
//! the GET binding of the NCA services.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::fmt::{self, Write};
use std::sync::Arc;
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
    /// The `Location` header of a 3xx reply that was not followed (redirects off, or a
    /// redirect not followed for its method); `None` for other replies.
    pub location: Option<String>,
    /// Body.
    pub body: Vec<u8>,
}

/// What kind of failure an [`HttpError`] is, as the plugins' network failures name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpErrorKind {
    /// The server's name does not resolve.
    UnknownHost,
    /// No connection to the server (or its proxy): refused, unreachable, reset.
    Connect,
    /// The request ran past its timeout.
    Timeout,
    /// The TLS handshake failed.
    Tls,
    /// Anything else: a refused request, an unreadable or oversized reply.
    Other,
}

/// No HTTP response arrived: connection, timeout, size-limit or protocol failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct HttpError {
    /// What kind of failure it is.
    pub kind: HttpErrorKind,
    /// What went wrong, for the log.
    pub message: String,
}

impl HttpError {
    /// A failure of `kind`.
    pub fn new(kind: HttpErrorKind, message: impl Into<String>) -> Self {
        HttpError {
            kind,
            message: message.into(),
        }
    }

    /// A failure of kind [`HttpErrorKind::Other`].
    pub fn other(message: impl Into<String>) -> Self {
        HttpError::new(HttpErrorKind::Other, message)
    }
}

/// Limits of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetOptions {
    /// Timeout of the whole request, connecting to reading the body.
    pub timeout: Duration,
    /// Timeout of each connection attempt (to an address of the server or of its proxy),
    /// within `timeout`.
    pub connect_timeout: Duration,
    /// Largest accepted body; a bigger one is an [`HttpError`].
    pub max_len: u64,
    /// Refuse a URL that is not `https://`, the request's and every redirect's: the request
    /// fails with an [`HttpError`] instead of going in clear.
    pub https_only: bool,
    /// Follow redirects ([`MAX_REDIRECTS`] at most). Off, a 3xx reply is the reply, with its
    /// `Location` in [`HttpReply::location`].
    pub redirects: bool,
}

impl Default for GetOptions {
    /// 10 seconds, [`CONNECT_TIMEOUT`], [`MAX_RESPONSE_LEN`], `http://` allowed, redirects
    /// followed.
    fn default() -> Self {
        GetOptions {
            timeout: TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
            max_len: MAX_RESPONSE_LEN,
            https_only: false,
            redirects: true,
        }
    }
}

/// The method of an [`HttpRequest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    /// `GET`, without a body.
    Get,
    /// `POST` of the request's body.
    Post,
}

/// One HTTP request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpRequest<'a> {
    /// The method.
    pub method: HttpMethod,
    /// The URL.
    pub url: &'a str,
    /// Headers sent as given, besides those of the transport (`Host`, `Content-Length`, …).
    /// They are not sent again to the target of a redirect.
    pub headers: &'a [(&'a str, &'a str)],
    /// The `Content-Type` of a POST body; `None` sends none.
    pub content_type: Option<&'a str>,
    /// The body of a POST; empty for a GET.
    pub body: &'a [u8],
    /// The limits.
    pub opts: GetOptions,
}

impl<'a> HttpRequest<'a> {
    /// `GET url` within `opts`, without headers of its own.
    pub fn get(url: &'a str, opts: GetOptions) -> Self {
        HttpRequest {
            method: HttpMethod::Get,
            url,
            headers: &[],
            content_type: None,
            body: &[],
            opts,
        }
    }

    /// `POST url` of `body` of type `content_type` within `opts`, without headers of its
    /// own.
    pub fn post(
        url: &'a str,
        content_type: Option<&'a str>,
        body: &'a [u8],
        opts: GetOptions,
    ) -> Self {
        HttpRequest {
            method: HttpMethod::Post,
            url,
            headers: &[],
            content_type,
            body,
            opts,
        }
    }
}

/// Sends HTTP requests. Any status code is a reply, not an error.
///
/// A transport implements [`HttpTransport::send`] with the request's [`GetOptions`]: every
/// option is a limit or a refusal its caller relies on, so none has a default that drops
/// it. The other methods are shorthands for it.
pub trait HttpTransport: Send + Sync {
    /// Sends `request`.
    ///
    /// # Errors
    ///
    /// [`HttpError`] if no response arrived, or the request's options refuse it.
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError>;

    /// `GET url` within `opts`.
    ///
    /// # Errors
    ///
    /// [`HttpError`] if no response arrived, or `opts` refuses the request.
    fn get_with(&self, url: &str, opts: GetOptions) -> Result<HttpReply, HttpError> {
        self.send(&HttpRequest::get(url, opts))
    }

    /// `POST url` with `body` of type `content_type`, within `opts`.
    ///
    /// # Errors
    ///
    /// [`HttpError`] if no response arrived, or `opts` refuses the request.
    fn post_with(
        &self,
        url: &str,
        content_type: &str,
        body: &[u8],
        opts: GetOptions,
    ) -> Result<HttpReply, HttpError> {
        self.send(&HttpRequest::post(url, Some(content_type), body, opts))
    }

    /// `GET url` with the default [`GetOptions`].
    ///
    /// # Errors
    ///
    /// [`HttpError`] if no response arrived.
    fn get(&self, url: &str) -> Result<HttpReply, HttpError> {
        self.get_with(url, GetOptions::default())
    }

    /// `POST url` with `body` of type `content_type`, with the default [`GetOptions`].
    ///
    /// # Errors
    ///
    /// [`HttpError`] if no response arrived.
    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<HttpReply, HttpError> {
        self.post_with(url, content_type, body, GetOptions::default())
    }
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
    let proxy = Proxy::new(url).map_err(|_| HttpError::other("invalid proxy URL"))?;
    usable(proxy)
}

/// `proxy` if it is an HTTP proxy.
fn usable(proxy: Proxy) -> Result<Proxy, HttpError> {
    if proxy.protocol() == ProxyProtocol::Http {
        Ok(proxy)
    } else {
        Err(HttpError::other(format!(
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
/// Redirects are followed unless [`GetOptions::redirects`] is off, as `ureq` follows them, at
/// most [`MAX_REDIRECTS`]: 301, 302 and 303 as a GET; 307 and 308 of a GET as a GET, of a
/// POST not at all (the 3xx is the reply). Each step takes its own route, so a redirect from
/// `https://` to `http://` goes through the proxy in absolute form too. A 3xx reply not
/// followed carries its `Location`.
#[derive(Clone, Debug, Default)]
pub struct UreqTransport {
    proxy: ProxySetting,
    /// HTTPS roots instead of the webpki roots (`ureq`'s default), if set.
    roots: Option<Arc<Vec<ureq::tls::Certificate<'static>>>>,
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
        UreqTransport { proxy, roots: None }
    }

    /// This transport, trusting the CA certificates `extra` (DER) on HTTPS on top of the
    /// webpki roots. Conformance builds only: a release trusts the webpki roots alone.
    #[cfg(feature = "extra-roots")]
    #[must_use]
    pub fn with_extra_roots(mut self, extra: &[Vec<u8>]) -> Self {
        let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(|der| ureq::tls::Certificate::from_der(der.as_ref()).to_owned())
            .chain(
                extra
                    .iter()
                    .map(|der| ureq::tls::Certificate::from_der(der).to_owned()),
            )
            .collect();
        self.roots = Some(Arc::new(roots));
        self
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
            .map_err(|e| HttpError::other(format!("invalid URL {url}: {e}")))?;
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
    fn agent(
        &self,
        proxy: Option<Proxy>,
        timeout: Duration,
        connect_timeout: Duration,
    ) -> ureq::Agent {
        let mut config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .timeout_connect(Some(connect_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(proxy);
        if let Some(roots) = &self.roots {
            config = config.tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::Specific(Arc::clone(roots)))
                    .build(),
            );
        }
        config.build().into()
    }

    /// `request`, following redirects if its options say so. A redirect is followed with a
    /// GET without the request's headers.
    fn send_following(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        let opts = request.opts;
        let deadline = Instant::now() + opts.timeout;
        let mut url = request.url.to_owned();
        let mut current = *request;
        for _ in 0..=MAX_REDIRECTS {
            if opts.https_only && !is_https(&url) {
                return Err(HttpError::other(format!("{url} is not an https URL")));
            }
            let step = HttpRequest {
                url: &url,
                ..current
            };
            let (mut reply, location) = self.send_once(&step, deadline)?;
            let next = if opts.redirects {
                redirect(
                    &url,
                    &reply,
                    location.as_deref(),
                    step.method == HttpMethod::Post,
                )?
            } else {
                None
            };
            match next {
                Some(next) => {
                    url = next;
                    current = HttpRequest::get("", opts);
                }
                None => {
                    if (300..400).contains(&reply.status) {
                        reply.location = location;
                    }
                    return Ok(reply);
                }
            }
        }
        Err(HttpError::other(format!(
            "too many redirects (more than {MAX_REDIRECTS})"
        )))
    }

    /// One request without following redirects: the reply and its `Location`.
    fn send_once(
        &self,
        request: &HttpRequest<'_>,
        deadline: Instant,
    ) -> Result<(HttpReply, Option<String>), HttpError> {
        let url = request.url;
        let opts = request.opts;
        let proxy = match self.route(url)? {
            Route::Forward(proxy) => {
                let post = match request.method {
                    HttpMethod::Post => Some((request.content_type, request.body)),
                    HttpMethod::Get => None,
                };
                let forwarded = forward::send(
                    &proxy,
                    url,
                    request.headers,
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
            return Err(HttpError::new(HttpErrorKind::Timeout, "timed out"));
        }
        let agent = self.agent(proxy, left, opts.connect_timeout);
        let response = match request.method {
            HttpMethod::Post => {
                let mut builder = agent.post(url);
                for (name, value) in request.headers {
                    builder = builder.header(*name, *value);
                }
                if let Some(content_type) = request.content_type {
                    builder = builder.header("Content-Type", content_type);
                }
                builder.send(request.body)
            }
            HttpMethod::Get => {
                let mut builder = agent.get(url);
                for (name, value) in request.headers {
                    builder = builder.header(*name, *value);
                }
                builder.call()
            }
        };
        reply(response, opts.max_len)
    }
}

/// The kind of an I/O failure of a request.
pub(crate) fn io_kind(e: &std::io::Error) -> HttpErrorKind {
    use std::io::ErrorKind;
    // A failed name lookup: WSAHOST_NOT_FOUND and WSANO_DATA on Windows; getaddrinfo's
    // errors elsewhere, which the standard library reports by their text.
    let text = e.to_string();
    if matches!(e.raw_os_error(), Some(11001 | 11004) if cfg!(windows))
        || text.contains("failed to lookup address")
    {
        return HttpErrorKind::UnknownHost;
    }
    match e.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => HttpErrorKind::Timeout,
        ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::NotConnected
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable
        | ErrorKind::AddrNotAvailable => HttpErrorKind::Connect,
        _ => HttpErrorKind::Other,
    }
}

/// The [`HttpError`] of a `ureq` failure.
fn ureq_error(e: ureq::Error) -> HttpError {
    let kind = match &e {
        ureq::Error::HostNotFound => HttpErrorKind::UnknownHost,
        ureq::Error::Timeout(_) => HttpErrorKind::Timeout,
        ureq::Error::ConnectionFailed | ureq::Error::ConnectProxyFailed(_) => {
            HttpErrorKind::Connect
        }
        ureq::Error::Io(io) => io_kind(io),
        ureq::Error::Tls(_) | ureq::Error::TlsRequired | ureq::Error::Rustls(_) => {
            HttpErrorKind::Tls
        }
        _ => HttpErrorKind::Other,
    };
    HttpError::new(kind, e.to_string())
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
    let location = location
        .ok_or_else(|| HttpError::other(format!("redirect {} without Location", reply.status)))?;
    join_url(url, location).map(Some)
}

/// `location` (absolute, scheme-relative, absolute-path or relative) resolved against
/// `base`; only `http://` and `https://` results.
fn join_url(base: &str, location: &str) -> Result<String, HttpError> {
    let bad = || HttpError::other(format!("unusable redirect to {location}"));
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

/// Whether `url` is `https://` (the scheme in any case, as [`join_url`] accepts it).
fn is_https(url: &str) -> bool {
    url.get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
}

impl HttpTransport for UreqTransport {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.send_following(request)
    }
}

/// The reply of a `ureq` response, with at most `max_len` bytes of body, and its
/// `Location`.
fn reply(
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    max_len: u64,
) -> Result<(HttpReply, Option<String>), HttpError> {
    let http_error = ureq_error;
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
        location: None,
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

/// How a request reaches a PKI service (a TSA or an OCSP responder), as the clients of the
/// NCA services differ in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PkiMethod {
    /// `GET url/<base64 of the DER request>`, the base64 not percent-encoded.
    Get,
    /// The NCA GET binding: [`nca_get_url`].
    GetUrlEncoded,
    /// `POST url` of the DER request, with this `Content-Type` or, without one, the
    /// protocol's own.
    Post {
        /// The `Content-Type`.
        content_type: Option<String>,
    },
    /// `POST` of the DER request to the URL of the NCA GET binding, with the protocol's
    /// `Content-Type`.
    PostWithPath,
    /// The NCA GET binding while the percent-encoded request is shorter than this many
    /// bytes, else a POST with the protocol's `Content-Type` (RFC 6960 appendix A.1 uses
    /// 255).
    GetUnder(u16),
}

/// The nonce of a request to a PKI service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NonceSpec {
    /// No nonce.
    None,
    /// This many random bytes, drawn for each request.
    Random(u8),
    /// These bytes.
    Value(Vec<u8>),
}

impl NonceSpec {
    /// The nonce of a request now: `None` for [`NonceSpec::None`].
    ///
    /// # Panics
    ///
    /// If the operating system's generator fails.
    pub fn draw(&self) -> Option<Vec<u8>> {
        match self {
            NonceSpec::None => None,
            NonceSpec::Random(len) => {
                let mut nonce = vec![0; usize::from(*len)];
                getrandom::fill(&mut nonce).expect("operating system RNG failed");
                Some(nonce)
            }
            NonceSpec::Value(nonce) => Some(nonce.clone()),
        }
    }
}

/// Sends the DER `request` to the PKI service at `url` by `method`; `media_type` is the
/// protocol's `Content-Type` of a POSTed request.
///
/// # Errors
///
/// The transport's.
pub fn pki_send(
    http: &dyn HttpTransport,
    method: &PkiMethod,
    url: &str,
    media_type: &str,
    request: &[u8],
    opts: GetOptions,
) -> Result<HttpReply, HttpError> {
    match method {
        PkiMethod::Get => {
            let base = url.strip_suffix('/').unwrap_or(url);
            let url = format!("{base}/{}", STANDARD.encode(request));
            http.send(&HttpRequest::get(&url, opts))
        }
        PkiMethod::GetUrlEncoded => http.send(&HttpRequest::get(&nca_get_url(url, request), opts)),
        PkiMethod::Post { content_type } => http.send(&HttpRequest::post(
            url,
            Some(content_type.as_deref().unwrap_or(media_type)),
            request,
            opts,
        )),
        PkiMethod::PostWithPath => http.send(&HttpRequest::post(
            &nca_get_url(url, request),
            Some(media_type),
            request,
            opts,
        )),
        PkiMethod::GetUnder(limit) => {
            let get = nca_get_url(url, request);
            let encoded = get.len() - url.strip_suffix('/').unwrap_or(url).len() - 1;
            if encoded < usize::from(*limit) {
                http.send(&HttpRequest::get(&get, opts))
            } else {
                http.send(&HttpRequest::post(url, Some(media_type), request, opts))
            }
        }
    }
}

/// What went wrong talking to a PKI service, as the plugins see it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetKind {
    /// The service's name does not resolve.
    UnknownHost,
    /// No connection to the service.
    Connect,
    /// No answer in time.
    Timeout,
    /// The TLS handshake failed.
    Tls,
    /// An HTTP status other than 200.
    Http(u16),
    /// An answer that is not a valid one of the protocol, or not to this request.
    InvalidResponse,
    /// The service refused the request: its status (PKIStatus, OCSPResponseStatus).
    Rejected(u8),
    /// The answer's time is too far from the core's clock.
    ClockSkew,
    /// Anything else.
    Other,
}

impl From<HttpErrorKind> for NetKind {
    fn from(kind: HttpErrorKind) -> Self {
        match kind {
            HttpErrorKind::UnknownHost => NetKind::UnknownHost,
            HttpErrorKind::Connect => NetKind::Connect,
            HttpErrorKind::Timeout => NetKind::Timeout,
            HttpErrorKind::Tls => NetKind::Tls,
            HttpErrorKind::Other => NetKind::Other,
        }
    }
}

#[cfg(feature = "testing")]
pub use route::RouteTransport;
#[cfg(feature = "testing")]
pub(crate) use route::{request_in_url, text_reply};

#[cfg(feature = "testing")]
mod route {
    use super::{HttpError, HttpReply, HttpRequest, HttpTransport};
    use std::sync::Arc;

    /// An [`HttpTransport`] that hands each request to the first transport whose URL prefix
    /// the request URL starts with; a URL no prefix matches gets `HttpError::other("no route")`.
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
                .ok_or_else(|| HttpError::other("no route"))
        }
    }

    impl HttpTransport for RouteTransport {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            self.route(request.url)?.send(request)
        }
    }

    /// A reply of `status` with a `text/plain` body.
    pub(crate) fn text_reply(status: u16, text: &str) -> HttpReply {
        HttpReply {
            status,
            content_type: Some("text/plain".to_owned()),
            location: None,
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

    /// The DER request a GET binding carries in `url`: the base64 (percent-encoded or not)
    /// of a DER value that ends the URL's path, after one of its `/`.
    pub(crate) fn request_in_url(url: &str) -> Option<Vec<u8>> {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        use der::Decode;
        let path = url.splitn(4, '/').nth(3)?;
        let starts = std::iter::once(0).chain(path.match_indices('/').map(|(i, _)| i + 1));
        starts
            .filter_map(|start| percent_decode(&path[start..]))
            .filter_map(|b64| STANDARD.decode(b64).ok())
            .find(|der| der::AnyRef::from_der(der).is_ok())
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
        let agent = direct().agent(None, Duration::from_secs(5), CONNECT_TIMEOUT);
        let timeouts = agent.config().timeouts();
        assert_eq!(
            (timeouts.global, timeouts.connect),
            (Some(Duration::from_secs(5)), Some(CONNECT_TIMEOUT))
        );
    }

    /// A local address whose connections never complete: a listener with a backlog of 0
    /// and its accept queue filled by connections it never accepts, so the system drops
    /// further SYNs, as a dead host does. Only Linux behaves so: Windows refuses them (after
    /// its own SYN retries, about 2 s) and macOS keeps completing connections on loopback,
    /// so there `agent_connects_within_the_connect_timeout` covers the setting alone.
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
    const DEAD_HOST: GetOptions = GetOptions {
        timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(2),
        max_len: MAX_RESPONSE_LEN,
        https_only: false,
        redirects: true,
    };

    /// Whether a request that cannot connect failed after the connect timeout, not the
    /// whole request timeout.
    #[cfg(target_os = "linux")]
    fn fails_at_the_connect_timeout(request: impl FnOnce() -> Result<HttpReply, HttpError>) {
        let start = Instant::now();
        let err = request().unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(1900) && elapsed < Duration::from_millis(2500),
            "{elapsed:?}: {err}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unconnectable_server_fails_at_the_connect_timeout() {
        let (address, _listener, _held) = unconnectable();
        fails_at_the_connect_timeout(|| {
            direct().get_with(&format!("http://{address}/x"), DEAD_HOST)
        });
    }

    #[cfg(target_os = "linux")]
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
            validated.unwrap_err().message
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
        assert_eq!(e.message, "too many redirects (more than 10)");
        assert_eq!(heads.join().unwrap().len(), MAX_REDIRECTS + 1);

        let no_location = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n".to_owned();
        let (proxy, _) = serve_in_turn(vec![no_location]);
        let through = UreqTransport::with_proxy(ProxySetting::Manual(proxy));
        let e = through.get("http://nca.invalid/").unwrap_err();
        assert_eq!(e.message, "redirect 302 without Location");

        let (proxy, _) = serve_in_turn(vec![redirect_to(302, "ftp://x/")]);
        let through = UreqTransport::with_proxy(ProxySetting::Manual(proxy));
        let e = through.get("http://nca.invalid/").unwrap_err();
        assert_eq!(e.message, "unusable redirect to ftp://x/");
    }

    #[test]
    fn https_only_refuses_plain_http_without_connecting() {
        // The check runs on every URL of the chain, before its request: the first one here,
        // a redirect's the same way.
        let (proxy, heads) = serve_in_turn(Vec::new());
        let through = UreqTransport::with_proxy(ProxySetting::Manual(proxy));
        let opts = GetOptions {
            https_only: true,
            ..GetOptions::default()
        };
        let e = through.get_with("http://nca.invalid/x", opts).unwrap_err();
        assert_eq!(e.message, "http://nca.invalid/x is not an https URL");
        assert!(heads.join().unwrap().is_empty());
        assert!(is_https("https://h/") && is_https("HTTPS://h/"));
        assert!(!is_https("http://h/") && !is_https("https:/") && !is_https(""));
    }

    #[test]
    fn redirects_false_returns_3xx_with_location() {
        let (origin, heads) = serve_in_turn(vec![redirect_to(302, "/next")]);
        let opts = GetOptions {
            redirects: false,
            ..GetOptions::default()
        };
        let reply = direct().get_with(&format!("{origin}/first"), opts).unwrap();
        assert_eq!(
            (reply.status, reply.location.as_deref()),
            (302, Some("/next"))
        );
        assert_eq!(
            request_lines(&heads.join().unwrap()),
            ["GET /first HTTP/1.1"]
        );

        // A POST's 303 would go on as a GET: not without redirects.
        let (origin, heads) = serve_in_turn(vec![redirect_to(303, "https://other.invalid/")]);
        let reply = direct()
            .post_with(&format!("{origin}/q"), "t/q", b"x", opts)
            .unwrap();
        assert_eq!(
            (reply.status, reply.location.as_deref()),
            (303, Some("https://other.invalid/"))
        );
        assert_eq!(heads.join().unwrap().len(), 1);

        // With redirects on, a 3xx that is not followed still carries its Location; other
        // replies carry none.
        let (origin, heads) = serve_in_turn(vec![redirect_to(308, "/next")]);
        let reply = direct().post(&format!("{origin}/q"), "t/q", b"x").unwrap();
        assert_eq!(
            (reply.status, reply.location.as_deref()),
            (308, Some("/next"))
        );
        heads.join().unwrap();
        let (origin, heads) = serve_in_turn(vec![ok("fine")]);
        let reply = direct().get_with(&origin, opts).unwrap();
        assert_eq!((reply.status, reply.location), (200, None));
        heads.join().unwrap();
    }

    #[test]
    fn post_with_enforces_https_only_and_max_len() {
        let (proxy, heads) = serve_in_turn(Vec::new());
        let through = UreqTransport::with_proxy(ProxySetting::Manual(proxy));
        let https_only = GetOptions {
            https_only: true,
            ..GetOptions::default()
        };
        let e = through
            .post_with("http://nca.invalid/x", "t/q", b"x", https_only)
            .unwrap_err();
        assert_eq!(e.message, "http://nca.invalid/x is not an https URL");
        assert!(heads.join().unwrap().is_empty(), "nothing was sent");

        let body = "z".repeat(2048);
        let (origin, heads) = serve_in_turn(vec![ok(&body), ok(&body)]);
        let small = GetOptions {
            max_len: 1024,
            ..GetOptions::default()
        };
        direct().post_with(&origin, "t/q", b"x", small).unwrap_err();
        let large = GetOptions {
            max_len: 4096,
            ..GetOptions::default()
        };
        let reply = direct().post_with(&origin, "t/q", b"x", large).unwrap();
        assert_eq!(reply.body.len(), 2048);
        assert_eq!(heads.join().unwrap().len(), 2);
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
        assert_eq!(
            route::percent_decode("a%2Bb%2f").as_deref(),
            Some(&b"a+b/"[..])
        );
        assert_eq!(route::percent_decode("%2"), None);
        assert_eq!(route::percent_decode("%zz"), None);
        assert_eq!(route::percent_decode("%+1"), None);
    }

    #[test]
    fn default_options_are_ten_seconds_two_to_connect_and_one_mib() {
        assert_eq!(
            GetOptions::default(),
            GetOptions {
                timeout: Duration::from_secs(10),
                connect_timeout: Duration::from_secs(2),
                max_len: 1 << 20,
                https_only: false,
                redirects: true,
            }
        );
    }

    #[cfg(feature = "testing")]
    #[test]
    fn route_transport_picks_the_first_matching_prefix() {
        use std::sync::Arc;

        struct Fixed(u16);
        impl HttpTransport for Fixed {
            fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
                match request.method {
                    HttpMethod::Get => {
                        let (_, opts) = (request.url, request.opts);
                        Ok(HttpReply {
                            status: self.0,
                            content_type: Some(opts.max_len.to_string()),
                            location: None,
                            body: Vec::new(),
                        })
                    }
                    HttpMethod::Post => {
                        let (url, _, _, opts) = (
                            request.url,
                            request.content_type.unwrap_or_default(),
                            request.body,
                            request.opts,
                        );
                        self.get_with(url, opts)
                    }
                }
            }
        }

        let routes = RouteTransport::new(vec![
            ("http://a.test/x".to_owned(), Arc::new(Fixed(201)) as _),
            ("http://a.test".to_owned(), Arc::new(Fixed(202)) as _),
        ]);
        let status = |url| routes.get(url).map(|r| r.status);
        assert_eq!(status("http://a.test/x/1"), Ok(201));
        assert_eq!(status("http://a.test/y"), Ok(202));
        let opts = GetOptions {
            max_len: 7,
            ..GetOptions::default()
        };
        let limit = |r: Result<HttpReply, HttpError>| r.map(|r| (r.status, r.content_type));
        assert_eq!(
            limit(routes.get_with("http://a.test/y", opts)),
            Ok((202, Some("7".to_owned())))
        );
        assert_eq!(
            limit(routes.post_with("http://a.test/x", "t", b"", opts)),
            Ok((201, Some("7".to_owned())))
        );
        assert_eq!(
            routes.post("http://a.test/x", "t", b"").map(|r| r.status),
            Ok(201)
        );
        assert_eq!(status("http://b.test"), Err(HttpError::other("no route")));
    }

    #[test]
    fn send_with_headers() {
        let ok = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_owned();
        let headers = [("Cookie", "a=1"), ("X-Requested-With", "XMLHttpRequest")];
        // Directly and through a proxy (absolute form): the headers go, no Content-Type.
        let (url, heads) = serve_in_turn(vec![ok.clone()]);
        UreqTransport::default()
            .send(&HttpRequest {
                headers: &headers,
                ..HttpRequest::post(&format!("{url}/a"), None, b"body", GetOptions::default())
            })
            .unwrap();
        let (proxy, proxied) = serve_in_turn(vec![ok.clone()]);
        UreqTransport::with_proxy(ProxySetting::Manual(proxy))
            .send(&HttpRequest {
                headers: &headers,
                ..HttpRequest::post("http://nca.invalid/a", None, b"body", GetOptions::default())
            })
            .unwrap();
        for head in [heads.join().unwrap(), proxied.join().unwrap()] {
            let head = head[0].to_ascii_lowercase();
            assert!(head.starts_with("post "), "{head}");
            assert!(head.contains("\r\ncookie: a=1\r\n"), "{head}");
            assert!(
                head.contains("\r\nx-requested-with: xmlhttprequest\r\n"),
                "{head}"
            );
            assert!(head.contains("\r\ncontent-length: 4\r\n"), "{head}");
            assert!(!head.contains("content-type"), "{head}");
        }
        // A redirect is followed with a GET without them.
        let (url, heads) = serve_in_turn(vec![redirect_to(302, "/b"), ok]);
        let target = format!("{url}/a");
        let get = HttpRequest {
            headers: &headers,
            ..HttpRequest::get(&target, GetOptions::default())
        };
        UreqTransport::default().send(&get).unwrap();
        let heads = heads.join().unwrap();
        assert!(
            heads[0].contains("Cookie: a=1")
                || heads[0].to_ascii_lowercase().contains("cookie: a=1")
        );
        assert!(
            !heads[1].to_ascii_lowercase().contains("cookie"),
            "{}",
            heads[1]
        );
        // A header that does not fit a request line is refused.
        let bad = [("X-Evil", "a\r\nHost: b")];
        let refused = HttpRequest {
            headers: &bad,
            ..HttpRequest::get("http://nca.invalid/", GetOptions::default())
        };
        let (proxy, _) = serve_in_turn(Vec::new());
        assert!(
            UreqTransport::with_proxy(ProxySetting::Manual(proxy))
                .send(&refused)
                .is_err()
        );
    }

    #[test]
    fn errors_have_kinds() {
        let e = UreqTransport::default()
            .get("http://nca.invalid/")
            .unwrap_err();
        assert_eq!(e.kind, HttpErrorKind::UnknownHost, "{e}");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        drop(listener);
        let e = UreqTransport::default().get(&url).unwrap_err();
        // Refused at once, or (Windows retries a refused SYN) past the connect timeout.
        assert!(
            matches!(e.kind, HttpErrorKind::Connect | HttpErrorKind::Timeout),
            "{e}"
        );
    }
}
