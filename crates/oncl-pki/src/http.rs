//! HTTP transport shared by the network clients: time-stamping, OCSP and CRL downloads, and
//! the GET binding of the NCA services.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::fmt::{self, Write};
use std::time::Duration;
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
    /// Largest accepted body; a bigger one is an [`HttpError`].
    pub max_len: u64,
}

impl Default for GetOptions {
    /// 10 seconds and [`MAX_RESPONSE_LEN`].
    fn default() -> Self {
        GetOptions {
            timeout: TIMEOUT,
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

/// `url` with the user name and password before its host replaced by `***`.
fn without_userinfo(url: &str) -> String {
    let start = url.find("://").map_or(0, |i| i + 3);
    let end = url[start..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| start + i);
    match url[start..end].rfind('@') {
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
/// Both the timeout and the body limit of [`GetOptions`] are enforced.
///
/// Through a proxy, HTTPS goes in a `CONNECT` tunnel (`ureq`), and plain HTTP as an
/// absolute-form request to the proxy (`GET http://host/path HTTP/1.1`, see `forward`),
/// which `ureq` cannot send.
#[derive(Clone, Debug, Default)]
pub struct UreqTransport {
    proxy: ProxySetting,
}

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

    /// A `ureq` agent connecting directly or through the tunnel of `proxy`.
    fn agent(proxy: Option<Proxy>, timeout: Duration) -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .proxy(proxy)
            .build()
            .into()
    }

    /// `url` with `post` (content type and body) or GET, within `opts`.
    fn send(
        &self,
        url: &str,
        post: Option<(&str, &[u8])>,
        opts: GetOptions,
    ) -> Result<HttpReply, HttpError> {
        let proxy = match self.route(url)? {
            Route::Forward(proxy) => return forward::send(&proxy, url, post, opts),
            Route::Tunnel(proxy) => Some(proxy),
            Route::Direct => None,
        };
        let agent = Self::agent(proxy, opts.timeout);
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

fn reply(
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    max_len: u64,
) -> Result<HttpReply, HttpError> {
    let http_error = |e: ureq::Error| HttpError(e.to_string());
    let mut response = response.map_err(http_error)?;
    let content_type = response
        .headers()
        .get(ureq::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = response
        .body_mut()
        .with_config()
        .limit(max_len)
        .read_to_vec()
        .map_err(http_error)?;
    Ok(HttpReply {
        status: response.status().as_u16(),
        content_type,
        body,
    })
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
    use std::time::Instant;

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
            max_len: MAX_RESPONSE_LEN,
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
        assert_eq!(
            shown("http://user:secret@h:1/x@y"),
            r#"Manual("http://***@h:1/x@y")"#
        );
        assert_eq!(shown("a:b@c@h:1"), r#"Manual("***@h:1")"#);
        assert_eq!(shown("http://h:1"), r#"Manual("http://h:1")"#);
        let transport = UreqTransport::with_proxy(ProxySetting::Manual("http://u:pw@h".to_owned()));
        assert!(!format!("{transport:?}").contains("pw"));
        assert_eq!(format!("{:?}", ProxySetting::System), "System");
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
    fn default_options_are_ten_seconds_and_one_mib() {
        assert_eq!(
            GetOptions::default(),
            GetOptions {
                timeout: Duration::from_secs(10),
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
