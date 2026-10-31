//! HTTP of the watcher: size limits (more bytes than the limit is an error, never a
//! truncation), redirects followed by hand with every hop checked, and public destination
//! addresses only. Error messages never carry bytes of a response body.
//!
//! A host is resolved once per request and every address is checked; the connection goes to
//! exactly those addresses (no second lookup, no proxy), so a DNS answer that changes in
//! between (DNS rebinding) cannot lead it elsewhere. Proxy variables are ignored for that
//! reason ([`proxy_ignored`]). A request without a [`Session`] may use any of them (the next
//! one when one cannot be connected to). Requests of a session go to the address the session
//! first reached for the host: the download page keeps its PHP session on one backend of
//! several behind the same name.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha1::Sha1;
use sha2::{Digest, Sha256};
use ureq::Agent;
use ureq::config::Config;
use ureq::http::Uri;
use ureq::tls::{Certificate as TlsCertificate, RootCerts, TlsConfig};
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

use super::{REDIRECTS_MAX, hex};

/// Which roots verify a host's TLS certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootsChoice {
    /// The webpki roots.
    WebPki,
    /// The NCA's TLS roots (`oncl_pki::roots::nca_tls_roots`).
    NcaTls,
}

/// TLS roots by host suffix; other hosts use [`RootsChoice::WebPki`]. The sites of the NCA
/// (`*.pki.gov.kz`) present certificates of a public WebPKI CA, so the table is empty; a
/// host whose certificate the NCA issues goes here with [`RootsChoice::NcaTls`].
const TLS_ROOTS: &[(&str, RootsChoice)] = &[];

/// The roots for `host`.
pub fn roots_for(host: &str) -> RootsChoice {
    TLS_ROOTS
        .iter()
        .find(|(suffix, _)| host == *suffix || host.ends_with(&format!(".{suffix}")))
        .map_or(RootsChoice::WebPki, |(_, choice)| *choice)
}

/// Why a request failed. No variant carries response bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchError {
    /// A final status other than 2xx.
    Status(u16),
    /// The body is larger than the limit.
    TooLarge {
        /// The limit.
        limit: u64,
    },
    /// The host resolves to an address that is not public.
    RefusedAddress(String),
    /// More than [`REDIRECTS_MAX`] redirects.
    TooManyRedirects,
    /// Connection, DNS, I/O or URL failure.
    Network(String),
    /// TLS failure.
    Tls(String),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Status(s) => write!(f, "HTTP status {s}"),
            FetchError::TooLarge { limit } => write!(f, "body over the limit of {limit} bytes"),
            FetchError::RefusedAddress(h) => write!(f, "{h} is not a public address"),
            FetchError::TooManyRedirects => write!(f, "more than {REDIRECTS_MAX} redirects"),
            FetchError::Network(e) => write!(f, "network: {e}"),
            FetchError::Tls(e) => write!(f, "TLS: {e}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// A browsing session: the cookies set by responses (`name=value` by host, no attributes but
/// the host) and, by host and port, the address the session first reached.
#[derive(Debug, Default)]
pub struct Session {
    by_host: BTreeMap<String, BTreeMap<String, String>>,
    pinned: BTreeMap<(String, u16), SocketAddr>,
}

impl Session {
    /// Stores the cookie of a `Set-Cookie` value for `host`.
    pub fn set_cookie(&mut self, host: &str, set_cookie: &str) {
        let pair = set_cookie.split(';').next().unwrap_or_default();
        if let Some((name, value)) = pair.split_once('=') {
            let name = name.trim();
            if !name.is_empty() {
                self.by_host
                    .entry(host.to_ascii_lowercase())
                    .or_default()
                    .insert(name.to_owned(), value.trim().to_owned());
            }
        }
    }

    /// The `Cookie` header for `host`, if any.
    pub fn cookie_header(&self, host: &str) -> Option<String> {
        let cookies = self.by_host.get(&host.to_ascii_lowercase())?;
        (!cookies.is_empty()).then(|| {
            cookies
                .iter()
                .map(|(n, v)| format!("{n}={v}"))
                .collect::<Vec<_>>()
                .join("; ")
        })
    }

    /// The address of `host`:`port` the session is pinned to, if any.
    pub fn pinned(&self, host: &str, port: u16) -> Option<SocketAddr> {
        self.pinned.get(&(host.to_ascii_lowercase(), port)).copied()
    }

    /// Pins `host`:`port` to `addr` unless it is pinned already.
    pub fn pin(&mut self, host: &str, port: u16, addr: SocketAddr) {
        self.pinned
            .entry((host.to_ascii_lowercase(), port))
            .or_insert(addr);
    }
}

/// What goes with a request: `Referer` and the session.
#[derive(Clone, Debug, Default)]
pub struct RequestCtx {
    /// The `Referer` header.
    pub referer: Option<String>,
    /// Cookies to send and to store, and the addresses to stick to.
    pub session: Option<Arc<Mutex<Session>>>,
}

/// A HEAD response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    /// Final status.
    pub status: u16,
    /// `Content-Length`.
    pub content_length: Option<u64>,
    /// `ETag`.
    pub etag: Option<String>,
    /// `Last-Modified`.
    pub last_modified: Option<String>,
    /// `Content-Type`.
    pub content_type: Option<String>,
}

/// A GET response read into memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    /// Final status.
    pub status: u16,
    /// `Content-Type`.
    pub content_type: Option<String>,
    /// `Content-Disposition`.
    pub content_disposition: Option<String>,
    /// `ETag`.
    pub etag: Option<String>,
    /// `Last-Modified`.
    pub last_modified: Option<String>,
    /// The body.
    pub body: Vec<u8>,
}

/// A GET response streamed into a file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Downloaded {
    /// The file.
    pub path: PathBuf,
    /// Its size.
    pub size: u64,
    /// SHA-256, lowercase hex.
    pub sha256: String,
    /// SHA-1, lowercase hex.
    pub sha1: String,
    /// `Content-Type`.
    pub content_type: Option<String>,
    /// The file name of `Content-Disposition`, else the last URL segment.
    pub filename: Option<String>,
}

/// Name resolution in place of DNS: the addresses of a host and port.
type Lookup = Arc<dyn Fn(&str, u16) -> Vec<SocketAddr> + Send + Sync>;

/// The HTTP client of the watcher.
#[derive(Clone)]
pub struct Fetcher {
    allow_loopback: bool,
    timeout: Duration,
    connect_timeout: Duration,
    lookup: Option<Lookup>,
}

impl fmt::Debug for Fetcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fetcher")
            .field("allow_loopback", &self.allow_loopback)
            .field("timeout", &self.timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("lookup", &self.lookup.as_ref().map(|_| "custom"))
            .finish()
    }
}

/// The connection's resolver: the addresses already checked, nothing else.
#[derive(Debug)]
struct Checked(Vec<SocketAddr>);

impl Resolver for Checked {
    fn resolve(
        &self,
        _: &Uri,
        _: &Config,
        _: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let mut addrs = self.empty();
        for addr in &self.0 {
            if addrs.try_push(*addr).is_err() {
                break;
            }
        }
        if addrs.is_empty() {
            Err(ureq::Error::HostNotFound)
        } else {
            Ok(addrs)
        }
    }
}

impl Default for Fetcher {
    fn default() -> Self {
        Fetcher::new()
    }
}

/// A response before its body is read.
struct Answer {
    status: u16,
    headers: BTreeMap<String, String>,
    body: ureq::Body,
}

impl Fetcher {
    /// Public addresses only; 30 s to connect, 30 min per request.
    pub fn new() -> Fetcher {
        Fetcher {
            allow_loopback: false,
            timeout: Duration::from_secs(30 * 60),
            connect_timeout: Duration::from_secs(30),
            lookup: None,
        }
    }

    /// Like [`Fetcher::new`], but loopback addresses (a local mock) are allowed and the
    /// timeouts are short.
    pub fn for_tests() -> Fetcher {
        Fetcher {
            allow_loopback: true,
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(5),
            lookup: None,
        }
    }

    /// For tests: host names resolve through `lookup` instead of DNS (no address is an
    /// unknown name). The answers are checked like those of DNS; IP literals bypass it.
    #[must_use]
    pub fn resolving_with(
        mut self,
        lookup: impl Fn(&str, u16) -> Vec<SocketAddr> + Send + Sync + 'static,
    ) -> Fetcher {
        self.lookup = Some(Arc::new(lookup));
        self
    }

    /// HEAD of `url`, redirects followed.
    ///
    /// # Errors
    ///
    /// [`FetchError`]; a non-2xx final status is [`FetchError::Status`].
    pub fn head(&self, url: &str, ctx: &RequestCtx) -> Result<Head, FetchError> {
        let (_, answer) = self.send("HEAD", url, ctx)?;
        Ok(Head {
            status: answer.status,
            content_length: answer
                .headers
                .get("content-length")
                .and_then(|v| v.parse().ok()),
            etag: answer.headers.get("etag").cloned(),
            last_modified: answer.headers.get("last-modified").cloned(),
            content_type: answer.headers.get("content-type").cloned(),
        })
    }

    /// GET of `url` into memory, at most `limit` bytes.
    ///
    /// # Errors
    ///
    /// [`FetchError`].
    pub fn get(&self, url: &str, limit: u64, ctx: &RequestCtx) -> Result<Fetched, FetchError> {
        let (_, answer) = self.send("GET", url, ctx)?;
        check_length(&answer, limit)?;
        let mut body = Vec::new();
        read_limited(answer.body, limit, |chunk| {
            body.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(Fetched {
            status: answer.status,
            content_type: answer.headers.get("content-type").cloned(),
            content_disposition: answer.headers.get("content-disposition").cloned(),
            etag: answer.headers.get("etag").cloned(),
            last_modified: answer.headers.get("last-modified").cloned(),
            body,
        })
    }

    /// GET of `url` streamed into `dest`, at most `limit` bytes; the file is removed on any
    /// error.
    ///
    /// # Errors
    ///
    /// [`FetchError`].
    pub fn download(
        &self,
        url: &str,
        limit: u64,
        ctx: &RequestCtx,
        dest: &Path,
    ) -> Result<Downloaded, FetchError> {
        let (final_url, answer) = self.send("GET", url, ctx)?;
        check_length(&answer, limit)?;
        let result = (|| {
            let mut file = File::create(dest).map_err(io_error)?;
            let mut sha256 = Sha256::new();
            let mut sha1 = Sha1::new();
            let size = read_limited(answer.body, limit, |chunk| {
                sha256.update(chunk);
                sha1.update(chunk);
                file.write_all(chunk).map_err(io_error)
            })?;
            file.flush().map_err(io_error)?;
            Ok(Downloaded {
                path: dest.to_owned(),
                size,
                sha256: hex(&sha256.finalize()),
                sha1: hex(&sha1.finalize()),
                content_type: answer.headers.get("content-type").cloned(),
                filename: answer
                    .headers
                    .get("content-disposition")
                    .and_then(|v| disposition_filename(v))
                    .or_else(|| url_filename(&final_url)),
            })
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(dest);
        }
        result
    }

    /// `method` of `url`, redirects followed by hand (each hop's addresses checked): the
    /// final URL and the 2xx answer.
    fn send(
        &self,
        method: &str,
        url: &str,
        ctx: &RequestCtx,
    ) -> Result<(String, Answer), FetchError> {
        let mut url = url.to_owned();
        for _ in 0..=REDIRECTS_MAX {
            let parts = UrlParts::parse(&url)?;
            let response = self.call(method, &url, &parts, ctx)?;
            let status = response.status().as_u16();
            let mut headers = BTreeMap::new();
            for (name, value) in response.headers() {
                let Ok(value) = value.to_str() else { continue };
                if name.as_str() == "set-cookie" {
                    if let Some(session) = &ctx.session {
                        session
                            .lock()
                            .expect("session")
                            .set_cookie(&parts.host, value);
                    }
                    continue;
                }
                headers.insert(name.as_str().to_owned(), value.to_owned());
            }
            if (300..400).contains(&status)
                && let Some(location) = headers.get("location")
            {
                url = parts.join(location);
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(FetchError::Status(status));
            }
            return Ok((
                url,
                Answer {
                    status,
                    headers,
                    body: response.into_body(),
                },
            ));
        }
        Err(FetchError::TooManyRedirects)
    }

    /// One request of `url` (no redirect followed). Without a session it may go to any
    /// checked address of the host. In a session it goes to the pinned address; before one
    /// is pinned, the checked addresses are tried in turn (the next one only when one cannot
    /// be connected to) and the first that answers is pinned.
    fn call(
        &self,
        method: &str,
        url: &str,
        parts: &UrlParts,
        ctx: &RequestCtx,
    ) -> Result<ureq::http::Response<ureq::Body>, FetchError> {
        let session = ctx.session.as_ref();
        let pinned =
            session.and_then(|s| s.lock().expect("session").pinned(&parts.host, parts.port));
        let tries: Vec<Vec<SocketAddr>> = match pinned {
            Some(addr) => vec![vec![addr]],
            None => {
                let addrs = self.public_addrs(&parts.host, parts.port)?;
                if session.is_some() {
                    addrs.into_iter().map(|a| vec![a]).collect()
                } else {
                    vec![addrs]
                }
            }
        };
        let mut last = FetchError::Network(format!("{} has no address", parts.host));
        for addrs in tries {
            let agent = self.agent(&parts.host, addrs.clone());
            let mut request = match method {
                "HEAD" => agent.head(url),
                _ => agent.get(url),
            };
            if let Some(referer) = &ctx.referer {
                request = request.header("Referer", referer);
            }
            if let Some(session) = session
                && let Some(cookie) = session.lock().expect("session").cookie_header(&parts.host)
            {
                request = request.header("Cookie", cookie);
            }
            match request.call() {
                Ok(response) => {
                    if let Some(session) = session
                        && let [addr] = addrs[..]
                    {
                        session
                            .lock()
                            .expect("session")
                            .pin(&parts.host, parts.port, addr);
                    }
                    return Ok(response);
                }
                Err(e) if is_connect_error(&e) => last = ureq_error(e),
                Err(e) => return Err(ureq_error(e)),
            }
        }
        Err(last)
    }

    /// The addresses of `host`:`port`, every one public (loopback allowed with
    /// `allow_loopback`).
    ///
    /// # Errors
    ///
    /// [`FetchError::RefusedAddress`] if any is not, [`FetchError::Network`] if it does not
    /// resolve.
    fn public_addrs(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, FetchError> {
        let addrs: Vec<SocketAddr> = match (host.parse::<IpAddr>(), &self.lookup) {
            (Ok(ip), _) => vec![SocketAddr::new(ip, port)],
            (Err(_), Some(lookup)) => lookup(host, port),
            (Err(_), None) => (host, port)
                .to_socket_addrs()
                .map_err(|e| FetchError::Network(format!("resolve {host}: {}", e.kind())))?
                .collect(),
        };
        if addrs.is_empty() {
            return Err(FetchError::Network(format!("{host} has no address")));
        }
        if addrs
            .iter()
            .any(|a| !(is_public(a.ip()) || self.allow_loopback && a.ip().is_loopback()))
        {
            return Err(FetchError::RefusedAddress(host.to_owned()));
        }
        Ok(addrs)
    }

    /// An agent for `host` that connects to `addrs` only.
    fn agent(&self, host: &str, addrs: Vec<SocketAddr>) -> Agent {
        let mut config = Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .timeout_global(Some(self.timeout))
            .timeout_connect(Some(self.connect_timeout))
            .proxy(None)
            .user_agent("OpenNCALayer-upstream-watch");
        if roots_for(host) == RootsChoice::NcaTls {
            let roots = oncl_pki::roots::nca_tls_roots()
                .unwrap_or_default()
                .into_iter()
                .map(|(_, der)| TlsCertificate::from_der(der))
                .collect();
            config = config.tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::Specific(Arc::new(roots)))
                    .build(),
            );
        }
        Agent::with_parts(config.build(), DefaultConnector::new(), Checked(addrs))
    }
}

fn check_length(answer: &Answer, limit: u64) -> Result<(), FetchError> {
    match answer
        .headers
        .get("content-length")
        .and_then(|v| v.parse::<u64>().ok())
    {
        Some(n) if n > limit => Err(FetchError::TooLarge { limit }),
        _ => Ok(()),
    }
}

/// Reads `body` in chunks to `sink`; more than `limit` bytes is [`FetchError::TooLarge`].
fn read_limited(
    body: ureq::Body,
    limit: u64,
    mut sink: impl FnMut(&[u8]) -> Result<(), FetchError>,
) -> Result<u64, FetchError> {
    let mut reader = body.into_with_config().limit(u64::MAX).reader();
    let mut buf = vec![0; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).map_err(io_error)?;
        if n == 0 {
            return Ok(total);
        }
        total += n as u64;
        if total > limit {
            return Err(FetchError::TooLarge { limit });
        }
        sink(&buf[..n])?;
    }
}

/// Whether `e` is of connecting to the address (refused, unreachable, connect timeout), so
/// that another address may still answer.
fn is_connect_error(e: &ureq::Error) -> bool {
    use std::io::ErrorKind;
    match e {
        ureq::Error::Timeout(ureq::Timeout::Connect) | ureq::Error::ConnectionFailed => true,
        ureq::Error::Io(e) => matches!(
            e.kind(),
            ErrorKind::ConnectionRefused
                | ErrorKind::HostUnreachable
                | ErrorKind::NetworkUnreachable
                | ErrorKind::AddrNotAvailable
                | ErrorKind::TimedOut
        ),
        _ => false,
    }
}

/// A note when a proxy variable (`HTTPS_PROXY`, `ALL_PROXY`, …) is set: the watcher
/// connects directly, as only a direct connection goes to the addresses it checked.
pub fn proxy_ignored() -> Option<&'static str> {
    ureq::Proxy::try_from_env().map(|_| {
        "note: proxy variables are ignored: the watcher connects directly to the addresses it checked"
    })
}

fn io_error(e: std::io::Error) -> FetchError {
    FetchError::Network(e.kind().to_string())
}

fn ureq_error(e: ureq::Error) -> FetchError {
    match e {
        ureq::Error::StatusCode(s) => FetchError::Status(s),
        ureq::Error::BodyExceedsLimit(limit) => FetchError::TooLarge { limit },
        ureq::Error::Tls(m) => FetchError::Tls(m.to_owned()),
        ureq::Error::Rustls(e) => FetchError::Tls(e.to_string()),
        ureq::Error::Io(e) => io_error(e),
        other => FetchError::Network(other.to_string()),
    }
}

/// The `filename` of a `Content-Disposition` value, as a bare name.
pub fn disposition_filename(value: &str) -> Option<String> {
    let at = value.to_ascii_lowercase().find("filename=")?;
    let raw = value[at + "filename=".len()..].split(';').next()?.trim();
    bare_name(raw.trim_matches('"'))
}

/// The last path segment of `url`, without the query.
pub fn url_filename(url: &str) -> Option<String> {
    let path = url.split(['?', '#']).next()?;
    let after_host = path.split_once("://").map_or(path, |(_, rest)| rest);
    let (_, path) = after_host.split_once('/')?;
    bare_name(path.rsplit('/').next()?)
}

fn bare_name(name: &str) -> Option<String> {
    let name = name.rsplit(['/', '\\']).next()?.trim();
    (!name.is_empty() && name != "." && name != ".." && name.len() <= 255).then(|| name.to_owned())
}

/// The scheme, host and port of an `http`/`https` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlParts {
    /// `http` or `https`.
    pub scheme: String,
    /// The host, without IPv6 brackets.
    pub host: String,
    /// The port (the scheme's default when absent).
    pub port: u16,
    /// The path and query, starting with `/`.
    pub path: String,
}

impl UrlParts {
    /// Parses `url`.
    ///
    /// # Errors
    ///
    /// [`FetchError::Network`] for other schemes or a malformed authority.
    pub fn parse(url: &str) -> Result<UrlParts, FetchError> {
        let bad = || FetchError::Network("invalid URL".to_owned());
        let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
        let scheme = scheme.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "http" => 80,
            "https" => 443,
            _ => return Err(FetchError::Network(format!("scheme {scheme} is not HTTP"))),
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        if authority.contains('@') {
            return Err(bad());
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (host, after) = v6.split_once(']').ok_or_else(bad)?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| bad())?,
                None if after.is_empty() => default_port,
                None => return Err(bad()),
            };
            (host.to_owned(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_owned(), p.parse().map_err(|_| bad())?),
                None => (authority.to_owned(), default_port),
            }
        };
        if host.is_empty() {
            return Err(bad());
        }
        let path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        Ok(UrlParts {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
            path,
        })
    }

    /// `scheme://host[:port]`.
    pub fn origin(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.scheme == "https" { 443 } else { 80 };
        if self.port == default {
            format!("{}://{host}", self.scheme)
        } else {
            format!("{}://{host}:{}", self.scheme, self.port)
        }
    }

    /// `reference` resolved against this URL.
    pub fn join(&self, reference: &str) -> String {
        if reference.contains("://") {
            reference.to_owned()
        } else if let Some(rest) = reference.strip_prefix("//") {
            format!("{}://{rest}", self.scheme)
        } else if reference.starts_with('/') {
            format!("{}{reference}", self.origin())
        } else {
            let path = self.path.split(['?', '#']).next().unwrap_or("/");
            let dir = &path[..=path.rfind('/').unwrap_or(0)];
            format!("{}{dir}{reference}", self.origin())
        }
    }
}

/// Whether `ip` is a public unicast address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..128).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let s = ip.segments();
    // NAT64 64:ff9b::/96 embeds an IPv4 address.
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [a, b] = s[6].to_be_bytes();
        let [c, d] = s[7].to_be_bytes();
        return is_public_v4(Ipv4Addr::new(a, b, c, d));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || s[..6] == [0, 0, 0, 0, 0, 0])
}
