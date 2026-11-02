//! Host-authorized, operation-scoped PKI HTTP. No DNS or cancellation threads.
use super::{
    HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport, MAX_REDIRECTS, MAX_RESPONSE_LEN,
    Uri,
};
use crate::resource::{Deadline, OperationControl, ProcessingError, Progress, ResourceScope};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Default)]
pub struct NetworkPolicy {
    endpoints: Vec<Endpoint>,
}
#[derive(Clone, Debug)]
struct Endpoint {
    origin: String,
    port: u16,
    pins: Vec<SocketAddr>,
}
fn endpoint(url: &str) -> Result<Endpoint, HttpError> {
    let uri: Uri = url
        .parse()
        .map_err(|_| HttpError::other("invalid PKI endpoint"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| HttpError::other("missing PKI scheme"))?
        .to_ascii_lowercase();
    let default = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return Err(HttpError::other("unsupported PKI scheme")),
    };
    let authority = uri
        .authority()
        .ok_or_else(|| HttpError::other("missing PKI authority"))?;
    if authority.as_str().contains('@') || uri.host().is_none() {
        return Err(HttpError::other("invalid PKI authority"));
    }
    let host = uri.host().unwrap().to_ascii_lowercase();
    let plain = host.trim_start_matches('[').trim_end_matches(']');
    let host_end = if authority.as_str().starts_with('[') {
        authority
            .as_str()
            .find(']')
            .ok_or_else(|| HttpError::other("invalid PKI IPv6 address"))?
            + 1
    } else {
        host.len()
    };
    let suffix = &authority.as_str()[host_end..];
    let port = if suffix.is_empty() {
        default
    } else {
        suffix
            .strip_prefix(':')
            .filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|p| p.parse::<u16>().ok())
            .ok_or_else(|| HttpError::other("invalid PKI port"))?
    };
    if port == 0 {
        return Err(HttpError::other("invalid PKI port"));
    }
    let ip = plain.parse::<IpAddr>().ok();
    // Reject alternate numeric IPv4 spellings rather than let a resolver reinterpret them.
    if ip.is_none()
        && (plain.chars().all(|c| c.is_ascii_digit() || c == '.') || plain.starts_with("0x"))
    {
        return Err(HttpError::other("noncanonical PKI address"));
    }
    let canonical = match ip {
        Some(IpAddr::V6(ip)) => format!("[{ip}]"),
        Some(ip) => ip.to_string(),
        None => host,
    };
    Ok(Endpoint {
        origin: format!("{scheme}://{canonical}:{port}"),
        port,
        pins: ip
            .map(|ip| vec![SocketAddr::new(ip, port)])
            .unwrap_or_default(),
    })
}
impl NetworkPolicy {
    pub fn deny_all() -> Self {
        Self::default()
    }
    /// Exact operator-approved origins. Literal IP origins pin themselves. DNS
    /// names require with_resolved_endpoint for actual Ureq; custom transports
    /// are trusted host code and are responsible for their own connection routing.
    pub fn only_endpoints<I, S>(origins: I) -> Result<Self, HttpError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut policy = Self::default();
        for origin in origins {
            policy.endpoints.push(endpoint(origin.as_ref())?);
        }
        Ok(policy)
    }
    /// Supply operator-approved destination addresses, without performing DNS.
    /// URI/TLS hostname is preserved. Every pin must use the origin's port.
    pub fn with_resolved_endpoint(
        mut self,
        origin: &str,
        pins: Vec<SocketAddr>,
    ) -> Result<Self, HttpError> {
        let mut entry = endpoint(origin)?;
        if pins.is_empty()
            || pins.len() > 16
            || pins
                .iter()
                .any(|a| a.port() != entry.port || a.ip().is_unspecified() || a.ip().is_multicast())
        {
            return Err(HttpError::other("invalid PKI address pins"));
        }
        if !entry.pins.is_empty() && pins != entry.pins {
            return Err(HttpError::other(
                "literal PKI endpoint cannot change address",
            ));
        }
        entry.pins = pins;
        self.endpoints.retain(|e| e.origin != entry.origin);
        self.endpoints.push(entry);
        Ok(self)
    }
    fn pins(&self, url: &str) -> Result<&[SocketAddr], HttpError> {
        let origin = endpoint(url)?.origin;
        self.endpoints
            .iter()
            .find(|e| e.origin == origin)
            .map(|e| e.pins.as_slice())
            .ok_or_else(|| HttpError::other("PKI endpoint is not authorized"))
    }
}

/// Delegates must honor synchronous request limits; this cannot preempt arbitrary
/// host code. Ureq's scoped path uses only pinned addresses, not its DNS resolver.
pub struct DeadlineTransport<'a> {
    inner: &'a dyn HttpTransport,
    policy: &'a NetworkPolicy,
    deadline: Deadline,
    control: Arc<dyn OperationControl>,
    fatal: Mutex<Option<ProcessingError>>,
    scope: ResourceScope,
}
impl<'a> DeadlineTransport<'a> {
    pub fn new(
        inner: &'a dyn HttpTransport,
        policy: &'a NetworkPolicy,
        scope: &ResourceScope,
    ) -> Self {
        Self {
            inner,
            policy,
            deadline: scope.deadline(),
            control: scope.operation_control(),
            fatal: Mutex::new(None),
            scope: scope.retain(),
        }
    }
    fn checkpoint(&self) -> Result<(), HttpError> {
        if self
            .fatal
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_some()
        {
            return Err(HttpError::other("PKI operation already failed"));
        }
        let check = self
            .deadline
            .checkpoint()
            .and_then(|()| self.control.checkpoint(Progress::default()));
        if let Err(error) = check {
            let mut fatal = self.fatal.lock().unwrap_or_else(|e| e.into_inner());
            if fatal.is_none() {
                *fatal = Some(error);
            }
            return Err(HttpError::other("PKI operation interrupted"));
        }
        Ok(())
    }
    /// Restore the exact typed fatal cause after a PKI parser/report call, which
    /// may otherwise classify a failed HTTP call as unavailable evidence.
    pub fn finish(&self) -> Result<(), ProcessingError> {
        if let Some(error) = self.fatal.lock().unwrap_or_else(|e| e.into_inner()).take() {
            return Err(error);
        }
        self.deadline.checkpoint()?;
        self.control.checkpoint(Progress::default())
    }
}
impl DeadlineTransport<'_> {
    fn send_impl<'a>(
        &'a self,
        request: &HttpRequest<'_>,
        budget: Option<super::ResponseBudget<'a>>,
        outer_pins: Option<&[SocketAddr]>,
    ) -> Result<super::ScopedHttpReply<'a>, HttpError> {
        let mut url = request.url.to_owned();
        let mut current = *request;
        let request_deadline = std::time::Instant::now()
            .checked_add(request.opts.timeout)
            .ok_or_else(|| HttpError::other("invalid PKI request timeout"))?;
        for _ in 0..=MAX_REDIRECTS {
            if let Some(budget) = &budget {
                budget.checkpoint()?;
            }
            self.checkpoint()?;
            let pins = self.policy.pins(&url)?;
            let mut intersection = [SocketAddr::from(([0, 0, 0, 0], 0)); 16];
            let mut count = 0;
            let pins = match outer_pins {
                // Empty means no address map at this policy layer, as for a
                // trusted custom host transport. It is not a deny-all map.
                // Preserve any actual map supplied by the other layer; do not
                // invent addresses or perform DNS. Built-in Ureq still refuses
                // the resulting empty map before connecting.
                Some([]) => pins,
                Some(outer) if pins.is_empty() => outer,
                Some(outer) => {
                    for pin in pins.iter().filter(|pin| outer.contains(pin)) {
                        intersection[count] = *pin;
                        count += 1;
                    }
                    if count == 0 {
                        return Err(HttpError::other(
                            "PKI layered address pins do not intersect",
                        ));
                    }
                    &intersection[..count]
                }
                None => pins,
            };
            let left = self.deadline.remaining();
            let mut opts = current.opts;
            opts.timeout = opts
                .timeout
                .min(left)
                .min(request_deadline.saturating_duration_since(std::time::Instant::now()));
            if opts.timeout.is_zero() {
                return Err(HttpError::new(
                    super::HttpErrorKind::Timeout,
                    "PKI request timed out",
                ));
            }
            opts.connect_timeout = opts.connect_timeout.min(opts.timeout);
            opts.max_len = opts.max_len.min(MAX_RESPONSE_LEN);
            opts.redirects = false;
            if opts.https_only && !super::is_https(&url) {
                return Err(HttpError::other("PKI requires HTTPS"));
            }
            let actual = HttpRequest {
                url: &url,
                opts,
                ..current
            };
            let result = if let Some(budget) = &budget {
                self.inner
                    .send_pinned_scoped(&actual, pins, budget.reborrow())
            } else {
                self.inner
                    .send_pinned(&actual, pins)
                    .map(super::ScopedHttpReply::unscoped)
            };
            if let Some(budget) = &budget {
                budget.checkpoint()?;
            }
            self.checkpoint()?;
            let reply = result?;
            if reply.body().len() as u64 > opts.max_len {
                return Err(HttpError::other("oversized PKI response"));
            }
            let next = if request.opts.redirects {
                super::redirect(
                    &url,
                    &reply.reply,
                    reply.reply.location.as_deref(),
                    current.method == HttpMethod::Post,
                )?
            } else {
                None
            };
            match next {
                None => return Ok(reply),
                Some(next) => {
                    self.policy.pins(&next)?;
                    url = next;
                    current = HttpRequest::get("", request.opts);
                }
            }
        }
        Err(HttpError::other("too many PKI redirects"))
    }
}

impl HttpTransport for DeadlineTransport<'_> {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.send_impl(request, None, None)
            .and_then(super::ScopedHttpReply::into_unscoped)
    }
    fn send_scoped<'a>(
        &'a self,
        request: &HttpRequest<'_>,
    ) -> Result<super::ScopedHttpReply<'a>, HttpError> {
        self.send_impl(
            request,
            Some(super::ResponseBudget::new(&self.scope, self)),
            None,
        )
    }
    fn send_scoped_with<'a>(
        &'a self,
        request: &HttpRequest<'_>,
        budget: super::ResponseBudget<'a>,
    ) -> Result<super::ScopedHttpReply<'a>, HttpError> {
        self.send_impl(request, Some(budget.with_scope(&self.scope, self)?), None)
    }
    fn send_pinned_scoped<'a>(
        &'a self,
        request: &HttpRequest<'_>,
        pins: &[SocketAddr],
        budget: super::ResponseBudget<'a>,
    ) -> Result<super::ScopedHttpReply<'a>, HttpError> {
        self.send_impl(
            request,
            Some(budget.with_scope(&self.scope, self)?),
            Some(pins),
        )
    }
    fn resource_scope(&self) -> Option<&ResourceScope> {
        Some(&self.scope)
    }
    fn resource_failure(&self, error: ProcessingError) -> HttpError {
        let mut fatal = self.fatal.lock().unwrap_or_else(|error| error.into_inner());
        if fatal.is_none() {
            *fatal = Some(error);
        }
        HttpError::other("PKI resource admission failed")
    }
}
