//! `http`: requests to URLs under the manifest's prefixes (`http_request`,
//! `http_request_ex`), and with `http_request_ex` to the page's own origin when the
//! manifest's `origins` list it, or under an exact `http_insecure` prefix; redirects not
//! followed.

use super::{denied, failed, invalid, limit};
use crate::host::HostState;
use crate::manifest::{Capabilities, HttpPrefix, parse_web_url};
use oncl_pdk::abi::{
    ALLOWED_HEADERS, Bytes, ErrorCode, HostError, HostResult, HttpArgs, HttpExArgs, HttpResponse,
    MAX_HEADER_BYTES, MAX_HEADERS, Method,
};
use oncl_pki::http::{CONNECT_TIMEOUT, GetOptions, HttpMethod, HttpRequest, HttpTransport};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use url::Url;

/// The largest body of an HTTP request or reply.
pub const MAX_HTTP_BODY: u64 = 32 << 20;

/// The most HTTP requests of one `oncl_process` call, the plugin's own and those the core
/// sends to the PKI hosts for it together: more are a `limit` error (a failed PKI request).
pub const MAX_HTTP_REQUESTS: u32 = 64;

/// The HTTP requests of one call, counted against [`MAX_HTTP_REQUESTS`]; clones share the
/// count.
#[derive(Clone, Default)]
pub(crate) struct RequestBudget(Arc<AtomicU32>);

impl RequestBudget {
    /// Counts one more request, or refuses it past [`MAX_HTTP_REQUESTS`].
    pub(crate) fn take(&self) -> HostResult<()> {
        self.0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |sent| {
                (sent < MAX_HTTP_REQUESTS).then_some(sent + 1)
            })
            .map(drop)
            .map_err(|_| {
                limit(format!(
                    "at most {MAX_HTTP_REQUESTS} HTTP requests in one call"
                ))
            })
    }
}

/// The timeout of an HTTP request, connecting to reading the reply.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

/// `http_request`: one HTTPS request to a URL under a prefix of the manifest, sent as
/// checked, without following redirects; at most [`MAX_HTTP_REQUESTS`] in one call.
pub(crate) fn http_request(state: &mut HostState, args: HttpArgs) -> HostResult<HttpResponse> {
    let url = allowed_url(&state.capabilities.http, &args.url)?;
    if args.body.len() as u64 > MAX_HTTP_BODY {
        return Err(limit(format!("the body is over {MAX_HTTP_BODY} bytes")));
    }
    state.call.http_requests.take()?;
    let opts = GetOptions {
        timeout: HTTP_TIMEOUT,
        connect_timeout: CONNECT_TIMEOUT,
        max_len: MAX_HTTP_BODY,
        https_only: true,
        redirects: false,
    };
    let http: &dyn HttpTransport = state.services.http.as_ref();
    let reply = match args.method {
        Method::Get if !args.body.is_empty() || args.content_type.is_some() => {
            return Err(invalid("a GET has no body"));
        }
        Method::Get => http.get_with(url.as_str(), opts),
        Method::Post => http.post_with(
            url.as_str(),
            args.content_type
                .as_deref()
                .unwrap_or("application/octet-stream"),
            &args.body,
            opts,
        ),
    }
    .map_err(failed)?;
    Ok(HttpResponse {
        status: reply.status,
        content_type: reply.content_type,
        location: reply.location,
        body: Bytes::from(reply.body),
    })
}

/// `url` as checked under the first of `prefixes` that allows it, without its fragment
/// (which stays with the client, as in browsers).
fn allowed_url(prefixes: &[HttpPrefix], url: &str) -> HostResult<url::Url> {
    let mut checked = prefixes
        .iter()
        .find_map(|prefix| prefix.check(url))
        .ok_or_else(|| {
            HostError::new(
                ErrorCode::Denied,
                format!("{url} is not under the plugin's HTTP prefixes"),
            )
        })?;
    checked.set_fragment(None);
    Ok(checked)
}

/// `http_request_ex`: one request to a URL the manifest allows (see [`allowed_ex_url`]),
/// with the allowed headers, sent as checked, without following redirects; it counts
/// towards [`MAX_HTTP_REQUESTS`] with `http_request`.
pub(crate) fn http_request_ex(state: &mut HostState, args: HttpExArgs) -> HostResult<HttpResponse> {
    let headers = checked_headers(&args)?;
    if let Some(content_type) = &args.content_type
        && has_line_break(content_type)
    {
        return Err(invalid("the content type has CR, LF or NUL"));
    }
    if args.method == Method::Get && (!args.body.is_empty() || args.content_type.is_some()) {
        return Err(invalid("a GET has no body"));
    }
    let timeout = match args.timeout_ms {
        None => HTTP_TIMEOUT,
        Some(ms) => {
            let timeout = Duration::from_millis(u64::from(ms));
            if timeout.is_zero() || timeout > HTTP_TIMEOUT {
                return Err(invalid(format!(
                    "the timeout is not within 1 to {} ms",
                    HTTP_TIMEOUT.as_millis()
                )));
            }
            timeout
        }
    };
    if args.body.len() as u64 > MAX_HTTP_BODY {
        return Err(limit(format!("the body is over {MAX_HTTP_BODY} bytes")));
    }
    let url = allowed_ex_url(
        &state.capabilities,
        state.call.origin.as_deref(),
        &args.url,
        args.relative_to_origin,
    )?;
    state.call.http_requests.take()?;
    let request = HttpRequest {
        method: match args.method {
            Method::Get => HttpMethod::Get,
            Method::Post => HttpMethod::Post,
        },
        url: url.as_str(),
        headers: &headers,
        content_type: args.content_type.as_deref(),
        body: &args.body,
        opts: GetOptions {
            timeout,
            connect_timeout: CONNECT_TIMEOUT.min(timeout),
            max_len: MAX_HTTP_BODY,
            https_only: url.scheme() == "https",
            redirects: false,
        },
    };
    let reply = state.services.http.send(&request).map_err(failed)?;
    Ok(HttpResponse {
        status: reply.status,
        content_type: reply.content_type,
        location: reply.location,
        body: Bytes::from(reply.body),
    })
}

/// Whether `text` has CR, LF or NUL, which would end a header line.
fn has_line_break(text: &str) -> bool {
    text.contains(['\r', '\n', '\0'])
}

/// The headers of `args` as the transport takes them: at most [`MAX_HEADERS`] of
/// [`ALLOWED_HEADERS`] (any case), without CR, LF or NUL, [`MAX_HEADER_BYTES`] together.
fn checked_headers(args: &HttpExArgs) -> HostResult<Vec<(&str, &str)>> {
    if args.headers.len() > MAX_HEADERS {
        return Err(limit(format!("more than {MAX_HEADERS} headers")));
    }
    let mut total = 0;
    let mut headers = Vec::with_capacity(args.headers.len());
    for header in &args.headers {
        if has_line_break(&header.name) || has_line_break(&header.value) {
            return Err(invalid(format!(
                "the header {:?} has CR, LF or NUL",
                header.name
            )));
        }
        if !ALLOWED_HEADERS
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&header.name))
        {
            return Err(denied(format!(
                "the header {:?} is not one a plugin may send",
                header.name
            )));
        }
        total += header.name.len() + header.value.len();
        if total > MAX_HEADER_BYTES {
            return Err(limit(format!(
                "the headers are over {MAX_HEADER_BYTES} bytes"
            )));
        }
        headers.push((header.name.as_str(), header.value.as_str()));
    }
    Ok(headers)
}

/// The URL `http_request_ex` sends to, without its fragment, if one holds:
///
/// - (a) it is under a prefix of `http` (`https`, wildcard hosts on a label boundary);
/// - (b) it is relative and resolved against the call's origin, or absolute with the
///   call's origin (scheme, host, port), and that origin matches a pattern of `origins`;
/// - (c) it is under a prefix of `http_insecure` (`http`, exact host and port).
///
/// Anything else, other schemes and calls without a URL origin included, is denied.
fn allowed_ex_url(
    caps: &Capabilities,
    origin: Option<&str>,
    url: &str,
    relative: bool,
) -> HostResult<Url> {
    let refused = || denied(format!("{url} is not a URL the plugin may reach"));
    let mut checked = if relative {
        let origin = listed_origin(caps, origin).ok_or_else(refused)?;
        if url
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b == b'\\')
        {
            return Err(refused());
        }
        let resolved = origin.join(url).map_err(|_| refused())?;
        if !same_origin(&resolved, &origin)
            || !resolved.username().is_empty()
            || resolved.password().is_some()
        {
            return Err(refused());
        }
        resolved
    } else if let Some(url) = caps
        .http
        .iter()
        .chain(&caps.http_insecure)
        .find_map(|prefix| prefix.check(url))
    {
        url
    } else {
        let origin = listed_origin(caps, origin).ok_or_else(refused)?;
        let url = parse_web_url(url).ok_or_else(refused)?;
        if !same_origin(&url, &origin) {
            return Err(refused());
        }
        url
    };
    checked.set_fragment(None);
    Ok(checked)
}

/// The call's origin as a URL, if it is an `https://` or `http://` origin matching a
/// pattern of `origins`.
fn listed_origin(caps: &Capabilities, origin: Option<&str>) -> Option<Url> {
    let origin = parse_web_url(origin?)?;
    let bare = origin.path() == "/" && origin.query().is_none() && origin.fragment().is_none();
    (bare && caps.origins.iter().any(|p| p.matches(&origin))).then_some(origin)
}

/// Whether `a` and `b` have the same scheme, host and port.
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host() == b.host()
        && a.port_or_known_default() == b.port_or_known_default()
}
