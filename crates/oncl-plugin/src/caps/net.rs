//! `http`: HTTPS requests to URLs under the manifest's prefixes, redirects not followed.

use super::{failed, invalid, limit};
use crate::host::HostState;
use crate::manifest::HttpPrefix;
use oncl_pdk::abi::{Bytes, ErrorCode, HostError, HostResult, HttpArgs, HttpResponse, Method};
use oncl_pki::http::{CONNECT_TIMEOUT, GetOptions, HttpTransport};
use std::time::Duration;

/// The largest body of an HTTP request or reply.
pub const MAX_HTTP_BODY: u64 = 32 << 20;

/// The timeout of an HTTP request, connecting to reading the reply.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

/// The most HTTP requests of one `oncl_process` call: more are a `limit` error.
pub const MAX_HTTP_REQUESTS: u32 = 64;

/// `http_request`: one HTTPS request to a URL under a prefix of the manifest, sent as
/// checked, without following redirects; at most [`MAX_HTTP_REQUESTS`] in one call.
pub(crate) fn http_request(state: &mut HostState, args: HttpArgs) -> HostResult<HttpResponse> {
    let url = allowed_url(&state.capabilities.http, &args.url)?;
    if args.body.len() as u64 > MAX_HTTP_BODY {
        return Err(limit(format!("the body is over {MAX_HTTP_BODY} bytes")));
    }
    if state.call.http_requests >= MAX_HTTP_REQUESTS {
        return Err(limit(format!(
            "at most {MAX_HTTP_REQUESTS} HTTP requests in one call"
        )));
    }
    state.call.http_requests += 1;
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
