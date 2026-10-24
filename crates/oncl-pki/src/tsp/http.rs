//! HTTP transport of time-stamp requests.

use super::TspError;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::fmt::Write;
use std::time::Duration;

/// Media type of a POSTed `TimeStampReq` (RFC 3161 §3.4).
pub(crate) const TIMESTAMP_QUERY: &str = "application/timestamp-query";
/// Media type of a `TimeStampResp` (RFC 3161 §3.4).
pub(crate) const TIMESTAMP_REPLY: &str = "application/timestamp-reply";

/// Largest response body [`UreqTransport`] reads: 1 MiB. A time-stamp reply is a few
/// kilobytes (a token with the TSA certificate); the NCA TSA is reached over plain HTTP, so
/// anything on the path can answer, and a bigger body is refused instead of buffered.
pub const MAX_RESPONSE_LEN: u64 = 1 << 20;

/// Timeout of a whole request, connecting to reading the body.
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

/// Sends time-stamp requests. Any status code is a reply, not an error.
pub trait HttpTransport: Send + Sync {
    /// `GET url`.
    ///
    /// # Errors
    ///
    /// [`TspError::Http`] if no response arrived.
    fn get(&self, url: &str) -> Result<HttpReply, TspError>;

    /// `POST url` with `body` of type `content_type`.
    ///
    /// # Errors
    ///
    /// [`TspError::Http`] if no response arrived.
    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<HttpReply, TspError>;
}

/// [`HttpTransport`] over `ureq`: plain HTTP (the NCA TSA has no TLS) or HTTPS on rustls,
/// a 10-second timeout per request and bodies up to [`MAX_RESPONSE_LEN`].
#[derive(Clone, Copy, Debug, Default)]
pub struct UreqTransport;

impl UreqTransport {
    fn agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into()
    }
}

impl HttpTransport for UreqTransport {
    fn get(&self, url: &str) -> Result<HttpReply, TspError> {
        reply(Self::agent().get(url).call())
    }

    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<HttpReply, TspError> {
        reply(
            Self::agent()
                .post(url)
                .header("Content-Type", content_type)
                .send(body),
        )
    }
}

fn reply(
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<HttpReply, TspError> {
    let http_error = |e: ureq::Error| TspError::Http(e.to_string());
    let mut response = response.map_err(http_error)?;
    let content_type = response
        .headers()
        .get(ureq::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_LEN)
        .read_to_vec()
        .map_err(http_error)?;
    Ok(HttpReply {
        status: response.status().as_u16(),
        content_type,
        body,
    })
}

/// URL of the GET binding of the NCA TSA: `base/` and the base64 of the DER request with
/// every character but the unreserved ones (RFC 3986) percent-encoded.
pub(crate) fn get_url(base: &str, request: &[u8]) -> String {
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

/// Whether a `Content-Type` is `application/timestamp-reply`, ignoring case and parameters.
pub(crate) fn is_timestamp_reply(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|v| v.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case(TIMESTAMP_REPLY))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_url_encodes_all_but_unreserved() {
        // base64 "+/8=" for [0xfb, 0xff].
        assert_eq!(
            get_url("http://h/tsp", &[0xfb, 0xff]),
            "http://h/tsp/%2B%2F8%3D"
        );
        assert_eq!(get_url("http://h/", &[0xfb, 0xff]), "http://h/%2B%2F8%3D");
    }

    #[test]
    fn timestamp_reply_media_type() {
        assert!(is_timestamp_reply(Some("application/timestamp-reply")));
        assert!(is_timestamp_reply(Some(
            " APPLICATION/TimeStamp-Reply ; q=1"
        )));
        assert!(!is_timestamp_reply(Some("application/timestamp-query")));
        assert!(!is_timestamp_reply(Some("")));
        assert!(!is_timestamp_reply(None));
    }
}
