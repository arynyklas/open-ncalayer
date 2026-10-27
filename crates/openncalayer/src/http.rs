//! Plain HTTPS requests (everything that is not a WebSocket upgrade): the self-test page
//! and its report of the browser that opened it, and the demo page with its vendored
//! ncalayer-js-client and that client's MIT notice.

use std::borrow::Cow;

use oncl_tls::SelftestReports;
use time::OffsetDateTime;

/// The self-test page the TLS wizard opens (`/` serves it too).
pub(crate) const SELFTEST: &str = "/openncalayer/selftest";
/// Where the self-test page posts `navigator.userAgent`.
pub(crate) const SELFTEST_REPORT: &str = "/openncalayer/selftest/report";
/// Largest report body accepted.
pub(crate) const MAX_REPORT_BODY: usize = 1024;

const SELFTEST_PAGE: &str = include_str!("../../../web/selftest/index.html");
const DEMO: &[u8] = include_bytes!("../../../web/demo/index.html");
/// ncalayer-js-client 1.6.1 as published on npm (MIT, see [`NCALAYER_CLIENT_LICENSE`]).
const NCALAYER_CLIENT: &[u8] = include_bytes!("../../../web/demo/vendor/ncalayer-client.js");
/// The MIT notice of ncalayer-js-client, served next to it: the published file has none.
const NCALAYER_CLIENT_LICENSE: &str = include_str!("../../../web/demo/vendor/LICENSE");

/// A complete HTTP/1.1 response; the connection is closed after it.
pub(crate) struct Response {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    /// The `Allow` header (405).
    allow: Option<&'static str>,
    body: Cow<'static, [u8]>,
}

impl Response {
    fn text(status: u16, reason: &'static str, body: &'static str) -> Self {
        Response {
            status,
            reason,
            content_type: "text/plain; charset=utf-8",
            allow: None,
            body: Cow::Borrowed(body.as_bytes()),
        }
    }

    /// 405 with `Allow: allow`.
    fn method_not_allowed(allow: &'static str, body: &'static str) -> Self {
        Response {
            allow: Some(allow),
            ..Self::text(405, "Method Not Allowed", body)
        }
    }

    /// 200 with a static body.
    fn ok(content_type: &'static str, body: &'static [u8]) -> Self {
        Response {
            status: 200,
            reason: "OK",
            content_type,
            allow: None,
            body: Cow::Borrowed(body),
        }
    }

    /// 411: a report without `Content-Length`.
    pub(crate) fn length_required() -> Self {
        Self::text(411, "Length Required", "Length Required")
    }

    /// 413: a report longer than [`MAX_REPORT_BODY`].
    pub(crate) fn payload_too_large() -> Self {
        Self::text(413, "Content Too Large", "Content Too Large")
    }

    /// 400: the request head cannot be parsed.
    pub(crate) fn bad_request() -> Self {
        Self::text(400, "Bad Request", "Bad Request")
    }

    /// 431: the request head is longer than the server reads.
    pub(crate) fn header_too_large() -> Self {
        Self::text(
            431,
            "Request Header Fields Too Large",
            "Request Header Fields Too Large",
        )
    }

    /// Status code.
    pub(crate) fn status(&self) -> u16 {
        self.status
    }

    /// The response as sent on the wire.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\
             Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body.len()
        );
        if let Some(allow) = self.allow {
            head.push_str(&format!("Allow: {allow}\r\n"));
        }
        head.push_str("\r\n");
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

/// The response to a request that is neither a WebSocket upgrade nor a self-test report
/// (`POST` [`SELFTEST_REPORT`], see [`selftest_report`]).
pub(crate) fn respond(method: &str, target: &str) -> Response {
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    if path == SELFTEST_REPORT {
        return Response::method_not_allowed("POST", "Only POST is accepted here");
    }
    if method != "GET" {
        return Response::method_not_allowed(
            "GET",
            "Only GET and WebSocket connections are accepted",
        );
    }
    match path {
        "/" | SELFTEST => Response {
            status: 200,
            reason: "OK",
            content_type: "text/html; charset=utf-8",
            allow: None,
            body: Cow::Owned(
                SELFTEST_PAGE
                    .replace("{{version}}", env!("CARGO_PKG_VERSION"))
                    .replace("{{report}}", SELFTEST_REPORT)
                    .into_bytes(),
            ),
        },
        "/demo/" => Response::ok("text/html; charset=utf-8", DEMO),
        "/demo/vendor/ncalayer-client.js" => {
            Response::ok("text/javascript; charset=utf-8", NCALAYER_CLIENT)
        }
        "/demo/vendor/LICENSE" => Response::ok(
            "text/plain; charset=utf-8",
            NCALAYER_CLIENT_LICENSE.as_bytes(),
        ),
        _ => Response::text(404, "Not Found", "Not Found"),
    }
}

/// A self-test report: `body` is the page's `navigator.userAgent` (UTF-8, at most
/// [`MAX_REPORT_BODY`] bytes, checked by the caller). It is recorded in `reports` only from
/// the page itself, whose `Origin` is `own_origin` (`https://127.0.0.1:<port>`): 204. Any
/// other origin, or none, is 403; a body that is not UTF-8 is 400.
pub(crate) fn selftest_report(
    origin: Option<&str>,
    own_origin: &str,
    body: &[u8],
    reports: &SelftestReports,
) -> Response {
    if origin != Some(own_origin) {
        return Response::text(403, "Forbidden", "Forbidden");
    }
    let Ok(user_agent) = std::str::from_utf8(body) else {
        return Response::bad_request();
    };
    reports.record(user_agent, OffsetDateTime::now_utc());
    Response::text(204, "No Content", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_only_from_the_page_itself() {
        let reports = SelftestReports::new();
        let own = "https://127.0.0.1:13579";
        for origin in [
            None,
            Some("https://example.kz"),
            Some("http://127.0.0.1:13579"),
            Some("https://127.0.0.1:13580"),
            Some("https://localhost:13579"),
            Some("null"),
        ] {
            let response = selftest_report(origin, own, b"Mozilla/5.0", &reports);
            assert_eq!(response.status(), 403, "{origin:?}");
        }
        assert!(reports.latest().is_empty());
        assert_eq!(
            selftest_report(Some(own), own, b"\xff", &reports).status(),
            400
        );
        let response = selftest_report(Some(own), own, b"Mozilla/5.0 Firefox/140.0", &reports);
        assert_eq!(response.status(), 204);
        let bytes = String::from_utf8(response.to_bytes()).unwrap();
        assert!(bytes.contains("\r\nContent-Length: 0\r\n"), "{bytes}");
        assert_eq!(reports.latest()[0].user_agent, "Mozilla/5.0 Firefox/140.0");

        let get = respond("GET", SELFTEST_REPORT).to_bytes();
        let get = String::from_utf8(get).unwrap();
        assert!(get.starts_with("HTTP/1.1 405 "), "{get}");
        assert!(get.contains("\r\nAllow: POST\r\n"), "{get}");
    }

    #[test]
    fn routes() {
        assert_eq!(respond("GET", "/").status(), 200);
        assert_eq!(respond("GET", "/?check=1").status(), 200);
        let page = String::from_utf8(respond("GET", SELFTEST).to_bytes()).unwrap();
        assert!(page.starts_with("HTTP/1.1 200 OK\r\n"), "{page}");
        assert!(page.contains(SELFTEST_REPORT), "{page}");
        assert!(!page.contains("{{"), "{page}");
        assert_eq!(respond("GET", "/demo").status(), 404);
        assert_eq!(respond("GET", "/demo/").status(), 200);
        assert_eq!(
            respond("GET", "/demo/vendor/ncalayer-client.js").status(),
            200
        );
        let license = respond("GET", "/demo/vendor/LICENSE").to_bytes();
        let license = String::from_utf8(license).unwrap();
        assert!(license.starts_with("HTTP/1.1 200 OK\r\n"), "{license}");
        assert!(license.contains("\r\nContent-Type: text/plain; charset=utf-8\r\n"));
        assert!(license.ends_with(NCALAYER_CLIENT_LICENSE), "{license}");
        assert!(NCALAYER_CLIENT_LICENSE.contains("MIT License"));
        assert_eq!(respond("HEAD", "/").status(), 405);
        let bytes = respond("PUT", "/x").to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(text.contains("\r\nAllow: GET\r\n"));
        assert!(text.contains("\r\nContent-Length: 47\r\n"));
    }
}
