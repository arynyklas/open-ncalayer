//! Plain HTTPS requests (everything that is not a WebSocket upgrade): the self-test page.

use std::borrow::Cow;

const SELFTEST: &str = include_str!("../../../web/selftest/index.html");

/// A complete HTTP/1.1 response; the connection is closed after it.
pub(crate) struct Response {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    /// Adds `Allow: GET` (405).
    allow_get: bool,
    body: Cow<'static, [u8]>,
}

impl Response {
    fn text(status: u16, reason: &'static str, body: &'static str) -> Self {
        Response {
            status,
            reason,
            content_type: "text/plain; charset=utf-8",
            allow_get: false,
            body: Cow::Borrowed(body.as_bytes()),
        }
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
        if self.allow_get {
            head.push_str("Allow: GET\r\n");
        }
        head.push_str("\r\n");
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

/// The response to a request that is not a WebSocket upgrade.
pub(crate) fn respond(method: &str, target: &str) -> Response {
    if method != "GET" {
        return Response {
            allow_get: true,
            ..Response::text(
                405,
                "Method Not Allowed",
                "Only GET and WebSocket connections are accepted",
            )
        };
    }
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    match path {
        "/" => Response {
            status: 200,
            reason: "OK",
            content_type: "text/html; charset=utf-8",
            allow_get: false,
            body: Cow::Owned(
                SELFTEST
                    .replace("{{version}}", env!("CARGO_PKG_VERSION"))
                    .into_bytes(),
            ),
        },
        _ => Response::text(404, "Not Found", "Not Found"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        assert_eq!(respond("GET", "/").status(), 200);
        assert_eq!(respond("GET", "/?check=1").status(), 200);
        assert_eq!(respond("GET", "/demo").status(), 404);
        assert_eq!(respond("HEAD", "/").status(), 405);
        let bytes = respond("PUT", "/x").to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(text.contains("\r\nAllow: GET\r\n"));
        assert!(text.contains("\r\nContent-Length: 47\r\n"));
    }
}
