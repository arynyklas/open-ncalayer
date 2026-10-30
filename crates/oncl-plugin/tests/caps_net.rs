//! `http_request_ex`: wildcard prefixes on label boundaries, the page's own origin when the
//! manifest lists it (relative URLs resolved only against it), plain HTTP only same-origin
//! for an http page or under an exact `http_insecure` prefix, and the headers a plugin may
//! send.

mod common;

use common::*;
use oncl_pdk::abi::{
    self, Bytes, ErrorCode, Header, HostResult, HttpExArgs, HttpResponse, Import, MAX_HEADERS,
    Method,
};
use oncl_pki::http::{HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport};
use oncl_plugin::{Engine, HostServices};
use oncl_protocol::AddInfo;
use std::sync::{Arc, Mutex};

/// A request the transport got.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Sent {
    method: HttpMethod,
    url: String,
    headers: Vec<(String, String)>,
    content_type: Option<String>,
    body: Vec<u8>,
    https_only: bool,
    redirects: bool,
}

/// Records every request and answers `reply`.
struct Recording {
    sent: Mutex<Vec<Sent>>,
    reply: HttpReply,
}

impl Recording {
    fn new(reply: HttpReply) -> Arc<Recording> {
        Arc::new(Recording {
            sent: Mutex::new(Vec::new()),
            reply,
        })
    }

    fn ok() -> Arc<Recording> {
        Recording::new(HttpReply {
            status: 200,
            content_type: Some("text/plain".to_owned()),
            location: None,
            body: b"ok".to_vec(),
        })
    }

    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }
}

impl HttpTransport for Recording {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.sent.lock().unwrap().push(Sent {
            method: request.method,
            url: request.url.to_owned(),
            headers: request
                .headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            content_type: request.content_type.map(str::to_owned),
            body: request.body.to_vec(),
            https_only: request.opts.https_only,
            redirects: request.opts.redirects,
        });
        Ok(self.reply.clone())
    }
}

fn services(http: Arc<Recording>) -> HostServices {
    services_with(
        Arc::new(oncl_basics::testing::ScriptedPrompter::new(Vec::new())),
        http,
    )
}

fn get(url: &str) -> HttpExArgs {
    HttpExArgs {
        method: Method::Get,
        url: url.to_owned(),
        relative_to_origin: false,
        headers: Vec::new(),
        content_type: None,
        body: Bytes::new(),
        timeout_ms: None,
    }
}

fn relative(url: &str) -> HttpExArgs {
    HttpExArgs {
        relative_to_origin: true,
        ..get(url)
    }
}

/// The results of `requests`, one request (call) each, from `add_info`.
fn run_from(
    caps: &str,
    http: &Arc<Recording>,
    add_info: &AddInfo,
    requests: &[HttpExArgs],
) -> Vec<HostResult<HttpResponse>> {
    let services = services(Arc::clone(http));
    requests
        .iter()
        .map(|args| {
            let calls = [(Import::HttpRequestEx, abi::encode(args))];
            let mut instance = Engine::new()
                .compile(&manifest(caps), &wasm(&probe(&calls)))
                .unwrap()
                .instantiate(&services, session(1))
                .unwrap();
            probe_result(instance.process("{}", add_info).unwrap().text().unwrap())
        })
        .collect()
}

fn run(
    caps: &str,
    http: &Arc<Recording>,
    origin: &str,
    requests: &[HttpExArgs],
) -> Vec<HostResult<HttpResponse>> {
    run_from(caps, http, &from(origin), requests)
}

fn code(result: &HostResult<HttpResponse>) -> Option<ErrorCode> {
    result.as_ref().err().map(|e| e.code)
}

#[test]
fn wildcard_matches_label_boundary() {
    let http = Recording::ok();
    let caps = r#"http = ["https://*.gov.kz/"]"#;
    let allowed = ["https://a.gov.kz/x", "https://x.y.gov.kz/"];
    let results = run(caps, &http, "https://page.kz", &allowed.map(get));
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    let urls: Vec<String> = http.sent().into_iter().map(|s| s.url).collect();
    assert_eq!(urls, allowed);
    let denied = [
        "https://gov.kz/",
        "https://evilgov.kz/",
        "https://gov.kz.evil/",
        "https://a.gov.kz@evil/",
        "http://a.gov.kz/",
    ];
    for result in run(caps, &http, "https://page.kz", &denied.map(get)) {
        assert_eq!(code(&result), Some(ErrorCode::Denied), "{result:?}");
    }
    assert_eq!(http.sent().len(), 2);
}

#[test]
fn relative_resolves_against_call_origin() {
    let http = Recording::ok();
    let caps = r#"origins = ["https://*.ecc.kz"]"#;
    let results = run(
        caps,
        &http,
        "https://egz.ecc.kz",
        &[relative("/api/x?y=1"), relative("upload")],
    );
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    let urls: Vec<String> = http.sent().into_iter().map(|s| s.url).collect();
    assert_eq!(
        urls,
        ["https://egz.ecc.kz/api/x?y=1", "https://egz.ecc.kz/upload"]
    );
    // A relative URL that leaves the origin.
    for args in [relative("//evil.kz/x"), relative("https://other.ecc.kz/x")] {
        let result = &run(caps, &http, "https://egz.ecc.kz", &[args])[0];
        assert_eq!(code(result), Some(ErrorCode::Denied), "{result:?}");
    }
    assert_eq!(http.sent().len(), 2);
}

#[test]
fn relative_without_origin_is_denied() {
    let http = Recording::ok();
    let caps = r#"origins = ["https://*.ecc.kz"]"#;
    let no_origin = AddInfo {
        origin: None,
        session: 1,
    };
    let result = &run_from(caps, &http, &no_origin, &[relative("/api")])[0];
    assert_eq!(code(result), Some(ErrorCode::Denied));
    // An origin that is not a URL.
    let result = &run(caps, &http, "null", &[relative("/api")])[0];
    assert_eq!(code(result), Some(ErrorCode::Denied));
    assert!(http.sent().is_empty());
}

#[test]
fn same_origin_absolute_allowed_only_for_listed_origin() {
    let http = Recording::ok();
    let caps = r#"origins = ["https://*.ecc.kz", "https://a.kz:8443"]"#;
    assert!(
        run(
            caps,
            &http,
            "https://egz.ecc.kz",
            &[get("https://egz.ecc.kz/a")]
        )[0]
        .is_ok()
    );
    assert!(
        run(
            caps,
            &http,
            "https://a.kz:8443",
            &[get("https://a.kz:8443/b")]
        )[0]
        .is_ok()
    );
    for (origin, url) in [
        // Not listed.
        ("https://evil.kz", "https://evil.kz/a"),
        ("https://ecc.kz", "https://ecc.kz/a"),
        ("https://a.kz", "https://a.kz/a"),
        // Listed, another origin.
        ("https://egz.ecc.kz", "https://other.ecc.kz/a"),
        ("https://a.kz:8443", "https://a.kz/a"),
    ] {
        let result = &run(caps, &http, origin, &[get(url)])[0];
        assert_eq!(code(result), Some(ErrorCode::Denied), "{origin} {url}");
    }
    assert_eq!(http.sent().len(), 2);
}

#[test]
fn http_page_origin_allows_http_same_origin() {
    let http = Recording::ok();
    let caps = r#"origins = ["http://client2.kazynashylyk.kz"]"#;
    let page = "http://client2.kazynashylyk.kz";
    let results = run(
        caps,
        &http,
        page,
        &[relative("/sign"), get("http://client2.kazynashylyk.kz/x")],
    );
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    let sent = http.sent();
    assert_eq!(sent[0].url, "http://client2.kazynashylyk.kz/sign");
    assert!(sent.iter().all(|s| !s.https_only && !s.redirects));
    // Not to https on the same host: another origin.
    let result = &run(
        caps,
        &http,
        page,
        &[get("https://client2.kazynashylyk.kz/x")],
    )[0];
    assert_eq!(code(result), Some(ErrorCode::Denied));
}

#[test]
fn https_page_cannot_reach_http_same_host() {
    let http = Recording::ok();
    let caps = r#"origins = ["https://*.ecc.kz"]"#;
    let result = &run(caps, &http, "https://a.ecc.kz", &[get("http://a.ecc.kz/x")])[0];
    assert_eq!(code(result), Some(ErrorCode::Denied));
    // Nor is an http page of a listed https pattern.
    let result = &run(caps, &http, "http://a.ecc.kz", &[relative("/x")])[0];
    assert_eq!(code(result), Some(ErrorCode::Denied));
    assert!(http.sent().is_empty());
}

#[test]
fn insecure_prefix_exact_host_port() {
    let http = Recording::ok();
    let caps = r#"http_insecure = ["http://ncalayer.uchet.kz:8080/api/"]"#;
    assert!(
        run(
            caps,
            &http,
            "https://uchet.kz",
            &[get("http://ncalayer.uchet.kz:8080/api/x")]
        )[0]
        .is_ok()
    );
    assert!(!http.sent()[0].https_only);
    for url in [
        "http://ncalayer.uchet.kz/api/x",
        "http://ncalayer.uchet.kz:8081/api/x",
        "http://x.ncalayer.uchet.kz:8080/api/x",
        "http://ncalayer.uchet.kz:8080/other",
        "https://ncalayer.uchet.kz:8080/api/x",
        "http://ncalayer.uchet.kz:8080/api/..%2f..%2fadmin",
    ] {
        let result = &run(caps, &http, "https://uchet.kz", &[get(url)])[0];
        assert_eq!(code(result), Some(ErrorCode::Denied), "{url}");
    }
    assert_eq!(http.sent().len(), 1);
}

#[test]
fn file_and_data_schemes_denied() {
    let http = Recording::ok();
    let caps = r#"http = ["https://*.gov.kz/"]
origins = ["https://*.ecc.kz"]"#;
    for url in [
        "file:///etc/passwd",
        "file://a.gov.kz/x",
        "data:text/plain,x",
        "ftp://a.gov.kz/",
        "javascript:alert(1)",
    ] {
        for args in [get(url), relative(url)] {
            let result = &run(caps, &http, "https://a.ecc.kz", &[args])[0];
            assert_eq!(code(result), Some(ErrorCode::Denied), "{url}");
        }
    }
    assert!(http.sent().is_empty());
}

fn with_headers(headers: &[(&str, &str)]) -> HttpExArgs {
    HttpExArgs {
        headers: headers
            .iter()
            .map(|(name, value)| Header {
                name: (*name).to_owned(),
                value: (*value).to_owned(),
            })
            .collect(),
        ..get("https://a.gov.kz/x")
    }
}

const GOV: &str = r#"http = ["https://*.gov.kz/"]"#;

#[test]
fn header_allowlist() {
    let http = Recording::ok();
    for name in [
        "Cookie",
        "cookie",
        "User-Agent",
        "Accept",
        "Accept-Language",
        "X-Requested-With",
    ] {
        assert!(
            run(GOV, &http, "https://p.kz", &[with_headers(&[(name, "v")])])[0].is_ok(),
            "{name}"
        );
    }
    for name in [
        "Host",
        "Authorization",
        "Content-Length",
        "Content-Type",
        "Origin",
        "Transfer-Encoding",
        "X-Other",
    ] {
        let result = &run(GOV, &http, "https://p.kz", &[with_headers(&[(name, "v")])])[0];
        assert_eq!(code(result), Some(ErrorCode::Denied), "{name}");
    }
    let many: Vec<(&str, &str)> = vec![("Accept", "x"); MAX_HEADERS + 1];
    let result = &run(GOV, &http, "https://p.kz", &[with_headers(&many)])[0];
    assert_eq!(code(result), Some(ErrorCode::Limit));
    let long = "x".repeat(oncl_pdk::abi::MAX_HEADER_BYTES);
    let result = &run(
        GOV,
        &http,
        "https://p.kz",
        &[with_headers(&[("Cookie", &long)])],
    )[0];
    assert_eq!(code(result), Some(ErrorCode::Limit));
    assert_eq!(http.sent().len(), 6);
}

#[test]
fn header_crlf_is_invalid() {
    let http = Recording::ok();
    for value in ["a\r\nHost: evil", "a\nb", "a\rb", "a\0b"] {
        let result = &run(
            GOV,
            &http,
            "https://p.kz",
            &[with_headers(&[("Cookie", value)])],
        )[0];
        assert_eq!(code(result), Some(ErrorCode::Invalid), "{value:?}");
    }
    let bad_type = HttpExArgs {
        method: Method::Post,
        content_type: Some("text/plain\r\nX: y".to_owned()),
        ..get("https://a.gov.kz/x")
    };
    let result = &run(GOV, &http, "https://p.kz", &[bad_type])[0];
    assert_eq!(code(result), Some(ErrorCode::Invalid));
    assert!(http.sent().is_empty());
}

#[test]
fn headers_reach_transport() {
    let http = Recording::ok();
    let args = with_headers(&[("Cookie", "JSESSIONID=1"), ("Accept-Language", "ru")]);
    let reply = run(GOV, &http, "https://p.kz", &[args])[0].clone().unwrap();
    assert_eq!(reply.body.as_slice(), b"ok");
    assert_eq!(
        http.sent()[0].headers,
        [
            ("Cookie".to_owned(), "JSESSIONID=1".to_owned()),
            ("Accept-Language".to_owned(), "ru".to_owned())
        ]
    );
    assert!(http.sent()[0].https_only);
}

#[test]
fn post_without_content_type() {
    let http = Recording::ok();
    let post = |content_type: Option<&str>| HttpExArgs {
        method: Method::Post,
        content_type: content_type.map(str::to_owned),
        body: Bytes::from(b"{}".to_vec()),
        ..get("https://a.gov.kz/x")
    };
    let results = run(
        GOV,
        &http,
        "https://p.kz",
        &[post(None), post(Some("application/json"))],
    );
    assert!(results.iter().all(Result::is_ok));
    let sent = http.sent();
    assert_eq!(sent[0].method, HttpMethod::Post);
    assert_eq!(sent[0].content_type, None);
    assert_eq!(sent[0].body, b"{}");
    assert_eq!(sent[1].content_type.as_deref(), Some("application/json"));
    // A GET has no body.
    let get_body = HttpExArgs {
        body: Bytes::from(b"x".to_vec()),
        ..get("https://a.gov.kz/x")
    };
    let result = &run(GOV, &http, "https://p.kz", &[get_body])[0];
    assert_eq!(code(result), Some(ErrorCode::Invalid));
    // A timeout over the core's.
    let slow = HttpExArgs {
        timeout_ms: Some(600_000),
        ..get("https://a.gov.kz/x")
    };
    let result = &run(GOV, &http, "https://p.kz", &[slow])[0];
    assert_eq!(code(result), Some(ErrorCode::Invalid));
}

#[test]
fn redirect_not_followed_and_rechecked() {
    let http = Recording::new(HttpReply {
        status: 302,
        content_type: None,
        location: Some("https://evil.kz/steal".to_owned()),
        body: Vec::new(),
    });
    let reply = run(GOV, &http, "https://p.kz", &[get("https://a.gov.kz/x")])[0]
        .clone()
        .unwrap();
    assert_eq!(reply.status, 302);
    assert_eq!(reply.location.as_deref(), Some("https://evil.kz/steal"));
    assert!(!http.sent()[0].redirects);
    // Following it is a request of its own, checked as any.
    let follow = &run(GOV, &http, "https://p.kz", &[get("https://evil.kz/steal")])[0];
    assert_eq!(code(follow), Some(ErrorCode::Denied));
    assert_eq!(http.sent().len(), 1);
}
