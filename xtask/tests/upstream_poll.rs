//! Polling the sources of the original: identities, change detection, failures and the
//! address and redirect policy of the HTTP client.

mod upstream_common;

use oncl_testkit::{fixture, read};
use upstream_common::{
    MockServer, Response, endpoints, key, manifest_json, page_html, serve_manifest_and_page, signed,
};
use xtask::upstream::http::{FetchError, Fetcher, RequestCtx};
use xtask::upstream::poll::{AlertKind, Change, ModReason, PollResult, poll};
use xtask::upstream::sources::parse_download_page;
use xtask::upstream::state::{SourceState, SourceStatus, State};
use xtask::upstream::testkit::synthetic_issuers;

const SHA1S: [&str; 4] = [
    "1111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222",
    "3333333333333333333333333333333333333333",
    "4444444444444444444444444444444444444444",
];

/// The mock with the synthetic manifest, the page (keys of `k`) and 200 for every file.
fn world(k: char) -> MockServer {
    let server = MockServer::start();
    let json = manifest_json(&server, |j| j);
    let k = key(k);
    serve_manifest_and_page(&server, signed(&json), &page_html([&k, &k, &k, &k], SHA1S));
    for path in [
        "/updates/lite.exe",
        "/updates/installer.sh",
        "/updates/ncalayer.zip",
        "/updates/jre/tzdb.dat",
    ] {
        server.route(
            "HEAD",
            path,
            Response::ok(vec![0; 10]).header("ETag", "\"e1\""),
        );
    }
    server.route("HEAD", "/download.php", Response::ok(vec![0; 10]));
    server
}

/// Serves another page, the manifest file unchanged.
fn serve_page(server: &MockServer, html: &str) {
    server.route(
        "GET",
        "/",
        Response::html(html.as_bytes().to_vec()).header("Set-Cookie", "sid=synthetic; Path=/"),
    );
}

fn run(server: &MockServer, prev: &State) -> PollResult {
    poll(
        prev,
        &Fetcher::for_tests(),
        &endpoints(server),
        None,
        &synthetic_issuers(),
    )
}

fn ids(changes: &[Change]) -> Vec<String> {
    changes.iter().map(|c| c.id().to_owned()).collect()
}

#[test]
fn first_poll_adds_all_sources() {
    let server = world('a');
    let r = run(&server, &State::default());
    assert!(r.alerts.is_empty(), "{:?}", r.alerts);
    assert!(r.changes.iter().all(|c| matches!(c, Change::Added { .. })));
    assert_eq!(
        ids(&r.changes),
        [
            "bundle:kz.example.core",
            "bundle:kz.example.demo",
            "bundle:kz.example.private",
            "bundle:kz.example.ws",
            "dist:setupexe",
            "dist:setupsh",
            "fixed:ncalayer.zip",
            "fixed:tzdb.dat",
            "manifest",
            "page:windows-64-bit",
            "page:macosx",
            "page:linux",
            "page:korporativnoy-seti",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
    );
    // Bundles are not requested while polling.
    assert!(
        server
            .requests()
            .iter()
            .all(|r| !r.target.contains("bundles/"))
    );
}

#[test]
fn same_content_new_etag_is_modified_headers_only() {
    let server = world('a');
    let first = run(&server, &State::default());
    server.route(
        "HEAD",
        "/updates/lite.exe",
        Response::ok(vec![0; 10]).header("ETag", "\"e2\""),
    );
    let second = run(&server, &first.next);
    assert_eq!(
        second.changes,
        [Change::Modified {
            id: "dist:setupexe".to_owned(),
            reason: ModReason::Headers
        }]
    );
}

#[test]
fn download_key_rotation_is_not_a_change() {
    let server = world('a');
    let first = run(&server, &State::default());
    let k = key('b');
    serve_page(&server, &page_html([&k, &k, &k, &k], SHA1S));
    let second = run(&server, &first.next);
    assert!(second.changes.is_empty(), "{:?}", second.changes);
    let a: Vec<_> = first.sources.iter().map(|s| &s.id).collect();
    let b: Vec<_> = second.sources.iter().map(|s| &s.id).collect();
    assert_eq!(a, b);
    assert_eq!(first.next, second.next);
}

#[test]
fn published_sha1_change_is_modified() {
    let server = world('a');
    let first = run(&server, &State::default());
    let k = key('a');
    let mut sha1s = SHA1S;
    sha1s[0] = "5555555555555555555555555555555555555555";
    serve_page(&server, &page_html([&k, &k, &k, &k], sha1s));
    let second = run(&server, &first.next);
    assert_eq!(
        second.changes,
        [Change::Modified {
            id: "page:windows-64-bit".to_owned(),
            reason: ModReason::PublishedSha1
        }]
    );
}

#[test]
fn three_failures_then_removed() {
    let server = world('a');
    let mut state = run(&server, &State::default()).next;
    server.route("HEAD", "/updates/installer.sh", Response::status(503));
    for n in 1..=2 {
        let r = run(&server, &state);
        assert!(r.changes.is_empty(), "{:?}", r.changes);
        state = r.next;
        assert_eq!(state.sources["dist:setupsh"].failures, n);
        assert_eq!(state.sources["dist:setupsh"].status, SourceStatus::Failing);
    }
    let r = run(&server, &state);
    assert_eq!(
        r.changes,
        [Change::Removed {
            id: "dist:setupsh".to_owned()
        }]
    );
    assert_eq!(r.next.sources["dist:setupsh"].status, SourceStatus::Gone);
}

#[test]
fn failure_then_success_resets_count() {
    let server = world('a');
    let state = run(&server, &State::default()).next;
    server.route_seq(
        "HEAD",
        "/updates/installer.sh",
        vec![
            Response::status(503),
            Response::ok(vec![0; 10]).header("ETag", "\"e1\""),
        ],
    );
    let failed = run(&server, &state);
    assert_eq!(failed.next.sources["dist:setupsh"].failures, 1);
    let ok = run(&server, &failed.next);
    assert_eq!(ok.next.sources["dist:setupsh"].failures, 0);
    assert_eq!(ok.next.sources["dist:setupsh"].status, SourceStatus::Ok);
    assert!(ok.changes.is_empty(), "{:?}", ok.changes);
}

#[test]
fn page_html_instead_of_file_is_failure_not_change() {
    let server = world('a');
    let state = run(&server, &State::default()).next;
    server.route(
        "HEAD",
        "/download.php",
        Response::html(read(fixture("upstream/error.html"))),
    );
    let r = run(&server, &state);
    assert!(r.changes.is_empty(), "{:?}", r.changes);
    assert_eq!(r.next.sources["page:windows-64-bit"].failures, 1);
}

#[test]
fn bundle_version_bump_is_modified_manifest_hash() {
    let server = world('a');
    let state = run(&server, &State::default()).next;
    let json = manifest_json(&server, |j| {
        j.replacen(
            "\"version\":\"1.0.0\",\"info\":\"synthetic plugin\",\"url\":",
            "\"version\":\"1.1.0\",\"info\":\"synthetic plugin\",\"url\":",
            1,
        )
        .replace("bundle-a.jar\",\"hash\":\"", "bundle-a.jar\",\"hash\":\"ff")
    });
    let k = key('a');
    serve_manifest_and_page(&server, signed(&json), &page_html([&k, &k, &k, &k], SHA1S));
    let r = run(&server, &state);
    assert!(r.changes.contains(&Change::Modified {
        id: "bundle:kz.example.demo".to_owned(),
        reason: ModReason::ManifestHash
    }));
}

#[test]
fn bundle_dropped_from_manifest_is_removed_at_once() {
    let server = world('a');
    let state = run(&server, &State::default()).next;
    let json = manifest_json(&server, |j| {
        let start = j.find(",{\"name\":\"Example private\"").unwrap();
        let end = j[start..].find('}').unwrap() + start + 1;
        format!("{}{}", &j[..start], &j[end..])
    });
    let k = key('a');
    serve_manifest_and_page(&server, signed(&json), &page_html([&k, &k, &k, &k], SHA1S));
    let r = run(&server, &state);
    assert!(r.changes.contains(&Change::Removed {
        id: "bundle:kz.example.private".to_owned()
    }));
    assert!(!r.next.sources.contains_key("bundle:kz.example.private"));
}

#[test]
fn first_run_manifest_unreachable_alerts() {
    let server = world('a');
    server.route("GET", "/updates/ncalayer.der", Response::status(503));
    let r = run(&server, &State::default());
    assert_eq!(
        r.alerts.iter().map(|a| a.kind).collect::<Vec<_>>(),
        [AlertKind::ManifestUnreachable]
    );
    assert!(r.manifest.is_err());
}

#[test]
fn bad_signature_alerts_and_keeps_state() {
    let server = world('a');
    let state = run(&server, &State::default()).next;
    let mut der = signed(&manifest_json(&server, |j| j));
    let at = der.windows(5).position(|w| w == b"\"1.4\"").unwrap();
    der[at + 3] = b'5';
    let k = key('a');
    serve_manifest_and_page(&server, der, &page_html([&k, &k, &k, &k], SHA1S));
    let r = run(&server, &state);
    assert_eq!(
        r.alerts.iter().map(|a| a.kind).collect::<Vec<_>>(),
        [AlertKind::BadSignature]
    );
    assert_eq!(
        r.next.sources["manifest"].sha256,
        state.sources["manifest"].sha256
    );
    assert_eq!(r.next, state);
}

#[test]
fn signer_change_is_noted_not_failure() {
    let server = world('a');
    let first = run(&server, &State::default());
    let prev = first.manifest.clone().unwrap();
    let mut other = prev.clone();
    other.signer.serial = "01".to_owned();
    let r = poll(
        &first.next,
        &Fetcher::for_tests(),
        &endpoints(&server),
        Some(&other),
        &synthetic_issuers(),
    );
    assert!(r.manifest.is_ok());
    assert_eq!(
        r.alerts.iter().map(|a| a.kind).collect::<Vec<_>>(),
        [AlertKind::SignerChanged]
    );
}

#[test]
fn refuses_private_addresses() {
    let server = world('a');
    let fetcher = Fetcher::new();
    let ctx = RequestCtx::default();
    assert!(matches!(
        fetcher.get(&server.url("/"), 1024, &ctx),
        Err(FetchError::RefusedAddress(_))
    ));
    assert!(server.requests().is_empty());
    for url in [
        "http://10.1.2.3/x.jar",
        "http://[::1]/",
        "http://[::ffff:192.168.1.1]/",
        "http://100.64.0.1/",
        "http://[fd00::1]/",
        "http://0.0.0.0/",
        "http://192.0.2.1/",
    ] {
        assert!(
            matches!(fetcher.head(url, &ctx), Err(FetchError::RefusedAddress(_))),
            "{url}"
        );
    }
}

#[test]
fn redirect_to_private_refused() {
    let server = MockServer::start();
    server.route(
        "GET",
        "/r",
        Response::redirect("http://169.254.169.254/latest"),
    );
    assert!(matches!(
        Fetcher::for_tests().get(&server.url("/r"), 1024, &RequestCtx::default()),
        Err(FetchError::RefusedAddress(_))
    ));
}

#[test]
fn too_many_redirects() {
    let server = MockServer::start();
    for n in 0..6 {
        server.route(
            "GET",
            &format!("/r{n}"),
            Response::redirect(&format!("/r{}", n + 1)),
        );
    }
    server.route("GET", "/r6", Response::ok(b"x".to_vec()));
    let fetcher = Fetcher::for_tests();
    assert_eq!(
        fetcher.get(&server.url("/r0"), 1024, &RequestCtx::default()),
        Err(FetchError::TooManyRedirects)
    );
    assert_eq!(
        fetcher
            .get(&server.url("/r1"), 1024, &RequestCtx::default())
            .unwrap()
            .body,
        b"x"
    );
}

#[test]
fn oversized_body_is_error_not_truncation() {
    let server = MockServer::start();
    server.route("GET", "/big", Response::ok(vec![7; 2000]));
    let fetcher = Fetcher::for_tests();
    assert_eq!(
        fetcher.get(&server.url("/big"), 1999, &RequestCtx::default()),
        Err(FetchError::TooLarge { limit: 1999 })
    );
    let dest = tempfile::tempdir().unwrap();
    let path = dest.path().join("big");
    assert_eq!(
        fetcher.download(&server.url("/big"), 1999, &RequestCtx::default(), &path),
        Err(FetchError::TooLarge { limit: 1999 })
    );
    assert!(!path.exists());
    assert_eq!(
        fetcher
            .get(&server.url("/big"), 2000, &RequestCtx::default())
            .unwrap()
            .body
            .len(),
        2000
    );
}

#[test]
fn cookies_and_referer_sent_for_page_downloads() {
    let server = world('a');
    let page = server.url("/");
    server.handler(move |r| {
        (r.path() == "/download.php").then(|| {
            let cookie_ok = r
                .headers
                .get("cookie")
                .is_some_and(|c| c.contains("sid=synthetic"));
            let referer_ok = r.headers.get("referer") == Some(&page);
            if cookie_ok && referer_ok {
                Response::ok(vec![0; 10])
            } else {
                Response::status(403)
            }
        })
    });
    let r = run(&server, &State::default());
    assert!(
        r.next.sources["page:windows-64-bit"].status == SourceStatus::Ok,
        "{:?}",
        r.next.sources["page:windows-64-bit"]
    );
    let downloads: Vec<_> = server
        .requests()
        .into_iter()
        .filter(|r| r.path() == "/download.php")
        .collect();
    assert_eq!(downloads.len(), 4);
}

#[test]
fn state_json_is_sorted_and_stable() {
    let entry = |url: &str| SourceState {
        url: url.to_owned(),
        ..SourceState::default()
    };
    let mut a = State::default();
    a.sources.insert("b".to_owned(), entry("2"));
    a.sources.insert("a".to_owned(), entry("1"));
    let mut b = State::default();
    b.sources.insert("a".to_owned(), entry("1"));
    b.sources.insert("b".to_owned(), entry("2"));
    assert_eq!(a.to_json(), b.to_json());
    assert!(a.to_json().ends_with(b"}\n"));
}

#[test]
fn page_links_skip_other_keys() {
    let k = key('c');
    let links = parse_download_page(&page_html([&k, &k, &k, &k], SHA1S), "https://example.test/");
    assert_eq!(links.len(), 4);
    assert_eq!(links[0].slug, "windows-64-bit");
    assert_eq!(
        links[0].url,
        format!("https://example.test/download.php?key={k}")
    );
    assert_eq!(links[0].published_sha1.as_deref(), Some(SHA1S[0]));
    assert_eq!(links[3].published_sha1.as_deref(), Some(SHA1S[3]));
}

#[test]
#[ignore = "network: the live sources of the original"]
fn live_sources_discovered() {
    let r = poll(
        &State::default(),
        &Fetcher::new(),
        &xtask::upstream::Endpoints::default(),
        None,
        oncl_pki::roots::nca_production(),
    );
    assert!(r.manifest.is_ok(), "{:?}", r.alerts);
    let count = |p: &str| r.sources.iter().filter(|s| s.id.starts_with(p)).count();
    assert!(count("dist:") >= 2);
    assert!(count("page:") >= 4, "{:?}", r.sources);
}

#[test]
fn html_on_the_manifest_url_is_unreachable_not_bad_signature() {
    let server = world('a');
    let error = read(fixture("upstream/error.html"));
    // First run: an error page with status 200 is "unreachable".
    server.route(
        "GET",
        "/updates/ncalayer.der",
        Response::html(error.clone()),
    );
    let r = run(&server, &State::default());
    assert_eq!(
        r.alerts.iter().map(|a| a.kind).collect::<Vec<_>>(),
        [AlertKind::ManifestUnreachable]
    );
    // After a baseline: a counted failure, no alert before the third.
    let server = world('a');
    let state = run(&server, &State::default()).next;
    server.route(
        "GET",
        "/updates/ncalayer.der",
        Response::ok(error).header("Content-Type", "application/octet-stream"),
    );
    let r = run(&server, &state);
    assert!(r.alerts.is_empty(), "{:?}", r.alerts);
    assert_eq!(r.next.sources["manifest"].failures, 1);
}

#[test]
fn manifest_failures_are_capped() {
    let server = world('a');
    let mut state = run(&server, &State::default()).next;
    server.route("GET", "/updates/ncalayer.der", Response::status(503));
    let mut seen = Vec::new();
    for _ in 0..5 {
        let r = run(&server, &state);
        state = r.next;
        seen.push(state.sources["manifest"].failures);
    }
    assert_eq!(seen, [1, 2, 3, 3, 3]);
    // The state no longer changes while the manifest stays unreachable.
    assert_eq!(run(&server, &state).next.to_json(), state.to_json());
}
