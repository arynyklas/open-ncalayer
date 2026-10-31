//! A local HTTP/1.1 mock for the upstream tests: routes by method and path (the query is
//! ignored unless a route names it), a sequence of responses per route (the last repeats),
//! and a record of every request.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

/// A canned response.
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn ok(body: impl Into<Vec<u8>>) -> Response {
        Response {
            status: 200,
            headers: vec![(
                "Content-Type".to_owned(),
                "application/octet-stream".to_owned(),
            )],
            body: body.into(),
        }
    }

    pub fn status(status: u16) -> Response {
        Response {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn html(body: impl Into<Vec<u8>>) -> Response {
        Response {
            status: 200,
            headers: vec![(
                "Content-Type".to_owned(),
                "text/html; charset=utf-8".to_owned(),
            )],
            body: body.into(),
        }
    }

    pub fn json(status: u16, body: &serde_json::Value) -> Response {
        Response {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: serde_json::to_vec(body).unwrap(),
        }
    }

    pub fn redirect(location: &str) -> Response {
        Response {
            status: 302,
            headers: vec![("Location".to_owned(), location.to_owned())],
            body: Vec::new(),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Response {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

/// A request the mock received.
#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    /// Path and query.
    pub target: String,
    /// Lowercase names.
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Recorded {
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap()
    }
}

type Handler = Box<dyn FnMut(&Recorded) -> Option<Response> + Send>;

#[derive(Default)]
struct Shared {
    routes: BTreeMap<(String, String), Vec<Response>>,
    handlers: Vec<Handler>,
    requests: Vec<Recorded>,
}

/// The mock; it serves until dropped with the test process.
pub struct MockServer {
    pub base: String,
    pub port: u16,
    shared: Arc<Mutex<Shared>>,
}

impl MockServer {
    pub fn start() -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let shared = Arc::new(Mutex::new(Shared::default()));
        let worker = Arc::clone(&shared);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let shared = Arc::clone(&worker);
                thread::spawn(move || serve(stream, &shared));
            }
        });
        MockServer {
            base: format!("http://127.0.0.1:{port}"),
            port,
            shared,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// One response for every request to `method path`.
    pub fn route(&self, method: &str, path: &str, response: Response) {
        self.route_seq(method, path, vec![response]);
    }

    /// Responses in turn; the last repeats.
    pub fn route_seq(&self, method: &str, path: &str, responses: Vec<Response>) {
        assert!(!responses.is_empty());
        self.shared
            .lock()
            .unwrap()
            .routes
            .insert((method.to_owned(), path.to_owned()), responses);
    }

    /// A handler tried before the routes; `None` falls through.
    pub fn handler(&self, f: impl FnMut(&Recorded) -> Option<Response> + Send + 'static) {
        self.shared.lock().unwrap().handlers.push(Box::new(f));
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.shared.lock().unwrap().requests.clone()
    }

    pub fn clear_requests(&self) {
        self.shared.lock().unwrap().requests.clear();
    }
}

fn serve(stream: TcpStream, shared: &Arc<Mutex<Shared>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let mut headers = BTreeMap::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        if let Some((n, v)) = h.split_once(':') {
            headers.insert(n.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    let len = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0usize);
    let mut body = vec![0; len];
    let _ = reader.read_exact(&mut body);
    let recorded = Recorded {
        method: method.clone(),
        target: target.clone(),
        headers,
        body,
    };
    let response = {
        let mut s = shared.lock().unwrap();
        s.requests.push(recorded.clone());
        let mut found = None;
        for h in &mut s.handlers {
            if let Some(r) = h(&recorded) {
                found = Some(r);
                break;
            }
        }
        found.or_else(|| {
            let lookup = |m: &str, p: &str| (m.to_owned(), p.to_owned());
            let key = [
                lookup(&method, &target),
                lookup(&method, recorded.path()),
                lookup("GET", &target),
                lookup("GET", recorded.path()),
            ]
            .into_iter()
            .filter(|(m, _)| m == &method || method == "HEAD")
            .find(|k| s.routes.contains_key(k))?;
            let seq = s.routes.get_mut(&key).unwrap();
            Some(if seq.len() > 1 {
                seq.remove(0)
            } else {
                seq[0].clone()
            })
        })
    }
    .unwrap_or_else(|| Response::status(404));
    let mut out = stream;
    let reason = match response.status {
        200 => "OK",
        302 => "Found",
        404 => "Not Found",
        _ => "Status",
    };
    let mut head = format!("HTTP/1.1 {} {reason}\r\n", response.status);
    for (n, v) in &response.headers {
        head.push_str(&format!("{n}: {v}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        response.body.len()
    ));
    let _ = out.write_all(head.as_bytes());
    if method != "HEAD" {
        let _ = out.write_all(&response.body);
    }
    let _ = out.flush();
}

// ---- The synthetic world of the original: manifest, page, files. ----

use oncl_testkit::{fixture, read};
use xtask::upstream::Endpoints;

/// The host of the committed synthetic manifest, replaced by the mock's address.
pub const TEST_HOST: &str = "http://upstream.test";

/// The committed `manifest.json` with its URLs on `server`, edited by `edit`.
pub fn manifest_json(server: &MockServer, edit: impl FnOnce(String) -> String) -> String {
    let json = String::from_utf8(read(fixture("upstream/manifest.json"))).unwrap();
    edit(json.replace(TEST_HOST, &server.base))
}

/// `json` signed by the synthetic `CN=NCALayer`.
pub fn signed(json: &str) -> Vec<u8> {
    xtask::upstream::testkit::sign_manifest(
        json.as_bytes(),
        &xtask::upstream::testkit::synthetic_signer("NCALayer"),
    )
}

/// The download page with `keys` and `sha1s` (win, mac, lin, msi).
pub fn page_html(keys: [&str; 4], sha1s: [&str; 4]) -> String {
    let mut html = String::from_utf8(read(fixture("upstream/download-page.html"))).unwrap();
    for (i, name) in ["win", "mac", "lin", "msi"].iter().enumerate() {
        html = html
            .replace(&format!("{{{{key_{name}}}}}"), keys[i])
            .replace(&format!("{{{{sha1_{name}}}}}"), sha1s[i]);
    }
    html
}

/// A 32-hex-digit key made of `c`.
pub fn key(c: char) -> String {
    std::iter::repeat_n(c, 32).collect()
}

/// The endpoints of the mock.
pub fn endpoints(server: &MockServer) -> Endpoints {
    Endpoints {
        manifest: server.url("/updates/ncalayer.der"),
        page: server.url("/"),
        fixed: vec![
            (
                "fixed:ncalayer.zip".to_owned(),
                server.url("/updates/ncalayer.zip"),
            ),
            (
                "fixed:tzdb.dat".to_owned(),
                server.url("/updates/jre/tzdb.dat"),
            ),
        ],
    }
}

/// Serves the page (with a session cookie) and the manifest `der`.
pub fn serve_manifest_and_page(server: &MockServer, der: Vec<u8>, page: &str) {
    server.route("GET", "/updates/ncalayer.der", Response::ok(der));
    server.route(
        "GET",
        "/",
        Response::html(page.as_bytes().to_vec()).header("Set-Cookie", "sid=synthetic; Path=/"),
    );
}

/// The download page's files: (key char, fixture).
pub const PAGE_FILES: [(char, &str); 4] = [
    ('1', "inno-like.exe"),
    ('2', "fake.dmg"),
    ('3', "dist.zip"),
    ('4', "msi-like.msi"),
];

pub fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::Digest;
    sha1::Sha1::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The download page of [`PAGE_FILES`] with their real SHA-1.
pub fn world_page() -> String {
    let keys: Vec<String> = PAGE_FILES.iter().map(|(c, _)| key(*c)).collect();
    let sha1s: Vec<String> = PAGE_FILES
        .iter()
        .map(|(_, f)| sha1_hex(&read(fixture(&format!("upstream/{f}")))))
        .collect();
    page_html(
        [&keys[0], &keys[1], &keys[2], &keys[3]],
        [&sha1s[0], &sha1s[1], &sha1s[2], &sha1s[3]],
    )
}

/// Serves every file of the synthetic world; the manifest is `manifest_json` edited by
/// `edit`, signed.
pub fn serve_world(server: &MockServer, edit: impl FnOnce(String) -> String) {
    let json = manifest_json(server, edit);
    serve_manifest_and_page(server, signed(&json), &world_page());
    for (c, file) in PAGE_FILES {
        server.route(
            "GET",
            &format!("/download.php?key={}", key(c)),
            Response::ok(read(fixture(&format!("upstream/{file}")))).header(
                "Content-Disposition",
                &format!("attachment; filename={file}"),
            ),
        );
    }
    for (path, file) in [
        ("/updates/lite.exe", "lite.exe"),
        ("/updates/installer.sh", "installer.sh"),
        ("/updates/ncalayer.zip", "dist.zip"),
        ("/updates/jre/tzdb.dat", "tzdb.dat"),
        ("/updates/bundles/app.jar", "app.jar"),
        ("/updates/bundles/bundle-a.jar", "bundle-a.jar"),
    ] {
        server.route(
            "GET",
            path,
            Response::ok(read(fixture(&format!("upstream/{file}")))),
        );
    }
}

static NEXT_KEY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Serves the download page of [`PAGE_FILES`] as the original does: every load gives fresh
/// keys and the session cookie `sid=<sid>`; a key answers exactly one request of any method
/// (HEAD included) with that cookie and `referer`, after that (and for a key of another
/// server) 302 to `/404.php`, an HTML page. Tried before the routes of `server`.
pub fn serve_one_shot_page(server: &MockServer, sid: &str, referer: &str) {
    let keys: Arc<Mutex<BTreeMap<String, &'static str>>> = Arc::default();
    let cookie = format!("sid={sid}");
    let sha1s: Vec<String> = PAGE_FILES
        .iter()
        .map(|(_, f)| sha1_hex(&read(fixture(&format!("upstream/{f}")))))
        .collect();
    let page_keys = Arc::clone(&keys);
    let set_cookie = format!("{cookie}; Path=/");
    server.handler(move |r| {
        (r.method == "GET" && r.path() == "/").then(|| {
            let mut issued = page_keys.lock().unwrap();
            let fresh: Vec<String> = PAGE_FILES
                .iter()
                .map(|(_, file)| {
                    let k = format!(
                        "{:032x}",
                        NEXT_KEY.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    );
                    issued.insert(k.clone(), *file);
                    k
                })
                .collect();
            let html = page_html(
                [&fresh[0], &fresh[1], &fresh[2], &fresh[3]],
                [&sha1s[0], &sha1s[1], &sha1s[2], &sha1s[3]],
            );
            Response::html(html.into_bytes()).header("Set-Cookie", &set_cookie)
        })
    });
    let referer = referer.to_owned();
    server.handler(move |r| {
        (r.path() == "/download.php").then(|| {
            let file = r
                .target
                .split_once("key=")
                .and_then(|(_, k)| keys.lock().unwrap().remove(k));
            let session = r
                .headers
                .get("cookie")
                .is_some_and(|c| c.split(';').any(|p| p.trim() == cookie))
                && r.headers.get("referer") == Some(&referer);
            match file {
                Some(file) if session => Response::ok(read(fixture(&format!("upstream/{file}"))))
                    .header(
                        "Content-Disposition",
                        &format!("attachment; filename={file}"),
                    ),
                _ => Response::redirect("/404.php"),
            }
        })
    });
    server.route(
        "GET",
        "/404.php",
        Response::html(read(fixture("upstream/error.html"))),
    );
}
