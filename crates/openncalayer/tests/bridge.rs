//! The browser extension bridge over a real IPC endpoint: in process (`serve_ipc`) and, with
//! feature `e2e-prompter`, through the `openncalayer` binary.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures_util::{SinkExt, StreamExt};
use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_basics::{Basics, MODULE_NAME};
use oncl_ipc::{Endpoint, IpcStream, connect, endpoint, read_frame, write_frame};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::tsp::MockTsa;
use oncl_protocol::{AddInfo, HEARTBEAT, Module, Registry};
use oncl_testkit::{read, synthetic};
use oncl_tls::TlsFiles;
use openncalayer::{NM_FRAME_LIMIT, ServerConfig, build_registry, serve, serve_ipc, split_message};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::{Arc, Barrier, LazyLock, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

/// Upper bound for anything a test waits for; generous for unoptimized builds.
const PATIENCE: Duration = Duration::from_secs(120);
const GREETING: &str = r#"{"result":{"version":"1.4"}}"#;

// ---- fixtures ---------------------------------------------------------------------------

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password)
        .unwrap()
        .swap_remove(0)
}

fn storage(name: &str) -> Step {
    let key = synthetic(name);
    Step::Storage {
        path: key.path,
        password: key.password,
    }
}

/// The request of ncalayer-js-client 1.6.1 `basicsSignCMS(basicsStorageAll, data, params,
/// basicsSignerTestAny)`.
fn basics_sign_cms(data_b64: &str, signing_params: Value) -> String {
    json!({
        "module": "kz.gov.pki.knca.basics",
        "method": "sign",
        "args": {
            "allowedStorages": null,
            "format": "cms",
            "data": data_b64,
            "signingParams": signing_params,
            "signerParams": {"extKeyUsageOids": [], "chain": []},
            "locale": "ru",
        },
    })
    .to_string()
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

/// A fresh data directory, with sockets kept out of the user's runtime directory.
fn data_dir() -> TempDir {
    #[cfg(unix)]
    isolate_runtime_dir();
    tempfile::tempdir().expect("tempdir")
}

/// Points `XDG_RUNTIME_DIR` at a private test directory (also for the daemons the tests
/// start) so that sockets never land in the user's real runtime directory. Runs once, before
/// any endpoint of this binary is computed.
#[cfg(unix)]
fn isolate_runtime_dir() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    static ISOLATED: LazyLock<()> = LazyLock::new(|| {
        let probe = tempfile::tempdir().expect("probe tempdir");
        let uid = std::fs::metadata(probe.path())
            .expect("probe metadata")
            .uid();
        let dir = std::env::temp_dir().join(format!("oncl-bridge-rt-{uid}"));
        if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::AlreadyExists,
                "{}: {e}",
                dir.display()
            );
        }
        // SAFETY: other tests may run meanwhile, but this binary reads and inherits the
        // environment only through std (`env::var_os`, `env::temp_dir`, `Command`), which
        // takes the same environment lock as `set_var`; nothing calls libc `getenv` directly.
        // Every endpoint is computed after this ran (`data_dir` forces it).
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", &dir) };
    });
    LazyLock::force(&ISOLATED);
}

/// `serve_ipc` with `registry` on the endpoint of a fresh data directory.
async fn start_ipc(registry: Arc<Registry>) -> (TempDir, Endpoint) {
    let dir = data_dir();
    let ep = endpoint(dir.path()).unwrap();
    let listener = oncl_ipc::bind(&ep).await.unwrap();
    tokio::spawn(serve_ipc(listener, registry));
    (dir, ep)
}

/// The daemon's registry answering dialogs with `steps`.
fn scripted_registry(steps: Vec<Step>) -> (Arc<Registry>, Arc<ScriptedPrompter>) {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let registry = build_registry(
        prompter.clone(),
        Arc::new(MemoryRecentPath::new(None)),
        Arc::new(MockTsa::new(entry("tsa-gost2015"))),
        Arc::new(|_| {}),
    );
    (Arc::new(registry), prompter)
}

// ---- bridge client ----------------------------------------------------------------------

/// The relay's side of an IPC connection.
struct Client(IpcStream);

impl Client {
    /// Connects and checks the `hello` frame.
    async fn connect(ep: &Endpoint) -> Client {
        let mut c = Client(connect(ep).await.unwrap());
        let hello = c.next().await;
        assert_eq!(hello["t"], "hello", "{hello}");
        c
    }

    async fn send(&mut self, frame: &Value) {
        write_frame(&mut self.0, frame.to_string().as_bytes())
            .await
            .unwrap();
    }

    async fn next_raw(&mut self) -> String {
        self.next_raw_within(PATIENCE).await
    }

    /// The next frame, which must come within `limit` and fit a native message.
    async fn next_raw_within(&mut self, limit: Duration) -> String {
        let frame = timeout(limit, read_frame(&mut self.0))
            .await
            .expect("no frame in time")
            .unwrap()
            .expect("connection closed");
        assert!(
            frame.len() <= NM_FRAME_LIMIT,
            "frame of {} bytes",
            frame.len()
        );
        String::from_utf8(frame).unwrap()
    }

    async fn next(&mut self) -> Value {
        json(&self.next_raw().await)
    }

    /// Opens `sid` and checks the reply and the greeting.
    async fn open(&mut self, sid: u32, origin: &str) {
        self.send(
            &json!({"t": "open", "sid": sid, "origin": origin, "url": format!("{origin}/page")}),
        )
        .await;
        assert_eq!(
            self.next_raw().await,
            format!(r#"{{"t":"open","sid":{sid}}}"#)
        );
        assert_eq!(self.message(sid).await, GREETING);
    }

    /// Sends `text` to `sid` in one frame.
    async fn send_text(&mut self, sid: u32, text: &str) {
        self.send(&json!({"t": "msg", "sid": sid, "data": text}))
            .await;
    }

    /// The next message, which must be for `sid`.
    async fn message(&mut self, sid: u32) -> String {
        let mut text = String::new();
        loop {
            let frame = self.next().await;
            assert_eq!(frame["t"], "msg", "{frame}");
            assert_eq!(frame["sid"], sid, "{frame}");
            text.push_str(frame["data"].as_str().unwrap());
            match frame.get("more") {
                None => return text,
                Some(more) => assert_eq!(more, true, "{frame}"),
            }
        }
    }

    async fn call(&mut self, sid: u32, text: &str) -> String {
        self.send_text(sid, text).await;
        self.message(sid).await
    }
}

// ---- wss client, for replies to compare with ----------------------------------------------

struct Wss {
    addr: SocketAddr,
    ca_der: Vec<u8>,
    _dir: TempDir,
}

async fn start_wss(registry: Arc<Registry>) -> Wss {
    let dir = tempfile::tempdir().unwrap();
    let material = oncl_tls::generate(OffsetDateTime::now_utc(), "bridge").unwrap();
    let files = TlsFiles {
        dir: dir.path().join("tls"),
    };
    oncl_tls::save(&files, &material).unwrap();
    let tls = Arc::new(oncl_tls::server_config(&files).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, ServerConfig::new(tls, registry)));
    Wss {
        addr,
        ca_der: material.ca_der.unwrap(),
        _dir: dir,
    }
}

type WsClient = WebSocketStream<TlsStream<TcpStream>>;

async fn wss_connect(addr: SocketAddr, ca_der: &[u8]) -> WsClient {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der.to_vec())).unwrap();
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await
        .unwrap();
    let request = format!("wss://127.0.0.1:{}/", addr.port())
        .into_client_request()
        .unwrap();
    let config = WebSocketConfig::default()
        .max_message_size(None)
        .max_frame_size(None);
    let mut ws = tokio_tungstenite::client_async_with_config(request, tls, Some(config))
        .await
        .unwrap()
        .0;
    assert_eq!(wss_next(&mut ws).await, GREETING);
    ws
}

async fn wss_next(ws: &mut WsClient) -> String {
    loop {
        let message = timeout(PATIENCE, ws.next())
            .await
            .expect("no message in time")
            .expect("connection closed")
            .unwrap();
        match message {
            Message::Text(text) => return text.as_str().to_owned(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected message {other:?}"),
        }
    }
}

async fn wss_call(ws: &mut WsClient, text: &str) -> String {
    ws.send(Message::text(text)).await.unwrap();
    wss_next(ws).await
}

// ---- in-process tests ---------------------------------------------------------------------

#[tokio::test]
async fn hello_then_open_then_greeting() {
    let (registry, _) = scripted_registry(vec![]);
    let (_dir, ep) = start_ipc(registry).await;
    let mut c = Client(connect(&ep).await.unwrap());
    assert_eq!(
        c.next_raw().await,
        format!(
            r#"{{"t":"hello","v":1,"version":"{}","compat":"1.4"}}"#,
            env!("CARGO_PKG_VERSION")
        )
    );
    c.send(&json!({"t": "open", "sid": 1, "origin": "https://a.test", "url": "https://a.test/"}))
        .await;
    assert_eq!(c.next_raw().await, r#"{"t":"open","sid":1}"#);
    assert_eq!(
        c.next_raw().await,
        r#"{"t":"msg","sid":1,"data":"{\"result\":{\"version\":\"1.4\"}}"}"#
    );
}

#[tokio::test]
async fn heartbeat_and_module_not_found() {
    let (registry, _) = scripted_registry(vec![]);
    let wss = start_wss(registry.clone()).await;
    let (_dir, ep) = start_ipc(registry).await;
    let mut ws = wss_connect(wss.addr, &wss.ca_der).await;
    let mut c = Client::connect(&ep).await;
    c.open(1, "https://a.test").await;
    let unknown = r#"{"module":"kz.digiflow.mobile.extensions","method":"getVersion"}"#;
    for request in [HEARTBEAT, unknown] {
        let over_wss = wss_call(&mut ws, request).await;
        assert_eq!(c.call(1, request).await, over_wss);
    }
    assert_eq!(c.call(1, HEARTBEAT).await, HEARTBEAT);
    assert_eq!(
        c.call(1, unknown).await,
        r#"{"success":false,"errorCode":"MODULE_NOT_FOUND"}"#
    );
}

/// Records the `addInfo` of each call.
#[derive(Default)]
struct Capture(Mutex<Vec<AddInfo>>);

impl Module for Capture {
    fn process(&self, _request: &str, add_info: &AddInfo) -> String {
        self.0.lock().unwrap().push(add_info.clone());
        r#"{"captured":true}"#.to_owned()
    }
}

#[tokio::test]
async fn origin_reaches_add_info() {
    let capture = Arc::new(Capture::default());
    let mut registry = Registry::default();
    registry.register("test.capture", capture.clone());
    let (_dir, ep) = start_ipc(Arc::new(registry)).await;
    let mut c = Client::connect(&ep).await;
    c.open(1, "https://first.test").await;
    c.open(2, "https://second.test").await;
    let request = r#"{"module":"test.capture"}"#;
    assert_eq!(c.call(2, request).await, r#"{"captured":true}"#);
    assert_eq!(c.call(1, request).await, r#"{"captured":true}"#);
    let origins: Vec<Option<String>> = capture
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|info| info.origin.clone())
        .collect();
    assert_eq!(
        origins,
        [
            Some("https://second.test".to_owned()),
            Some("https://first.test".to_owned())
        ]
    );
}

const INSTALL_BUNDLE: &str = r#"{"module":"kz.gov.pki.ncalayerservices.accessory","method":"installBundle","symname":"kz.x"}"#;
/// The original's reply when the connection has no `Origin` (its headers are
/// `{"origin":null}`).
const NO_ORIGIN: &str =
    r#"{"errorCode":"org.json.JSONException: JSONObject[\"origin\"] is not a string."}"#;

#[tokio::test]
async fn accessory_lists_the_daemon_modules() {
    let (registry, _) = scripted_registry(Vec::new());
    // Every module of the registry, the accessory included: none is registered after it.
    let names = registry.names();
    assert!(names.contains(&"kz.gov.pki.ncalayerservices.accessory".to_owned()));
    let (_dir, ep) = start_ipc(registry).await;
    let mut c = Client::connect(&ep).await;
    c.open(1, "https://page.test").await;
    let reply = c
        .call(
            1,
            r#"{"module":"kz.gov.pki.ncalayerservices.accessory","method":"getServices","uuid":"u"}"#,
        )
        .await;
    assert_eq!(
        json(&reply),
        serde_json::json!({"services": names, "uuid": "u"})
    );
    assert_eq!(
        json(&c.call(1, INSTALL_BUNDLE).await),
        serde_json::json!({"errorCode": "BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED"})
    );
}

#[tokio::test]
async fn accessory_without_origin_over_the_bridge() {
    let (registry, _) = scripted_registry(Vec::new());
    let (_dir, ep) = start_ipc(registry).await;
    let mut c = Client::connect(&ep).await;
    c.send(&json!({"t": "open", "sid": 1, "origin": null}))
        .await;
    assert_eq!(c.next_raw().await, r#"{"t":"open","sid":1}"#);
    assert_eq!(c.message(1).await, GREETING);
    assert_eq!(c.call(1, INSTALL_BUNDLE).await, NO_ORIGIN);
}

#[tokio::test]
async fn accessory_without_origin_over_wss() {
    let (registry, _) = scripted_registry(Vec::new());
    let wss = start_wss(registry).await;
    // The client sends no `Origin` header.
    let mut ws = wss_connect(wss.addr, &wss.ca_der).await;
    assert_eq!(wss_call(&mut ws, INSTALL_BUNDLE).await, NO_ORIGIN);
}

/// The time of the first call, ever after: CMS replies of two calls are byte-equal.
fn fixed_clock() -> OffsetDateTime {
    static AT: LazyLock<OffsetDateTime> = LazyLock::new(OffsetDateTime::now_utc);
    *AT
}

#[tokio::test]
async fn large_reply_is_chunked_and_reassembles() {
    // RSA PKCS#1 v1.5 signatures and a fixed signing time: the same call gives the same reply.
    let prompter = Arc::new(ScriptedPrompter::new(vec![
        storage("user-rsa-sign"),
        Step::Key(0),
        storage("user-rsa-sign"),
        Step::Key(0),
    ]));
    let mut registry = Registry::default();
    registry.register(
        MODULE_NAME,
        Arc::new(
            Basics::new(
                prompter,
                Arc::new(MemoryRecentPath::new(None)),
                Arc::new(MockTsa::new(entry("tsa-gost2015"))),
            )
            .with_clock(fixed_clock),
        ),
    );
    let registry = Arc::new(registry);
    let wss = start_wss(registry.clone()).await;
    let (_dir, ep) = start_ipc(registry).await;

    let data: Vec<u8> = (0..1_500_000usize).map(|i| (i % 251) as u8).collect();
    let params = json!({"decode": true, "encapsulate": true, "digested": false});
    let request = basics_sign_cms(&STANDARD.encode(&data), params);
    let mut ws = wss_connect(wss.addr, &wss.ca_der).await;
    let over_wss = wss_call(&mut ws, &request).await;
    assert_eq!(json(&over_wss)["status"], true, "{over_wss:.300}");

    let mut c = Client::connect(&ep).await;
    c.open(1, "https://a.test").await;
    c.send_text(1, &request).await;
    let mut frames = Vec::new();
    loop {
        let raw = c.next_raw().await;
        assert!(raw.len() <= NM_FRAME_LIMIT);
        let frame = json(&raw);
        frames.push(frame.clone());
        if frame.get("more").is_none() {
            break;
        }
    }
    assert!(
        frames.len() > 1,
        "a reply over 2 MB in {} frame",
        frames.len()
    );
    let (last, rest) = frames.split_last().unwrap();
    for frame in rest {
        assert_eq!(frame["more"], true);
    }
    assert!(last.get("more").is_none());
    let reassembled: String = frames
        .iter()
        .map(|frame| {
            assert_eq!(frame["t"], "msg");
            assert_eq!(frame["sid"], 1);
            frame["data"].as_str().unwrap()
        })
        .collect();
    assert_eq!(reassembled.len(), over_wss.len());
    assert!(
        reassembled == over_wss,
        "the bridge reply differs from the wss reply"
    );
}

#[tokio::test]
async fn inbound_40_mib_request_in_8_mib_pieces() {
    let (registry, _) = scripted_registry(vec![storage("user-gost2015-sign"), Step::Key(0)]);
    let (_dir, ep) = start_ipc(registry).await;
    let mut c = Client::connect(&ep).await;
    c.open(1, "https://a.test").await;
    let data: Vec<u8> = (0..40usize << 20).map(|i| (i % 251) as u8).collect();
    let params = json!({"decode": true, "encapsulate": true, "digested": false, "tsaProfile": {}});
    let request = basics_sign_cms(&STANDARD.encode(&data), params);
    assert!(request.len() > 53 << 20);
    // Base64 and JSON punctuation: one byte per UTF-16 code unit.
    let pieces: Vec<&str> = request
        .as_bytes()
        .chunks(8 << 20)
        .map(|piece| std::str::from_utf8(piece).unwrap())
        .collect();
    let (last, rest) = pieces.split_last().unwrap();
    for piece in rest {
        c.send(&json!({"t": "msg", "sid": 1, "data": piece, "more": true}))
            .await;
    }
    c.send(&json!({"t": "msg", "sid": 1, "data": last})).await;
    let reply = c.message(1).await;
    assert!(reply.len() > 55 << 20, "reply of {} bytes", reply.len());
    let reply = json(&reply);
    assert_eq!(reply["status"], true);
    let pem = reply["body"]["result"][0].as_str().unwrap();
    assert!(pem.starts_with("-----BEGIN CMS-----"));
}

#[test]
fn split_respects_char_boundaries_and_escaping() {
    const LIMIT: usize = 1000;
    // Every cut position meets 'ж' (2 bytes), '\u{1}' (6 bytes escaped) and the two-byte
    // escapes for some prefix length.
    let unit = "ж\u{1}ab\"\\\nж";
    for prefix in 0..16 {
        let text: String = "x".repeat(prefix) + &unit.repeat(400);
        let frames = split_message(7, &text, LIMIT);
        assert!(frames.len() > 1);
        let mut joined = String::new();
        for (i, raw) in frames.iter().enumerate() {
            assert!(raw.len() <= LIMIT, "frame {i} of {} bytes", raw.len());
            let frame = json(raw);
            assert_eq!(frame["t"], "msg");
            assert_eq!(frame["sid"], 7);
            if i + 1 < frames.len() {
                assert_eq!(frame["more"], true, "{raw}");
                // Full up to the longest escape (6 bytes) that did not fit.
                assert!(raw.len() > LIMIT - 6, "frame {i} of {} bytes", raw.len());
            } else {
                assert!(frame.get("more").is_none(), "{raw}");
            }
            joined.push_str(frame["data"].as_str().unwrap());
        }
        assert_eq!(joined, text, "prefix {prefix}");
    }
}

#[tokio::test]
async fn invalid_json_closes_only_that_sid() {
    let (registry, _) = scripted_registry(vec![]);
    let (_dir, ep) = start_ipc(registry).await;
    let mut c = Client::connect(&ep).await;
    c.open(1, "https://a.test").await;
    c.open(2, "https://b.test").await;
    c.send_text(1, "nope").await;
    assert_eq!(c.next_raw().await, r#"{"t":"close","sid":1}"#);
    // sid 1 is gone: its messages are ignored; sid 2 answers.
    c.send_text(1, HEARTBEAT).await;
    assert_eq!(c.call(2, HEARTBEAT).await, HEARTBEAT);
}

/// A module that panics.
struct Panics;

impl Module for Panics {
    fn process(&self, _request: &str, _add_info: &AddInfo) -> String {
        panic!("test module panics on purpose");
    }
}

#[tokio::test]
async fn module_panic_closes_only_that_sid() {
    let mut registry = Registry::default();
    registry.register("test.panics", Arc::new(Panics));
    let (_dir, ep) = start_ipc(Arc::new(registry)).await;
    let mut c = Client::connect(&ep).await;
    c.open(1, "https://a.test").await;
    c.open(2, "https://b.test").await;
    c.send_text(1, r#"{"module":"test.panics"}"#).await;
    assert_eq!(c.next_raw().await, r#"{"t":"close","sid":1}"#);
    assert_eq!(c.call(2, HEARTBEAT).await, HEARTBEAT);
    // The daemon goes on: sid 1 may be opened again.
    c.open(1, "https://a.test").await;
    assert_eq!(c.call(1, HEARTBEAT).await, HEARTBEAT);
}

/// Releases the scripted dialog's barrier when dropped, also while a test unwinds, from a
/// detached thread so that dropping never blocks.
struct Release(Arc<Barrier>);

impl Drop for Release {
    fn drop(&mut self) {
        let barrier = Arc::clone(&self.0);
        std::thread::spawn(move || {
            barrier.wait();
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_sid_not_blocked_by_open_dialog() {
    let signal = Arc::new(Barrier::new(2));
    let (registry, prompter) = scripted_registry(vec![
        Step::Wait(signal.clone()),
        storage("user-gost2015-sign"),
        Step::Key(0),
    ]);
    let (_dir, ep) = start_ipc(registry).await;
    let mut c = Client::connect(&ep).await;
    c.open(1, "https://first.test").await;
    let release = Release(signal);
    let params = json!({"decode": true, "encapsulate": false, "digested": false, "tsaProfile": {}});
    c.send_text(1, &basics_sign_cms(&STANDARD.encode(b"tab"), params))
        .await;
    let deadline = Instant::now() + PATIENCE;
    while prompter.storage_prompts().is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let first_shown = !prompter.storage_prompts().is_empty();

    // Observe everything first, release the dialog, assert afterwards.
    let started = Instant::now();
    let within = Duration::from_secs(2);
    c.send(&json!({"t": "open", "sid": 2, "origin": "https://second.test"}))
        .await;
    let opened = c.next_raw_within(within).await;
    let greeting = c.next_raw_within(within).await;
    c.send_text(2, HEARTBEAT).await;
    let heartbeat = c.next_raw_within(within).await;
    let elapsed = started.elapsed();
    drop(release);

    assert!(first_shown, "the first dialog never opened");
    assert_eq!(opened, r#"{"t":"open","sid":2}"#);
    assert_eq!(
        json(&greeting),
        json!({"t": "msg", "sid": 2, "data": GREETING})
    );
    assert_eq!(
        json(&heartbeat),
        json!({"t": "msg", "sid": 2, "data": HEARTBEAT})
    );
    assert!(elapsed < within, "{elapsed:?}");
    let reply = json(&c.message(1).await);
    assert_eq!(reply["status"], true, "{reply}");
    assert_eq!(prompter.storage_prompts()[0].origin, "https://first.test");
}

#[tokio::test]
async fn unknown_type_and_unknown_sid_are_ignored() {
    let (registry, _) = scripted_registry(vec![]);
    let (_dir, ep) = start_ipc(registry).await;
    let mut c = Client::connect(&ep).await;
    c.send(&json!({"t": "future", "sid": 1, "data": [1, 2]}))
        .await;
    c.send_text(9, HEARTBEAT).await;
    c.send(&json!({"t": "close", "sid": 9})).await;
    // Nothing came back for those: the next frames are the replies to sid 1.
    c.open(1, "https://a.test").await;
    assert_eq!(c.call(1, HEARTBEAT).await, HEARTBEAT);
}

#[tokio::test]
async fn duplicate_open_closes_sid() {
    let (registry, _) = scripted_registry(vec![]);
    let (_dir, ep) = start_ipc(registry).await;
    let mut c = Client::connect(&ep).await;
    c.open(1, "https://a.test").await;
    c.send(&json!({"t": "open", "sid": 1, "origin": "https://a.test"}))
        .await;
    assert_eq!(c.next_raw().await, r#"{"t":"close","sid":1}"#);
    c.send_text(1, HEARTBEAT).await;
    c.open(2, "https://b.test").await;
    assert_eq!(c.call(2, HEARTBEAT).await, HEARTBEAT);
    // A closed sid may be opened again.
    c.open(1, "https://a.test").await;
    assert_eq!(c.call(1, HEARTBEAT).await, HEARTBEAT);
}

#[tokio::test]
async fn closed_sid_is_forgotten() {
    let (registry, _) = scripted_registry(vec![]);
    let (_dir, ep) = start_ipc(registry).await;
    let mut c = Client::connect(&ep).await;
    c.open(1, "https://a.test").await;
    c.send(&json!({"t": "close", "sid": 1})).await;
    c.send_text(1, HEARTBEAT).await;
    // Neither a reply nor a close for sid 1: the next frame opens sid 2.
    c.open(2, "https://b.test").await;
    c.open(1, "https://a.test").await;
    assert_eq!(c.call(1, HEARTBEAT).await, HEARTBEAT);
}

#[tokio::test]
async fn client_eof_ends_session_cleanly() {
    let (registry, _) = scripted_registry(vec![]);
    let (_dir, ep) = start_ipc(registry).await;
    let mut c = Client::connect(&ep).await;
    c.open(1, "https://a.test").await;
    #[cfg(unix)]
    {
        // The end of the relay's stream ends the connection: the daemon closes its side.
        tokio::io::AsyncWriteExt::shutdown(&mut c.0).await.unwrap();
        let end = timeout(PATIENCE, read_frame(&mut c.0))
            .await
            .expect("the daemon kept the connection open");
        assert!(matches!(end, Ok(None)), "{end:?}");
    }
    drop(c);
    // The daemon serves the next relay; sids belong to their connection.
    let mut c = Client::connect(&ep).await;
    c.open(1, "https://a.test").await;
    assert_eq!(c.call(1, HEARTBEAT).await, HEARTBEAT);
}

// ---- the binary -------------------------------------------------------------------------

#[cfg(feature = "e2e-prompter")]
mod binary {
    use super::*;
    use std::io::Read;
    use std::path::Path;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicU16, Ordering};

    /// A data directory for a daemon: no TLS, an empty dialog script.
    fn daemon_dir() -> TempDir {
        let dir = data_dir();
        write_steps(dir.path(), &json!([]));
        dir
    }

    fn write_steps(data: &Path, steps: &Value) {
        std::fs::write(data.join("steps.json"), steps.to_string()).unwrap();
    }

    /// Sets TLS up in `data`; the local CA's certificate.
    fn configure_tls(data: &Path) -> Vec<u8> {
        let material = oncl_tls::generate(OffsetDateTime::now_utc(), "bridge").unwrap();
        let files = TlsFiles {
            dir: data.join("tls"),
        };
        oncl_tls::save(&files, &material).unwrap();
        material.ca_der.unwrap()
    }

    /// `openncalayer <args>` on `data`, listening on `port` if it serves wss, answering
    /// dialogs from `<data>/steps.json`. Its output goes nowhere: assertions read the log
    /// files, and an undrained pipe would block the daemon once full.
    fn daemon(data: &Path, port: u16, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_openncalayer"));
        command
            .args(args)
            .env("ONCL_DATA_DIR", data)
            .env("NCALAYERPORT", port.to_string())
            .env("ONCL_E2E_PROMPTER", data.join("steps.json"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    /// Ports of the range `NCALAYERPORT` accepts, never 13579 (a real NCALayer may run).
    const FIRST_PORT: u16 = 13580;
    const PORTS: u16 = 100;

    /// A free port of 13580..=13679 that no other test of this binary got, held. Ports are
    /// handed out in turn, so tests running at the same time never share one.
    fn hold_port() -> (u16, std::net::TcpListener) {
        static NEXT: AtomicU16 = AtomicU16::new(0);
        (0..PORTS)
            .find_map(|_| {
                let port = FIRST_PORT + NEXT.fetch_add(1, Ordering::Relaxed) % PORTS;
                std::net::TcpListener::bind(("127.0.0.1", port))
                    .ok()
                    .map(|l| (port, l))
            })
            .expect("a free port in 13580..=13679")
    }

    /// A port of [`hold_port`], released for a daemon to bind.
    fn free_port() -> u16 {
        hold_port().0
    }

    /// Runs `command` to its end (at most [`PATIENCE`]); its exit code and stderr.
    fn exit_of(mut command: Command) -> (ExitStatus, String) {
        let mut child = command.stderr(Stdio::piped()).spawn().unwrap();
        // Drained while the daemon runs, so that it never blocks on a full pipe.
        let mut pipe = child.stderr.take().unwrap();
        let stderr = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = pipe.read_to_string(&mut text);
            text
        });
        let deadline = Instant::now() + PATIENCE;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("the daemon did not exit");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        (status, stderr.join().unwrap())
    }

    /// A running daemon, killed on drop.
    struct Running {
        child: Child,
        #[cfg_attr(not(unix), allow(dead_code))]
        ep: Endpoint,
    }

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            // A killed daemon leaves its socket and lock files.
            #[cfg(unix)]
            {
                let socket = self.ep.to_string();
                let _ = std::fs::remove_file(&socket);
                let _ = std::fs::remove_file(format!("{socket}.lock"));
            }
        }
    }

    /// Starts `command` and waits until its bridge says hello.
    async fn start(mut command: Command, data: &Path) -> (Running, Client) {
        let ep = endpoint(data).unwrap();
        let mut running = Running {
            child: command.spawn().unwrap(),
            ep: ep.clone(),
        };
        let deadline = Instant::now() + PATIENCE;
        loop {
            if let Some(status) = running.child.try_wait().unwrap() {
                panic!("the daemon exited with {status}; its log:\n{}", logs(data));
            }
            if let Ok(stream) = connect(&ep).await {
                let mut c = Client(stream);
                let hello = c.next().await;
                assert_eq!(hello["t"], "hello", "{hello}");
                return (running, c);
            }
            assert!(Instant::now() < deadline, "the bridge never came up");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn second_daemon_exits_4() {
        let dir = daemon_dir();
        let port = free_port();
        runtime().block_on(async {
            let (_first, _c) = start(
                daemon(dir.path(), port, &["run", "--allow-no-wss"]),
                dir.path(),
            )
            .await;
            // Already running wins over TLS not being set up (2).
            let (status, stderr) = exit_of(daemon(dir.path(), port, &["run"]));
            assert_eq!(status.code(), Some(4), "{stderr}");
            assert!(stderr.contains("OpenNCALayer уже запущен"), "{stderr}");
        });
    }

    #[test]
    fn no_tls_without_flag_exits_2_with_flag_serves_ipc() {
        let dir = daemon_dir();
        let port = free_port();
        let (status, stderr) = exit_of(daemon(dir.path(), port, &["run"]));
        assert_eq!(status.code(), Some(2), "{stderr}");
        assert!(stderr.contains("TLS не настроен"), "{stderr}");

        let key = synthetic("user-gost2015-sign");
        write_steps(
            dir.path(),
            &json!([{"storage": {"path": key.path, "password": key.password}}, {"key": 0}]),
        );
        runtime().block_on(async {
            let (_daemon, mut c) = start(
                daemon(dir.path(), port, &["run", "--allow-no-wss"]),
                dir.path(),
            )
            .await;
            c.open(1, "https://binary.test").await;
            // No `tsaProfile`: no time-stamp, no network.
            let params = json!({"decode": true, "encapsulate": false, "digested": false});
            let reply = c
                .call(1, &basics_sign_cms(&STANDARD.encode(b"binary"), params))
                .await;
            let reply = json(&reply);
            assert_eq!(reply["status"], true, "{reply}");
            assert!(
                reply["body"]["result"][0]
                    .as_str()
                    .unwrap()
                    .starts_with("-----BEGIN CMS-----")
            );
            // The script is used up: the next dialog counts as cancelled.
            let reply = c
                .call(1, &basics_sign_cms(&STANDARD.encode(b"again"), json!({})))
                .await;
            assert_eq!(json(&reply)["body"], json!({}), "{reply}");
        });
        let log = logs(dir.path());
        assert!(log.contains("sid=1"), "{log}");
        assert!(log.contains("origin=https://binary.test"), "{log}");
        assert!(log.contains("wss is off"), "{log}");
    }

    /// The text of the daemon's log files under `data`.
    fn logs(data: &Path) -> String {
        let Ok(entries) = std::fs::read_dir(data.join("logs")) else {
            return String::new();
        };
        entries
            .map(|entry| std::fs::read_to_string(entry.unwrap().path()).unwrap())
            .collect()
    }

    #[test]
    fn broken_tls_exits_1_with_flag_serves_ipc() {
        // A corrupt `tls.json`; a corrupt server key under a valid `tls.json`.
        let breakages = [
            ("tls.json", "{garbage"),
            ("server.key", "-----BEGIN PRIVATE KEY-----\nAAAA\n"),
        ];
        for (broken, content) in breakages {
            let dir = daemon_dir();
            configure_tls(dir.path());
            std::fs::write(dir.path().join("tls").join(broken), content).unwrap();
            let port = free_port();
            let (status, stderr) = exit_of(daemon(dir.path(), port, &["run"]));
            assert_eq!(status.code(), Some(1), "{broken}: {stderr}");
            assert!(stderr.contains("Не удалось"), "{broken}: {stderr}");
            runtime().block_on(async {
                let (_daemon, mut c) = start(
                    daemon(dir.path(), port, &["run", "--allow-no-wss"]),
                    dir.path(),
                )
                .await;
                c.open(1, "https://a.test").await;
                assert_eq!(c.call(1, HEARTBEAT).await, HEARTBEAT);
                // Nothing listens on the port.
                assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
            });
            let log = logs(dir.path());
            assert!(log.contains("wss is off"), "{broken}: {log}");
            assert!(log.contains("code=1"), "{broken}: {log}");
        }
    }

    #[test]
    fn busy_port_with_flag_serves_ipc() {
        let dir = daemon_dir();
        configure_tls(dir.path());
        let (port, _held) = hold_port();
        let (status, stderr) = exit_of(daemon(dir.path(), port, &["run"]));
        assert_eq!(status.code(), Some(3), "{stderr}");
        assert!(stderr.contains(&format!("Порт {port} занят")), "{stderr}");
        runtime().block_on(async {
            let (_daemon, mut c) = start(
                daemon(dir.path(), port, &["run", "--allow-no-wss"]),
                dir.path(),
            )
            .await;
            c.open(1, "https://a.test").await;
            assert_eq!(c.call(1, HEARTBEAT).await, HEARTBEAT);
        });
    }

    #[test]
    fn serves_wss_and_ipc_together() {
        let dir = daemon_dir();
        let ca_der = configure_tls(dir.path());
        let port = free_port();
        runtime().block_on(async {
            let (_daemon, mut c) = start(daemon(dir.path(), port, &["run"]), dir.path()).await;
            c.open(1, "https://a.test").await;
            let mut ws = wss_connect(SocketAddr::from(([127, 0, 0, 1], port)), &ca_der).await;
            assert_eq!(wss_call(&mut ws, HEARTBEAT).await, HEARTBEAT);
            assert_eq!(c.call(1, HEARTBEAT).await, HEARTBEAT);
        });
    }
}
