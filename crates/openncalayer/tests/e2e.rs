//! The daemon end to end: a server on `127.0.0.1:0` with a freshly generated local CA, a
//! `tokio-tungstenite` client over its own `tokio-rustls` stream trusting that CA, a scripted
//! prompter and an in-process TSA.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures_util::{SinkExt, StreamExt};
use oncl_basics::RecentPathStore;
use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_pki::cert;
use oncl_pki::cms::{SignOptions, sign, verify};
use oncl_pki::key::SigAlg;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::CaSet;
use oncl_pki::tsp::{MockTsa, TsaProfile, timestamp_signer, verify_token};
use oncl_protocol::{AddInfo, DynamicModules, Module, Registry, Reply, SessionId};
use oncl_testkit::{read, synthetic, synthetic_cert};
use oncl_tls::{SelftestReports, TlsFiles};
use openncalayer::cms_verify::{NOT_CHECKED, Options, cms_verify_report_with};
use openncalayer::{JsonSettings, LiveTls, ServerConfig, build_registry, listen_port_from, serve};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

const ORIGIN: &str = "https://e2e.test";
/// Upper bound for anything a test waits for; generous for unoptimized builds.
const PATIENCE: Duration = Duration::from_secs(120);

/// `basicsCMSParamsDetached` of ncalayer-js-client 1.6.1.
fn cms_params_detached() -> Value {
    json!({"decode": true, "encapsulate": false, "digested": false, "tsaProfile": {}})
}

/// `basicsCMSParamsAttached` of ncalayer-js-client 1.6.1.
fn cms_params_attached() -> Value {
    json!({"decode": true, "encapsulate": true, "digested": false, "tsaProfile": {}})
}

/// The request of ncalayer-js-client 1.6.1 `basicsSignCMS(basicsStorageAll, data, params,
/// basicsSignerTestAny)` with its default locale.
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

fn pem_to_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    STANDARD.decode(body).unwrap()
}

struct Srv {
    addr: SocketAddr,
    ca_der: Vec<u8>,
    prompter: Arc<ScriptedPrompter>,
    tsa: Arc<MockTsa>,
    tls: Arc<LiveTls>,
    reports: Arc<SelftestReports>,
    _dir: TempDir,
}

async fn start(steps: Vec<Step>) -> Srv {
    start_with(steps, |_| {}).await
}

/// [`start`] with `extra` modules registered besides the daemon's.
async fn start_with(steps: Vec<Step>, extra: impl FnOnce(&mut Registry)) -> Srv {
    let dir = tempfile::tempdir().unwrap();
    let material = oncl_tls::generate(OffsetDateTime::now_utc(), "e2e").unwrap();
    let files = TlsFiles {
        dir: dir.path().join("tls"),
    };
    oncl_tls::save(&files, &material).unwrap();
    let tls = Arc::new(LiveTls::new(Arc::new(
        oncl_tls::server_config(&files).unwrap(),
    )));
    let reports = Arc::new(SelftestReports::new());
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let mut registry = build_registry(
        prompter.clone(),
        Arc::new(MemoryRecentPath::new(None)),
        tsa.clone(),
        oncl_token::Tokens::disabled(),
        Arc::new(|_| {}),
        None,
    );
    extra(&mut registry);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        ServerConfig {
            selftest: Arc::clone(&reports),
            ..ServerConfig::new(Arc::clone(&tls), Arc::new(registry))
        },
    ));
    Srv {
        addr,
        ca_der: material.ca_der.unwrap(),
        prompter,
        tsa,
        tls,
        reports,
        _dir: dir,
    }
}

async fn tls_connect(srv: &Srv) -> TlsStream<TcpStream> {
    tls_connect_trusting(srv, &srv.ca_der).await
}

/// A TLS connection to `srv` from a client that trusts the CA `ca_der`.
async fn tls_connect_trusting(srv: &Srv, ca_der: &[u8]) -> TlsStream<TcpStream> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der.to_vec())).unwrap();
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let tcp = TcpStream::connect(srv.addr).await.unwrap();
    TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await
        .unwrap()
}

type Client = WebSocketStream<TlsStream<TcpStream>>;

async fn connect_from(srv: &Srv, origin: &str) -> Client {
    websocket_over(srv, tls_connect(srv).await, origin).await
}

/// The WebSocket handshake from `origin` over `stream`.
async fn websocket_over(srv: &Srv, stream: TlsStream<TcpStream>, origin: &str) -> Client {
    let mut request = format!("wss://127.0.0.1:{}/", srv.addr.port())
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("Origin", HeaderValue::from_str(origin).unwrap());
    // No limits: an attached-PEM reply to 40 MiB of data is about 55 MiB.
    let config = WebSocketConfig::default()
        .max_message_size(None)
        .max_frame_size(None);
    tokio_tungstenite::client_async_with_config(request, stream, Some(config))
        .await
        .unwrap()
        .0
}

async fn connect(srv: &Srv) -> Client {
    connect_from(srv, ORIGIN).await
}

async fn send(c: &mut Client, text: &str) {
    c.send(Message::text(text)).await.unwrap();
}

async fn next_text(c: &mut Client) -> String {
    next_text_within(c, PATIENCE).await
}

async fn next_text_within(c: &mut Client, limit: Duration) -> String {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        let message = tokio::time::timeout_at(deadline, c.next())
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

fn json(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

#[tokio::test]
async fn greeting_then_heartbeat() {
    let srv = start(vec![]).await;
    let mut c = connect(&srv).await;
    assert_eq!(next_text(&mut c).await, r#"{"result":{"version":"1.4"}}"#);
    send(&mut c, "--heartbeat--").await;
    assert_eq!(next_text(&mut c).await, "--heartbeat--");
}

#[tokio::test]
async fn unknown_module() {
    let srv = start(vec![]).await;
    let mut c = connect(&srv).await;
    next_text(&mut c).await;
    send(
        &mut c,
        r#"{"module":"kz.digiflow.mobile.extensions","method":"getVersion"}"#,
    )
    .await;
    assert_eq!(
        next_text(&mut c).await,
        r#"{"success":false,"errorCode":"MODULE_NOT_FOUND"}"#
    );
}

/// Dynamic modules serving nothing that record what they are told.
#[derive(Default)]
struct Recorder {
    missing: Mutex<Vec<(String, AddInfo)>>,
    closed: Mutex<Vec<SessionId>>,
}

impl DynamicModules for Recorder {
    fn module(&self, _: &str) -> Option<Arc<dyn Module>> {
        None
    }

    fn names(&self) -> Vec<String> {
        Vec::new()
    }

    fn session_closed(&self, session: SessionId) {
        self.closed.lock().unwrap().push(session);
    }

    fn missing(&self, name: &str, add_info: &AddInfo) {
        self.missing
            .lock()
            .unwrap()
            .push((name.to_owned(), add_info.clone()));
    }
}

#[tokio::test]
async fn wss_connections_are_sessions_closed_once_each() {
    let recorder = Arc::new(Recorder::default());
    let dynamic: Arc<dyn DynamicModules> = Arc::clone(&recorder) as _;
    let srv = start_with(vec![], move |registry| registry.set_dynamic(dynamic)).await;
    let origins = ["https://a.e2e.test", "https://b.e2e.test"];
    let mut clients = Vec::new();
    for origin in origins {
        let mut c = connect_from(&srv, origin).await;
        next_text(&mut c).await;
        send(&mut c, r#"{"module":"kz.example.Gone","method":"x"}"#).await;
        assert_eq!(
            next_text(&mut c).await,
            r#"{"success":false,"errorCode":"MODULE_NOT_FOUND"}"#
        );
        clients.push(c);
    }
    let missing = recorder.missing.lock().unwrap().clone();
    assert_eq!(missing.len(), 2, "{missing:?}");
    for ((name, info), origin) in missing.iter().zip(origins) {
        assert_eq!(name, "kz.example.Gone");
        assert_eq!(info.origin.as_deref(), Some(origin));
        assert_ne!(info.session, 0);
    }
    assert_ne!(missing[0].1.session, missing[1].1.session);
    let mut sessions: Vec<_> = missing.iter().map(|(_, info)| info.session).collect();
    sessions.sort_unstable();
    // One closed by the client, the other dropped without a close frame.
    let dropped = clients.pop().unwrap();
    let mut closing = clients.pop().unwrap();
    closing.close(None).await.unwrap();
    drop(dropped);
    let closed = timeout(PATIENCE, async {
        loop {
            let mut closed = recorder.closed.lock().unwrap().clone();
            if closed.len() >= 2 {
                closed.sort_unstable();
                return closed;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("sessions not closed in time");
    assert_eq!(closed, sessions);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(recorder.closed.lock().unwrap().len(), 2, "closed once each");
}

#[tokio::test]
async fn common_utils_over_wss() {
    let srv = start(vec![storage("user-gost2015-sign"), Step::Key(0)]).await;
    let mut c = connect(&srv).await;
    next_text(&mut c).await;
    send(
        &mut c,
        r#"{"module":"kz.gov.pki.knca.commonUtils","method":"getActiveTokens","args":[]}"#,
    )
    .await;
    assert_eq!(
        next_text(&mut c).await,
        r#"{"code":"200","responseObject":[]}"#
    );
    send(
        &mut c,
        r#"{"module":"kz.gov.pki.knca.commonUtils","method":"signXml","args":["PKCS12","SIGNATURE","<doc>текст</doc>","",""],"uuid":"u-7"}"#,
    )
    .await;
    let reply = json(&next_text(&mut c).await);
    assert_eq!(reply["code"], "200", "{reply}");
    assert_eq!(reply["uuid"], "u-7");
    let signed = reply["responseObject"].as_str().unwrap();
    assert_eq!(
        oncl_pki::xmldsig::verify(signed.as_bytes()).unwrap().len(),
        1
    );
    assert_eq!(srv.prompter.storage_prompts()[0].origin, ORIGIN);
}

#[tokio::test]
async fn basics_sign_cms_with_tsa_over_wss() {
    let srv = start(vec![storage("user-gost2015-sign"), Step::Key(0)]).await;
    let mut c = connect(&srv).await;
    next_text(&mut c).await;
    let data = "Документ для подписи".as_bytes();
    send(
        &mut c,
        &basics_sign_cms(&STANDARD.encode(data), cms_params_detached()),
    )
    .await;
    let reply = json(&next_text(&mut c).await);
    assert_eq!(reply["status"], true, "{reply}");
    let pem = reply["body"]["result"][0].as_str().unwrap();
    assert!(pem.starts_with("-----BEGIN CMS-----"), "{pem}");

    let signers = verify(&pem_to_der(pem), Some(data)).unwrap();
    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0].sig_alg, SigAlg::Gost2015_512);
    let token = signers[0].timestamp_token.as_ref().expect("time-stamp");
    verify_token(token).unwrap();
    assert_eq!(srv.tsa.calls().len(), 1);

    let prompts = srv.prompter.storage_prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].origin, ORIGIN);
    assert_eq!(srv.prompter.key_prompts()[0].origin, ORIGIN);
}

#[tokio::test]
async fn basics_sign_xml_egov_login_over_wss() {
    let srv = start(vec![storage("user-gost2015-auth"), Step::Key(0)]).await;
    let mut c = connect(&srv).await;
    next_text(&mut c).await;
    // The eGov portal's login request as captured live, plus `"chain":[]`: without a chain
    // the embedded production CAs would disable the synthetic key.
    let request = r#"{"module":"kz.gov.pki.knca.basics","method":"sign","args":{"data":"<?xml version=\"1.0\" encoding=\"UTF-8\"?><login><client-type>PORTAL</client-type></login>","allowedStorages":["PKCS12","AKKaztokenStore","AKKZIDCardStore"],"format":"xml","signingParams":{},"signerParams":{"extKeyUsageOids":["1.3.6.1.5.5.7.3.2"],"chain":[]},"locale":"ru"}}"#;
    send(&mut c, request).await;
    let reply = json(&next_text(&mut c).await);
    // `{"status":true,"body":{"result":["<signed xml>"]}}`, nothing more.
    assert_eq!(reply.as_object().unwrap().len(), 2, "{reply}");
    assert_eq!(reply["body"].as_object().unwrap().len(), 1, "{reply}");
    assert_eq!(reply["status"], true, "{reply}");
    let result = reply["body"]["result"].as_array().unwrap();
    assert_eq!(result.len(), 1, "{reply}");
    let signed = result[0].as_str().unwrap();
    let infos = oncl_pki::xmldsig::verify(signed.as_bytes()).unwrap();
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].cert, entry("user-gost2015-auth").cert);
    assert_eq!(srv.prompter.storage_prompts()[0].origin, ORIGIN);
}

#[tokio::test]
async fn e2e_accepts_40_mib_request() {
    let srv = start(vec![storage("user-gost2015-sign"), Step::Key(0)]).await;
    let mut c = connect(&srv).await;
    next_text(&mut c).await;
    let data: Vec<u8> = (0..40usize << 20).map(|i| (i % 251) as u8).collect();
    let request = basics_sign_cms(&STANDARD.encode(&data), cms_params_attached());
    assert!(request.len() > 53 << 20);
    send(&mut c, &request).await;
    let reply = next_text(&mut c).await;
    assert!(reply.len() > 55 << 20, "reply of {} bytes", reply.len());
    let reply = json(&reply);
    assert_eq!(reply["status"], true);
    let pem = reply["body"]["result"][0].as_str().unwrap();
    assert!(pem.starts_with("-----BEGIN CMS-----"));
}

/// Releases the scripted dialog's barrier when dropped, also while a test unwinds: a server
/// thread left in `Barrier::wait` would keep the runtime from shutting down, so a failing
/// test would hang. The waiting happens on a detached thread, so dropping never blocks, also
/// if the dialog reaches the barrier only later or never.
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
async fn e2e_second_connection_not_blocked_by_open_dialog() {
    let signal = Arc::new(Barrier::new(2));
    let srv = start(vec![
        Step::Wait(signal.clone()),
        storage("user-gost2015-sign"),
        Step::Key(0),
        storage("user-gost2015-sign"),
        Step::Key(0),
    ])
    .await;
    let request = basics_sign_cms(&STANDARD.encode(b"tab"), cms_params_detached());

    let mut first = connect_from(&srv, "https://first.test").await;
    next_text(&mut first).await;
    // From here on the first dialog will wait on the barrier: release it on every path out
    // of this test, including panics and a first prompt arriving after the deadline.
    let release = Release(signal.clone());
    send(&mut first, &request).await;
    let deadline = Instant::now() + PATIENCE;
    while srv.prompter.storage_prompts().is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The first storage prompt is recorded before it waits for the signal, so from here on
    // the first dialog is "open" until the signal.
    let first_shown = !srv.prompter.storage_prompts().is_empty();

    // Observe everything first, release the dialog, assert afterwards.
    let second = async {
        let started = Instant::now();
        let mut c = connect_from(&srv, "https://second.test").await;
        let greeting = timeout(Duration::from_secs(1), next_text(&mut c)).await;
        send(&mut c, "--heartbeat--").await;
        let heartbeat = timeout(Duration::from_secs(1), next_text(&mut c)).await;
        let elapsed = started.elapsed();
        send(&mut c, &request).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        (c, greeting, heartbeat, elapsed)
    };
    let (mut second, greeting, heartbeat, elapsed) = second.await;
    let storage_prompts_while_open = srv.prompter.storage_prompts().len();
    let key_prompts_while_open = srv.prompter.key_prompts().len();
    drop(release);

    assert!(first_shown, "the first dialog never opened");
    assert_eq!(
        greeting.expect("greeting within 1 s"),
        r#"{"result":{"version":"1.4"}}"#
    );
    assert_eq!(heartbeat.expect("heartbeat within 1 s"), "--heartbeat--");
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    assert_eq!(storage_prompts_while_open, 1, "second dialog shown early");
    assert_eq!(key_prompts_while_open, 0);

    assert_eq!(json(&next_text(&mut first).await)["status"], true);
    assert_eq!(json(&next_text(&mut second).await)["status"], true);
    let storage_origins: Vec<String> = srv
        .prompter
        .storage_prompts()
        .into_iter()
        .map(|p| p.origin)
        .collect();
    let key_origins: Vec<String> = srv
        .prompter
        .key_prompts()
        .into_iter()
        .map(|p| p.origin)
        .collect();
    assert_eq!(
        storage_origins,
        ["https://first.test", "https://second.test"]
    );
    assert_eq!(key_origins, ["https://first.test", "https://second.test"]);
}

#[tokio::test]
async fn invalid_json_drops_connection_without_close_frame() {
    let srv = start(vec![]).await;
    let mut c = connect(&srv).await;
    next_text(&mut c).await;
    send(&mut c, "nope").await;
    match timeout(PATIENCE, c.next())
        .await
        .expect("no reaction in time")
    {
        None | Some(Err(_)) => {}
        Some(Ok(message)) => panic!("expected a dropped connection, got {message:?}"),
    }
}

/// Asks for the connection to be dropped.
struct Dropping;

impl Module for Dropping {
    fn process(&self, _request: &str, _add_info: &AddInfo) -> Reply {
        Reply::Drop
    }
}

#[tokio::test]
async fn dropped_reply_closes_without_frame() {
    let srv = start_with(vec![], |registry| {
        registry.register("test.Drop", Arc::new(Dropping));
    })
    .await;
    let mut c = connect(&srv).await;
    next_text(&mut c).await;
    send(&mut c, r#"{"module":"test.Drop","method":"x"}"#).await;
    match timeout(PATIENCE, c.next())
        .await
        .expect("no reaction in time")
    {
        None | Some(Err(_)) => {}
        Some(Ok(message)) => panic!("expected a dropped connection, got {message:?}"),
    }
}

/// Sends a raw HTTP request over TLS and returns the status code, the response head and
/// the body.
async fn http_raw(srv: &Srv, request: &str) -> (u16, String, Vec<u8>) {
    let mut stream = tls_connect(srv).await;
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(PATIENCE, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(response[..end].to_vec()).unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, head, response[end + 4..].to_vec())
}

/// Sends a raw HTTP request over TLS and returns the status code and the body as text.
async fn http(srv: &Srv, request: &str) -> (u16, String) {
    let (status, _, body) = http_raw(srv, request).await;
    (status, String::from_utf8(body).unwrap())
}

#[tokio::test]
async fn http_selftest_and_methods() {
    let srv = start(vec![]).await;
    let (status, body) = http(&srv, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").await;
    assert_eq!(status, 200);
    assert!(body.contains("OpenNCALayer"), "{body}");
    assert!(body.contains(env!("CARGO_PKG_VERSION")), "{body}");
    assert!(!body.contains("{{version}}"));

    let (status, body) = http(
        &srv,
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert_eq!(status, 405);
    assert_eq!(body, "Only GET and WebSocket connections are accepted");

    let (status, _) = http(&srv, "GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").await;
    assert_eq!(status, 404);

    let (status, body) = http(
        &srv,
        "GET /openncalayer/selftest HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains("/openncalayer/selftest/report"), "{body}");
}

/// `POST /openncalayer/selftest/report` with `origin` (none if empty) and `body`.
async fn report(srv: &Srv, origin: &str, body: &str) -> u16 {
    let origin = if origin.is_empty() {
        String::new()
    } else {
        format!("Origin: {origin}\r\n")
    };
    let request = format!(
        "POST /openncalayer/selftest/report HTTP/1.1\r\nHost: 127.0.0.1\r\n{origin}\
         Content-Type: text/plain;charset=UTF-8\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    http(srv, &request).await.0
}

#[tokio::test]
async fn selftest_page_reports_its_browser() {
    let srv = start(vec![]).await;
    let own = format!("https://127.0.0.1:{}", srv.addr.port());
    let firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
    assert_eq!(report(&srv, &own, firefox).await, 204);
    let latest = srv.reports.latest();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].user_agent, firefox);

    // Only the page itself may report.
    assert_eq!(report(&srv, "https://evil.example", "x").await, 403);
    assert_eq!(report(&srv, "", "x").await, 403);
    assert_eq!(
        report(&srv, &format!("http://127.0.0.1:{}", srv.addr.port()), "x").await,
        403
    );
    // A small body only, and its length is required.
    assert_eq!(report(&srv, &own, &"a".repeat(2000)).await, 413);
    let (status, _) = http(
        &srv,
        &format!(
            "POST /openncalayer/selftest/report HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: {own}\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(status, 411);
    assert_eq!(srv.reports.latest().len(), 1);

    // A body that arrives after the head is read whole.
    let mut stream = tls_connect(&srv).await;
    let chrome = "Mozilla/5.0 Chrome/141.0.0.0 Safari/537.36";
    let head = format!(
        "POST /openncalayer/selftest/report HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: {own}\r\n\
         Content-Length: {}\r\n\r\n",
        chrome.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    stream.write_all(chrome.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(PATIENCE, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 204 "), "{response:?}");
    assert_eq!(srv.reports.latest()[0].user_agent, chrome);
}

/// The leaf the server presented on `stream`.
fn peer_leaf(stream: &TlsStream<TcpStream>) -> Vec<u8> {
    stream.get_ref().1.peer_certificates().unwrap()[0].to_vec()
}

#[tokio::test]
async fn a_reissued_certificate_serves_new_connections_only() {
    let srv = start(vec![]).await;
    let old_stream = tls_connect(&srv).await;
    let old_leaf = peer_leaf(&old_stream);
    let mut old = websocket_over(&srv, old_stream, ORIGIN).await;
    next_text(&mut old).await;

    // Re-issued: a new CA and leaf, taken by the server without a restart.
    let dir = tempfile::tempdir().unwrap();
    let files = TlsFiles {
        dir: dir.path().join("tls"),
    };
    let material = oncl_tls::generate(OffsetDateTime::now_utc(), "reissued").unwrap();
    oncl_tls::save(&files, &material).unwrap();
    srv.tls
        .replace(Arc::new(oncl_tls::server_config(&files).unwrap()));

    let new_ca = material.ca_der.unwrap();
    let new_stream = tls_connect_trusting(&srv, &new_ca).await;
    let new_leaf = peer_leaf(&new_stream);
    assert_ne!(new_leaf, old_leaf);
    assert_eq!(
        new_leaf,
        CertificateDer::from_pem_slice(material.chain_pem.as_bytes())
            .unwrap()
            .to_vec()
    );
    let mut new = websocket_over(&srv, new_stream, ORIGIN).await;
    next_text(&mut new).await;

    // The connection made before goes on with the old certificate.
    send(&mut old, "--heartbeat--").await;
    assert_eq!(next_text(&mut old).await, "--heartbeat--");
    send(&mut new, "--heartbeat--").await;
    assert_eq!(next_text(&mut new).await, "--heartbeat--");
}

/// sha256 of `package/ncalayer-client.js` in the npm package `ncalayer-js-client@1.6.1`.
const NCALAYER_CLIENT_SHA256: &str =
    "bdf2015c3e422eed70ccf38eef3246af67a0d38639e6b70fe6b8655a2fa03489";

#[tokio::test]
async fn demo_assets_served() {
    let srv = start(vec![]).await;
    let (status, head, body) =
        http_raw(&srv, "GET /demo/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").await;
    assert_eq!(status, 200);
    assert!(
        head.contains("\r\nContent-Type: text/html; charset=utf-8\r\n"),
        "{head}"
    );
    let page = String::from_utf8(body).unwrap();
    assert!(page.contains("vendor/ncalayer-client.js"), "{page}");

    let (status, head, body) = http_raw(
        &srv,
        "GET /demo/vendor/ncalayer-client.js HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        head.contains("\r\nContent-Type: text/javascript; charset=utf-8\r\n"),
        "{head}"
    );
    let digest: String = Sha256::digest(&body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(digest, NCALAYER_CLIENT_SHA256);
}

/// `cms-verify` of `input` against the synthetic GOST 2015 root, offline.
fn cms_verify_offline(input: &[u8]) -> (String, bool) {
    let root = cert::parse(&synthetic_cert("root-gost2015")).unwrap();
    let opts = Options {
        cas: CaSet::new(vec![root]),
        online: None,
        now: OffsetDateTime::now_utc(),
    };
    cms_verify_report_with(input, None, &opts)
}

#[tokio::test]
async fn cms_verify_reports_signers() {
    let srv = start(vec![storage("user-gost2015-sign"), Step::Key(0)]).await;
    let mut c = connect(&srv).await;
    next_text(&mut c).await;
    send(
        &mut c,
        &basics_sign_cms(&STANDARD.encode(b"cms-verify"), cms_params_attached()),
    )
    .await;
    let reply = json(&next_text(&mut c).await);
    let pem = reply["body"]["result"][0].as_str().unwrap();

    for input in [pem.as_bytes().to_vec(), pem_to_der(pem)] {
        let (report, ok) = cms_verify_offline(&input);
        let lines: Vec<&str> = report.lines().collect();
        assert!(ok, "{report}");
        assert_eq!(lines.len(), 8, "{report}");
        assert!(lines[0].starts_with("signer 0: CN="), "{report}");
        assert!(lines[0].contains(", IIN="), "{report}");
        assert!(
            lines[0].contains(", alg=Gost2015_512, signingTime=20"),
            "{report}"
        );
        assert_eq!(lines[1], "timestamp: yes");
        assert_eq!(lines[2], "chain: OpenNCALayer Synthetic Root GOST 2015");
        assert!(lines[3].starts_with("validity: ok at 20"), "{report}");
        assert_eq!(lines[4], "tsa chain: OpenNCALayer Synthetic Root GOST 2015");
        assert_eq!(lines[5], "revocation: not checked (--offline)");
        assert_eq!(lines[6], NOT_CHECKED);
        assert_eq!(lines[7], "OK");
    }

    let (report, ok) = cms_verify_offline(b"not a CMS");
    assert!(!ok);
    assert!(
        report.lines().last().unwrap().starts_with("FAIL: "),
        "{report}"
    );
}

#[test]
fn cms_verify_rejects_a_token_of_another_signature() {
    // Two GOST signatures of the same content with the same signed attributes differ only
    // in the signature value (random k). Time-stamp the first, then put the second's
    // signature value in its place: every signature still verifies, but the token covers a
    // signature the CMS no longer has.
    let key = entry("user-gost2015-sign");
    let opts = SignOptions {
        encapsulate: true,
        digested: false,
        signing_time: OffsetDateTime::now_utc(),
    };
    let first = sign(&key, b"doc", &opts).unwrap();
    let second = sign(&key, b"doc", &opts).unwrap();
    let tsa = MockTsa::new(entry("tsa-gost2015"));
    let stamped = timestamp_signer(&first, 0, &TsaProfile::basics_default(), &tsa).unwrap();
    let (report, ok) = cms_verify_offline(&stamped);
    assert!(ok, "{report}");
    assert!(
        report.ends_with(&format!(
            "\nrevocation: not checked (--offline)\n{NOT_CHECKED}\nOK\n"
        )),
        "{report}"
    );

    let old = verify(&first, None).unwrap().swap_remove(0).signature;
    let new = verify(&second, None).unwrap().swap_remove(0).signature;
    assert_eq!(old.len(), new.len());
    assert_ne!(old, new);
    let at: Vec<usize> = stamped
        .windows(old.len())
        .enumerate()
        .filter(|(_, w)| *w == old.as_slice())
        .map(|(i, _)| i)
        .collect();
    assert_eq!(at.len(), 1);
    let mut forged = stamped.clone();
    forged[at[0]..at[0] + new.len()].copy_from_slice(&new);
    assert_eq!(
        verify(&forged, None).unwrap().len(),
        1,
        "the signature itself verifies"
    );

    let (report, ok) = cms_verify_offline(&forged);
    assert!(!ok, "{report}");
    assert!(
        report.contains("\ntimestamp: yes\n"),
        "the token is still there: {report}"
    );
    assert!(
        report.contains("\ntsa chain: not checked (time-stamp does not verify)\n"),
        "{report}"
    );
    assert_eq!(
        report.lines().last(),
        Some("FAIL: time-stamp of signer 0 does not cover its signature"),
        "{report}"
    );
}

#[test]
fn port_from_value() {
    assert_eq!(listen_port_from(Some("13600")), 13600);
    assert_eq!(listen_port_from(Some("13679")), 13679);
    assert_eq!(listen_port_from(Some("13500")), 13579);
    assert_eq!(listen_port_from(Some("abc")), 13579);
    assert_eq!(listen_port_from(None), 13579);
}

#[test]
fn settings_recent_path_roundtrip() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("settings.json");
    assert_eq!(JsonSettings::new(f.clone()).load(), None);
    JsonSettings::new(f.clone()).save(Path::new("keys/a.p12"));
    assert_eq!(
        JsonSettings::new(f).load(),
        Some(PathBuf::from("keys/a.p12"))
    );
}
