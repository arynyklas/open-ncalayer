//! The daemon end to end: a server on `127.0.0.1:0` with a freshly generated local CA, a
//! `tokio-tungstenite` client over its own `tokio-rustls` stream trusting that CA, a scripted
//! prompter and an in-process TSA.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures_util::{SinkExt, StreamExt};
use oncl_basics::RecentPathStore;
use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_pki::cms::verify;
use oncl_pki::key::SigAlg;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::tsp::{MockTsa, verify_token};
use oncl_testkit::{read, synthetic};
use oncl_tls::TlsFiles;
use openncalayer::cli::cms_verify_report;
use openncalayer::{JsonSettings, ServerConfig, build_registry, listen_port_from, serve};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
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
/// basicsSignerAny)` with its default locale.
fn basics_sign_cms(data_b64: &str, signing_params: Value) -> String {
    json!({
        "module": "kz.gov.pki.knca.basics",
        "method": "sign",
        "args": {
            "allowedStorages": null,
            "format": "cms",
            "data": data_b64,
            "signingParams": signing_params,
            "signerParams": {"extKeyUsageOids": []},
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
    _dir: TempDir,
}

async fn start(steps: Vec<Step>) -> Srv {
    let dir = tempfile::tempdir().unwrap();
    let material = oncl_tls::generate(OffsetDateTime::now_utc(), "e2e").unwrap();
    let files = TlsFiles {
        dir: dir.path().join("tls"),
    };
    oncl_tls::save(&files, &material).unwrap();
    let tls = Arc::new(oncl_tls::server_config(&files).unwrap());
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let registry = build_registry(
        prompter.clone(),
        Arc::new(MemoryRecentPath::new(None)),
        tsa.clone(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, ServerConfig::new(tls, Arc::new(registry))));
    Srv {
        addr,
        ca_der: material.ca_der.unwrap(),
        prompter,
        tsa,
        _dir: dir,
    }
}

async fn tls_connect(srv: &Srv) -> TlsStream<TcpStream> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(srv.ca_der.clone())).unwrap();
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
    let stream = tls_connect(srv).await;
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
    send(&mut first, &request).await;
    let deadline = Instant::now() + PATIENCE;
    while srv.prompter.storage_prompts().is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The first storage prompt is recorded before it waits for the signal, so from here on
    // the first dialog is "open" until the signal.
    let first_shown = !srv.prompter.storage_prompts().is_empty();

    // Observe everything first, release the dialog, assert afterwards: a failed assertion
    // must not leave the first request blocked on the barrier.
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
    if first_shown {
        let signal = signal.clone();
        tokio::task::spawn_blocking(move || signal.wait())
            .await
            .unwrap();
    }

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

/// Sends a raw HTTP request over TLS and returns the status code and the body.
async fn http(srv: &Srv, request: &str) -> (u16, String) {
    let mut stream = tls_connect(srv).await;
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(PATIENCE, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, body.to_owned())
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
        let (report, ok) = cms_verify_report(&input, None);
        let lines: Vec<&str> = report.lines().collect();
        assert!(ok, "{report}");
        assert_eq!(lines.len(), 3, "{report}");
        assert!(lines[0].starts_with("signer 0: CN="), "{report}");
        assert!(lines[0].contains(", IIN="), "{report}");
        assert!(
            lines[0].contains(", alg=Gost2015_512, signingTime=20"),
            "{report}"
        );
        assert_eq!(lines[1], "timestamp: yes");
        assert_eq!(lines[2], "OK");
    }

    let (report, ok) = cms_verify_report(b"not a CMS", None);
    assert!(!ok);
    assert!(
        report.lines().last().unwrap().starts_with("FAIL: "),
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
