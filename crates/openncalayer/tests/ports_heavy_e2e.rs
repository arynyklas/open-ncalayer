//! Ports of the heavy plugins behind the daemon's WSS server: each socket is a session of
//! its own, a dialog held in one does not hold the others, a dropped reply closes the
//! socket without a frame.

use futures_util::{SinkExt, StreamExt};
use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_basics::{Locale, OcspCache};
use oncl_pki::pkix::CaSet;
use oncl_pki::tsp::{MockTsa, TsaProfile};
use oncl_plugin::{Engine, HostServices, Package, PluginModules};
use oncl_testkit::{read, synthetic};
use openncalayer::{LiveTls, ServerConfig, build_registry, serve};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::json;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

const PATIENCE: Duration = Duration::from_secs(120);

struct Srv {
    addr: std::net::SocketAddr,
    ca_der: Vec<u8>,
    prompter: Arc<ScriptedPrompter>,
    _dir: tempfile::TempDir,
}

/// The `.onclp` of the port `short` (built for wasm32 once per process).
fn port_package(short: &str) -> Vec<u8> {
    let manifest = read(
        oncl_testkit::plugin::ports_dir()
            .join(short)
            .join("plugin.toml"),
    );
    let wasm = read(oncl_testkit::plugin::port_wasm(short));
    oncl_plugin::archive(&manifest, &wasm).unwrap()
}

/// A daemon whose dialogs answer `steps`, with the ports `shorts` loaded.
async fn start(steps: Vec<Step>, shorts: &[&str]) -> Srv {
    let dir = tempfile::tempdir().unwrap();
    let material = oncl_tls::generate(OffsetDateTime::now_utc(), "e2e").unwrap();
    let files = oncl_tls::TlsFiles {
        dir: dir.path().join("tls"),
    };
    oncl_tls::save(&files, &material).unwrap();
    let tls = Arc::new(LiveTls::new(Arc::new(
        oncl_tls::server_config(&files).unwrap(),
    )));
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let tsa_key = synthetic("tsa-gost2015");
    let tsa = Arc::new(MockTsa::new(
        oncl_pki::pkcs12::load(&read(&tsa_key.path), &tsa_key.password)
            .unwrap()
            .swap_remove(0),
    ));
    let mut registry = build_registry(
        prompter.clone(),
        Arc::new(MemoryRecentPath::new(None)),
        tsa.clone(),
        Arc::new(|_| {}),
        None,
    );
    let services = HostServices {
        prompter: prompter.clone(),
        recent: Arc::new(MemoryRecentPath::new(None)),
        http: tsa,
        ocsp_cache: Arc::new(OcspCache::new()),
        tsa: TsaProfile::basics_default(),
        clock: OffsetDateTime::now_utc,
        locale: Arc::new(|| Locale::Ru),
        cas: Arc::new(CaSet::nca_production()),
        pki_hosts: oncl_plugin::nca_pki_hosts(),
        settings_dir: None,
    };
    let plugins = PluginModules::new(Arc::new(Engine::new()), services, registry.names());
    for short in shorts {
        plugins
            .load(Package::read(&port_package(short)).unwrap())
            .unwrap();
    }
    registry.set_dynamic(Arc::new(plugins));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        ServerConfig::new(Arc::clone(&tls), Arc::new(registry)),
    ));
    Srv {
        addr,
        ca_der: material.ca_der.unwrap(),
        prompter,
        _dir: dir,
    }
}

type Client = WebSocketStream<TlsStream<TcpStream>>;

async fn connect(srv: &Srv, origin: &str) -> Client {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(srv.ca_der.clone())).unwrap();
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let tcp = TcpStream::connect(srv.addr).await.unwrap();
    let stream = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await
        .unwrap();
    let mut request = format!("wss://127.0.0.1:{}/", srv.addr.port())
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("Origin", HeaderValue::from_str(origin).unwrap());
    let mut client = tokio_tungstenite::client_async(request, stream)
        .await
        .unwrap()
        .0;
    // The greeting.
    next_text(&mut client).await;
    client
}

async fn send(c: &mut Client, text: &str) {
    c.send(Message::text(text)).await.unwrap();
}

async fn next_text(c: &mut Client) -> String {
    let deadline = tokio::time::Instant::now() + PATIENCE;
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

/// Releases the held dialog on every way out of the test.
struct Release(Arc<Barrier>);

impl Drop for Release {
    fn drop(&mut self) {
        let barrier = Arc::clone(&self.0);
        std::thread::spawn(move || barrier.wait());
    }
}

const ACBANK: &str = "kz.acbank.business.api.ncalayer.module";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acbank_healthcheck_from_second_socket_e2e() {
    let held = Arc::new(Barrier::new(2));
    let srv = start(
        vec![Step::Wait(held.clone()), Step::CancelChoice],
        &["acbank"],
    )
    .await;
    let healthcheck =
        json!({"module": ACBANK, "method": "healthcheck", "args": {"ping": true}}).to_string();
    let mut page = connect(&srv, "https://business.acbank.kz").await;
    send(&mut page, &healthcheck).await;
    assert_eq!(
        next_text(&mut page).await,
        r#"{"code":"ncalayer.module.healthcheck.session.inactive","status":false}"#
    );

    let mut signing = connect(&srv, "https://business.acbank.kz").await;
    let release = Release(held.clone());
    let sign = json!({"module": ACBANK, "method": "signJsonWithJws", "args": {"signableItems":
        [{"id": "1", "name": "Платёж", "content": "{}", "contentType": "application/json"}]}});
    send(&mut signing, &sign.to_string()).await;
    let deadline = Instant::now() + PATIENCE;
    while srv.prompter.choice_prompts().is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        srv.prompter.choice_prompts().len(),
        1,
        "the window never opened"
    );
    // The window waits in the first socket; the second answers at once.
    send(&mut page, &healthcheck).await;
    let open = timeout(Duration::from_secs(30), next_text(&mut page)).await;
    drop(release);
    assert_eq!(
        open.expect("healthcheck while the window is open"),
        r#"{"code":"success","message":null,"body":{"healthcheck":true},"status":true}"#
    );
    assert_eq!(
        next_text(&mut signing).await,
        r#"{"code":"ncalayer.module.window.closed","status":false}"#
    );
    send(&mut page, &healthcheck).await;
    assert_eq!(
        next_text(&mut page).await,
        r#"{"code":"ncalayer.module.healthcheck.session.inactive","status":false}"#
    );
}
