//! The daemon with a plugin installed in its data directory, through the `openncalayer`
//! binary (feature `e2e-prompter`) and the browser extension bridge: the page calls the
//! plugin's module, each socket has its own instance, and the accessory module lists it.
//! `e2e install-plugin` installs a package for `run`, and `ONCL_E2E_EXTRA_CA` lets the
//! plugins' HTTPS trust another CA.

#![cfg(feature = "e2e-prompter")]

use futures_util::{SinkExt, StreamExt};
use oncl_ipc::{IpcStream, connect, endpoint, read_frame, write_frame};
use oncl_plugin::{Package, Source, Store};
use oncl_tls::TlsFiles;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

const PATIENCE: Duration = Duration::from_secs(120);
const MODULE: &str = "io.github.arynyklas.openncalayer.Example";
const ACCESSORY: &str = "kz.gov.pki.ncalayerservices.accessory";

struct Client(IpcStream);

impl Client {
    async fn send(&mut self, frame: Value) {
        write_frame(&mut self.0, frame.to_string().as_bytes())
            .await
            .unwrap();
    }

    async fn next(&mut self) -> Value {
        let frame = timeout(PATIENCE, read_frame(&mut self.0))
            .await
            .expect("no frame in time")
            .unwrap()
            .expect("connection closed");
        serde_json::from_slice(&frame).unwrap()
    }

    async fn open(&mut self, sid: u32) {
        self.send(json!({"t": "open", "sid": sid, "origin": "https://page.test"}))
            .await;
        assert_eq!(self.next().await, json!({"t": "open", "sid": sid}));
        // The greeting.
        assert_eq!(self.next().await["t"], "msg");
    }

    async fn call(&mut self, sid: u32, request: Value) -> Value {
        self.send(json!({"t": "msg", "sid": sid, "data": request.to_string()}))
            .await;
        let frame = self.next().await;
        assert_eq!(frame["t"], "msg", "{frame}");
        assert_eq!(frame["sid"], sid, "{frame}");
        serde_json::from_str(frame["data"].as_str().unwrap()).unwrap()
    }
}

/// A daemon on `data`, killed on drop.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn example_call(method: &str) -> Value {
    json!({"module": MODULE, "class": "Example", "method": method, "args": {"text": "hi"}})
}

/// A port of 13580..=13679 free now (never 13579: a real NCALayer may run).
fn free_port() -> u16 {
    (13640..13680)
        .find(|port| std::net::TcpListener::bind(("127.0.0.1", *port)).is_ok())
        .expect("a free port")
}

fn install_example(data: &Path) {
    let bytes = oncl_testkit::plugin::example_package();
    let store = Store::open(data).unwrap();
    store
        .install(&Package::read(&bytes).unwrap(), &bytes, Source::Local)
        .unwrap();
}

#[test]
fn an_installed_plugin_serves_the_page() {
    let dir = tempfile::tempdir().unwrap();
    install_example(dir.path());
    std::fs::write(dir.path().join("steps.json"), "[]").unwrap();
    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_openncalayer"))
            .args(["run", "--allow-no-wss", "--no-tray"])
            .env("ONCL_DATA_DIR", dir.path())
            .env("NCALAYERPORT", free_port().to_string())
            .env("ONCL_E2E_PROMPTER", dir.path().join("steps.json"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let ep = endpoint(dir.path()).unwrap();
        let deadline = Instant::now() + PATIENCE;
        let mut c = loop {
            assert!(daemon.0.try_wait().unwrap().is_none(), "the daemon exited");
            if let Ok(stream) = connect(&ep).await {
                let mut c = Client(stream);
                assert_eq!(c.next().await["t"], "hello");
                break c;
            }
            assert!(Instant::now() < deadline, "the bridge never came up");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        c.open(1).await;
        c.open(2).await;
        assert_eq!(
            c.call(1, example_call("echo")).await,
            json!({"status": true, "body": "hi"})
        );
        assert_eq!(c.call(1, example_call("count")).await["body"], 1);
        assert_eq!(c.call(1, example_call("count")).await["body"], 2);
        // Another socket, another instance.
        assert_eq!(c.call(2, example_call("count")).await["body"], 1);
        let services = c
            .call(1, json!({"module": ACCESSORY, "method": "getServices"}))
            .await;
        assert!(
            services["services"]
                .as_array()
                .unwrap()
                .contains(&json!(MODULE)),
            "{services}"
        );
        let bundles = c
            .call(1, json!({"module": ACCESSORY, "method": "getBundles"}))
            .await;
        assert_eq!(bundles["kz.example.echo"], "1.0.0", "{bundles}");
        // No catalog in a build without keys: the original's answer.
        assert_eq!(
            c.call(
                1,
                json!({"module": ACCESSORY, "method": "installBundle", "symname": "kz.x"})
            )
            .await,
            json!({"errorCode": "BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED"})
        );
    });
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// `run` on `data` with an empty dialog script, the bridge always and wss if TLS is set up,
/// and the environment `env` (no `ONCL_E2E_EXTRA_CA` otherwise).
fn spawn_daemon(data: &Path, port: u16, env: &[(&str, &Path)]) -> Daemon {
    std::fs::write(data.join("steps.json"), "[]").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_openncalayer"));
    command
        .args(["run", "--allow-no-wss", "--no-tray"])
        .env("ONCL_DATA_DIR", data)
        .env("NCALAYERPORT", port.to_string())
        .env("ONCL_E2E_PROMPTER", data.join("steps.json"))
        .env_remove("ONCL_E2E_EXTRA_CA")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (name, value) in env {
        command.env(name, value);
    }
    Daemon(command.spawn().unwrap())
}

/// The bridge of `daemon` once it says hello.
async fn bridge(daemon: &mut Daemon, data: &Path) -> Client {
    let ep = endpoint(data).unwrap();
    let deadline = Instant::now() + PATIENCE;
    loop {
        assert!(daemon.0.try_wait().unwrap().is_none(), "the daemon exited");
        if let Ok(stream) = connect(&ep).await {
            let mut c = Client(stream);
            assert_eq!(c.next().await["t"], "hello");
            return c;
        }
        assert!(Instant::now() < deadline, "the bridge never came up");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A CA (PEM) and an HTTPS server on 127.0.0.1 with a certificate it issued, answering
/// every request `200 ok`; its port.
fn https_server() -> (String, u16) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap(),
    )
    .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                let conn = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let mut request = Vec::new();
                let mut buf = [0; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    (ca.pem(), port)
}

#[test]
fn e2e_extra_ca_reaches_plugin_http() {
    let (ca_pem, port) = https_server();
    let base = format!("https://127.0.0.1:{port}/");
    let bytes = oncl_testkit::plugin::example_package_with(|m| {
        m.replace("https://example.invalid/", &base)
    });
    let fetch = json!({
        "module": MODULE, "class": "Example", "method": "fetch", "args": {"url": format!("{base}x")}
    });
    let ca_dir = tempfile::tempdir().unwrap();
    let ca_file = ca_dir.path().join("ca.pem");
    std::fs::write(&ca_file, ca_pem).unwrap();
    for extra in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        Store::open(dir.path())
            .unwrap()
            .install(&Package::read(&bytes).unwrap(), &bytes, Source::Local)
            .unwrap();
        let env: &[(&str, &Path)] = if extra {
            &[("ONCL_E2E_EXTRA_CA", &ca_file)]
        } else {
            &[]
        };
        let mut daemon = spawn_daemon(dir.path(), free_port(), env);
        let reply = runtime().block_on(async {
            let mut c = bridge(&mut daemon, dir.path()).await;
            c.open(1).await;
            c.call(1, fetch.clone()).await
        });
        if extra {
            assert_eq!(reply["status"], true, "{reply}");
            assert_eq!(reply["body"]["status"], 200, "{reply}");
            assert_eq!(reply["body"]["body_b64"], "b2s=", "{reply}");
        } else {
            assert!(reply.to_string().contains("HOST_FAILED"), "{reply}");
        }
    }
}

#[test]
fn e2e_install_plugin_then_module_routes() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = oncl_testkit::plugin::example_package();
    let package = Package::read(&bytes).unwrap();
    let file = dir.path().join("example.onclp");
    std::fs::write(&file, &bytes).unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_openncalayer"))
        .args(["e2e", "install-plugin"])
        .arg(&file)
        .env("ONCL_DATA_DIR", &data)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("{} {}\n", package.manifest.id, package.manifest.version)
    );
    let state = Store::open(&data).unwrap().state();
    let installed = &state.plugins[&package.manifest.id];
    assert!(installed.enabled && installed.source == Source::Local);

    let material = oncl_tls::generate(OffsetDateTime::now_utc(), "plugins").unwrap();
    oncl_tls::save(
        &TlsFiles {
            dir: data.join("tls"),
        },
        &material,
    )
    .unwrap();
    let ca_der = material.ca_der.unwrap();
    let port = free_port();
    let mut daemon = spawn_daemon(&data, port, &[]);
    runtime().block_on(async {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(ca_der)).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let deadline = Instant::now() + PATIENCE;
        let tcp = loop {
            assert!(daemon.0.try_wait().unwrap().is_none(), "the daemon exited");
            if let Ok(tcp) = TcpStream::connect(("127.0.0.1", port)).await {
                break tcp;
            }
            assert!(Instant::now() < deadline, "wss never came up");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let tls = connector
            .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
            .await
            .unwrap();
        let request = format!("wss://127.0.0.1:{port}/")
            .into_client_request()
            .unwrap();
        let mut ws = tokio_tungstenite::client_async(request, tls)
            .await
            .unwrap()
            .0;
        // The greeting.
        ws_next(&mut ws).await;
        ws.send(Message::text(example_call("echo").to_string()))
            .await
            .unwrap();
        assert_eq!(
            ws_next(&mut ws).await,
            json!({"status": true, "body": "hi"})
        );
        let bundles = json!({"module": ACCESSORY, "method": "getBundles"});
        ws.send(Message::text(bundles.to_string())).await.unwrap();
        let bundles = ws_next(&mut ws).await;
        assert_eq!(bundles["kz.example.echo"], "1.0.0", "{bundles}");
    });
}

/// The next text message of `ws`, as JSON.
async fn ws_next<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> Value
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let message = timeout(PATIENCE, ws.next())
            .await
            .expect("no message in time")
            .expect("connection closed")
            .unwrap();
        if let Message::Text(text) = message {
            return serde_json::from_str(text.as_str()).unwrap();
        }
    }
}
