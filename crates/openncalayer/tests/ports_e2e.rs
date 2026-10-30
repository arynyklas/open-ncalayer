//! Plugin ports in the daemon, through the `openncalayer` binary (feature `e2e-prompter`)
//! and the browser extension bridge: a port installed in the data directory answers the
//! page with the core's windows answered by a script.

#![cfg(feature = "e2e-prompter")]

use oncl_ipc::{IpcStream, connect, endpoint, read_frame, write_frame};
use oncl_plugin::{Package, Source, Store};
use serde_json::{Value, json};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::time::timeout;

const PATIENCE: Duration = Duration::from_secs(120);

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
        self.send(json!({"t": "open", "sid": sid, "origin": "https://uchet.kz"}))
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

/// A daemon, killed on drop.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A port of 13580..=13679 free now (never 13579: a real NCALayer may run).
fn free_port() -> u16 {
    (13600..13640)
        .find(|port| std::net::TcpListener::bind(("127.0.0.1", *port)).is_ok())
        .expect("a free port")
}

/// The port `short` of `plugins/`, packaged and installed into `data`.
fn install_port(data: &Path, short: &str) {
    let manifest = oncl_testkit::read(
        oncl_testkit::plugin::ports_dir()
            .join(short)
            .join("plugin.toml"),
    );
    let wasm = oncl_testkit::read(oncl_testkit::plugin::port_wasm(short));
    let bytes = oncl_plugin::archive(&manifest, &wasm).unwrap();
    Store::open(data)
        .unwrap()
        .install(&Package::read(&bytes).unwrap(), &bytes, Source::Local)
        .unwrap();
}

/// `signXmlApi` of the uchet port: a key file the page names opens once the user allows
/// it, once for each socket (each its own session).
#[test]
fn uchet_page_path_consent_e2e() {
    let dir = tempfile::tempdir().unwrap();
    install_port(dir.path(), "uchet");
    // Two consents: the first socket's, then the second's; a third question would find
    // no step and be answered no.
    std::fs::write(
        dir.path().join("steps.json"),
        r#"[{"confirm": {"yes": true}}, {"confirm": {"yes": true}}]"#,
    )
    .unwrap();
    let key = oncl_testkit::synthetic("user-gost2015-sign");
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
        let request = json!({
            "module": "kz.uchet.signUtil.commonUtils",
            "method": "signXmlApi",
            "args": [key.path.to_str().unwrap(), key.password, "<doc>1</doc>"],
        });
        let signed = |reply: &Value| {
            assert_eq!(reply["code"], "200", "{reply}");
            let xml = reply["message"].as_str().unwrap();
            assert!(xml.contains("SignatureValue"), "{xml}");
        };
        c.open(1).await;
        signed(&c.call(1, request.clone()).await);
        // The same session: no question.
        signed(&c.call(1, request.clone()).await);
        // A new socket asks again.
        c.open(2).await;
        signed(&c.call(2, request.clone()).await);
        // Both steps are spent: one more question would be answered no.
        c.open(3).await;
        assert_eq!(
            c.call(3, request).await,
            json!({"code": "500", "message": "Не удалось открыть хранилище"})
        );
    });
}
