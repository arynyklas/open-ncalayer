//! The daemon with a plugin installed in its data directory, through the `openncalayer`
//! binary (feature `e2e-prompter`) and the browser extension bridge: the page calls the
//! plugin's module, each socket has its own instance, and the accessory module lists it.

#![cfg(feature = "e2e-prompter")]

use oncl_ipc::{IpcStream, connect, endpoint, read_frame, write_frame};
use oncl_plugin::{Package, Source, Store};
use serde_json::{Value, json};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::time::timeout;

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
