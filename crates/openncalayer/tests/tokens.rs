//! Hardware tokens end to end: the `openncalayer` binary (features `e2e-prompter` and
//! `token-emulator`) reading the emulated Kaztoken and ID card of `tests/data/tokens.toml`,
//! called through the browser extension bridge.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_ipc::{IpcStream, connect, endpoint, read_frame, write_frame};
use oncl_pki::cms::verify;
use oncl_pki::pkcs12::load;
use oncl_testkit::{read, synthetic};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::time::timeout;

const PATIENCE: Duration = Duration::from_secs(120);
const KAZTOKEN: &str = "OpenNCALayer Emulated Kaztoken 0";
const ID_CARD: &str = "OpenNCALayer Emulated ID Card 0";

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
        self.send(json!({"t": "open", "sid": sid, "origin": "https://tokens.test"}))
            .await;
        assert_eq!(self.next().await, json!({"t": "open", "sid": sid}));
        // The greeting.
        assert_eq!(self.next().await["t"], "msg");
    }

    /// The reply to `request`, joined from its frames.
    async fn call(&mut self, sid: u32, request: Value) -> Value {
        self.send(json!({"t": "msg", "sid": sid, "data": request.to_string()}))
            .await;
        let mut text = String::new();
        loop {
            let frame = self.next().await;
            assert_eq!(frame["t"], "msg", "{frame}");
            assert_eq!(frame["sid"], sid, "{frame}");
            text.push_str(frame["data"].as_str().unwrap());
            if frame.get("more").is_none() {
                return serde_json::from_str(&text).unwrap();
            }
        }
    }
}

/// A daemon on its own data directory, killed on drop.
struct Daemon {
    child: Child,
    dir: TempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A port of 13580..=13679 free now (never 13579: a real NCALayer may run).
fn free_port() -> u16 {
    (13620..13640)
        .find(|port| std::net::TcpListener::bind(("127.0.0.1", *port)).is_ok())
        .expect("a free port")
}

fn config() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/tokens.toml")
}

/// The daemon with the emulated tokens, answering dialogs with `steps`; the bridge, with
/// session 1 open.
async fn start(steps: Value) -> (Daemon, Client) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("steps.json"), steps.to_string()).unwrap();
    let mut daemon = Daemon {
        child: Command::new(env!("CARGO_BIN_EXE_openncalayer"))
            .args(["run", "--allow-no-wss", "--no-tray"])
            .env("ONCL_DATA_DIR", dir.path())
            .env("NCALAYERPORT", free_port().to_string())
            .env("ONCL_E2E_PROMPTER", dir.path().join("steps.json"))
            .env("ONCL_TOKEN_EMULATOR", config())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir,
    };
    let ep = endpoint(daemon.dir.path()).unwrap();
    let deadline = Instant::now() + PATIENCE;
    let mut c = loop {
        assert!(
            daemon.child.try_wait().unwrap().is_none(),
            "the daemon exited"
        );
        if let Ok(stream) = connect(&ep).await {
            let mut c = Client(stream);
            assert_eq!(c.next().await["t"], "hello");
            break c;
        }
        assert!(Instant::now() < deadline, "the bridge never came up");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    c.open(1).await;
    (daemon, c)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn applet(method: &str, args: Value) -> Value {
    json!({"module": "kz.gov.pki.knca.applet.Applet", "method": method, "args": args})
}

#[test]
fn active_tokens_over_the_wire() {
    runtime().block_on(async {
        let (_daemon, mut c) = start(json!([])).await;
        let reply = c
            .call(
                1,
                json!({"module": "kz.gov.pki.knca.commonUtils", "method": "getActiveTokens"}),
            )
            .await;
        assert_eq!(reply["code"], "200", "{reply}");
        assert_eq!(
            reply["responseObject"],
            json!(["AKKaztokenStore", "AKKZIDCardStore"])
        );
    });
}

#[test]
fn load_slot_list_over_the_wire() {
    runtime().block_on(async {
        let (_daemon, mut c) = start(json!([])).await;
        assert_eq!(
            c.call(1, applet("loadSlotList", json!(["AKKaztokenStore"])))
                .await,
            json!({"errorCode": "NONE", "result": KAZTOKEN})
        );
        assert_eq!(
            c.call(1, applet("loadSlotList", json!(["AKEToken72KStore"])))
                .await,
            json!({"errorCode": "EMPTY_SLOT"})
        );
    });
}

#[test]
fn public_part_info_over_the_wire() {
    runtime().block_on(async {
        let (_daemon, mut c) = start(json!([])).await;
        assert_eq!(
            c.call(1, applet("getPublicPartInfo", json!([ID_CARD])))
                .await,
            json!({"errorCode": "NONE", "result": "IIN123456789012 ТЕСТОВ ТЕСТ ТЕСТОВИЧ"})
        );
        assert_eq!(
            c.call(1, applet("getPublicPartInfo", json!([KAZTOKEN])))
                .await,
            json!({"errorCode": "GETPUBLICPART_EXCEPTION"})
        );
    });
}

#[test]
fn basics_sign_with_emulated_kaztoken_verifies() {
    let token = |pin: &str| json!({"token": {"storage": "AKKaztokenStore", "reader": KAZTOKEN, "pin": pin}});
    // A wrong PIN first: the dialog asks again.
    let steps = json!([token("000000"), token("123456"), {"key": 0}]);
    runtime().block_on(async {
        let (_daemon, mut c) = start(steps).await;
        let request = json!({
            "module": "kz.gov.pki.knca.basics",
            "method": "sign",
            "args": {
                "allowedStorages": ["AKKaztokenStore"],
                "format": "cms",
                "data": STANDARD.encode(b"token"),
                "signingParams": {"decode": true, "encapsulate": true},
                "signerParams": {"extKeyUsageOids": [], "chain": []},
                "locale": "ru",
            },
        });
        let reply = c.call(1, request).await;
        assert_eq!(reply["status"], true, "{reply}");
        let pem = reply["body"]["result"][0].as_str().unwrap();
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let signers = verify(&STANDARD.decode(body).unwrap(), None).unwrap();
        assert_eq!(signers.len(), 1);
        let key = synthetic("user-gost2015-sign");
        let entry = load(&read(&key.path), &key.password)
            .unwrap()
            .swap_remove(0);
        assert_eq!(signers[0].cert, entry.cert);
    });
}
