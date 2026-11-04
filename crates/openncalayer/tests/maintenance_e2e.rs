//! The real `openncalayer` daemon (headless: `run --allow-no-wss --no-tray`, a throw-away data
//! directory) behind its real per-user management endpoint, driven by the real installer
//! entry logic (`oncl-winget-harness wrapper`, which calls `oncl_winget_setup::run`) with the
//! labelled fake Setup. No real user profile, registry key or elevation is involved; the
//! installation and the Apps & Features key are throw-away.
//!
//! Needs the harness binary: `cargo build -p oncl-winget-setup --bin oncl-winget-harness`
//! first, then `cargo test -p openncalayer --features e2e-prompter --test maintenance_e2e --
//! --ignored`. Not covered here: the check for an open window, which needs the real UI.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_ipc::maintenance::{self, Client, Reply};
use oncl_ipc::{IpcStream, connect, endpoint, read_frame, write_frame};
use oncl_registry::TestKey;
use oncl_testkit::synthetic;
use oncl_winget_setup::Exit;
use oncl_winget_setup::payload::{self, Arch};
use serde_json::{Value, json};
use tempfile::TempDir;

const PATIENCE: Duration = Duration::from_secs(60);
const IGNORE: &str = "needs oncl-winget-harness built (see the module docs)";

fn harness() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let path = exe
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .join("oncl-winget-harness.exe");
    assert!(path.is_file(), "{IGNORE}: {}", path.display());
    path
}

struct Fixture {
    dir: TempDir,
    key: TestKey,
    daemon: Child,
    spawned: Vec<u32>,
}

impl Fixture {
    fn root(&self) -> PathBuf {
        self.dir.path().join("install")
    }
    fn data(&self) -> PathBuf {
        self.dir.path().join("data")
    }
    fn log(&self) -> PathBuf {
        self.dir.path().join("log.txt")
    }
    fn log_text(&self) -> String {
        std::fs::read_to_string(self.log()).unwrap_or_default()
    }

    /// The real daemon, headless, answering dialogs from `steps`; waits for both endpoints.
    fn start(steps: &Value) -> Fixture {
        let dir = tempfile::Builder::new()
            .prefix("w01-e2e-")
            .tempdir()
            .unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("steps.json"), steps.to_string()).unwrap();
        let daemon = Command::new(env!("CARGO_BIN_EXE_openncalayer"))
            .args(["run", "--allow-no-wss", "--no-tray"])
            .env("ONCL_DATA_DIR", &data)
            .env("ONCL_E2E_PROMPTER", data.join("steps.json"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let fx = Fixture {
            dir,
            key: TestKey::new(),
            daemon,
            spawned: Vec::new(),
        };
        let rt = runtime();
        let deadline = Instant::now() + PATIENCE;
        loop {
            let up = rt.block_on(async {
                let management = maintenance::endpoint(&fx.data()).unwrap();
                Client::connect(&management).await.is_ok()
                    && connect(&endpoint(&fx.data()).unwrap()).await.is_ok()
            });
            if up {
                return fx;
            }
            assert!(Instant::now() < deadline, "the daemon did not come up");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// `oncl-winget-harness wrapper`: the installer entry as a process, against this
    /// daemon's data directory and a throw-away installation.
    fn entry(&mut self, wait_ms: u64, setup: &[(&str, &str)]) -> Child {
        let harness = harness();
        let bytes = std::fs::read(&harness).unwrap();
        let image = payload::append(
            &bytes,
            &bytes,
            &semver::Version::parse("0.2.0").unwrap(),
            Arch::X64,
        )
        .unwrap();
        let image_path = self.dir.path().join("entry.exe");
        std::fs::write(&image_path, image).unwrap();
        let work = self.dir.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let mut command = Command::new(&harness);
        command
            .arg("wrapper")
            .arg(&image_path)
            .env("ONCL_HARNESS_ROOT", self.root())
            .env("ONCL_HARNESS_DATA_DIR", self.data())
            .env("ONCL_HARNESS_ARP_KEY", self.key.path())
            .env("ONCL_HARNESS_TEMP", &work)
            .env("ONCL_HARNESS_LOG", self.log())
            .env("ONCL_HARNESS_VERSION", "0.2.0")
            .env("ONCL_HARNESS_WAIT_MS", wait_ms.to_string())
            .env("ONCL_DATA_DIR", self.data())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (name, value) in setup {
            command.env(format!("ONCL_HARNESS_{name}"), value);
        }
        let child = command.spawn().unwrap();
        self.spawned.push(child.id());
        child
    }

    fn setups_started(&self) -> usize {
        self.log_text().matches("setup started").count()
    }

    fn wait_for_log(&self, what: &str) {
        let deadline = Instant::now() + PATIENCE;
        while !self.log_text().contains(what) {
            assert!(Instant::now() < deadline, "no {what:?} in the log");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_TERMINATE, TerminateProcess,
        };
        let mut pids = self.spawned.clone();
        pids.push(self.daemon.id());
        pids.extend(
            oncl_winget_setup::processes::running_from(&self.root())
                .unwrap_or_default()
                .iter()
                .map(|p| p.pid),
        );
        for line in self.log_text().lines() {
            if let Some((pid, rest)) = line.split_once(' ')
                && rest.starts_with("setup")
                && let Ok(pid) = pid.parse()
            {
                pids.push(pid);
            }
        }
        for pid in pids {
            // A recorded PID may belong to another program by now: only a process whose
            // image is the daemon, the harness or lies under this fixture is ended.
            if !is_ours(pid, self.dir.path()) {
                continue;
            }
            // SAFETY: plain calls; the handle is checked and closed.
            unsafe {
                let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
                if !handle.is_null() {
                    TerminateProcess(handle, 1);
                    CloseHandle(handle);
                }
            }
        }
        let _ = self.daemon.wait();
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn is_ours(pid: u32, dir: &Path) -> bool {
    let norm = |path: &Path| {
        let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
        let text = path.to_string_lossy().to_lowercase();
        text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
    };
    oncl_winget_setup::processes::image_of(pid).is_some_and(|image| {
        let image = norm(&image);
        image.starts_with(&norm(dir))
            || image == norm(&harness())
            || image == norm(Path::new(env!("CARGO_BIN_EXE_openncalayer")))
    })
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// The browser relay's side of the daemon's bridge, enough to open a page and call a module.
struct Bridge(IpcStream);

impl Bridge {
    async fn open(data: &Path) -> Bridge {
        let mut stream = connect(&endpoint(data).unwrap()).await.unwrap();
        let hello = read_frame(&mut stream).await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&hello).contains("hello"));
        let mut bridge = Bridge(stream);
        bridge
            .send(
                &json!({"t":"open","sid":1,"origin":"https://w01.test","url":"https://w01.test/p"}),
            )
            .await;
        // The open reply, then the greeting message.
        bridge.next().await;
        bridge.next().await;
        bridge
    }

    async fn send(&mut self, frame: &Value) {
        write_frame(&mut self.0, frame.to_string().as_bytes())
            .await
            .unwrap();
    }

    async fn call_no_wait(&mut self, text: &str) {
        self.send(&json!({"t":"msg","sid":1,"data":text})).await;
    }

    async fn next(&mut self) -> Value {
        let frame = read_frame(&mut self.0).await.unwrap().expect("closed");
        serde_json::from_slice(&frame).unwrap()
    }

    /// The reply text of the next `msg` frame, or `None` if none comes within `within`.
    async fn reply_within(&mut self, within: Duration) -> Option<String> {
        let frame = tokio::time::timeout(within, self.next()).await.ok()?;
        Some(frame["data"].as_str().unwrap().to_owned())
    }
}

const TOKENS: &str =
    r#"{"module":"kz.gov.pki.knca.commonUtils","method":"getActiveTokens","args":[]}"#;
const TOKENS_REPLY: &str = r#"{"responseObject":[],"code":"200"}"#;

#[test]
#[ignore = "needs oncl-winget-harness built (see the module docs)"]
fn real_idle_daemon_is_held_for_setup_and_released() {
    let mut fx = Fixture::start(&json!([]));
    let release = fx.dir.path().join("release-setup");
    let mut entry = fx.entry(
        10_000,
        &[
            ("WAIT_FOR", release.to_str().unwrap()),
            ("SETUP", "install"),
        ],
    );
    // The real daemon granted the hold; the fake Setup is running.
    fx.wait_for_log("setup waiting");
    runtime().block_on(async {
        let mut bridge = Bridge::open(&fx.data()).await;
        bridge.call_no_wait(TOKENS).await;
        assert!(
            bridge
                .reply_within(Duration::from_millis(1500))
                .await
                .is_none(),
            "a request was answered while the daemon was held for the replacement"
        );
        std::fs::write(&release, b"go").unwrap();
        // Setup ends, the lease ends with the entry, and the waiting request goes on.
        assert_eq!(
            bridge.reply_within(PATIENCE).await.as_deref(),
            Some(TOKENS_REPLY)
        );
    });
    let status = entry.wait().unwrap();
    assert_eq!(status.code(), Some(Exit::Success as i32));
    assert_eq!(fx.setups_started(), 1);
    assert!(
        fx.daemon.try_wait().unwrap().is_none(),
        "the daemon was stopped"
    );
}

#[test]
#[ignore = "needs oncl-winget-harness built (see the module docs)"]
fn real_signing_in_flight_gets_busy_and_completes_correctly() {
    let key = synthetic("user-gost2015-sign");
    let gate_dir = tempfile::tempdir().unwrap();
    let gate = gate_dir.path().join("sign-may-go-on");
    let mut fx = Fixture::start(&json!([
        {"wait_file": gate},
        {"storage": {"path": key.path, "password": key.password}},
        {"key": 0},
    ]));
    let data = b"in flight";
    let request = json!({
        "module": "kz.gov.pki.knca.basics",
        "method": "sign",
        "args": {
            "allowedStorages": null,
            "format": "cms",
            "data": STANDARD.encode(data),
            "signingParams": {"decode": true, "encapsulate": false, "digested": false},
            "signerParams": {"extKeyUsageOids": [], "chain": []},
            "locale": "ru",
        },
    })
    .to_string();
    let rt = runtime();
    let mut bridge = rt.block_on(Bridge::open(&fx.data()));
    rt.block_on(bridge.call_no_wait(&request));
    // The daemon is answering the request (its dialog waits for the gate): the real
    // endpoint says busy. Before the request is dispatched it may still be idle, and a
    // grant is given straight back.
    rt.block_on(async {
        let mut client = Client::connect(&maintenance::endpoint(&fx.data()).unwrap())
            .await
            .unwrap();
        let deadline = Instant::now() + PATIENCE;
        loop {
            match client.hold().await.unwrap() {
                Reply::Busy => break,
                Reply::Granted { .. } => client.release().await.unwrap(),
            }
            assert!(Instant::now() < deadline, "the daemon never became busy");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    // The installer entry: honest busy, Setup never started, nothing stopped.
    let status = fx
        .entry(500, &[("FORCE_STOP", "1"), ("SETUP", "install")])
        .wait()
        .unwrap();
    assert_eq!(status.code(), Some(Exit::Busy as i32));
    assert_eq!(fx.setups_started(), 0);
    assert!(
        fx.daemon.try_wait().unwrap().is_none(),
        "the daemon was stopped"
    );

    // The signing is not cut: it completes with a signature that verifies.
    std::fs::write(&gate, b"go").unwrap();
    let reply = rt
        .block_on(bridge.reply_within(PATIENCE))
        .expect("the signing was cut");
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["status"], true, "{reply}");
    let pem = reply["body"]["result"][0].as_str().unwrap();
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    let signers = oncl_pki::cms::verify(&STANDARD.decode(body).unwrap(), Some(data)).unwrap();
    assert_eq!(signers.len(), 1);
}

#[test]
#[ignore = "needs oncl-winget-harness built (see the module docs)"]
fn a_killed_installer_releases_the_real_daemon() {
    let mut fx = Fixture::start(&json!([]));
    let never = fx.dir.path().join("never");
    let mut entry = fx.entry(
        10_000,
        &[("WAIT_FOR", never.to_str().unwrap()), ("SETUP", "install")],
    );
    fx.wait_for_log("setup waiting");
    let rt = runtime();
    rt.block_on(async {
        let mut bridge = Bridge::open(&fx.data()).await;
        bridge.call_no_wait(TOKENS).await;
        assert!(
            bridge
                .reply_within(Duration::from_millis(1000))
                .await
                .is_none(),
            "the daemon answered while held"
        );
        // The installer dies (WinGet's timeout, a crash, the user): its connection closes.
        entry.kill().unwrap();
        entry.wait().unwrap();
        assert_eq!(
            bridge.reply_within(PATIENCE).await.as_deref(),
            Some(TOKENS_REPLY),
            "the daemon stayed held after its installer died"
        );
        // And another maintainer can hold it, once it is quiet: it is not busy for ever.
        assert!(fx.daemon.try_wait().unwrap().is_none());
    });
}
