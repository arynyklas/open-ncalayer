//! `cargo xtask ext-e2e`: the browser extension end to end, Linux only.
//!
//! For each browser, everything lives in a fresh sandbox `target/ext-e2e/<browser>/`:
//! - `home/` (`HOME`, Firefox finds the host manifest in `home/.mozilla/`), `run/`
//!   (`XDG_RUNTIME_DIR`, the daemon's IPC socket), `chromium/` (Chromium `--user-data-dir`,
//!   with `NativeMessagingHosts/`), `profiles/` (geckodriver `--profile-root`), `relay/`;
//! - `data/` (`ONCL_DATA_DIR`): the daemon's data and logs; `steps.json`
//!   (`ONCL_E2E_PROMPTER`): the dialog answers.
//!
//! `openncalayer nm install --sandbox` registers the relay there. The browser starts through
//! its WebDriver driver with that environment, which the browser passes to the relay and the
//! relay to the daemon. The browser opens the scenario page ([`page::INDEX_HTML`]) from
//! `http://127.0.0.1:<port>/` and the xtask runs its steps with `execute/async`, asserting
//! what they saw, the daemon's processes and logs.
//!
//! Inputs: `target/release/{openncalayer,nmhost}` (`openncalayer` with feature
//! `e2e-prompter`), `target/extension/{chromium,firefox}/` (`cargo xtask ext build`).
//!
//! `TMPDIR` is a short throwaway directory under the system temp directory instead: Chrome
//! binds its process-singleton socket in `$TMPDIR`, and a Unix socket path must fit in 108
//! bytes, which a checkout path like a CI runner's leaves no room for under `target/`.

pub mod browsers;
mod page;
mod webdriver;

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::asn1::{AnyRef, OctetStringRef};
use der::{Decode, SliceReader};
use serde_json::{Value, json};

pub use browsers::Browser;
use oncl_ipc::ids::FIREFOX_EXTENSION_ID;
use webdriver::{Driver, Session};

/// Which browsers `ext-e2e` runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Selection {
    Chromium,
    Firefox,
    All,
}

impl Selection {
    fn browsers(self) -> &'static [Browser] {
        match self {
            Selection::Chromium => &[Browser::Chromium],
            Selection::Firefox => &[Browser::Firefox],
            Selection::All => &[Browser::Chromium, Browser::Firefox],
        }
    }
}

/// The scenarios, in the order they run.
pub const SCENARIOS: [&str; 7] = [
    "1. autostart: greeting via relay and daemon",
    "2. heartbeat echo, unknown module",
    "3. fetch probe resolves",
    "4. basics.sign CMS over 1.5 MiB",
    "5. origin set by the browser, not the page",
    "6. daemon killed: close 1006, restart",
    "7. no host: page's own WebSocket and fetch",
];

/// Size of the document signed in scenario 4: 1.5 MiB.
const SIGNED_SIZE: usize = 3 << 19;
/// The scenario 4 key: a synthetic GOST 2015 container valid until 2099 (the NCANode test
/// keys have expired, and an expired key cannot sign).
const SIGNING_KEY: &str = "user-gost2015-sign";
/// A socket the daemon dropped must close in the page within this.
const CLOSE_WITHIN: Duration = Duration::from_secs(5);
/// How long the extension gets to put its shim into a fresh page.
const SHIM_PATIENCE: Duration = Duration::from_secs(30);
/// Longest page step (the signature included).
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(240);
/// What Chrome appends to `$TMPDIR` for its process-singleton socket.
const CHROME_SINGLETON: &str = "/org.chromium.Chromium.XXXXXX/SingletonSocket";
/// `sizeof(sockaddr_un.sun_path)` on Linux: the path and its NUL.
const SUN_PATH: usize = 108;
/// The NCALayer port, served by a TCP sink in scenario 7.
const NCALAYER_PORT: u16 = 13579;

/// Variables of this process the browser must not inherit: a display (the browsers run
/// headless), the user's session bus, a daemon port other than the default.
const UNSET: [&str; 5] = [
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_SESSION_TYPE",
    "NCALAYERPORT",
];

/// Runs the scenarios in the selected browsers and prints the scenario × browser table.
///
/// # Errors
///
/// If an input is missing, a server cannot start, or a scenario fails in a browser.
pub fn run(root: &Path, selection: Selection, download: bool) -> anyhow::Result<()> {
    if !cfg!(target_os = "linux") {
        println!("e2e расширения запускается в Linux");
        return Ok(());
    }
    let target = root.join("target");
    let release = target.join("release");
    let inputs = Inputs {
        daemon: release.join("openncalayer"),
        relay: release.join("nmhost"),
        extension: target.join("extension"),
    };
    for binary in [&inputs.daemon, &inputs.relay] {
        ensure!(
            binary.is_file(),
            "{} is missing: run `cargo build --release -p openncalayer --features e2e-prompter -p oncl-nmhost`",
            binary.display()
        );
    }
    for browser in selection.browsers() {
        let dir = inputs.extension.join(browser.name());
        ensure!(
            dir.join("manifest.json").is_file(),
            "{} is missing: run `cargo xtask ext build`",
            dir.display()
        );
    }

    let page_port = page::serve_page()?;
    page::serve_original()?;
    let mut columns = Vec::new();
    for &browser in selection.browsers() {
        let binaries = if download {
            browsers::download(browser, &target.join("browsers"))
        } else {
            browsers::from_env(browser)
        };
        let outcomes = binaries
            .context("browser")
            .and_then(|binaries| run_browser(&inputs, browser, &binaries, &target, page_port))
            .map_err(|error| format!("{error:#}"));
        columns.push((browser, outcomes));
    }

    print_table(&columns);
    let mut failures = 0;
    for (browser, outcomes) in &columns {
        match outcomes {
            Err(error) => {
                eprintln!("FAIL {}: {error}", browser.name());
                failures += SCENARIOS.len();
            }
            Ok(outcomes) => {
                for (scenario, outcome) in SCENARIOS.iter().zip(outcomes) {
                    if let Err(error) = outcome {
                        eprintln!("FAIL {} / {scenario}: {error}", browser.name());
                        failures += 1;
                    }
                }
            }
        }
    }
    ensure!(failures == 0, "{failures} scenario runs failed");
    Ok(())
}

/// What the run tests.
struct Inputs {
    daemon: PathBuf,
    relay: PathBuf,
    extension: PathBuf,
}

/// The outcome of every scenario in one browser, an error text for a failed one; an error
/// text alone if the browser did not get to the scenarios.
type Outcomes = Result<Vec<Result<(), String>>, String>;

fn print_table(columns: &[(Browser, Outcomes)]) {
    let width = SCENARIOS.iter().map(|s| s.len()).max().unwrap_or(0);
    let mut header = format!("{:width$}", "scenario");
    for (browser, _) in columns {
        header.push_str(&format!("  {:8}", browser.name()));
    }
    println!("{}", header.trim_end());
    for (i, scenario) in SCENARIOS.iter().enumerate() {
        let mut line = format!("{scenario:width$}");
        for (_, outcomes) in columns {
            let passed = outcomes.as_ref().is_ok_and(|outcomes| outcomes[i].is_ok());
            let mark = if passed { "PASS" } else { "FAIL" };
            line.push_str(&format!("  {mark:8}"));
        }
        println!("{}", line.trim_end());
    }
}

/// One browser: sandbox, host registration, browser, scenarios, cleanup.
fn run_browser(
    inputs: &Inputs,
    browser: Browser,
    binaries: &browsers::Binaries,
    target: &Path,
    page_port: u16,
) -> anyhow::Result<Vec<Result<(), String>>> {
    let root = target.join("ext-e2e").join(browser.name());
    // A daemon left by an interrupted run would keep serving the sandbox's endpoint.
    for pid in daemon_pids(&inputs.daemon, &root.join("data")) {
        kill(pid);
    }
    let tmp = tempfile::Builder::new()
        .prefix("oncl-e2e-")
        .tempdir()
        .context("creating the browser's TMPDIR")?;
    let sandbox = Sandbox::create(&root, tmp.path()).context("sandbox")?;
    let outcomes = start_browser(inputs, browser, binaries, &sandbox, page_port);
    // Sessions and drivers are gone; a daemon outlives its relay.
    for pid in daemon_pids(&inputs.daemon, &sandbox.data) {
        kill(pid);
    }
    outcomes
}

fn start_browser(
    inputs: &Inputs,
    browser: Browser,
    binaries: &browsers::Binaries,
    sandbox: &Sandbox,
    page_port: u16,
) -> anyhow::Result<Vec<Result<(), String>>> {
    let env = sandbox.env();
    nm(
        inputs,
        sandbox,
        &["install", "--relay"],
        Some(&inputs.relay),
    )
    .context("nm install")?;
    let driver_args = match browser {
        Browser::Chromium => {
            let singleton = sandbox.tmp.display().to_string().len() + CHROME_SINGLETON.len();
            ensure!(
                singleton < SUN_PATH,
                "TMPDIR {} is too long for Chrome's singleton socket ({singleton} bytes, \
                 at most {} allowed)",
                sandbox.tmp.display(),
                SUN_PATH - 1
            );
            Vec::new()
        }
        // The Firefox profile stays under `target/`, not in the short TMPDIR.
        Browser::Firefox => vec![format!("--profile-root={}", sandbox.profiles.display())],
    };
    let driver = Driver::start(
        &binaries.driver,
        &driver_args,
        &env,
        &UNSET,
        &sandbox.root.join("driver.log"),
    )?;
    let extension = inputs.extension.join(browser.name());
    let session = driver.session(capabilities(browser, binaries, &extension, sandbox)?)?;
    session.set_script_timeout(SCRIPT_TIMEOUT)?;
    if browser == Browser::Firefox {
        let id = session
            .install_temporary_addon(&extension)
            .context("installing the add-on")?;
        ensure!(
            id == FIREFOX_EXTENSION_ID,
            "the add-on was installed as {id:?}, not {FIREFOX_EXTENSION_ID}"
        );
    }
    let scenarios = Scenarios {
        session: &session,
        inputs,
        sandbox,
        page_port,
    };
    scenarios.wait_for_shim()?;
    let steps: [&dyn Fn() -> anyhow::Result<()>; 7] = [
        &|| scenarios.autostart(),
        &|| scenarios.echo_and_unknown(),
        &|| scenarios.probe(),
        &|| scenarios.sign(),
        &|| scenarios.origin(),
        &|| scenarios.daemon_killed(),
        &|| scenarios.no_host(),
    ];
    Ok(steps
        .iter()
        .map(|step| step().map_err(|error| format!("{error:#}")))
        .collect())
}

/// `openncalayer nm <args> [extra] --sandbox <root>` in the sandbox's environment.
fn nm(
    inputs: &Inputs,
    sandbox: &Sandbox,
    args: &[&str],
    extra: Option<&Path>,
) -> anyhow::Result<()> {
    let mut command = Command::new(&inputs.daemon);
    command.arg("nm").args(args);
    if let Some(extra) = extra {
        command.arg(extra);
    }
    command.arg("--sandbox").arg(&sandbox.root);
    for name in UNSET {
        command.env_remove(name);
    }
    let output = command
        .envs(sandbox.env())
        .output()
        .context("running openncalayer nm")?;
    ensure!(
        output.status.success(),
        "exit {}: {}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// WebDriver capabilities: headless, the sandbox's profile, the extension (Chromium; Firefox
/// installs it once the session runs).
fn capabilities(
    browser: Browser,
    binaries: &browsers::Binaries,
    extension: &Path,
    sandbox: &Sandbox,
) -> anyhow::Result<Value> {
    let path = |p: &Path| -> anyhow::Result<String> {
        p.to_str()
            .map(str::to_owned)
            .with_context(|| format!("{} is not UTF-8", p.display()))
    };
    Ok(match browser {
        Browser::Chromium => json!({
            "browserName": "chrome",
            "goog:chromeOptions": {
                "binary": path(&binaries.browser)?,
                "args": [
                    "--headless=new",
                    format!("--user-data-dir={}", path(&sandbox.root.join("chromium"))?),
                    format!("--load-extension={}", path(extension)?),
                    // Chromium's own sandbox needs unprivileged user namespaces, which
                    // Ubuntu 24.04 restricts; the browser only opens the local page.
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--no-first-run",
                ],
            },
        }),
        Browser::Firefox => json!({
            "browserName": "firefox",
            "moz:firefoxOptions": {
                "binary": path(&binaries.browser)?,
                "args": ["-headless"],
            },
        }),
    })
}

/// The per-browser directories of a run, created empty.
struct Sandbox {
    root: PathBuf,
    data: PathBuf,
    home: PathBuf,
    runtime: PathBuf,
    profiles: PathBuf,
    /// The short `TMPDIR`, outside the sandbox.
    tmp: PathBuf,
    steps: PathBuf,
}

impl Sandbox {
    fn create(root: &Path, tmp: &Path) -> anyhow::Result<Sandbox> {
        if root.exists() {
            fs::remove_dir_all(root).with_context(|| format!("removing {}", root.display()))?;
        }
        let sandbox = Sandbox {
            root: root.to_owned(),
            data: root.join("data"),
            home: root.join("home"),
            runtime: root.join("run"),
            profiles: root.join("profiles"),
            tmp: tmp.to_owned(),
            steps: root.join("steps.json"),
        };
        for dir in [
            &sandbox.data,
            &sandbox.home,
            &sandbox.runtime,
            &sandbox.profiles,
        ] {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&sandbox.runtime, fs::Permissions::from_mode(0o700))?;
        }
        let key = oncl_testkit::synthetic(SIGNING_KEY);
        let storage = json!({"storage": {"path": key.path, "password": key.password}});
        let steps = json!([storage, {"key": 0}, storage, {"key": 0}]);
        fs::write(&sandbox.steps, steps.to_string())?;
        Ok(sandbox)
    }

    /// The environment of everything started in the sandbox.
    fn env(&self) -> Vec<(String, String)> {
        let path = |p: &Path| p.display().to_string();
        vec![
            ("HOME".into(), path(&self.home)),
            ("XDG_CONFIG_HOME".into(), path(&self.home.join(".config"))),
            ("XDG_CACHE_HOME".into(), path(&self.home.join(".cache"))),
            (
                "XDG_DATA_HOME".into(),
                path(&self.home.join(".local/share")),
            ),
            ("XDG_RUNTIME_DIR".into(), path(&self.runtime)),
            ("TMPDIR".into(), path(&self.tmp)),
            ("ONCL_DATA_DIR".into(), path(&self.data)),
            ("ONCL_E2E_PROMPTER".into(), path(&self.steps)),
            ("MOZ_HEADLESS".into(), "1".into()),
        ]
    }

    /// The daemon's log files, concatenated.
    fn logs(&self) -> String {
        let Ok(entries) = fs::read_dir(self.data.join("logs")) else {
            return String::new();
        };
        let mut files: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        files.sort();
        files
            .iter()
            .filter_map(|file| fs::read_to_string(file).ok())
            .collect()
    }
}

/// Runs a page step: `window.oncl_e2e.run(name, arg)`, settled into `{value}` or `{error}`.
const STEP_SCRIPT: &str = "const done = arguments[arguments.length - 1];\n\
    window.oncl_e2e.run(arguments[0], arguments[1]).then(\n\
    (value) => done({ value }),\n\
    (error) => done({ error: String((error && error.stack) || error) }));";

struct Scenarios<'a> {
    session: &'a Session<'a>,
    inputs: &'a Inputs,
    sandbox: &'a Sandbox,
    page_port: u16,
}

impl Scenarios<'_> {
    fn page_url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.page_port)
    }

    fn step(&self, name: &str, arg: Value) -> anyhow::Result<Value> {
        let mut result = self
            .session
            .execute_async(STEP_SCRIPT, json!([name, arg]))
            .with_context(|| format!("page step {name}"))?;
        if let Some(error) = result.get("error") {
            bail!("page step {name}: {}", error.as_str().unwrap_or_default());
        }
        Ok(result["value"].take())
    }

    fn daemons(&self) -> Vec<u32> {
        daemon_pids(&self.inputs.daemon, &self.sandbox.data)
    }

    /// Loads the page until the extension's shim is in it: the Chromium background registers
    /// the shim after the browser started.
    fn wait_for_shim(&self) -> anyhow::Result<()> {
        let deadline = Instant::now() + SHIM_PATIENCE;
        loop {
            self.session.navigate(&self.page_url())?;
            if self.step("shimmed", Value::Null)?["shimmed"] == true {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "the extension's shim is not in the page after {SHIM_PATIENCE:?}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// 1. With no daemon running, a page socket to NCALayer is a `WebSocket` and gets the
    ///    greeting: the browser started the relay, the relay the daemon.
    fn autostart(&self) -> anyhow::Result<()> {
        ensure!(
            self.daemons().is_empty(),
            "a daemon already runs before the first socket"
        );
        let result = self.step("greeting", Value::Null)?;
        ensure!(
            result["instance"] == true,
            "the socket is not instanceof WebSocket"
        );
        expect_text(
            &result["first"],
            &oncl_protocol::greeting(),
            "first message",
        )?;
        ensure!(
            !self.daemons().is_empty(),
            "no daemon process for the sandbox"
        );
        Ok(())
    }

    /// 2. Heartbeat echo; an unknown module answered byte for byte as by the wss server.
    fn echo_and_unknown(&self) -> anyhow::Result<()> {
        let result = self.step("echo_and_unknown", Value::Null)?;
        expect_text(&result["greeting"], &oncl_protocol::greeting(), "greeting")?;
        expect_text(&result["heartbeat"], oncl_protocol::HEARTBEAT, "heartbeat")?;
        expect_text(
            &result["unknown"],
            &oncl_protocol::module_not_found(),
            "unknown module reply",
        )
    }

    /// 3. `fetch("https://127.0.0.1:13579/", {mode: "no-cors"})` resolves (with the shim's
    ///    200: nothing listens on 13579, the browser's own fetch would reject).
    fn probe(&self) -> anyhow::Result<()> {
        let result = self.step("probe", Value::Null)?;
        ensure!(
            result["resolved"] == true,
            "fetch did not resolve: {result}"
        );
        ensure!(result["status"] == 200, "fetch status: {result}");
        Ok(())
    }

    /// 4. An attached CMS over 1.5 MiB: the reply (over 1 MiB, so cut into several native
    ///    messages) arrives whole, verifies, and encapsulates the signed bytes.
    fn sign(&self) -> anyhow::Result<()> {
        let result = self.step("sign", json!(SIGNED_SIZE))?;
        let reply = result["reply"].as_str().context("no reply text")?;
        ensure!(
            reply.len() > 1 << 20,
            "the reply is {} bytes, not over 1 MiB",
            reply.len()
        );
        let reply: Value = serde_json::from_str(reply).context("the reply is not JSON")?;
        ensure!(reply["status"] == true, "sign failed: {reply}");
        let pem = reply["body"]["result"][0]
            .as_str()
            .with_context(|| format!("no CMS in {reply}"))?;
        let cms = pem_to_der(pem)?;
        let signers = oncl_pki::cms::verify(&cms, None).context("verifying the CMS")?;
        ensure!(signers.len() == 1, "{} signers", signers.len());
        let content = encapsulated_content(&cms)?;
        ensure!(
            content == test_data(SIGNED_SIZE),
            "the encapsulated content ({} bytes) is not the signed data",
            content.len()
        );
        Ok(())
    }

    /// 5. A page forging a bridge `open` with `origin: "https://evil.example"` gets its socket
    ///    with the page's real origin: the daemon logs `origin=http://127.0.0.1:<port>`, never
    ///    the forged one.
    fn origin(&self) -> anyhow::Result<()> {
        let real = format!("origin=http://127.0.0.1:{}", self.page_port);
        let before = self.sandbox.logs().matches(&real).count();
        let result = self.step("forged_open", Value::Null)?;
        let frame = &result["frame"];
        ensure!(
            frame["t"] == "msg" && frame["data"] == oncl_protocol::greeting(),
            "the forged open was not served by the daemon: {frame}"
        );
        // The log writer runs on its own thread: give it a moment.
        let deadline = Instant::now() + Duration::from_secs(5);
        let logs = loop {
            let logs = self.sandbox.logs();
            if logs.matches(&real).count() > before || Instant::now() >= deadline {
                break logs;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        ensure!(
            logs.matches(&real).count() > before,
            "the daemon log has no new `{real}` for the forged open"
        );
        ensure!(
            !logs.contains("evil.example"),
            "the forged origin reached the daemon"
        );
        Ok(())
    }

    /// 6. Killing the daemon closes an open socket with 1006 within [`CLOSE_WITHIN`]; the
    ///    next socket gets the greeting from a daemon the relay started again.
    fn daemon_killed(&self) -> anyhow::Result<()> {
        let result = self.step("hold", Value::Null)?;
        expect_text(&result["first"], &oncl_protocol::greeting(), "greeting")?;
        let killed = self.daemons();
        ensure!(killed.len() == 1, "daemon processes: {killed:?}");
        let killed_at = unix_ms();
        kill(killed[0]);
        let result = self.step("held_close", Value::Null)?;
        let events = result["events"].as_array().context("no events")?;
        let close = events.last().context("no close event")?;
        ensure!(close["code"] == 1006, "events: {events:?}");
        let closed_at = close["at"].as_u64().context("close time")?;
        let took = closed_at.saturating_sub(killed_at);
        ensure!(
            took <= CLOSE_WITHIN.as_millis() as u64,
            "close came {took} ms after the kill"
        );

        let result = self.step("greeting", Value::Null)?;
        expect_text(
            &result["first"],
            &oncl_protocol::greeting(),
            "greeting after the restart",
        )?;
        let restarted = self.daemons();
        ensure!(
            !restarted.is_empty() && !restarted.contains(&killed[0]),
            "daemon processes after the restart: {restarted:?} (killed {})",
            killed[0]
        );
        Ok(())
    }

    /// 7. Without the host registration and the daemon, NCALayer sockets and the NCALayer
    ///    `fetch` are the browser's own: the stand-in original greets; on 13579 a TCP sink
    ///    accepts and drops the browser's connections, so the page sees `error` + `close` and
    ///    a rejected `fetch`, and the sink proves those requests left the browser.
    fn no_host(&self) -> anyhow::Result<()> {
        nm(self.inputs, self.sandbox, &["uninstall"], None).context("nm uninstall")?;
        for pid in self.daemons() {
            kill(pid);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.daemons().is_empty() {
            ensure!(Instant::now() < deadline, "the daemon did not die");
            std::thread::sleep(Duration::from_millis(50));
        }
        let sink = TcpSink::bind(NCALAYER_PORT)?;
        let result = self.step("fallback", Value::Null)?;
        expect_text(
            &result["original"],
            page::ORIGINAL_GREETING,
            "first message from ws://127.0.0.1:13600/",
        )?;
        let events = result["ncalayer"].as_array().context("no events")?;
        let types: Vec<&str> = events.iter().filter_map(|e| e["type"].as_str()).collect();
        ensure!(
            types == ["error", "close"],
            "wss://127.0.0.1:13579/ events: {events:?}"
        );
        ensure!(
            sink.accepted() > 0,
            "wss://127.0.0.1:13579/ never reached the port: the socket was not the browser's own"
        );

        let before = sink.accepted();
        let result = self.step("fallback_fetch", Value::Null)?;
        ensure!(
            result["rejected"] == true && result["name"] == "TypeError",
            "fetch(\"https://127.0.0.1:13579/\") without the host: {result}"
        );
        ensure!(
            sink.accepted() > before,
            "fetch(\"https://127.0.0.1:13579/\") never reached the port: it was not the browser's own"
        );
        ensure!(
            self.daemons().is_empty(),
            "a daemon was started without the host"
        );
        Ok(())
    }
}

/// Accepts TCP connections on `127.0.0.1:<port>` and closes them at once, counting them,
/// until dropped.
struct TcpSink {
    accepted: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TcpSink {
    fn bind(port: u16) -> anyhow::Result<TcpSink> {
        let listener = TcpListener::bind(("127.0.0.1", port)).with_context(|| {
            format!("binding 127.0.0.1:{port} (is NCALayer or OpenNCALayer running?)")
        })?;
        listener.set_nonblocking(true)?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (accepted, stop) = (Arc::clone(&accepted), Arc::clone(&stop));
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        // Counted before the close, which is what the page waits for.
                        Ok((stream, _)) => {
                            accepted.fetch_add(1, Ordering::SeqCst);
                            drop(stream);
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            })
        };
        Ok(TcpSink {
            accepted,
            stop,
            thread: Some(thread),
        })
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for TcpSink {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn expect_text(actual: &Value, expected: &str, what: &str) -> anyhow::Result<()> {
    ensure!(
        actual.as_str() == Some(expected),
        "{what}: expected {expected:?}, got {actual}"
    );
    Ok(())
}

/// The bytes the page signs in scenario 4: `i % 251`.
fn test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

fn pem_to_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .flat_map(|line| line.trim().chars())
        .collect();
    STANDARD.decode(body).context("the CMS PEM is not base64")
}

/// The encapsulated content of a `ContentInfo{SignedData}`:
/// `SignedData.encapContentInfo.eContent`.
pub fn encapsulated_content(cms: &[u8]) -> anyhow::Result<Vec<u8>> {
    let der = oncl_pki::ber::to_der(cms)?;
    let content_info = AnyRef::from_der(&der)?;
    let mut fields = SliceReader::new(content_info.value())?;
    let _content_type = AnyRef::decode(&mut fields)?;
    let signed_data = AnyRef::decode(&mut fields)?; // [0] EXPLICIT
    let signed_data = AnyRef::from_der(signed_data.value())?;
    let mut fields = SliceReader::new(signed_data.value())?;
    let _version = AnyRef::decode(&mut fields)?;
    let _digest_algorithms = AnyRef::decode(&mut fields)?;
    let encap = AnyRef::decode(&mut fields)?;
    let mut fields = SliceReader::new(encap.value())?;
    let _content_type = AnyRef::decode(&mut fields)?;
    let content = AnyRef::decode(&mut fields).context("the CMS has no encapsulated content")?;
    let octets = <&OctetStringRef>::from_der(content.value())?;
    Ok(octets.as_bytes().to_vec())
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// Live `openncalayer` processes (`daemon`'s file name, also once the binary was rebuilt
/// under them) with `ONCL_DATA_DIR=<data>`.
fn daemon_pids(daemon: &Path, data: &Path) -> Vec<u32> {
    let Some(name) = daemon.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let mut needles = vec![format!("ONCL_DATA_DIR={}", data.display()).into_bytes()];
    if let Ok(canonical) = fs::canonicalize(data) {
        needles.push(format!("ONCL_DATA_DIR={}", canonical.display()).into_bytes());
    }
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            // A zombie has no `exe`.
            let exe = fs::read_link(entry.path().join("exe")).ok()?;
            if exe_name(&exe)? != name {
                return None;
            }
            let environ = fs::read(entry.path().join("environ")).ok()?;
            environ
                .split(|&b| b == 0)
                .any(|var| needles.iter().any(|needle| var == needle.as_slice()))
                .then_some(pid)
        })
        .collect()
}

/// The file name of a `/proc/<pid>/exe` target, without the ` (deleted)` the kernel appends
/// once the file was replaced.
fn exe_name(exe: &Path) -> Option<&str> {
    let name = exe.file_name()?.to_str()?;
    Some(name.strip_suffix(" (deleted)").unwrap_or(name))
}

fn kill(pid: u32) {
    let _ = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pki::cms::{SignOptions, sign};
    use oncl_pki::pkcs12::load;
    use oncl_testkit::{read, synthetic};

    #[test]
    fn encapsulated_content_of_attached_cms() {
        let key = synthetic(SIGNING_KEY);
        let entry = load(&read(&key.path), &key.password)
            .unwrap()
            .swap_remove(0);
        let data = test_data(1000);
        let options = |encapsulate| SignOptions {
            encapsulate,
            digested: false,
            signing_time: time::OffsetDateTime::now_utc(),
        };
        let cms = sign(&entry, &data, &options(true)).unwrap();
        assert_eq!(encapsulated_content(&cms).unwrap(), data);

        let detached = sign(&entry, &data, &options(false)).unwrap();
        assert!(encapsulated_content(&detached).is_err());
    }

    #[test]
    fn test_data_matches_the_page() {
        // The page: `bytes[i] = i % 251`.
        assert_eq!(test_data(253)[250..], [250, 0, 1]);
    }

    #[test]
    fn exe_name_ignores_deleted_marker() {
        let name = |p: &str| exe_name(Path::new(p)).map(str::to_owned);
        assert_eq!(
            name("/x/release/openncalayer").as_deref(),
            Some("openncalayer")
        );
        assert_eq!(
            name("/x/release/openncalayer (deleted)").as_deref(),
            Some("openncalayer")
        );
        assert_eq!(name("/").as_deref(), None);
    }
}
