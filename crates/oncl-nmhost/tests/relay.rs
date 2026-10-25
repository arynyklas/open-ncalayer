//! The `nmhost` relay run as the browser runs it: a process speaking native messaging on its
//! stdio, configured by the `nmhost.json` next to its executable.
//!
//! The daemon is an `oncl_ipc` server inside the test or, where the relay has to start one,
//! this test executable started again by the relay with `ONCL_FAKE_DAEMON` set (see
//! [`fake_daemon`]).

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use oncl_ipc::{
    Endpoint, IpcListener, IpcStream, MAX_FRAME, NM_OUT_LIMIT, bind, endpoint, read_frame,
    read_nm_frame, write_frame,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

/// Upper bound for anything a test waits for; generous for unoptimized builds.
const PATIENCE: Duration = Duration::from_secs(60);

/// Set on the relay, which passes its environment on to the daemon it starts: makes this
/// executable a fake daemon. `1`: serve; `exit`: exit 2 without listening.
const FAKE_DAEMON_VAR: &str = "ONCL_FAKE_DAEMON";

/// The first frame of every connection to the daemon inside the test.
const HELLO: &str = r#"{"t":"hello","v":1,"version":"test","compat":"1.4"}"#;
/// The first frame of every connection to the fake daemon.
const FAKE_HELLO: &str = r#"{"t":"hello","v":1,"version":"fake","compat":"1.4"}"#;

fn relay_frame() -> String {
    format!(
        r#"{{"t":"relay","v":1,"version":"{}"}}"#,
        env!("CARGO_PKG_VERSION")
    )
}

/// `len` bytes that are neither JSON nor UTF-8: the relay must never look inside frames.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8 ^ 0x80).collect()
}

/// The `code` of an `error` frame, checking that it also explains itself.
fn error_code(frame: &Value) -> &str {
    assert_eq!(frame["t"], "error", "{frame}");
    assert!(
        frame["message"].as_str().is_some_and(|m| !m.is_empty()),
        "{frame}"
    );
    frame["code"].as_str().expect("error code")
}

// ---- sandbox and relay process ----------------------------------------------------------

/// A relay installed in a fresh directory under `target/tmp`: `relay/nmhost[.exe]` next to
/// its `nmhost.json`, and the data directory `data`. Unless set otherwise, the config names
/// a daemon executable that does not exist.
struct Sandbox {
    root: TempDir,
    data: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        #[cfg(unix)]
        isolate_runtime_dir();
        let root = tempfile::Builder::new()
            .prefix("nmhost-")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .expect("sandbox");
        let data = root.path().join("data");
        std::fs::create_dir(&data).expect("data dir");
        std::fs::create_dir(root.path().join("relay")).expect("relay dir");
        let sandbox = Self { root, data };
        // A hard link (same volume: `target/`) is never open for writing, unlike a copy that
        // a process forked meanwhile by another test may still hold (ETXTBSY).
        let relay = sandbox.relay_path();
        let built = Path::new(env!("CARGO_BIN_EXE_nmhost"));
        if std::fs::hard_link(built, &relay).is_err() {
            std::fs::copy(built, &relay).expect("install relay");
        }
        sandbox.configure(&sandbox.root.path().join("no-daemon"));
        sandbox
    }

    /// A sandbox whose config names `daemon`.
    fn with_daemon(daemon: &Path) -> Self {
        let sandbox = Self::new();
        sandbox.configure(daemon);
        sandbox
    }

    fn configure(&self, daemon: &Path) {
        self.write_config(&json!({"data_dir": self.data, "daemon": daemon}).to_string());
    }

    fn relay_path(&self) -> PathBuf {
        self.root
            .path()
            .join("relay")
            .join(format!("nmhost{}", std::env::consts::EXE_SUFFIX))
    }

    fn config_path(&self) -> PathBuf {
        self.root.path().join("relay").join("nmhost.json")
    }

    fn write_config(&self, text: &str) {
        std::fs::write(self.config_path(), text).expect("write nmhost.json");
    }

    fn endpoint(&self) -> Endpoint {
        endpoint(&self.data).expect("endpoint")
    }

    /// Plays the daemon of this sandbox.
    async fn listen(&self) -> IpcListener {
        bind(&self.endpoint()).await.expect("bind")
    }

    fn relay(&self) -> Relay {
        self.relay_with(&[], &[])
    }

    fn relay_with(&self, args: &[&str], envs: &[(&str, &str)]) -> Relay {
        Relay::start(&self.relay_path(), args, envs)
    }
}

/// Points `XDG_RUNTIME_DIR` at a private test directory (also for the relays and daemons
/// the tests start) so that sockets never land in the user's real runtime directory. Runs
/// once, before any endpoint of this binary is computed.
#[cfg(unix)]
fn isolate_runtime_dir() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::sync::LazyLock;

    static ISOLATED: LazyLock<()> = LazyLock::new(|| {
        let probe = tempfile::tempdir().expect("probe tempdir");
        let uid = std::fs::metadata(probe.path())
            .expect("probe metadata")
            .uid();
        let dir = std::env::temp_dir().join(format!("oncl-nmhost-rt-{uid}"));
        if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            assert_eq!(e.kind(), ErrorKind::AlreadyExists, "{}: {e}", dir.display());
        }
        // SAFETY: other tests may run meanwhile, but this binary reads and inherits the
        // environment only through std (`env::var_os`, `env::temp_dir`, `Command`), which
        // takes the same environment lock as `set_var`; nothing calls libc `getenv` directly.
        // Every endpoint is computed after this ran (`Sandbox::new` forces it).
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", &dir) };
    });
    LazyLock::force(&ISOLATED);
}

/// A running relay, its stdio held by the test as the browser holds it.
struct Relay {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    stderr: ChildStderr,
}

impl Relay {
    fn start(program: &Path, args: &[&str], envs: &[(&str, &str)]) -> Self {
        let mut command = Command::new(program);
        command
            .args(args)
            .envs(envs.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = loop {
            match command.spawn() {
                Ok(child) => break child,
                // A copied relay may still be open for writing in a child another test is
                // forking.
                Err(e) if e.kind() == ErrorKind::ExecutableFileBusy => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => panic!("cannot start {}: {e}", program.display()),
            }
        };
        Self {
            stdin: child.stdin.take(),
            stdout: child.stdout.take().expect("piped stdout"),
            stderr: child.stderr.take().expect("piped stderr"),
            child,
        }
    }

    /// Sends `payload` as one native messaging frame. Unlike `write_nm_frame` (host side),
    /// no 1 MiB limit: the browser sends larger frames.
    async fn send(&mut self, payload: &[u8]) {
        let len = u32::try_from(payload.len()).expect("frame length");
        self.send_raw(&len.to_ne_bytes()).await;
        self.send_raw(payload).await;
    }

    async fn send_raw(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("stdin still open");
        stdin.write_all(bytes).await.expect("write to the relay");
        stdin.flush().await.expect("flush to the relay");
    }

    /// The next frame from the relay; `None` once its output has ended.
    async fn recv(&mut self) -> Option<Vec<u8>> {
        timeout(PATIENCE, read_nm_frame(&mut self.stdout))
            .await
            .expect("relay output in time")
            .expect("relay output")
    }

    async fn recv_json(&mut self) -> Value {
        let frame = self.recv().await.expect("a frame from the relay");
        serde_json::from_slice(&frame).expect("a JSON frame from the relay")
    }

    /// The browser hangs up: the relay sees the end of its stdin.
    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Waits for the relay to exit: its exit code and everything it wrote to stderr.
    async fn finish(mut self) -> (i32, String) {
        let status = timeout(PATIENCE, self.child.wait())
            .await
            .expect("relay exits in time")
            .expect("wait for the relay");
        let mut stderr = String::new();
        timeout(PATIENCE, self.stderr.read_to_string(&mut stderr))
            .await
            .expect("relay stderr ends in time")
            .expect("read relay stderr");
        (status.code().expect("relay exit code"), stderr)
    }
}

/// Accepts the relay's connection on `listener` and says hello as the daemon does.
async fn accept(listener: &mut IpcListener) -> IpcStream {
    let mut stream = timeout(PATIENCE, listener.accept())
        .await
        .expect("relay connects in time")
        .expect("accept the relay");
    write_frame(&mut stream, HELLO.as_bytes())
        .await
        .expect("say hello");
    stream
}

async fn read_ipc(stream: &mut IpcStream) -> Option<Vec<u8>> {
    timeout(PATIENCE, read_frame(stream))
        .await
        .expect("frame from the relay in time")
        .expect("frame from the relay")
}

/// A relay of a fresh sandbox connected to the daemon inside the test, past the `relay` and
/// `hello` frames.
async fn connected() -> (Sandbox, IpcListener, Relay, IpcStream) {
    let sandbox = Sandbox::new();
    let mut listener = sandbox.listen().await;
    let mut relay = sandbox.relay();
    assert_eq!(
        relay.recv().await.as_deref(),
        Some(relay_frame().as_bytes())
    );
    let daemon = accept(&mut listener).await;
    assert_eq!(relay.recv().await.as_deref(), Some(HELLO.as_bytes()));
    (sandbox, listener, relay, daemon)
}

// ---- fake daemon records ----------------------------------------------------------------

/// What the fake daemons of a data directory recorded: per process id, its marks (`start`,
/// `bound`, `busy`, `error`, `exited`) and their text.
type Records = BTreeMap<String, BTreeMap<String, String>>;

fn records(data: &Path) -> Records {
    let mut records = Records::new();
    let Ok(entries) = std::fs::read_dir(data.join(fake_daemon::RECORDS)) else {
        return records;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some((pid, mark)) = name.split_once('.') else {
            continue;
        };
        if mark.ends_with(".tmp") {
            continue;
        }
        // A mark being renamed into place right now is picked up by the next poll.
        if let Ok(text) = std::fs::read_to_string(entry.path()) {
            records
                .entry(pid.to_owned())
                .or_default()
                .insert(mark.to_owned(), text);
        }
    }
    records
}

/// Polls the records of `data` until `done` holds for them.
async fn wait_for_records(data: &Path, done: impl Fn(&Records) -> bool) -> Records {
    let deadline = Instant::now() + PATIENCE;
    loop {
        let records = records(data);
        if done(&records) {
            return records;
        }
        assert!(
            Instant::now() < deadline,
            "the fake daemons never got there: {records:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn all_exited(records: &Records) -> bool {
    !records.is_empty() && records.values().all(|marks| marks.contains_key("exited"))
}

fn this_exe() -> PathBuf {
    std::env::current_exe().expect("test executable")
}

// ---- tests ------------------------------------------------------------------------------

#[tokio::test]
async fn relay_frame_comes_first() {
    let sandbox = Sandbox::new();
    let mut listener = sandbox.listen().await;
    let mut relay = sandbox.relay();
    assert_eq!(
        relay.recv().await.as_deref(),
        Some(relay_frame().as_bytes())
    );
    let _daemon = accept(&mut listener).await;
    assert_eq!(relay.recv().await.as_deref(), Some(HELLO.as_bytes()));
    relay.close_stdin();
    assert_eq!(relay.finish().await.0, 0);
}

#[tokio::test]
async fn browser_arguments_are_logged_and_ignored() {
    let sandbox = Sandbox::new();
    let mut listener = sandbox.listen().await;
    let args = [
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
        "--parent-window=0",
    ];
    let mut relay = sandbox.relay_with(&args, &[]);
    assert_eq!(
        relay.recv().await.as_deref(),
        Some(relay_frame().as_bytes())
    );
    let _daemon = accept(&mut listener).await;
    assert_eq!(relay.recv().await.as_deref(), Some(HELLO.as_bytes()));
    relay.close_stdin();
    let (code, stderr) = relay.finish().await;
    assert_eq!(code, 0);
    for arg in args {
        assert!(stderr.contains(arg), "{arg} not logged: {stderr}");
    }
}

#[tokio::test]
async fn frames_pass_through_both_ways_unchanged() {
    let (_sandbox, _listener, mut relay, mut daemon) = connected().await;
    for len in [0, 1024, 900_000] {
        let payload = pattern(len);
        let ((), got) = tokio::join!(relay.send(&payload), read_ipc(&mut daemon));
        assert!(
            got.as_deref() == Some(&payload[..]),
            "browser → daemon, {len} B"
        );
        let (sent, got) = tokio::join!(write_frame(&mut daemon, &payload), relay.recv());
        sent.expect("daemon writes");
        assert!(
            got.as_deref() == Some(&payload[..]),
            "daemon → browser, {len} B"
        );
    }
    // Towards the daemon frames may exceed the 1 MiB limit of the browser's direction.
    let large = pattern(3 << 20);
    let ((), got) = tokio::join!(relay.send(&large), read_ipc(&mut daemon));
    assert!(
        got.as_deref() == Some(&large[..]),
        "browser → daemon, 3 MiB"
    );
    relay.close_stdin();
    assert_eq!(relay.finish().await.0, 0);
}

#[tokio::test]
async fn stdin_eof_exits_0() {
    let (_sandbox, _listener, mut relay, mut daemon) = connected().await;
    relay.close_stdin();
    assert_eq!(relay.recv().await, None, "no error frame");
    assert_eq!(relay.finish().await.0, 0);
    // The relay's end of the connection is gone too.
    let end = timeout(PATIENCE, read_frame(&mut daemon))
        .await
        .expect("the daemon sees the end in time");
    assert!(matches!(end, Ok(None) | Err(_)), "{end:?}");
}

#[tokio::test]
async fn daemon_eof_sends_daemon_gone() {
    let (_sandbox, _listener, mut relay, daemon) = connected().await;
    drop(daemon);
    let frame = relay.recv_json().await;
    assert_eq!(error_code(&frame), "DAEMON_GONE");
    assert_eq!(relay.recv().await, None);
    assert_eq!(relay.finish().await.0, 0);
}

#[tokio::test]
async fn oversized_daemon_frame_sends_protocol_error() {
    let (_sandbox, _listener, mut relay, mut daemon) = connected().await;
    let at_limit = pattern(NM_OUT_LIMIT);
    let (sent, got) = tokio::join!(write_frame(&mut daemon, &at_limit), relay.recv());
    sent.expect("daemon writes");
    assert!(got.as_deref() == Some(&at_limit[..]), "1 MiB passes");

    let over_limit = pattern(NM_OUT_LIMIT + 1);
    let (sent, frame) = tokio::join!(write_frame(&mut daemon, &over_limit), relay.recv_json());
    sent.expect("daemon writes");
    assert_eq!(error_code(&frame), "PROTOCOL");
    assert_eq!(relay.recv().await, None);
    assert_eq!(relay.finish().await.0, 1);
}

#[tokio::test]
async fn oversized_browser_frame_sends_protocol_error() {
    let (_sandbox, _listener, mut relay, _daemon) = connected().await;
    let len = u32::try_from(MAX_FRAME + 1).expect("fits u32");
    relay.send_raw(&len.to_ne_bytes()).await;
    let frame = relay.recv_json().await;
    assert_eq!(error_code(&frame), "PROTOCOL");
    assert_eq!(relay.recv().await, None);
    assert_eq!(relay.finish().await.0, 1);
}

#[tokio::test]
async fn bad_config_sends_relay_config() {
    let sandbox = Sandbox::new();
    let daemon = sandbox.root.path().join("no-daemon");
    let cases = [
        ("missing", None),
        ("not JSON", Some("{\"data_dir\"".to_owned())),
        (
            "no daemon",
            Some(json!({"data_dir": sandbox.data}).to_string()),
        ),
        (
            "relative data_dir",
            Some(json!({"data_dir": "data", "daemon": daemon}).to_string()),
        ),
        (
            "relative daemon",
            Some(json!({"data_dir": sandbox.data, "daemon": "openncalayer"}).to_string()),
        ),
    ];
    for (case, config) in cases {
        match config {
            Some(text) => sandbox.write_config(&text),
            None => std::fs::remove_file(sandbox.config_path()).expect("remove nmhost.json"),
        }
        let mut relay = sandbox.relay();
        let frame = relay.recv_json().await;
        assert_eq!(error_code(&frame), "RELAY_CONFIG", "{case}: {frame}");
        assert_eq!(relay.recv().await, None, "{case}");
        assert_eq!(relay.finish().await.0, 1, "{case}");
    }
}

#[tokio::test]
async fn missing_daemon_is_spawned_then_connected() {
    let sandbox = Sandbox::with_daemon(&this_exe());
    let mut relay = sandbox.relay_with(&[], &[(FAKE_DAEMON_VAR, "1")]);
    assert_eq!(
        relay.recv().await.as_deref(),
        Some(relay_frame().as_bytes())
    );
    assert_eq!(relay.recv().await.as_deref(), Some(FAKE_HELLO.as_bytes()));
    relay.send(b"ping").await;
    assert_eq!(relay.recv().await.as_deref(), Some(&b"ping"[..]));

    let seen = records(&sandbox.data);
    assert_eq!(seen.len(), 1, "{seen:?}");
    let marks = seen.values().next().expect("one daemon");
    assert!(marks.contains_key("bound"), "{marks:?}");
    let start: Value = serde_json::from_str(&marks["start"]).expect("start record");
    assert_eq!(start["args"], json!(["run", "--allow-no-wss"]));
    assert_eq!(start["data_dir"], json!(sandbox.data));

    relay.close_stdin();
    // The daemon holds none of the browser's pipes: the relay's output ends with the relay,
    // while the daemon still runs.
    assert_eq!(relay.recv().await, None);
    assert_eq!(relay.finish().await.0, 0);
    let seen = records(&sandbox.data);
    assert!(
        !seen.values().any(|marks| marks.contains_key("exited")),
        "{seen:?}"
    );
    wait_for_records(&sandbox.data, all_exited).await;
}

#[tokio::test]
async fn unspawnable_daemon_gives_daemon_unavailable_within_16_s() {
    /// Runs a relay of `sandbox` to its `DAEMON_UNAVAILABLE`; the time that took.
    async fn unavailable(sandbox: &Sandbox, envs: &[(&str, &str)]) -> Duration {
        let started = Instant::now();
        let mut relay = sandbox.relay_with(&[], envs);
        assert_eq!(
            relay.recv().await.as_deref(),
            Some(relay_frame().as_bytes())
        );
        let frame = relay.recv_json().await;
        let took = started.elapsed();
        assert_eq!(error_code(&frame), "DAEMON_UNAVAILABLE", "{frame}");
        assert_eq!(relay.recv().await, None);
        assert_eq!(relay.finish().await.0, 1);
        took
    }

    // No daemon executable: nothing to wait for.
    let missing = Sandbox::new();
    // A daemon that starts but never listens gets 15 s.
    let mute = Sandbox::with_daemon(&this_exe());
    let (at_once, waited) = tokio::join!(
        unavailable(&missing, &[]),
        unavailable(&mute, &[(FAKE_DAEMON_VAR, "exit")])
    );
    assert!(at_once < Duration::from_secs(15), "{at_once:?}");
    assert!(
        waited >= Duration::from_secs(15) && waited < Duration::from_secs(16),
        "{waited:?}"
    );
    let records = wait_for_records(&mute.data, all_exited).await;
    assert_eq!(records.len(), 1, "{records:?}");
}

#[tokio::test]
async fn two_relays_racing_start_share_one_daemon() {
    let sandbox = Sandbox::with_daemon(&this_exe());
    let envs = [(FAKE_DAEMON_VAR, "1")];
    let mut relays = [
        sandbox.relay_with(&[], &envs),
        sandbox.relay_with(&[], &envs),
    ];
    for relay in &mut relays {
        assert_eq!(
            relay.recv().await.as_deref(),
            Some(relay_frame().as_bytes())
        );
        assert_eq!(relay.recv().await.as_deref(), Some(FAKE_HELLO.as_bytes()));
    }
    for mut relay in relays {
        relay.close_stdin();
        assert_eq!(relay.finish().await.0, 0);
    }
    // Both relays found no daemon and started one; one daemon bound, the other exited 4.
    let seen = wait_for_records(&sandbox.data, all_exited).await;
    let mut outcomes: Vec<_> = seen
        .values()
        .map(|marks| {
            let bind = ["bound", "busy", "error"]
                .into_iter()
                .find(|mark| marks.contains_key(*mark))
                .unwrap_or("none");
            (bind, marks["exited"].as_str())
        })
        .collect();
    outcomes.sort_unstable();
    assert_eq!(outcomes, [("bound", "0"), ("busy", "4")], "{seen:?}");
}

// ---- fake daemon ------------------------------------------------------------------------

/// This test executable as the daemon the relay starts (`<exe> run --allow-no-wss` with
/// `ONCL_FAKE_DAEMON` set). It keeps the single-instance rule of the real daemon (exit 4 when
/// the endpoint is taken), says hello and echoes frames, and records what it did under
/// `<ONCL_DATA_DIR>/fake-daemon/` for the tests to check.
mod fake_daemon {
    use std::ffi::OsStr;
    use std::io::ErrorKind;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use oncl_ipc::{IpcStream, bind, endpoint, read_frame, write_frame};
    use serde_json::json;
    use tokio::task::JoinSet;
    use tokio::time::sleep;

    use super::{FAKE_DAEMON_VAR, FAKE_HELLO};

    /// Subdirectory of the data directory with the records.
    pub const RECORDS: &str = "fake-daemon";
    /// A daemon is not up at once: long enough for two relays started together to both find
    /// no daemon and start one each.
    const START_DELAY: Duration = Duration::from_secs(1);
    /// Lifetime when no client comes.
    const IDLE: Duration = Duration::from_secs(30);
    /// Lifetime after the last client left: lets a test see that the relay's output ends
    /// while the daemon it started still runs.
    const LINGER: Duration = Duration::from_secs(3);

    // libtest rejects the daemon's command line (`run --allow-no-wss`), so the fake daemon
    // runs before `main`, from the platform's list of initializers, as the `ctor` crate does.
    #[used]
    #[cfg_attr(
        all(unix, not(target_vendor = "apple")),
        unsafe(link_section = ".init_array")
    )]
    #[cfg_attr(
        target_vendor = "apple",
        unsafe(link_section = "__DATA,__mod_init_func")
    )]
    #[cfg_attr(windows, unsafe(link_section = ".CRT$XCU"))]
    static BEFORE_MAIN: extern "C" fn() = before_main;

    extern "C" fn before_main() {
        if let Some(mode) = std::env::var_os(FAKE_DAEMON_VAR) {
            std::process::exit(run(&mode));
        }
    }

    fn run(mode: &OsStr) -> i32 {
        let Some(data) = std::env::var_os("ONCL_DATA_DIR").map(PathBuf::from) else {
            return 1;
        };
        let records = data.join(RECORDS);
        if std::fs::create_dir_all(&records).is_err() {
            return 1;
        }
        let pid = std::process::id();
        let mark = |what: &str, text: &str| {
            let tmp = records.join(format!("{pid}.{what}.tmp"));
            let _ = std::fs::write(&tmp, text)
                .and_then(|()| std::fs::rename(&tmp, records.join(format!("{pid}.{what}"))));
        };
        let args: Vec<String> = std::env::args().skip(1).collect();
        mark(
            "start",
            &json!({"args": args, "data_dir": data}).to_string(),
        );
        let code = if mode == "exit" {
            2
        } else {
            std::thread::sleep(START_DELAY);
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime.block_on(serve(&data, &mark)),
                Err(e) => {
                    mark("error", &e.to_string());
                    1
                }
            }
        };
        mark("exited", &code.to_string());
        code
    }

    async fn serve(data: &Path, mark: &dyn Fn(&str, &str)) -> i32 {
        let ep = match endpoint(data) {
            Ok(ep) => ep,
            Err(e) => {
                mark("error", &e.to_string());
                return 1;
            }
        };
        let mut listener = match bind(&ep).await {
            Ok(listener) => listener,
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                mark("busy", "");
                return 4;
            }
            Err(e) => {
                mark("error", &e.to_string());
                return 1;
            }
        };
        mark("bound", "");
        let mut clients = JoinSet::new();
        let mut served = false;
        loop {
            let wait = if served { LINGER } else { IDLE };
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(stream) => {
                        served = true;
                        clients.spawn(echo(stream));
                    }
                    Err(e) => {
                        mark("error", &e.to_string());
                        return 1;
                    }
                },
                Some(_) = clients.join_next(), if !clients.is_empty() => {}
                () = sleep(wait), if clients.is_empty() => return 0,
            }
        }
    }

    async fn echo(mut stream: IpcStream) {
        if write_frame(&mut stream, FAKE_HELLO.as_bytes())
            .await
            .is_err()
        {
            return;
        }
        while let Ok(Some(frame)) = read_frame(&mut stream).await {
            if write_frame(&mut stream, &frame).await.is_err() {
                return;
            }
        }
    }
}
