//! The installer entry against real processes: a fake desktop that serves the management
//! endpoint behind the real activity gate, the entry (as a process a test can watch and
//! kill) and a fake Setup that records its arguments, ends the program under the installation
//! as the real one does and leaves what a real installation leaves. The harness
//! (`oncl-winget-harness`) is labelled as such: none of this is the real Velopack Setup,
//! which writes the real Apps & Features entry and cannot be pointed at a throw-away one.
//!
//! The installation, the user's registry key and the data directory are throw-away; the
//! real ones are never touched.
#![cfg(windows)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use oncl_registry::TestKey;
use oncl_winget_setup::Exit;
use oncl_winget_setup::payload::{self, Arch};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const HARNESS: &str = env!("CARGO_BIN_EXE_oncl-winget-harness");
const ENTRY: &str = env!("CARGO_BIN_EXE_oncl-winget-setup");
/// The quiet time of the fake desktop: short, so that a test can wait it out.
const QUIET_MS: u64 = 500;
const PATIENCE: Duration = Duration::from_secs(30);
/// What a run that does not wait for anything may take.
const SHORT: Duration = Duration::from_secs(60);
/// What a run that waits for the program and runs Setup may take.
const LONG: Duration = Duration::from_secs(120);

/// `child`'s end within `within`; a child that does not end is killed and fails the test, so
/// that one hung process does not hang the suite.
fn wait_within(child: &mut Child, within: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("a process did not end within {within:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `command` run to its end within `within`, with its output.
fn output_within(mut command: Command, within: Duration) -> std::process::Output {
    use std::io::Read;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let mut pipes = Vec::new();
    for stream in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ] {
        let (tx, rx) = mpsc::channel();
        let mut stream = stream.unwrap();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stream.read_to_end(&mut bytes);
            let _ = tx.send(bytes);
        });
        pipes.push(rx);
    }
    let status = wait_within(&mut child, within);
    // A grandchild that kept a pipe open must not hold the test up.
    let collect =
        |rx: &Receiver<Vec<u8>>| rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    let stderr = collect(&pipes[1]);
    let stdout = collect(&pipes[0]);
    std::process::Output {
        status,
        stdout,
        stderr,
    }
}

fn sha(path: &Path) -> String {
    Sha256::digest(std::fs::read(path).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A throw-away installation, data directory, registry key and work area.
struct Fixture {
    dir: TempDir,
    key: TestKey,
    /// Every child a test starts, ended with the fixture.
    children: Vec<u32>,
    /// The quiet time of the fake desktop and of the entry's view of it.
    quiet_ms: u64,
}

impl Fixture {
    fn new() -> Fixture {
        Fixture {
            // Short, as Windows paths of a pipe name and a process image go.
            dir: tempfile::Builder::new().prefix("w01-").tempdir().unwrap(),
            key: TestKey::new(),
            children: Vec::new(),
            quiet_ms: QUIET_MS,
        }
    }

    fn root(&self) -> PathBuf {
        self.dir.path().join("OpenNCALayer")
    }

    fn data(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn work(&self) -> PathBuf {
        let work = self.dir.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        work
    }

    fn log(&self) -> PathBuf {
        self.dir.path().join("log.txt")
    }

    fn log_lines(&self) -> Vec<String> {
        std::fs::read_to_string(self.log())
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn setups_started(&self) -> usize {
        self.log_lines()
            .iter()
            .filter(|l| l.contains("setup started"))
            .count()
    }

    fn program(&self) -> PathBuf {
        self.root().join("current").join("openncalayer.exe")
    }

    /// An earlier version of the program, installed as Setup leaves one.
    fn install_before(&self, version: &str) {
        let current = self.root().join("current");
        std::fs::create_dir_all(&current).unwrap();
        std::fs::copy(HARNESS, self.root().join("Update.exe")).unwrap();
        std::fs::copy(HARNESS, self.program()).unwrap();
        std::fs::write(current.join("sq.version"), nuspec(version, "x64")).unwrap();
        let update = self.root().join("Update.exe");
        for (name, value) in [
            ("DisplayName", "OpenNCALayer".to_owned()),
            ("DisplayVersion", version.to_owned()),
            ("InstallLocation", self.root().display().to_string()),
            ("Publisher", "OpenNCALayer".to_owned()),
            (
                "UninstallString",
                format!("\"{}\" --uninstall", update.display()),
            ),
        ] {
            oncl_registry::set_string(self.arp(), Some(name), &value).unwrap();
        }
    }

    fn arp(&self) -> &str {
        self.key.path()
    }

    fn arp_version(&self) -> Option<String> {
        oncl_registry::get_string(
            oncl_registry::Hive::CurrentUser,
            self.arp(),
            Some("DisplayVersion"),
        )
        .unwrap()
    }

    /// The entry file: the harness (a PE without a payload) carrying the harness as its
    /// `Setup.exe`, for `version`.
    fn entry_image(&self, version: &str) -> PathBuf {
        let path = self.dir.path().join(format!("entry-{version}.exe"));
        // Made once: it takes longer than a quiet time a test may want to be inside of.
        if path.exists() {
            return path;
        }
        let harness = std::fs::read(HARNESS).unwrap();
        let image = payload::append(
            &harness,
            &harness,
            &semver::Version::parse(version).unwrap(),
            Arch::X64,
        )
        .unwrap();
        std::fs::write(&path, image).unwrap();
        path
    }

    /// Hashes of everything under the installation: what a refusal must leave as it was.
    fn tree(&self) -> BTreeMap<String, String> {
        fn walk(dir: &Path, base: &Path, out: &mut BTreeMap<String, String>) {
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, base, out);
                } else {
                    let rel = path.strip_prefix(base).unwrap().display().to_string();
                    out.insert(rel, sha(&path));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.root(), &self.root(), &mut out);
        out
    }

    /// The entry as a process: `harness wrapper <image>`, with the throw-away installation
    /// and what the fake Setup should do.
    fn entry_command(&self, image: &Path, version: &str, setup: &[(&str, &str)]) -> Command {
        let mut command = Command::new(HARNESS);
        command
            .arg("wrapper")
            .arg(image)
            .env("ONCL_HARNESS_ROOT", self.root())
            .env("ONCL_HARNESS_DATA_DIR", self.data())
            .env("ONCL_HARNESS_ARP_KEY", self.arp())
            .env("ONCL_HARNESS_TEMP", self.work())
            .env("ONCL_HARNESS_LOG", self.log())
            .env("ONCL_HARNESS_QUIET_MS", self.quiet_ms.to_string())
            .env("ONCL_HARNESS_VERSION", version)
            // The program the entry starts again finds its data directory the way the
            // daemon does.
            .env("ONCL_DATA_DIR", self.data())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in setup {
            command.env(format!("ONCL_HARNESS_{name}"), value);
        }
        command
    }

    /// Runs the entry to its end: its exit code and what it told.
    fn run_entry(&mut self, version: &str, wait_ms: u64, setup: &[(&str, &str)]) -> (u8, String) {
        let image = self.entry_image(version);
        let mut command = self.entry_command(&image, version, setup);
        command.env("ONCL_HARNESS_WAIT_MS", wait_ms.to_string());
        let output = output_within(command, LONG);
        let code = u8::try_from(output.status.code().unwrap()).unwrap();
        (code, String::from_utf8_lossy(&output.stderr).into_owned())
    }

    /// The fake desktop, running as the installed program.
    fn start_desktop(&mut self) -> Desktop {
        std::fs::create_dir_all(self.data()).unwrap();
        let mut child = Command::new(self.program())
            .args(["run", "--allow-no-wss"])
            .env("ONCL_DATA_DIR", self.data())
            .env("ONCL_HARNESS_QUIET_MS", self.quiet_ms.to_string())
            .env("ONCL_HARNESS_LOG", self.log())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.children.push(child.id());
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send((Instant::now(), line)).is_err() {
                    break;
                }
            }
        });
        let stdin = child.stdin.take().unwrap();
        let mut desktop = Desktop {
            child,
            stdin,
            lines,
            seen: Vec::new(),
        };
        desktop.expect("ready");
        desktop
    }

    /// Programs of the installation that run now.
    fn running(&self) -> Vec<oncl_winget_setup::processes::Running> {
        oncl_winget_setup::processes::running_from(&self.root()).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let mut pids = self.children.clone();
        pids.extend(self.running().iter().map(|p| p.pid));
        // The fake Setup's copy lives in the work area, which is not under the root.
        for line in self.log_lines() {
            if let Some((pid, rest)) = line.split_once(' ')
                && rest.starts_with("setup")
                && let Ok(pid) = pid.parse()
            {
                pids.push(pid);
            }
        }
        for pid in pids {
            // Opened once: the image is read and the process ended on the same handle, so a
            // recycled pid never ends a program this test did not start.
            oncl_winget_setup::processes::terminate_if(pid, |image| {
                is_ours_image(image, self.dir.path())
            });
        }
        // Let the images go before the directory does.
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Whether process `pid` runs the harness or a program under `dir`: what this test started.
fn is_ours_image(image: &Path, dir: &Path) -> bool {
    let norm = |path: &Path| {
        let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
        let text = path.to_string_lossy().to_lowercase();
        text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
    };
    let image = norm(image);
    image.starts_with(&norm(dir)) || image == norm(Path::new(HARNESS))
}

fn nuspec(version: &str, arch: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <package xmlns=\"http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd\">\n\
         <metadata>\n<id>OpenNCALayer</id>\n<version>{version}</version>\n\
         <title>OpenNCALayer</title>\n<authors>OpenNCALayer</authors>\n\
         <channel>win-{arch}</channel>\n<mainExe>openncalayer.exe</mainExe>\n<os>win</os>\n\
         <osMinVersion>10</osMinVersion>\n<machineArchitecture>{arch}</machineArchitecture>\n\
         </metadata>\n</package>"
    )
}

/// The fake desktop and its line protocol.
struct Desktop {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<(Instant, String)>,
    seen: Vec<(Instant, String)>,
}

impl Desktop {
    fn send(&mut self, command: &str) {
        writeln!(self.stdin, "{command}").unwrap();
        self.stdin.flush().unwrap();
    }

    /// The first line from now on that starts with `prefix`, within [`PATIENCE`].
    fn expect(&mut self, prefix: &str) -> Instant {
        self.expect_within(prefix, PATIENCE)
            .unwrap_or_else(|| panic!("no {prefix:?}; saw {:?}", self.seen))
    }

    fn expect_within(&mut self, prefix: &str, within: Duration) -> Option<Instant> {
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.checked_duration_since(Instant::now())?;
            match self.lines.recv_timeout(left) {
                Ok((at, line)) => {
                    let found = line.starts_with(prefix);
                    self.seen.push((at, line));
                    if found {
                        return Some(at);
                    }
                }
                Err(_) => return None,
            }
        }
    }

    /// Whether a line starting with `prefix` has come (draining what is there).
    fn saw(&mut self, prefix: &str) -> bool {
        while let Ok(item) = self.lines.try_recv() {
            self.seen.push(item);
        }
        self.seen.iter().any(|(_, line)| line.starts_with(prefix))
    }

    fn alive(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }
}

fn busy() -> u8 {
    Exit::Busy as u8
}

// ---------------------------------------------------------------------- the three leases

#[test]
fn active_sign_not_force_stopped() {
    let mut fx = Fixture::new();
    fx.install_before("0.1.0");
    let before = fx.tree();
    let mut desktop = fx.start_desktop();
    desktop.send("begin 1");
    desktop.expect("began 1");

    // The fake Setup would end the running program, as the real one does. It must never run.
    let (code, message) = fx.run_entry("0.2.0", 700, &[("FORCE_STOP", "1"), ("SETUP", "install")]);
    assert_eq!(code, busy(), "{message}");
    assert_eq!(
        fx.setups_started(),
        0,
        "Setup ran under an active operation"
    );
    assert!(desktop.alive(), "the running program was stopped");
    assert_eq!(fx.tree(), before, "the installation changed");
    assert_eq!(fx.arp_version().as_deref(), Some("0.1.0"));
    assert!(
        fx.work().read_dir().unwrap().next().is_none(),
        "a private copy of the payload was left"
    );
    // The refusal gave the program back: the operation goes on, and a new one is not held.
    desktop.send("begin 2");
    desktop.expect("began 2");
    desktop.send("end 1");
    desktop.send("end 2");
    desktop.expect("ended 2");

    // Once the operation ended and its quiet time passed, the same entry replaces it: Setup
    // runs once, with `--silent` and nothing else, and the program runs again.
    let old = desktop.child.id();
    std::thread::sleep(Duration::from_millis(QUIET_MS + 200));
    let (code, message) = fx.run_entry(
        "0.2.0",
        20_000,
        &[("FORCE_STOP", "1"), ("SETUP", "install")],
    );
    assert_eq!(code, Exit::Success as u8, "{message}");
    assert_eq!(fx.setups_started(), 1);
    assert!(
        fx.log_lines()
            .iter()
            .any(|l| l.ends_with("setup started: --silent")),
        "{:?}",
        fx.log_lines()
    );
    assert_eq!(fx.arp_version().as_deref(), Some("0.2.0"));
    assert!(
        !desktop.alive(),
        "the old program was replaced (and stopped by Setup)"
    );
    let running = fx.running();
    assert!(
        running
            .iter()
            .any(|p| p.pid != old && p.image.ends_with("openncalayer.exe")),
        "the program is not running again: {running:?}"
    );
    assert!(
        fx.log_lines()
            .iter()
            .any(|l| l.ends_with("program started: run --allow-no-wss")),
        "it is started as it ran: {:?}",
        fx.log_lines()
    );
    assert!(fx.work().read_dir().unwrap().next().is_none());
}

#[test]
fn an_operation_that_ends_while_the_installer_waits_lets_it_go_on() {
    let mut fx = Fixture::new();
    fx.install_before("0.1.0");
    let mut desktop = fx.start_desktop();
    desktop.send("begin 1");
    desktop.expect("began 1");
    let image = fx.entry_image("0.2.0");
    let mut command = fx.entry_command(
        &image,
        "0.2.0",
        &[("FORCE_STOP", "1"), ("SETUP", "install")],
    );
    command.env("ONCL_HARNESS_WAIT_MS", "30000");
    let mut entry = command.spawn().unwrap();
    fx.children.push(entry.id());
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(fx.setups_started(), 0, "it waits for the operation");
    assert!(entry.try_wait().unwrap().is_none());
    desktop.send("end 1");
    let ended = Instant::now();
    let granted = desktop.expect("hold-granted");
    assert!(
        granted.duration_since(ended) >= Duration::from_millis(QUIET_MS - 100),
        "the hold was granted {:?} after the operation ended: within its quiet time",
        granted.duration_since(ended)
    );
    let status = wait_within(&mut entry, LONG);
    assert_eq!(status.code(), Some(Exit::Success as i32));
    assert_eq!(fx.arp_version().as_deref(), Some("0.2.0"));
}

#[test]
fn new_operation_blocked_until_release() {
    let mut fx = Fixture::new();
    fx.install_before("0.1.0");
    let mut desktop = fx.start_desktop();
    let release = fx.dir.path().join("release-setup");
    let image = fx.entry_image("0.2.0");
    // Setup is held up (and does nothing else) for as long as the test wants the lease.
    let mut command = fx.entry_command(
        &image,
        "0.2.0",
        &[("WAIT_FOR", release.to_str().unwrap()), ("SETUP", "noop")],
    );
    command.env("ONCL_HARNESS_WAIT_MS", "10000");
    let mut entry = command.spawn().unwrap();
    fx.children.push(entry.id());
    desktop.expect("hold-granted");
    let deadline = Instant::now() + PATIENCE;
    while !fx.log_lines().iter().any(|l| l.contains("setup waiting")) {
        assert!(Instant::now() < deadline, "Setup did not start");
        std::thread::sleep(Duration::from_millis(20));
    }

    // While the installation is being replaced, a new operation waits.
    desktop.send("begin 7");
    assert!(
        desktop
            .expect_within("began 7", Duration::from_millis(1200))
            .is_none(),
        "an operation began while the program was held"
    );
    std::fs::write(&release, b"go").unwrap();
    let status = wait_within(&mut entry, LONG);
    // The fake Setup installed nothing, so the entry says so; what matters here is that the
    // lease ended with it, and the waiting operation goes on.
    assert_eq!(status.code(), Some(Exit::NotInstalled as i32));
    desktop.expect("released");
    desktop.expect("began 7");
}

#[test]
fn abandoned_lease_recovers() {
    let mut fx = Fixture::new();
    fx.install_before("0.1.0");
    let mut desktop = fx.start_desktop();
    let release = fx.dir.path().join("never");
    let image = fx.entry_image("0.2.0");
    let mut command = fx.entry_command(
        &image,
        "0.2.0",
        &[
            ("WAIT_FOR", release.to_str().unwrap()),
            ("SETUP", "install"),
        ],
    );
    command.env("ONCL_HARNESS_WAIT_MS", "10000");
    let mut entry = command.spawn().unwrap();
    desktop.expect("hold-granted");
    let deadline = Instant::now() + PATIENCE;
    while !fx.log_lines().iter().any(|l| l.contains("setup waiting")) {
        assert!(Instant::now() < deadline, "Setup did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    desktop.send("begin 1");
    assert!(
        desktop
            .expect_within("began 1", Duration::from_millis(600))
            .is_none()
    );

    // The installer is killed (a crash, WinGet's timeout, the user): its end of the
    // connection closes without a word.
    entry.kill().unwrap();
    entry.wait().unwrap();
    desktop.expect("released");
    desktop.expect("began 1");
    // The program is not left busy for good: another maintainer can hold it at once.
    desktop.send("end 1");
    std::thread::sleep(Duration::from_millis(QUIET_MS + 200));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let ep = oncl_ipc::maintenance::endpoint(&fx.data()).unwrap();
        let mut client = oncl_ipc::maintenance::Client::connect(&ep).await.unwrap();
        let reply = client.hold().await.unwrap();
        assert!(
            matches!(reply, oncl_ipc::maintenance::Reply::Granted { .. }),
            "{reply:?}"
        );
    });
    assert_eq!(
        fx.arp_version().as_deref(),
        Some("0.1.0"),
        "the old copy is intact"
    );
}

// ------------------------------------------------------------ window, quiet time and holds

#[test]
fn open_confirmation_is_busy() {
    let mut fx = Fixture::new();
    fx.install_before("0.1.0");
    let before = fx.tree();
    let mut desktop = fx.start_desktop();
    desktop.send("window open");
    desktop.expect("window open");

    let (code, message) = fx.run_entry("0.2.0", 600, &[("FORCE_STOP", "1"), ("SETUP", "install")]);
    assert_eq!(code, busy(), "{message}");
    assert_eq!(fx.setups_started(), 0);
    assert_eq!(fx.tree(), before);
    assert!(desktop.alive());
    // The window was seen with new operations held back, and the hold was let go again.
    desktop.expect("hold-refused");
    desktop.send("begin 1");
    desktop.expect("began 1");
    desktop.send("end 1");
    desktop.send("window close");
    desktop.expect("window close");
    std::thread::sleep(Duration::from_millis(QUIET_MS + 200));
    let (code, message) = fx.run_entry(
        "0.2.0",
        20_000,
        &[("FORCE_STOP", "1"), ("SETUP", "install")],
    );
    assert_eq!(code, Exit::Success as u8, "{message}");
}

#[test]
fn quiet_rechecked_after_hold() {
    let mut fx = Fixture::new();
    // A quiet time much longer than starting the entry takes, so that the first attempt is
    // certainly within it.
    fx.quiet_ms = 10_000;
    fx.install_before("0.1.0");
    fx.entry_image("0.2.0");
    let mut desktop = fx.start_desktop();
    desktop.send("begin 1");
    desktop.expect("began 1");
    desktop.send("end 1");
    desktop.expect("ended 1");

    // Nothing runs, but an operation ended a moment ago: the quiet time is not over.
    let (code, message) = fx.run_entry("0.2.0", 0, &[("FORCE_STOP", "1"), ("SETUP", "install")]);
    assert_eq!(code, busy(), "{message}");
    assert_eq!(fx.setups_started(), 0);
    assert!(desktop.saw("hold-refused"));
    assert!(!desktop.saw("hold-granted"));
    assert!(desktop.alive());
    // Not left held either.
    desktop.send("begin 2");
    desktop.expect("began 2");
    desktop.send("end 2");
    desktop.expect("ended 2");
    std::thread::sleep(Duration::from_millis(fx.quiet_ms + 300));
    let (code, message) = fx.run_entry("0.2.0", 0, &[("FORCE_STOP", "1"), ("SETUP", "install")]);
    assert_eq!(code, Exit::Success as u8, "{message}");
}

// ------------------------------------------------------ what Setup's exit code proves

#[test]
fn native_zero_without_install_is_failure() {
    // Nothing installed, nothing running; Setup exits 0 having installed nothing (as the
    // pinned Setup does when a prerequisite is not installed).
    let mut fx = Fixture::new();
    let (code, message) = fx.run_entry("0.2.0", 0, &[("SETUP", "noop")]);
    assert_eq!(fx.setups_started(), 1);
    assert_eq!(code, Exit::NotInstalled as u8, "{message}");
    assert!(message.contains("0.2.0"), "{message}");

    // An older copy that stays as it is does not make it a success either.
    let mut fx = Fixture::new();
    fx.install_before("0.1.0");
    let (code, message) = fx.run_entry("0.2.0", 0, &[("SETUP", "noop")]);
    assert_eq!(code, Exit::NotInstalled as u8, "{message}");
    assert_eq!(fx.arp_version().as_deref(), Some("0.1.0"));
}

#[test]
fn installed_version_mismatch_is_failure() {
    // Each of these is an installation that is not the entry's version, with exit code 0.
    for (case, setup) in [
        ("manifest", vec![("VERSION", "0.3.0")]),
        ("arp version", vec![("ARP_VERSION", "0.1.9")]),
        ("no arp entry", vec![("NO_ARP", "1")]),
        ("program version", vec![("EXE_VERSION", "0.1.9")]),
        (
            "arp location",
            vec![("ARP_LOCATION", "\\\\other-host\\share\\OpenNCALayer")],
        ),
        ("architecture", vec![("ARCH", "x86")]),
        ("another app id", vec![("ID", "SomethingElse")]),
        ("another main program", vec![("MAIN_EXE", "other.exe")]),
        (
            "uninstaller of another installation",
            vec![("UNINSTALL", "\"elsewhere\\Update.exe\" --uninstall")],
        ),
    ] {
        let mut fx = Fixture::new();
        let mut env = vec![("SETUP", "install")];
        env.extend(setup);
        let (code, message) = fx.run_entry("0.2.0", 0, &env);
        assert_eq!(code, Exit::NotInstalled as u8, "{case}: {message}");
    }
    // The control: all of it as it should be.
    let mut fx = Fixture::new();
    let (code, message) = fx.run_entry("0.2.0", 0, &[("SETUP", "install")]);
    assert_eq!(code, Exit::Success as u8, "{message}");
    assert_eq!(fx.arp_version().as_deref(), Some("0.2.0"));
    // A fresh installation does not open the program.
    assert!(
        !fx.log_lines().iter().any(|l| l.contains("program started")),
        "{:?}",
        fx.log_lines()
    );
    assert!(fx.running().is_empty());
}

#[test]
fn a_setup_that_fails_is_not_a_success_and_leaves_the_program_running() {
    let mut fx = Fixture::new();
    fx.install_before("0.1.0");
    let mut desktop = fx.start_desktop();
    let (code, message) = fx.run_entry("0.2.0", 0, &[("SETUP", "fail")]);
    assert_eq!(code, Exit::SetupFailed as u8, "{message}");
    assert!(desktop.alive());
    assert_eq!(fx.arp_version().as_deref(), Some("0.1.0"));
    // Only the test's own start of the desktop: nothing was started again.
    assert_eq!(
        fx.log_lines()
            .iter()
            .filter(|l| l.contains("program started"))
            .count(),
        1,
        "a program that never stopped was started again"
    );
    // Not left held.
    desktop.send("begin 1");
    desktop.expect("began 1");
}

#[test]
fn no_failure_has_the_exit_code_of_success() {
    for exit in [
        Exit::Failed,
        Exit::Usage,
        Exit::PayloadInvalid,
        Exit::Busy,
        Exit::Unreachable,
        Exit::SetupFailed,
        Exit::NotInstalled,
        Exit::Elevated,
        Exit::Unsupported,
    ] {
        assert_ne!(exit as u8, 0, "{exit:?}");
    }
    assert_eq!(Exit::Success as u8, 0);
}

// --------------------------------------------------- what must be refused before Setup runs

#[test]
fn a_running_program_that_cannot_be_asked_is_an_error_and_is_not_stopped() {
    let mut fx = Fixture::new();
    fx.install_before("0.1.0");
    let before = fx.tree();
    // A program of the installation that serves no management endpoint (an older version).
    let mut child = Command::new(fx.program())
        .arg("idle")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    fx.children.push(child.id());
    std::thread::sleep(Duration::from_millis(300));

    let (code, message) = fx.run_entry("0.2.0", 0, &[("FORCE_STOP", "1"), ("SETUP", "install")]);
    assert_eq!(code, Exit::Unreachable as u8, "{message}");
    assert_eq!(
        fx.setups_started(),
        0,
        "Setup ran against a program nobody could ask"
    );
    assert!(
        fx.running().iter().any(|p| p.pid == child.id()),
        "the program was stopped"
    );
    assert_eq!(fx.tree(), before);
    drop(child.kill());
    drop(child.wait());
}

#[test]
fn a_damaged_payload_is_refused_before_anything_is_looked_at() {
    let mut fx = Fixture::new();
    fx.install_before("0.1.0");
    let mut desktop = fx.start_desktop();
    let image = fx.entry_image("0.2.0");
    let mut bytes = std::fs::read(&image).unwrap();
    let range = payload::setup_range(&bytes).unwrap();
    bytes[range.start + range.len() / 2] ^= 0x55;
    std::fs::write(&image, bytes).unwrap();
    let mut command = fx.entry_command(&image, "0.2.0", &[("FORCE_STOP", "1")]);
    command.env("ONCL_HARNESS_WAIT_MS", "0");
    let output = output_within(command, SHORT);
    assert_eq!(output.status.code(), Some(Exit::PayloadInvalid as i32));
    assert_eq!(fx.setups_started(), 0);
    assert!(desktop.alive());
    assert!(
        !desktop.saw("hold"),
        "the program was asked to hold for a payload that is not trusted"
    );
}

#[test]
fn an_elevated_entry_writes_nothing() {
    let fx = Fixture::new();
    let image = fx.entry_image("0.2.0");
    let mut command = fx.entry_command(&image, "0.2.0", &[("SETUP", "install")]);
    command.env("ONCL_HARNESS_ELEVATED", "1");
    let output = output_within(command, SHORT);
    assert_eq!(output.status.code(), Some(Exit::Elevated as i32));
    assert_eq!(fx.setups_started(), 0);
    assert!(!fx.root().exists());
    assert!(fx.work().read_dir().unwrap().next().is_none());
    assert_eq!(fx.arp_version(), None);
}

// ------------------------------------------------------------------ the shipped program

#[test]
fn the_shipped_installer_says_what_it_is_missing_and_never_installs_without_a_payload() {
    // Without `--silent` it does not guess what to do.
    let output = output_within(Command::new(ENTRY), SHORT);
    assert_eq!(output.status.code(), Some(Exit::Usage as i32));
    let mut nonsense = Command::new(ENTRY);
    nonsense.args(["--silent", "--nonsense"]);
    let output = output_within(nonsense, SHORT);
    assert_eq!(output.status.code(), Some(Exit::Usage as i32));
    // This build carries no payload: it refuses before it asks anything or writes anything.
    let mut silent = Command::new(ENTRY);
    silent.arg("--silent");
    let output = output_within(silent, SHORT);
    assert_eq!(output.status.code(), Some(Exit::PayloadInvalid as i32));
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("payload"), "{message}");
}

// ----------------------------------------------------------- elevation and a late program

#[test]
fn elevation_is_asked_of_the_real_token() {
    // The predicate the shipped installer uses, on this process's real token: not elevated
    // means the entry goes on, elevated means it refuses before it writes anything.
    let mut fx = Fixture::new();
    // An oracle that does not share code with the predicate: Windows' own report of this
    // process's integrity level (High, S-1-16-12288, is an elevated token).
    let groups = Command::new("whoami").arg("/groups").output().unwrap();
    let elevated = String::from_utf8_lossy(&groups.stdout).contains("S-1-16-12288");
    assert_eq!(oncl_winget_setup::is_elevated().unwrap(), elevated);
    let (code, message) =
        fx.run_entry("0.2.0", 0, &[("REAL_ELEVATION", "1"), ("SETUP", "install")]);
    let expected = if elevated {
        Exit::Elevated
    } else {
        Exit::Success
    };
    assert_eq!(code, expected as u8, "{message}");
    if elevated {
        assert_eq!(fx.setups_started(), 0);
    }
}

#[test]
fn a_program_that_starts_while_the_installer_prepares_is_asked_not_stopped() {
    let mut fx = Fixture::new();
    fx.install_before("0.1.0");
    fx.entry_image("0.2.0");
    // Nothing runs when the entry first looks; the program starts while it prepares Setup.
    let (code, message) = fx.run_entry(
        "0.2.0",
        20_000,
        &[
            ("START_PROGRAM_BEFORE_CHECK", "1"),
            ("FORCE_STOP", "1"),
            ("SETUP", "install"),
        ],
    );
    assert_eq!(code, Exit::Success as u8, "{message}");
    // It was held (asked) before Setup, so it is started again after the replacement; had
    // it been left for Setup's force-stop it would be gone.
    assert!(message.contains("running again"), "{message}");
    let started = fx
        .log_lines()
        .iter()
        .filter(|l| l.ends_with("program started: run --allow-no-wss"))
        .count();
    assert_eq!(started, 2, "{:?}", fx.log_lines());
}

#[test]
fn another_program_under_the_root_is_not_force_stopped_by_setup() {
    // Setup ends EVERY process under the installation: the daemon that answered is asked,
    // but a second program of the installation (here a plain one, as `openncalayer tls …`
    // is) cannot be, so the installer must not start Setup at all.
    let mut fx = Fixture::new();
    fx.install_before("0.1.0");
    let before = fx.tree();
    let mut desktop = fx.start_desktop();
    let mut other = Command::new(fx.program())
        .arg("idle")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    fx.children.push(other.id());
    std::thread::sleep(Duration::from_millis(300));
    let (code, message) = fx.run_entry("0.2.0", 0, &[("FORCE_STOP", "1"), ("SETUP", "install")]);
    assert_eq!(code, busy(), "{message}");
    assert_eq!(
        fx.setups_started(),
        0,
        "Setup ran with another program under the root"
    );
    assert!(desktop.alive());
    assert!(fx.running().iter().any(|p| p.pid == other.id()));
    assert_eq!(fx.tree(), before);
    // The hold was given back.
    desktop.send("begin 1");
    desktop.expect("began 1");
    drop(other.kill());
    drop(other.wait());
}
