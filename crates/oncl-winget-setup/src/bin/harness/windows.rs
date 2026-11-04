//! The harness of the installer entry's tests: real processes standing in for what the entry
//! talks to. It is not the installer and is never shipped.
//!
//! One program, with its role from the name it runs under or its first argument:
//!
//! - `openncalayer.exe` (a copy of this file in a throw-away installation) is the **fake
//!   desktop**: `--version` says the installed version; `run …` serves the management
//!   endpoint of `ONCL_DATA_DIR` behind the real [`oncl_core::activity::ActivityGate`], with
//!   a line protocol on stdin (`begin <id>`, `end <id>`, `window open|close`, `quit`) and
//!   events on stdout. It is the daemon without the daemon's windows, wss and tray.
//! - `Setup.exe` (the payload the tests carry) is the **fake Setup**: it behaves as
//!   `ONCL_HARNESS_SETUP` says (install, do nothing and exit 0, fail, wait for a file),
//!   ending the program under the installation first if `ONCL_HARNESS_FORCE_STOP` is set, as
//!   the real one does. It writes what a real installation leaves: the manifest, the main
//!   program and the Apps & Features entry (under the key the test names, never the real one).
//! - `wrapper <image>`: [`oncl_winget_setup::run`] with the throw-away installation named by
//!   `ONCL_HARNESS_*`, as a process of its own that a test can start, watch and kill.
//! - `idle`: a program under the installation that serves nothing.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use oncl_core::activity::{ActivityGate, ActivityLease};
use oncl_ipc::maintenance::{self, Host};

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn millis(name: &str, default: u64) -> Duration {
    Duration::from_millis(var(name).and_then(|v| v.parse().ok()).unwrap_or(default))
}

/// One line to the shared log, if the test asked for one.
fn log(line: &str) {
    let Some(path) = var("ONCL_HARNESS_LOG") else {
        return;
    };
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{} {line}", std::process::id());
    }
}

fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

pub fn main() -> ExitCode {
    let exe = std::env::current_exe().expect("current exe");
    let stem = exe
        .file_stem()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match stem.as_str() {
        "setup" => fake_setup(&exe, &args),
        "openncalayer" => installed_program(&exe, &args),
        _ => match args.first().and_then(|a| a.to_str()) {
            Some("wrapper") => wrapper(&args),
            Some("desktop") => {
                let dir = PathBuf::from(args.get(1).expect("data dir"));
                desktop(&dir, &args)
            }
            Some("idle") => idle(),
            other => {
                eprintln!("harness: no role {other:?}");
                ExitCode::from(64)
            }
        },
    }
}

fn idle() -> ExitCode {
    log("idle started");
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

// ---------------------------------------------------------------- the installed program

fn installed_program(exe: &Path, args: &[OsString]) -> ExitCode {
    let first = args.first().and_then(|a| a.to_str());
    if first == Some("--version") {
        println!("openncalayer {}", installed_version(exe));
        return ExitCode::SUCCESS;
    }
    log(&format!(
        "program started: {}",
        args.iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    ));
    match first {
        Some("run") => {
            let data = var("ONCL_DATA_DIR").expect("ONCL_DATA_DIR");
            desktop(Path::new(&data), args)
        }
        _ => idle(),
    }
}

/// The version the installed program reports: a file next to it if the test made one, else
/// the installation's own manifest.
fn installed_version(exe: &Path) -> String {
    let dir = exe.parent().expect("directory");
    if let Ok(text) = std::fs::read_to_string(dir.join("harness-version.txt")) {
        return text.trim().to_owned();
    }
    let nuspec = std::fs::read_to_string(dir.join("sq.version")).unwrap_or_default();
    nuspec
        .split("<version>")
        .nth(1)
        .and_then(|rest| rest.split("</version>").next())
        .unwrap_or("0.0.0")
        .to_owned()
}

// ------------------------------------------------------------------------- the fake desktop

/// What the management endpoint of the fake desktop decides with: the real gate, and a
/// window that the test opens and closes.
struct Desktop {
    gate: Arc<ActivityGate>,
    window: AtomicBool,
    quiet: Duration,
    restart: Vec<String>,
}

impl Host for Desktop {
    fn hold(&self) -> bool {
        // As the daemon does it: the window is looked at once new operations are held.
        let held = self.gate.hold_unless(self.quiet, Instant::now, || {
            self.window.load(Ordering::SeqCst)
        });
        say(if held { "hold-granted" } else { "hold-refused" });
        held
    }

    fn release(&self) {
        self.gate.release();
        say("released");
    }

    fn restart_args(&self) -> Vec<String> {
        self.restart.clone()
    }
}

fn desktop(data_dir: &Path, args: &[OsString]) -> ExitCode {
    let gate = Arc::new(ActivityGate::new());
    let restart = oncl_restart(args);
    let host = Arc::new(Desktop {
        gate: Arc::clone(&gate),
        window: AtomicBool::new(false),
        quiet: millis("ONCL_HARNESS_QUIET_MS", 30_000),
        restart,
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let endpoint = maintenance::endpoint(data_dir).expect("endpoint");
    let listener = match runtime.block_on(oncl_ipc::bind(&endpoint)) {
        Ok(listener) => listener,
        Err(e) => {
            // Like the daemon: it runs without the endpoint, and says so.
            say(&format!("no-endpoint {e}"));
            return serve_stdin(&gate, &host);
        }
    };
    runtime.spawn(maintenance::serve(
        listener,
        Arc::clone(&host),
        Duration::from_secs(60),
    ));
    say("ready");
    let code = serve_stdin(&gate, &host);
    drop(runtime);
    code
}

/// The arguments `run` was started with, as the daemon tells a maintainer to start it again.
fn oncl_restart(args: &[OsString]) -> Vec<String> {
    let mut restart = vec!["run".to_owned()];
    if args.iter().any(|a| a == "--allow-no-wss") {
        restart.push("--allow-no-wss".to_owned());
    }
    restart
}

/// The test's commands, one per line; a closed stdin only means nobody commands any more.
fn serve_stdin(gate: &Arc<ActivityGate>, host: &Arc<Desktop>) -> ExitCode {
    let operations: Arc<Mutex<HashMap<u32, ActivityLease>>> = Arc::default();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let mut words = line.split_whitespace();
        match (words.next(), words.next()) {
            (Some("begin"), Some(id)) => {
                let id: u32 = id.parse().expect("operation id");
                let (gate, operations) = (Arc::clone(gate), Arc::clone(&operations));
                // `begin` waits while a maintainer holds the gate: on a thread of its own.
                std::thread::spawn(move || {
                    let lease = gate.begin();
                    operations.lock().unwrap().insert(id, lease);
                    say(&format!("began {id}"));
                });
            }
            (Some("end"), Some(id)) => {
                let id: u32 = id.parse().expect("operation id");
                drop(operations.lock().unwrap().remove(&id));
                say(&format!("ended {id}"));
            }
            (Some("window"), Some(state)) => {
                host.window.store(state == "open", Ordering::SeqCst);
                say(&format!("window {state}"));
            }
            (Some("quit"), _) => return ExitCode::SUCCESS,
            _ => say("unknown command"),
        }
    }
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

// -------------------------------------------------------------------------- the entry

fn wrapper(args: &[OsString]) -> ExitCode {
    let image = PathBuf::from(args.get(1).expect("image"));
    let root = PathBuf::from(var("ONCL_HARNESS_ROOT").expect("root"));
    let data = PathBuf::from(var("ONCL_HARNESS_DATA_DIR").expect("data dir"));
    let config = oncl_winget_setup::Config {
        image,
        install_root: root,
        arp_key: var("ONCL_HARNESS_ARP_KEY").expect("arp key"),
        endpoint: maintenance::endpoint(&data).expect("endpoint"),
        wait: millis("ONCL_HARNESS_WAIT_MS", 0),
        poll: millis("ONCL_HARNESS_POLL_MS", 50),
        setup_timeout: millis("ONCL_HARNESS_SETUP_TIMEOUT_MS", 120_000),
        temp_root: PathBuf::from(var("ONCL_HARNESS_TEMP").expect("temp")),
        elevated: var("ONCL_HARNESS_ELEVATED").is_some(),
    };
    let report = oncl_winget_setup::run(&config);
    eprintln!("{}", report.message);
    ExitCode::from(report.exit as u8)
}

// ------------------------------------------------------------------------ the fake Setup

fn fake_setup(exe: &Path, args: &[OsString]) -> ExitCode {
    log(&format!(
        "setup started: {}",
        args.iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    ));
    if let Some(file) = var("ONCL_HARNESS_WAIT_FOR") {
        log("setup waiting");
        while !Path::new(&file).exists() {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let root = PathBuf::from(var("ONCL_HARNESS_ROOT").expect("root"));
    if var("ONCL_HARNESS_FORCE_STOP").is_some() {
        force_stop(&root);
    }
    match var("ONCL_HARNESS_SETUP").as_deref() {
        Some("noop") => {
            log("setup: nothing installed, exit 0");
            ExitCode::SUCCESS
        }
        Some("fail") => {
            log("setup: failed");
            ExitCode::from(1)
        }
        _ => match install(exe, &root) {
            Ok(()) => {
                log("setup: installed");
                ExitCode::SUCCESS
            }
            Err(e) => {
                log(&format!("setup: {e}"));
                ExitCode::from(1)
            }
        },
    }
}

/// Ends the processes under `root`, as the real `Setup.exe` does before it replaces them.
fn force_stop(root: &Path) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
    let own = std::process::id();
    for process in oncl_winget_setup::processes::running_from(root).unwrap_or_default() {
        if process.pid == own {
            continue;
        }
        // SAFETY: plain calls; the handle is checked and closed.
        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, 0, process.pid);
            if !handle.is_null() {
                TerminateProcess(handle, 1);
                CloseHandle(handle);
            }
        }
        log(&format!("setup: force-stopped {}", process.pid));
    }
}

/// Makes the installation the way Velopack leaves one: `Update.exe`, `current\sq.version`,
/// `current\openncalayer.exe` and the Apps & Features entry.
fn install(setup: &Path, root: &Path) -> std::io::Result<()> {
    let version = var("ONCL_HARNESS_VERSION").expect("version");
    let arch = var("ONCL_HARNESS_ARCH").unwrap_or_else(|| "x64".to_owned());
    // The processes just ended may still hold their files for a moment.
    let started = Instant::now();
    while root.exists() {
        match std::fs::remove_dir_all(root) {
            Ok(()) => break,
            Err(e) if started.elapsed() > Duration::from_secs(10) => return Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let current = root.join("current");
    std::fs::create_dir_all(&current)?;
    std::fs::copy(setup, root.join("Update.exe"))?;
    std::fs::copy(setup, current.join("openncalayer.exe"))?;
    std::fs::write(
        current.join("sq.version"),
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
             <package xmlns=\"http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd\">\n\
             <metadata>\n<id>OpenNCALayer</id>\n<version>{version}</version>\n\
             <title>OpenNCALayer</title>\n<authors>OpenNCALayer</authors>\n\
             <channel>win-{arch}</channel>\n<mainExe>openncalayer.exe</mainExe>\n<os>win</os>\n\
             <osMinVersion>10</osMinVersion>\n<machineArchitecture>{arch}</machineArchitecture>\n\
             </metadata>\n</package>"
        ),
    )?;
    if let Some(exe_version) = var("ONCL_HARNESS_EXE_VERSION") {
        std::fs::write(current.join("harness-version.txt"), exe_version)?;
    }
    if var("ONCL_HARNESS_NO_ARP").is_none() {
        let key = var("ONCL_HARNESS_ARP_KEY").expect("arp key");
        let shown = var("ONCL_HARNESS_ARP_VERSION").unwrap_or_else(|| version.clone());
        let location =
            var("ONCL_HARNESS_ARP_LOCATION").unwrap_or_else(|| root.display().to_string());
        let update = root.join("Update.exe");
        for (name, value) in [
            ("DisplayName", "OpenNCALayer".to_owned()),
            ("DisplayVersion", shown),
            ("InstallLocation", location),
            ("Publisher", "OpenNCALayer".to_owned()),
            (
                "UninstallString",
                format!("\"{}\" --uninstall", update.display()),
            ),
        ] {
            oncl_registry::set_string(&key, Some(name), &value)?;
        }
    }
    Ok(())
}
