//! `cargo xtask win7`: the Windows 7 builds (roadmap D14).
//!
//! For each architecture: builds `openncalayer.exe`, `nmhost.exe` and the app-local DLLs on
//! the pinned nightly with `-Zbuild-std` and the static CRT, gathers them in
//! `<out>/<arch>/` under their shipping names, and runs the import gate on them. On a Windows
//! host it then starts the programs from there: on Windows 8 and later the loader must take
//! the system `combase.dll` and API sets, and the programs must work next to the app-local
//! copies.

use std::io::Read as _;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use ureq::Agent;
use ureq::tls::{Certificate, RootCerts, TlsConfig};

use crate::imports;

/// The nightly that builds the `*-win7-windows-msvc` targets with `-Zbuild-std`.
pub const TOOLCHAIN: &str = "nightly-2026-08-12";

/// The packages of a Windows 7 build.
const PACKAGES: [&str; 4] = [
    "openncalayer",
    "oncl-nmhost",
    "oncl-win7shim-combase",
    "oncl-win7shim-winrt-error",
];

/// The files of a Windows 7 build: the cargo target and the name the file ships under.
pub const FILES: [(&str, &str); 4] = [
    ("openncalayer", "openncalayer.exe"),
    ("nmhost", "nmhost.exe"),
    ("oncl_win7shim_combase", "combase.dll"),
    (
        "oncl_win7shim_winrt_error",
        "api-ms-win-core-winrt-error-l1-1-0.dll",
    ),
];

/// The executables of a Windows 7 build.
const EXECUTABLES: [&str; 2] = ["openncalayer.exe", "nmhost.exe"];

/// The native messaging relay: `openncalayer nm install` copies it alone into a directory of
/// its own (roadmap D27), so it has to run without the app-local DLLs.
const RELAY: &str = "nmhost.exe";

/// An architecture of the Windows 7 builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X64,
    X86,
}

impl Arch {
    /// The rustc target.
    pub fn target(self) -> &'static str {
        match self {
            Arch::X64 => "x86_64-win7-windows-msvc",
            Arch::X86 => "i686-win7-windows-msvc",
        }
    }

    /// The name of the output directory and of the release flavour (`win7-<name>`).
    pub fn name(self) -> &'static str {
        match self {
            Arch::X64 => "x64",
            Arch::X86 => "x86",
        }
    }
}

/// Which architectures `win7` builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Selection {
    X64,
    X86,
    All,
}

impl Selection {
    pub fn arches(self) -> &'static [Arch] {
        match self {
            Selection::X64 => &[Arch::X64],
            Selection::X86 => &[Arch::X86],
            Selection::All => &[Arch::X64, Arch::X86],
        }
    }
}

/// Builds, gates and (on Windows) starts the Windows 7 builds of `selection` in
/// `<out>/<arch>/`, with cargo's target directory `target_dir` if given (the workspace's
/// otherwise). Fails on the first build error, after every gate if any import is missing
/// on Windows 7, and on the first failed start.
pub fn run(
    root: &Path,
    selection: Selection,
    out: &Path,
    target_dir: Option<&Path>,
) -> anyhow::Result<()> {
    let out = std::path::absolute(out).with_context(|| format!("{}", out.display()))?;
    let target_dir = target_dir
        .map(|dir| std::path::absolute(dir).with_context(|| format!("{}", dir.display())))
        .transpose()?;
    let builtins = crate::builtins::prepare(root)?;
    let mut dirs = Vec::new();
    let mut violations = 0;
    for &arch in selection.arches() {
        let dir = build(root, arch, &out, target_dir.as_deref(), &builtins)?;
        violations += gate(&dir)?;
        dirs.push(dir);
    }
    if violations > 0 {
        anyhow::bail!("{violations} violations of the Windows 7 import gate");
    }
    if !cfg!(windows) {
        println!("Not a Windows host: the builds were not started");
        return Ok(());
    }
    let scratch = root.join("target").join("win7-smoke");
    std::fs::create_dir_all(&scratch).with_context(|| format!("{}", scratch.display()))?;
    for dir in &dirs {
        smoke(dir, &scratch).with_context(|| format!("starting the build in {}", dir.display()))?;
    }
    Ok(())
}

/// Builds the packages of a Windows 7 build for `arch`, in cargo's target directory
/// `target_dir` if given, embedding the built-in modules laid out in `builtins`, and copies
/// the files under their shipping names into `<out>/<arch>/`, which it returns.
pub fn build(
    root: &Path,
    arch: Arch,
    out: &Path,
    target_dir: Option<&Path>,
    builtins: &Path,
) -> anyhow::Result<PathBuf> {
    let mut cargo = Command::new("rustup");
    cargo
        .current_dir(root)
        .args(["run", TOOLCHAIN, "cargo", "build", "--locked", "--release"])
        .arg("-Zbuild-std=std,panic_abort")
        .args(["--target", arch.target()])
        // The pinned nightly is older than the workspace `rust-version`.
        .arg("--ignore-rust-version")
        .arg("--message-format=json-render-diagnostics");
    if let Some(dir) = target_dir {
        cargo.arg("--target-dir").arg(dir);
    }
    for package in PACKAGES {
        cargo.args(["-p", package]);
    }
    // The static CRT: no VC++ redistributable needed. With `--target`, RUSTFLAGS reaches the
    // target's crates only, not build scripts.
    cargo
        .env(oncl_builtins_build::BUILTINS_DIR_VAR, builtins)
        .env("RUSTFLAGS", "-C target-feature=+crt-static")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        // Set for xtask by the stable toolchain running it.
        .env_remove("RUSTC")
        .env_remove("RUSTDOC")
        .env_remove("RUSTUP_TOOLCHAIN")
        .stderr(Stdio::inherit());
    println!("Building for {} ({TOOLCHAIN})", arch.target());
    let output = cargo.output().context("running rustup")?;
    anyhow::ensure!(
        output.status.success(),
        "cargo build --target {}: {}",
        arch.target(),
        output.status
    );
    let messages = String::from_utf8(output.stdout).context("cargo messages are not UTF-8")?;
    let dir = out.join(arch.name());
    std::fs::create_dir_all(&dir).with_context(|| format!("{}", dir.display()))?;
    for (target, file) in FILES {
        let built = artifact(&messages, target, file)
            .with_context(|| format!("cargo reported no {file} of {target}"))?;
        let copy = dir.join(file);
        std::fs::copy(&built, &copy)
            .with_context(|| format!("copying {} to {}", built.display(), copy.display()))?;
    }
    println!("{}", dir.display());
    Ok(dir)
}

/// The file cargo built for `target` that has the extension of `file`, from the JSON
/// messages of `cargo build`.
fn artifact(messages: &str, target: &str, file: &str) -> Option<PathBuf> {
    let extension = Path::new(file).extension()?;
    messages
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|message| {
            message["reason"] == "compiler-artifact" && message["target"]["name"] == target
        })
        .find_map(|message| {
            let executable = message["executable"].as_str();
            let filenames = message["filenames"].as_array()?;
            executable
                .into_iter()
                .chain(filenames.iter().filter_map(|name| name.as_str()))
                .map(PathBuf::from)
                .find(|path| {
                    path.extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case(extension))
                })
        })
}

/// Runs the import gate on the executables in `dir`, with the app-local DLLs next to them,
/// and on the relay without them. Prints the findings and returns their count.
pub fn gate(dir: &Path) -> anyhow::Result<usize> {
    let exes = EXECUTABLES.map(|exe| dir.join(exe));
    let found = imports::check_imports(&exes)?;
    Ok(found + imports::check_imports_alone(&dir.join(RELAY))?)
}

/// Starts the programs in `dir` on this Windows, with the data directory and the native
/// messaging sandbox in a fresh directory under `scratch`: `openncalayer --help`,
/// `nm install` and `nm status` in the sandbox, `tls init`, then the daemon until it answers
/// `GET /` over HTTPS with its own CA.
pub fn smoke(dir: &Path, scratch: &Path) -> anyhow::Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("run-")
        .tempdir_in(scratch)
        .with_context(|| format!("a directory in {}", scratch.display()))?;
    let data = temp.path().join("data");
    let sandbox = temp.path().join("nm");
    let exe = dir.join("openncalayer.exe");
    let openncalayer = |args: &[&str]| {
        let mut command = Command::new(&exe);
        command
            .args(args)
            .env("ONCL_DATA_DIR", &data)
            .stdin(Stdio::null());
        command
    };
    let help = expect_success(openncalayer(&["--help"]), "openncalayer --help")?;
    anyhow::ensure!(
        help.contains("openncalayer"),
        "openncalayer --help printed no usage:\n{help}"
    );
    let sandbox_arg = sandbox.to_str().context("a non-UTF-8 sandbox path")?;
    expect_success(
        openncalayer(&["nm", "install", "--sandbox", sandbox_arg]),
        "openncalayer nm install --sandbox",
    )?;
    expect_success(
        openncalayer(&["nm", "status", "--sandbox", sandbox_arg]),
        "openncalayer nm status --sandbox",
    )?;
    expect_success(openncalayer(&["tls", "init"]), "openncalayer tls init")?;

    let port = free_port()?;
    let log = temp.path().join("daemon.log");
    let log_file = std::fs::File::create(&log).with_context(|| format!("{}", log.display()))?;
    let mut run = openncalayer(&["run", "--no-tray"]);
    run.env("NCALAYERPORT", port.to_string())
        .stdout(log_file.try_clone()?)
        .stderr(log_file);
    let daemon = Daemon(run.spawn().context("starting openncalayer run")?);
    let ca = std::fs::read(data.join("tls").join("OpenNCALayer-CA.crt"))
        .context("reading the CA of tls init")?;
    let result = selftest_page(daemon, port, &ca);
    let mut output = String::new();
    // The log is best effort: it only explains a failure.
    let _ = std::fs::File::open(&log).and_then(|mut file| file.read_to_string(&mut output));
    let body = result.with_context(|| format!("the daemon's output:\n{output}"))?;
    anyhow::ensure!(
        body.contains("OpenNCALayer"),
        "GET / returned no self-test page:\n{body}"
    );
    println!("{}: started, answers GET / on port {port}", exe.display());
    Ok(())
}

/// A started daemon, killed on drop.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        // Already exited if these fail.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Waits up to a minute for the daemon to answer `GET https://127.0.0.1:<port>/`, trusting
/// only `ca_pem`, and returns the body. Stops the daemon.
fn selftest_page(mut daemon: Daemon, port: u16, ca_pem: &[u8]) -> anyhow::Result<String> {
    let ca = Certificate::from_pem(ca_pem).context("parsing the CA")?;
    let agent: Agent = Agent::config_builder()
        .tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::Specific(Arc::new(vec![ca])))
                .build(),
        )
        .timeout_global(Some(Duration::from_secs(5)))
        .build()
        .into();
    let url = format!("https://127.0.0.1:{port}/");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = daemon.0.try_wait()? {
            anyhow::bail!("openncalayer run exited: {status}");
        }
        match agent.get(&url).call() {
            Ok(mut response) => return Ok(response.body_mut().read_to_string()?),
            Err(e) if Instant::now() > deadline => {
                return Err(e).with_context(|| format!("GET {url}"));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}

/// A port in the daemon's range (`NCALAYERPORT`, 13579..=13679) that is free now, from the
/// top: the default port may be taken by a running NCALayer.
fn free_port() -> anyhow::Result<u16> {
    (13579..=13679)
        .rev()
        .find(|&port| TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok())
        .context("no free port in 13579..=13679")
}

/// Runs `command` and returns its stdout; fails with its output if it does not exit with 0.
fn expect_success(mut command: Command, what: &str) -> anyhow::Result<String> {
    let output = command
        .output()
        .with_context(|| format!("running {what}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    anyhow::ensure!(
        output.status.success(),
        "{what}: {}\n{stdout}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{what}: ok");
    Ok(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ships_every_app_local_dll() {
        let dlls: Vec<&str> = FILES
            .iter()
            .map(|(_, file)| *file)
            .filter(|file| file.ends_with(".dll"))
            .collect();
        assert_eq!(dlls, imports::APP_LOCAL_DLLS);
        assert!(
            EXECUTABLES
                .iter()
                .all(|exe| FILES.iter().any(|(_, file)| file == exe))
        );
        assert!(EXECUTABLES.contains(&RELAY));
    }

    #[test]
    fn finds_artifacts_in_cargo_messages() {
        let messages = [
            r#"{"reason":"compiler-artifact","target":{"name":"openncalayer"},"filenames":["/t/libopenncalayer.rlib"],"executable":null}"#,
            r#"{"reason":"compiler-artifact","target":{"name":"openncalayer"},"filenames":["/t/openncalayer.exe","/t/openncalayer.pdb"],"executable":"/t/openncalayer.exe"}"#,
            r#"{"reason":"compiler-artifact","target":{"name":"oncl_win7shim_combase"},"filenames":["/t/oncl_win7shim_combase.dll","/t/oncl_win7shim_combase.dll.lib"],"executable":null}"#,
            r#"{"reason":"build-finished","success":true}"#,
            "not json",
        ]
        .join("\n");
        assert_eq!(
            artifact(&messages, "openncalayer", "openncalayer.exe"),
            Some(PathBuf::from("/t/openncalayer.exe"))
        );
        assert_eq!(
            artifact(&messages, "oncl_win7shim_combase", "combase.dll"),
            Some(PathBuf::from("/t/oncl_win7shim_combase.dll"))
        );
        assert_eq!(artifact(&messages, "nmhost", "nmhost.exe"), None);
    }

    #[test]
    fn arches_and_targets() {
        assert_eq!(Selection::All.arches(), [Arch::X64, Arch::X86]);
        assert_eq!(Arch::X64.target(), "x86_64-win7-windows-msvc");
        assert_eq!(Arch::X86.target(), "i686-win7-windows-msvc");
        assert_eq!([Arch::X64.name(), Arch::X86.name()], ["x64", "x86"]);
    }
}
