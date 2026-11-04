//! Running the payload and proving what it installed.
//!
//! Velopack's `Setup.exe` is not trusted to say that it installed: with a prerequisite it
//! cannot install, it ends `Ok` and exits with 0 having changed nothing, and a user who
//! cancels an overwrite does the same. So its exit code is only the end of the process;
//! [`verify`] looks at the installation itself: the manifest the installation's own locator
//! reads, the installed program and the user's Apps & Features entry.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use semver::Version;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::payload::Arch;

/// The id of the program in its package manifest.
pub const APP_ID: &str = "OpenNCALayer";
/// The main program of the package.
pub const MAIN_EXE: &str = "openncalayer.exe";
/// Where the user's Apps & Features entry of the program is, under `HKEY_CURRENT_USER`.
pub const ARP_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenNCALayer";

/// How long the installed program may take to say its version.
#[cfg(windows)]
const VERSION_ASK: Duration = Duration::from_secs(30);

/// What an installation must be, for it to be the payload's.
#[derive(Clone, Debug)]
pub struct Expected {
    /// The version of the package.
    pub version: Version,
    /// The architecture of the package.
    pub arch: Arch,
}

/// `path` as text for comparisons: made absolute where it exists, without the verbatim
/// prefix, without a trailing separator, in lower case.
#[cfg(windows)]
fn same_place(path: &Path) -> String {
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    let text = path.to_string_lossy();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    text.trim_end_matches(['\\', '/']).to_lowercase()
}

/// The version the installation at `root` says it is, from its own manifest.
///
/// # Errors
///
/// There is no installation there, or its manifest cannot be read.
#[cfg(windows)]
pub fn installed_version(root: &Path) -> Result<Version, String> {
    let config = velopack::locator::create_config_from_root_dir(root);
    if !config.UpdateExePath.is_file() {
        return Err(format!("{} is missing", config.UpdateExePath.display()));
    }
    config
        .load_manifest()
        .map(|manifest| manifest.version)
        .map_err(|e| format!("its manifest cannot be read: {e}"))
}

/// Checks that the installation at `root` is what `expected` describes, against everything
/// that can be looked at:
///
/// - the manifest the locator reads (`current\sq.version`): the program's id, main
///   program, version and architecture;
/// - the main program: it is there, and it says the version when asked (`--version`);
/// - the Apps & Features entry of the user under `arp_key`: its display name, display
///   version, install location (the root) and uninstaller (`Update.exe` of the root).
///
/// # Errors
///
/// The first thing that is not as it should be, as a sentence.
#[cfg(windows)]
pub fn verify(root: &Path, arp_key: &str, expected: &Expected) -> Result<(), String> {
    use oncl_registry::Hive;

    let config = velopack::locator::create_config_from_root_dir(root);
    if !config.UpdateExePath.is_file() {
        return Err(format!(
            "{} does not exist: nothing is installed there",
            config.UpdateExePath.display()
        ));
    }
    let manifest = config
        .load_manifest()
        .map_err(|e| format!("the installation's manifest cannot be read: {e}"))?;
    if manifest.id != APP_ID {
        return Err(format!(
            "the installation is of {:?}, not {APP_ID}",
            manifest.id
        ));
    }
    if manifest.main_exe != MAIN_EXE {
        return Err(format!(
            "the installation's main program is {:?}",
            manifest.main_exe
        ));
    }
    if manifest.version != expected.version {
        return Err(format!(
            "the installation is version {}, not {}",
            manifest.version, expected.version
        ));
    }
    if manifest.machine_architecture != expected.arch.manifest_name() {
        return Err(format!(
            "the installation is for {:?}, not {}",
            manifest.machine_architecture, expected.arch
        ));
    }
    let program = config.CurrentBinaryDir.join(MAIN_EXE);
    if !program.is_file() {
        return Err(format!("{} is missing", program.display()));
    }
    let said = ask_version(&program)?;
    if said != expected.version {
        return Err(format!(
            "the installed program says it is version {said}, not {}",
            expected.version
        ));
    }

    let text = |name: &str| {
        oncl_registry::get_string(Hive::CurrentUser, arp_key, Some(name))
            .map_err(|e| format!("the Apps & Features entry cannot be read: {e}"))
    };
    if text("DisplayName")?.is_none_or(|name| name.trim().is_empty()) {
        return Err("the user's Apps & Features entry is missing".to_owned());
    }
    let shown = text("DisplayVersion")?
        .ok_or_else(|| "the Apps & Features entry shows no version".to_owned())?;
    match Version::parse(shown.trim()) {
        Ok(shown) if shown == expected.version => {}
        _ => {
            return Err(format!(
                "the Apps & Features entry shows version {shown:?}, not {}",
                expected.version
            ));
        }
    }
    let location = text("InstallLocation")?
        .ok_or_else(|| "the Apps & Features entry has no install location".to_owned())?;
    if same_place(Path::new(location.trim())) != same_place(root) {
        return Err(format!(
            "the Apps & Features entry points at {location:?}, not at {}",
            root.display()
        ));
    }
    let uninstall = text("UninstallString")?.unwrap_or_default();
    let update = config.UpdateExePath.to_string_lossy().to_lowercase();
    if !uninstall.to_lowercase().contains(&update) {
        return Err("the Apps & Features entry does not uninstall this installation".to_owned());
    }
    Ok(())
}

/// The version `program --version` says (`openncalayer <version>`).
#[cfg(windows)]
fn ask_version(program: &Path) -> Result<Version, String> {
    let mut child = Command::new(program)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("the installed program cannot be started: {e}"))?;
    let mut stdout = child.stdout.take().expect("piped");
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.by_ref().take(4096).read_to_string(&mut text);
        text
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < VERSION_ASK => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("the installed program did not say its version".to_owned());
            }
            Err(e) => return Err(format!("the installed program cannot be waited for: {e}")),
        }
    }
    let text = reader.join().unwrap_or_default();
    text.split_whitespace()
        .last()
        .and_then(|word| Version::parse(word).ok())
        .ok_or_else(|| format!("the installed program's version is not understood: {text:?}"))
}

/// A private copy of the payload that is run, and what keeps it as it was checked.
pub struct PrivateCopy {
    // The lock goes first: the file is released before the directory is removed.
    lock: File,
    file: PathBuf,
    _dir: TempDir,
}

impl PrivateCopy {
    /// Writes `setup` as `Setup.exe` into a new directory, with a name nobody can guess,
    /// under `temp_root`; reads it back and checks its SHA-256 against `sha256`; and keeps it
    /// open so that nothing can write to it or delete it until this is dropped.
    ///
    /// # Errors
    ///
    /// The copy cannot be made, or what was read back is not `sha256`.
    pub fn new(temp_root: &Path, setup: &[u8], sha256: &[u8; 32]) -> io::Result<PrivateCopy> {
        let dir = tempfile::Builder::new()
            .prefix("oncl-setup-")
            .tempdir_in(temp_root)?;
        let file = dir.path().join("Setup.exe");
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file)?;
        out.write_all(setup)?;
        out.sync_all()?;
        drop(out);
        let lock = lock_for_reading(&file)?;
        let copy = PrivateCopy {
            lock,
            file,
            _dir: dir,
        };
        copy.check(sha256)?;
        Ok(copy)
    }

    /// Reads the copy through the handle that holds it and checks its SHA-256.
    ///
    /// # Errors
    ///
    /// The copy cannot be read, or is not `sha256`.
    pub fn check(&self, sha256: &[u8; 32]) -> io::Result<()> {
        let mut hasher = Sha256::new();
        let mut reader = &self.lock;
        std::io::Seek::rewind(&mut reader)?;
        let mut buffer = vec![0u8; 1 << 20];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        if hasher.finalize().as_slice() == sha256 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the private copy of Setup is not what was checked",
            ))
        }
    }

    /// The copy's path.
    pub fn path(&self) -> &Path {
        &self.file
    }
}

/// `file` open for reading that others may read but not write or delete.
#[cfg(windows)]
fn lock_for_reading(file: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_SHARE_READ only.
    OpenOptions::new().read(true).share_mode(1).open(file)
}

#[cfg(not(windows))]
fn lock_for_reading(file: &Path) -> io::Result<File> {
    File::open(file)
}

/// How `Setup.exe` ended.
#[derive(Debug)]
pub enum SetupEnd {
    /// It exited.
    Exited(ExitStatus),
    /// It is still running after the time given; it was not stopped.
    TimedOut,
}

/// Runs the checked copy with `--silent` and no other switch, and waits for it for
/// `timeout`. A Setup that runs longer is left running: ending it halfway through
/// replacing the installation is worse than waiting for it.
///
/// # Errors
///
/// The copy changed since it was checked, or cannot be started or waited for.
pub fn run_setup(copy: &PrivateCopy, sha256: &[u8; 32], timeout: Duration) -> io::Result<SetupEnd> {
    // The handle that holds the file lets nobody write to it: what runs is what was read.
    copy.check(sha256)?;
    let mut child = Command::new(copy.path())
        .arg("--silent")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(SetupEnd::Exited(status));
        }
        if started.elapsed() >= timeout {
            return Ok(SetupEnd::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
