//! What installing, updating and uninstalling OpenNCALayer changes for the user who runs it
//! (roadmap D12, D13, D27): the native messaging relay and host manifests, our autostart
//! entry and the original NCALayer's autostart. Nothing here touches certificates, trust
//! stores, the network or other users, and the data directory survives every step.
//!
//! - **Install** registers the relay ([`nm::install`]), turns our autostart on (the entry
//!   and `settings.json`) and disables the original's autostart entries of this user
//!   ([`disable_original`], journaled). Running it again repairs: every step is idempotent.
//! - **Update** refreshes what the user kept: the relay and its config if the relay is
//!   registered, our autostart entry if it is on (the program may have moved). It never
//!   turns anything on again and never touches the original, so «Вернуть оригинал» and an
//!   autostart switched off stay as the user left them.
//! - **Uninstall** removes only what is ours (the relay, its config, manifests and
//!   registry keys, our autostart entry) and puts back the original's entries we disabled
//!   ([`restore_original`]); `settings.json`, the TLS files and the logs stay.
//!
//! Each step runs even if an earlier one failed; the outcome lists every failure, and the
//! record of the installation (`installation.json`) is written only when all succeeded.
//!
//! Who runs them: Velopack's hooks on Windows ([`run_hook`]: `Setup.exe`, the updater and
//! the uninstaller; a failure ends the hook with a nonzero code), `openncalayer integration
//! install|uninstall` (the macOS `.pkg` and users of the other packages), and the daemon at
//! its start ([`Integration::at_start`]) for an installed copy that this user has not
//! integrated yet or that changed version or place since.

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use oncl_desktop::Autostart;
use oncl_desktop::OriginalLocations;
use oncl_desktop::original::{disable_original, restore_original};
use oncl_pki::fsutil::{Access, write_atomically};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::desktop::{ORIGINAL_JOURNAL, failures};
use crate::nm::{self, NmLayout};
use crate::paths::Paths;

/// Next to the executable: a file naming the package manager that installed this copy (one
/// line, e.g. `pacman`). Such a copy is updated by its package manager, never by itself.
pub const PACKAGE_MANAGER_FILE: &str = "package-manager";

/// The record of the installation in the data directory.
pub const STATE_FILE: &str = "installation.json";

/// How this copy got onto the system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Installation {
    /// Through Velopack: `Setup.exe`, the macOS `.pkg` or `.app`, the AppImage.
    Velopack,
    /// By the package manager it names ([`PACKAGE_MANAGER_FILE`]).
    PackageManager(String),
    /// From a release archive, or a build of its own.
    Portable,
}

impl Installation {
    /// This copy, run from `exe`: the package manager named next to it, otherwise Velopack's
    /// if Velopack locates the copy, otherwise portable.
    pub fn detect(exe: &Path) -> Installation {
        if let Some(manager) = package_manager(exe) {
            return Installation::PackageManager(manager);
        }
        match velopack::UpdateManager::new(velopack::sources::NoneSource {}, None, None) {
            Ok(_) => Installation::Velopack,
            Err(_) => Installation::Portable,
        }
    }

    /// The package manager that installed this copy, if one did.
    pub fn package_manager(&self) -> Option<&str> {
        match self {
            Installation::PackageManager(manager) => Some(manager),
            _ => None,
        }
    }
}

/// The package manager named in [`PACKAGE_MANAGER_FILE`] next to `exe`: its first line,
/// trimmed; `None` without the file or with an empty or unreadable one.
pub fn package_manager(exe: &Path) -> Option<String> {
    let text = std::fs::read_to_string(exe.with_file_name(PACKAGE_MANAGER_FILE)).ok()?;
    let name = text.lines().next()?.trim();
    (!name.is_empty() && !name.chars().any(char::is_control)).then(|| name.to_owned())
}

/// The programs an installation points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Executables {
    /// What our autostart and the relay start: this executable, or on Linux the AppImage it
    /// runs from (the mounted directory it is in changes at every start).
    pub program: PathBuf,
    /// The relay to install: `nmhost` next to this executable.
    pub relay: PathBuf,
}

/// The [`Executables`] of this process.
///
/// # Errors
///
/// The path of this executable is unknown.
pub fn executables() -> io::Result<Executables> {
    let exe = std::env::current_exe()?;
    Ok(executables_of(exe, |name| std::env::var_os(name)))
}

/// The [`Executables`] of `exe` with the environment `var`.
fn executables_of(exe: PathBuf, var: impl Fn(&str) -> Option<OsString>) -> Executables {
    let relay = exe.with_file_name(nm::relay_file_name());
    let program = if cfg!(target_os = "linux") {
        appimage_of(&exe, var).unwrap_or(exe)
    } else {
        exe
    };
    Executables { program, relay }
}

/// The AppImage `exe` runs from: `$APPIMAGE`, if `exe` is inside the mounted `$APPDIR` the
/// AppImage runtime set and `$APPIMAGE` is an absolute path to a file. Variables inherited
/// by a program that is not inside the AppImage do not count.
fn appimage_of(exe: &Path, var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let appdir = PathBuf::from(var("APPDIR")?);
    let image = PathBuf::from(var("APPIMAGE")?);
    (appdir.is_absolute() && image.is_absolute() && exe.starts_with(&appdir) && image.is_file())
        .then_some(image)
}

/// The record of the installation: what was integrated, for which program and version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub program: PathBuf,
    pub version: String,
}

/// A lifecycle event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Install,
    Update,
    Uninstall,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Event::Install => "install",
            Event::Update => "update",
            Event::Uninstall => "uninstall",
        })
    }
}

/// One step of an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The relay, its config and the host manifests installed.
    RegisterRelay,
    /// The registered relay and its config rewritten for this version and program.
    RefreshRelay,
    /// The relay is not registered (the user removed it): left so.
    RelayLeftOff,
    /// The relay, its config, the manifests and registry keys removed.
    UnregisterRelay,
    /// Our autostart entry written, `settings.json` saying so.
    EnableAutostart,
    /// Our autostart entry, which is on, rewritten for the program.
    RefreshAutostart,
    /// Our autostart is off: left so.
    AutostartLeftOff,
    /// Our autostart entry removed.
    RemoveAutostart,
    /// The original's autostart entries of this user disabled, journaled.
    DisableOriginal,
    /// The original's autostart entries we disabled put back.
    RestoreOriginal,
    /// The record written.
    SaveRecord,
    /// The record removed.
    RemoveRecord,
}

/// What an event did, step by step: `Err` holds why a step failed.
#[derive(Debug, Default)]
pub struct Outcome {
    pub steps: Vec<(Step, Result<(), String>)>,
}

impl Outcome {
    /// Whether every step succeeded.
    pub fn succeeded(&self) -> bool {
        self.steps.iter().all(|(_, result)| result.is_ok())
    }

    /// The steps that failed, with why.
    pub fn failures(&self) -> impl Iterator<Item = (Step, &str)> {
        self.steps
            .iter()
            .filter_map(|(step, result)| result.as_ref().err().map(|e| (*step, e.as_str())))
    }

    fn run(&mut self, step: Step, f: impl FnOnce() -> io::Result<()>) {
        let result = f().map_err(|e| e.to_string());
        match &result {
            Ok(()) => info!(?step, "lifecycle step done"),
            Err(e) => error!(?step, error = %e, "lifecycle step failed"),
        }
        self.steps.push((step, result));
    }
}

/// This user's desktop as installing, updating and uninstalling change it.
pub struct Integration {
    pub paths: Paths,
    pub executables: Executables,
    /// The version being installed (this build's).
    pub version: String,
    pub nm: NmLayout,
    pub autostart: Box<dyn Autostart + Send + Sync>,
    pub original: OriginalLocations,
}

impl Integration {
    /// The integration of the user running this process, for this executable and version.
    ///
    /// # Errors
    ///
    /// The executable's path, the native messaging layout or the autostart of this user is
    /// unknown (a variable such as `HOME` or `LOCALAPPDATA` is not set).
    pub fn for_this_user(paths: &Paths) -> io::Result<Integration> {
        Ok(Integration {
            paths: paths.clone(),
            executables: executables()?,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            nm: NmLayout::detect(paths)?,
            autostart: oncl_desktop::autostart::current_user()?,
            original: OriginalLocations::detect(),
        })
    }

    /// The record of the installation in the data directory.
    pub fn record_path(&self) -> PathBuf {
        self.paths.data.join(STATE_FILE)
    }

    /// The original's autostart journal in the data directory.
    pub fn journal(&self) -> PathBuf {
        self.paths.data.join(ORIGINAL_JOURNAL)
    }

    /// The record of the installation, if this user's desktop is integrated.
    ///
    /// # Errors
    ///
    /// The record cannot be read or is not one ([`io::ErrorKind::InvalidData`]).
    pub fn record(&self) -> io::Result<Option<Record>> {
        let bytes = match std::fs::read(self.record_path()) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Runs `event`.
    pub fn run(&self, event: Event) -> Outcome {
        info!(%event, version = %self.version, program = %self.executables.program.display(), "lifecycle event");
        match event {
            Event::Install => self.install(),
            Event::Update => self.update(),
            Event::Uninstall => self.uninstall(),
        }
    }

    /// The event the daemon's start owes this user for an `installation`: none for a
    /// portable copy; install if this user's desktop was never integrated (or its record is
    /// unreadable); update if the record names another program or version.
    pub fn due_at_start(&self, installation: &Installation) -> Option<Event> {
        if *installation == Installation::Portable {
            return None;
        }
        match self.record() {
            Ok(None) => Some(Event::Install),
            Err(e) => {
                warn!(error = %e, "the installation record is unreadable; installing again");
                Some(Event::Install)
            }
            Ok(Some(record))
                if record.program != self.executables.program || record.version != self.version =>
            {
                Some(Event::Update)
            }
            Ok(Some(_)) => None,
        }
    }

    /// Runs the event [`Integration::due_at_start`] finds, if any.
    pub fn at_start(&self, installation: &Installation) -> Option<(Event, Outcome)> {
        let event = self.due_at_start(installation)?;
        Some((event, self.run(event)))
    }

    fn install(&self) -> Outcome {
        let mut outcome = Outcome::default();
        outcome.run(Step::RegisterRelay, || self.register_relay());
        outcome.run(Step::EnableAutostart, || {
            self.autostart.set(true, &self.executables.program)?;
            oncl_desktop::settings::set_autostart(&self.paths.settings(), true)
        });
        outcome.run(Step::DisableOriginal, || {
            disable_original(&self.original, &self.journal()).map(drop)
        });
        self.save_record(&mut outcome);
        outcome
    }

    fn update(&self) -> Outcome {
        let mut outcome = Outcome::default();
        if self.nm.relay().exists() || self.nm.relay_config().exists() {
            outcome.run(Step::RefreshRelay, || self.register_relay());
        } else {
            outcome.run(Step::RelayLeftOff, || Ok(()));
        }
        match self.autostart.enabled() {
            Ok(true) => outcome.run(Step::RefreshAutostart, || {
                self.autostart.set(true, &self.executables.program)
            }),
            Ok(false) => outcome.run(Step::AutostartLeftOff, || Ok(())),
            Err(e) => outcome.run(Step::RefreshAutostart, || Err(e)),
        }
        self.save_record(&mut outcome);
        outcome
    }

    fn uninstall(&self) -> Outcome {
        let mut outcome = Outcome::default();
        outcome.run(Step::UnregisterRelay, || {
            let report = nm::uninstall(&self.nm)?;
            if report.has_in_use() {
                return Err(io::Error::other(
                    "a running browser holds the relay: close it and uninstall again",
                ));
            }
            failures(&report)
        });
        outcome.run(Step::RemoveAutostart, || {
            self.autostart.set(false, &self.executables.program)
        });
        outcome.run(Step::RestoreOriginal, || {
            restore_original(&self.original, &self.journal()).map(drop)
        });
        if outcome.succeeded() {
            outcome.run(Step::RemoveRecord, || {
                match std::fs::remove_file(self.record_path()) {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                    _ => Ok(()),
                }
            });
        }
        outcome
    }

    /// Installs the relay of [`Executables::relay`] for the program and the data directory.
    fn register_relay(&self) -> io::Result<()> {
        let Executables { program, relay } = &self.executables;
        if !relay.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("the relay is missing: {}", relay.display()),
            ));
        }
        let report = nm::install(&self.nm, relay, program, &self.paths.data)?;
        failures(&report)
    }

    /// Writes the record once every step before succeeded.
    fn save_record(&self, outcome: &mut Outcome) {
        if !outcome.succeeded() {
            return;
        }
        outcome.run(Step::SaveRecord, || {
            let record = Record {
                program: self.executables.program.clone(),
                version: self.version.clone(),
            };
            let json = serde_json::to_vec_pretty(&record).map_err(io::Error::other)?;
            std::fs::create_dir_all(&self.paths.data)?;
            write_atomically(&self.record_path(), &json, Access::Default)
        });
    }
}

/// Velopack's hook for `event` (Windows: `Setup.exe` after installing, the updater after
/// updating, the uninstaller before removing): runs it for this user, logs every step to
/// stderr and the log files, and exits — 0 if every step succeeded, 1 otherwise. Velopack
/// would exit 0 after any hook, so the hook exits itself: `Setup.exe` then warns that the
/// installation is incomplete, and the updater and the uninstaller log the code. A step
/// that failed is done again at the daemon's next start ([`Integration::at_start`]).
pub fn run_hook(event: Event) -> ! {
    let code = match hook(event) {
        Ok(()) => 0,
        Err(()) => 1,
    };
    std::process::exit(code)
}

fn hook(event: Event) -> Result<(), ()> {
    let paths = Paths::detect()
        .map_err(|e| eprintln!("lifecycle {event}: the data directory is unknown: {e}"))?;
    if let Err(e) = crate::logging::init(&paths.logs()) {
        warn!(error = %e, "file logging is disabled");
    }
    let integration = Integration::for_this_user(&paths).map_err(|e| {
        error!(%event, error = %e, "lifecycle: this user's desktop is unknown");
    })?;
    let outcome = integration.run(event);
    if outcome.succeeded() {
        info!(%event, "lifecycle event done");
        Ok(())
    } else {
        error!(%event, "lifecycle event incomplete");
        Err(())
    }
}

/// The daemon's part ([`Integration::at_start`]) for this process: logs the outcome; a
/// failure does not stop the daemon, and the event is due again at the next start.
pub fn at_daemon_start(paths: &Paths) {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            warn!(error = %e, "the program's path is unknown; the desktop integration is not checked");
            return;
        }
    };
    let installation = Installation::detect(&exe);
    if installation == Installation::Portable {
        return;
    }
    let integration = match Integration::for_this_user(paths) {
        Ok(integration) => integration,
        Err(e) => {
            error!(error = %e, "this user's desktop is unknown; the desktop integration is not checked");
            return;
        }
    };
    if let Some((event, outcome)) = integration.at_start(&installation) {
        if outcome.succeeded() {
            info!(%event, "the desktop integration is done");
        } else {
            error!(%event, "the desktop integration is incomplete; it is tried again at the next start");
        }
    }
}

/// The exit code of an outcome for the command line.
pub fn exit_code(outcome: &Outcome) -> ExitCode {
    if outcome.succeeded() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests;
