//! The installer entry's decisions, in order.

use std::path::PathBuf;
use std::time::Duration;

use oncl_ipc::Endpoint;

/// How the entry ended: the process exit code. Only [`Exit::Success`] means the installation
/// is the one this entry carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Exit {
    /// The installation was replaced (or made) and proven to be this entry's version.
    Success = 0,
    /// Something not covered by another code failed; nothing is claimed.
    Failed = 1,
    /// The command line is not understood.
    Usage = 2,
    /// The payload the entry carries is missing or damaged; nothing was started.
    PayloadInvalid = 3,
    /// The running program is busy (an operation, its quiet time, a window, another
    /// maintainer) and did not become idle in time; the installation is untouched.
    Busy = 4,
    /// A program of the installation runs, but it cannot be asked to hold still; nothing
    /// was stopped and the installation is untouched.
    Unreachable = 5,
    /// `Setup.exe` ended with a failure; the installation is not claimed to be new.
    SetupFailed = 6,
    /// `Setup.exe` ended, but what is installed is not what the entry carried.
    NotInstalled = 7,
    /// The entry runs elevated: it installs for the user, never for an administrator's
    /// profile; nothing was written.
    Elevated = 8,
    /// Not Windows.
    Unsupported = 9,
}

/// The outcome: the exit code and a sentence for the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The exit code.
    pub exit: Exit,
    /// What happened, for the user.
    pub message: String,
}

impl Report {
    fn new(exit: Exit, message: impl Into<String>) -> Report {
        Report {
            exit,
            message: message.into(),
        }
    }
}

/// Everything [`run`] looks at or changes, so that the same decisions run against a real
/// installation ([`production`]) and against a throw-away one.
#[derive(Clone, Debug)]
pub struct Config {
    /// The file of the entry whose payload is installed.
    pub image: PathBuf,
    /// The installation's root (`%LOCALAPPDATA%\OpenNCALayer`).
    pub install_root: PathBuf,
    /// The user's Apps & Features key of the program, under `HKEY_CURRENT_USER`.
    pub arp_key: String,
    /// The running program's management endpoint.
    pub endpoint: Endpoint,
    /// How long a busy program is waited for.
    pub wait: Duration,
    /// How often a busy program is asked again.
    pub poll: Duration,
    /// How long `Setup.exe` may run.
    pub setup_timeout: Duration,
    /// Where the private copy of the payload is made.
    pub temp_root: PathBuf,
    /// Whether this process runs with an elevated token (`production` sets
    /// [`crate::is_elevated`]); asked before anything is read or written.
    #[doc(hidden)]
    pub elevation: fn() -> std::io::Result<bool>,
    /// Run right before the last look for a program that started meanwhile; `None` in
    /// production. Tests use it to start one.
    #[doc(hidden)]
    pub before_setup_check: Option<fn()>,
}

/// Replaces the installation with the entry's payload, if it is safe to, and proves it.
#[cfg(not(windows))]
pub fn run(_config: &Config) -> Report {
    Report::new(
        Exit::Unsupported,
        "the WinGet installer entry of OpenNCALayer works on Windows only; nothing was installed",
    )
}

/// Replaces the installation with the entry's payload, if it is safe to, and proves it.
#[cfg(windows)]
pub fn run(config: &Config) -> Report {
    windows::run(config)
}

/// The configuration of the real installation of the current user: `wait` is how long a
/// busy program is waited for.
///
/// # Errors
///
/// The user's folders or token cannot be read.
#[cfg(windows)]
pub fn production(wait: Duration) -> std::io::Result<Config> {
    windows::production(wait)
}

#[cfg(windows)]
mod windows {
    use std::ffi::OsString;
    use std::io;
    use std::os::windows::ffi::OsStringExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use oncl_ipc::process::{
        CREATE_BREAKAWAY_FROM_JOB, DETACHED_CREATION_FLAGS, breakaway_refused,
    };
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath};

    use super::{Config, Exit, Report};
    use crate::install::{
        self, APP_ID, ARP_KEY, Expected, PrivateCopy, SetupEnd, installed_version,
    };
    use crate::maintenance::{self, Acquired, Lease, Refusal};
    use crate::payload::{self, Arch};
    use crate::processes;

    /// How long `Setup.exe` may run before the entry stops waiting for it.
    const SETUP_TIMEOUT: Duration = Duration::from_secs(15 * 60);
    /// How often a busy program is asked again.
    const POLL: Duration = Duration::from_secs(1);

    pub(super) fn run(config: &Config) -> Report {
        // Nothing this process starts (Setup, the program again) may keep the pipes WinGet or
        // a test reads this process's output through open after this process is done.
        let _ = oncl_ipc::process::prepare_detached_spawn();
        // Before anything is read or written: the installation is the user's own.
        match (config.elevation)() {
            Ok(false) => {}
            Ok(true) => {
                return Report::new(
                    Exit::Elevated,
                    "this installer must not run elevated: it installs for the signed-in user, \
                     never for an administrator's profile; nothing was changed",
                );
            }
            Err(e) => {
                return Report::new(
                    Exit::Failed,
                    format!(
                        "it cannot be told whether this installer is elevated ({e}); nothing was changed"
                    ),
                );
            }
        }
        let image = match std::fs::read(&config.image) {
            Ok(image) => image,
            Err(e) => {
                return Report::new(
                    Exit::PayloadInvalid,
                    format!("the installer cannot read its own file: {e}"),
                );
            }
        };
        let embedded = match payload::read(&image) {
            Ok(embedded) => embedded,
            Err(e) => return Report::new(Exit::PayloadInvalid, e.to_string()),
        };
        if Arch::this() != Some(embedded.arch) {
            return Report::new(
                Exit::PayloadInvalid,
                format!(
                    "this installer was built for {}, but its payload is for {}",
                    Arch::this().map_or("another architecture", Arch::manifest_name),
                    embedded.arch
                ),
            );
        }
        let expected = Expected {
            version: embedded.version.clone(),
            arch: embedded.arch,
        };

        // Who runs: ask it, hold it, and keep holding it until the installation is replaced.
        let mut lease = match hold(config) {
            Ok(lease) => lease,
            Err(report) => return report,
        };
        let old = installed_version(&config.install_root).ok();

        let copy = match PrivateCopy::new(&config.temp_root, embedded.setup, &embedded.sha256) {
            Ok(copy) => copy,
            Err(e) => {
                return Report::new(
                    Exit::Failed,
                    format!("the installer cannot prepare Setup: {e}; nothing was changed"),
                );
            }
        };
        // The last look is the last step before Setup is started (after its re-hash).
        let end = match install::run_setup(&copy, &embedded.sha256, config.setup_timeout, || {
            last_look(config, &mut lease)
        }) {
            Ok(end) => end,
            Err(e) => {
                restore(config, lease.as_mut(), old.as_ref());
                return Report::new(Exit::Failed, format!("Setup could not be run: {e}"));
            }
        };
        let status = match end {
            SetupEnd::Exited(status) => status,
            SetupEnd::Refused(report) => return report,
            SetupEnd::TimedOut => {
                return Report::new(
                    Exit::Failed,
                    format!(
                        "Setup is still running after {} minutes; it was not stopped, and the \
                         installation is not claimed to be version {}",
                        config.setup_timeout.as_secs() / 60,
                        expected.version
                    ),
                );
            }
        };
        if !status.success() {
            restore(config, lease.as_mut(), old.as_ref());
            return Report::new(
                Exit::SetupFailed,
                format!(
                    "Setup failed ({status}); the installation is not claimed to be version {}",
                    expected.version
                ),
            );
        }
        // Exit code 0 proves nothing: look at what is installed.
        if let Err(why) = install::verify(&config.install_root, &config.arp_key, &expected) {
            restore(config, lease.as_mut(), old.as_ref());
            return Report::new(
                Exit::NotInstalled,
                format!(
                    "Setup exited normally, but version {} is not installed: {why}",
                    expected.version
                ),
            );
        }
        let started = lease
            .as_ref()
            .map(|lease| start_again(&config.install_root, lease.restart_args()));
        drop(lease);
        let tail = match started {
            Some(Ok(())) => "; the program that ran before is running again".to_owned(),
            Some(Err(e)) => format!("; the program could not be started again: {e}"),
            None => String::new(),
        };
        Report::new(
            Exit::Success,
            format!("OpenNCALayer {} is installed{tail}", expected.version),
        )
    }

    /// The last look before Setup starts, which ends every process under the installation:
    /// a program that runs but was not asked (another `openncalayer.exe`, `Update.exe`, a
    /// second daemon) refuses the start; the held daemon is confirmed once more; with nothing
    /// held, a program that started since the first look is asked like any other. One look,
    /// no retries. It sits right before the spawn; what is left is the time Setup itself needs
    /// to start up and reach its own stop of the processes (seconds), which only Setup could
    /// close.
    fn last_look(config: &Config, lease: &mut Option<Lease>) -> Option<Report> {
        if let Some(hook) = config.before_setup_check {
            hook();
        }
        if lease.is_none() {
            match hold(config) {
                Ok(found) => *lease = found,
                Err(mut report) => {
                    report.message = format!(
                        "OpenNCALayer started while the installer was preparing: {}",
                        report.message
                    );
                    return Some(report);
                }
            }
        }
        let held_pid = match lease {
            Some(lease) => {
                if let Err(e) = lease.confirm() {
                    return Some(Report::new(
                        Exit::Unreachable,
                        format!(
                            "the running program no longer holds still ({e}); Setup was not started"
                        ),
                    ));
                }
                Some(lease.pid())
            }
            None => None,
        };
        let running = match processes::running_from(&config.install_root) {
            Ok(running) => running,
            Err(e) => {
                return Some(Report::new(
                    Exit::Failed,
                    format!("the running programs cannot be listed ({e}); Setup was not started"),
                ));
            }
        };
        let own = std::process::id();
        let other = running.iter().find(|process| {
            let relay = process
                .image
                .file_stem()
                .is_some_and(|stem| stem.to_string_lossy().eq_ignore_ascii_case("nmhost"));
            process.pid != own && Some(process.pid) != held_pid && !relay
        })?;
        Some(Report::new(
            Exit::Busy,
            format!(
                "{} runs (process {}) besides the program that was asked to hold still; Setup \
                 would end it by force, so it was not started. Close it and run the installer \
                 again. The installation was not changed",
                other.image.display(),
                other.pid
            ),
        ))
    }

    /// Holds the running program, if one runs: `Ok(None)` if nothing of the installation
    /// runs.
    fn hold(config: &Config) -> Result<Option<Lease>, Report> {
        match maintenance::acquire(&config.endpoint, config.wait, config.poll) {
            Ok(Acquired::Held(lease)) => Ok(Some(lease)),
            Err(Refusal::Busy) => Err(Report::new(
                Exit::Busy,
                format!(
                    "OpenNCALayer is busy (something is being signed or was a moment ago, a \
                     window is open, or it is being updated); it was waited for {} seconds. \
                     The installation was not changed",
                    config.wait.as_secs()
                ),
            )),
            Err(Refusal::Unreachable(e)) => Err(Report::new(
                Exit::Unreachable,
                format!(
                    "the running OpenNCALayer cannot be asked to hold still ({e}); it was not \
                     stopped and the installation was not changed"
                ),
            )),
            Ok(Acquired::Absent) => {
                // No endpoint is not the same as no program: an older version, or one that
                // could not bind it, runs without.
                let running = processes::running_from(&config.install_root).map_err(|e| {
                    Report::new(
                        Exit::Failed,
                        format!("the running programs cannot be listed ({e}); nothing was changed"),
                    )
                })?;
                let updating = running.iter().any(|process| {
                    process.image.file_stem().is_some_and(|stem| {
                        let stem = stem.to_string_lossy().to_lowercase();
                        stem == "update" || stem == "squirrel"
                    })
                });
                if updating {
                    return Err(Report::new(
                        Exit::Busy,
                        "OpenNCALayer is being updated by its own updater; try again when it \
                         is done. The installation was not changed",
                    ));
                }
                if let Some(process) = running.first() {
                    return Err(Report::new(
                        Exit::Unreachable,
                        format!(
                            "{} runs (process {}) but does not answer on its management \
                             endpoint, so it cannot be asked to hold still; close OpenNCALayer \
                             and run the installer again. It was not stopped",
                            process.image.display(),
                            process.pid
                        ),
                    ));
                }
                Ok(None)
            }
        }
    }

    /// After a Setup that did not install: the program that ran before, if the old copy is
    /// still the installation, runs again.
    fn restore(config: &Config, lease: Option<&mut Lease>, old: Option<&semver::Version>) {
        let (Some(lease), Some(old)) = (lease, old) else {
            return;
        };
        // A program that still answers on its held connection was never stopped (Setup failed
        // or did nothing before it ended processes): it runs, nothing to start.
        if lease.confirm().is_ok() {
            return;
        }
        if installed_version(&config.install_root).ok().as_ref() == Some(old) {
            let _ = start_again(&config.install_root, lease.restart_args());
        }
    }

    /// Starts the installed program with `args`, detached from this process and its job: an
    /// installer's job ends with it, and the program must outlive it.
    fn start_again(root: &Path, args: &[String]) -> io::Result<()> {
        let program = root.join("current").join(install::MAIN_EXE);
        // Only what the daemon starts with (`run` and its two flags): the arguments the
        // program announced are not trusted blindly.
        let mut allowed: Vec<&str> = vec!["run"];
        for arg in args.iter().map(String::as_str) {
            if matches!(arg, "--allow-no-wss" | "--no-tray") && !allowed.contains(&arg) {
                allowed.push(arg);
            }
        }
        let mut command = Command::new(program);
        command
            .args(allowed)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        use std::os::windows::process::CommandExt;
        match command
            .creation_flags(DETACHED_CREATION_FLAGS | CREATE_BREAKAWAY_FROM_JOB)
            .spawn()
        {
            Err(e) if breakaway_refused(&e) => command
                .creation_flags(DETACHED_CREATION_FLAGS)
                .spawn()
                .map(drop),
            spawned => spawned.map(drop),
        }
    }

    pub(super) fn production(wait: Duration) -> io::Result<Config> {
        let local = known_folder_local_app_data()?;
        let data = data_dir()?;
        Ok(Config {
            image: std::env::current_exe()?,
            install_root: local.join(APP_ID),
            arp_key: ARP_KEY.to_owned(),
            endpoint: oncl_ipc::maintenance::endpoint(&data)?,
            wait,
            poll: POLL,
            setup_timeout: SETUP_TIMEOUT,
            temp_root: std::env::temp_dir(),
            elevation: is_elevated,
            before_setup_check: None,
        })
    }

    /// The data directory of the program, by the rule the program itself uses
    /// ([`oncl_ipc::data_dir_from`], which `openncalayer::Paths::detect` calls too).
    pub fn data_dir() -> io::Result<PathBuf> {
        std::path::absolute(oncl_ipc::data_dir_from(|name| std::env::var_os(name))?)
    }

    /// `%LOCALAPPDATA%` of the user, asked of the system as Velopack's `Setup.exe` asks it,
    /// not read from the environment.
    fn known_folder_local_app_data() -> io::Result<PathBuf> {
        let mut path: *mut u16 = std::ptr::null_mut();
        // SAFETY: `path` receives a CoTaskMem string on success; it is freed below.
        let hr = unsafe {
            SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, std::ptr::null_mut(), &mut path)
        };
        let result = if hr >= 0 && !path.is_null() {
            // SAFETY: on success `path` is a NUL-terminated UTF-16 string.
            let wide = unsafe {
                let len = (0..).take_while(|&i| *path.add(i) != 0).count();
                std::slice::from_raw_parts(path, len)
            };
            Ok(PathBuf::from(OsString::from_wide(wide)))
        } else {
            Err(io::Error::other(
                "the user's local application data folder is unknown",
            ))
        };
        // SAFETY: `path` is null or allocated by the call above, and freed once.
        unsafe { CoTaskMemFree(path.cast()) };
        result
    }

    /// Whether this process runs with an elevated token (`TokenElevation` of its token).
    pub fn is_elevated() -> io::Result<bool> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: plain call; the handle is closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0;
        // SAFETY: `token` is open with the query right; `elevation` is the size given.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                std::ptr::from_mut(&mut elevation).cast(),
                u32::try_from(size_of::<TOKEN_ELEVATION>()).expect("small struct"),
                &mut returned,
            )
        };
        let result = if ok == FALSE {
            Err(io::Error::last_os_error())
        } else {
            Ok(elevation.TokenIsElevated != 0)
        };
        // SAFETY: `token` is open and not used again.
        unsafe { CloseHandle(token) };
        result
    }
}

/// The data directory of the program as the program finds it: the one rule
/// [`oncl_ipc::data_dir_from`], which `openncalayer::Paths::detect` calls too, made absolute.
///
/// # Errors
///
/// Neither variable is set.
#[cfg(windows)]
pub fn data_dir() -> std::io::Result<PathBuf> {
    windows::data_dir()
}

/// Whether this process runs with an elevated token: what `production` asks, and what
/// [`run`] refuses on.
///
/// # Errors
///
/// The process token cannot be read.
#[cfg(windows)]
pub fn is_elevated() -> std::io::Result<bool> {
    windows::is_elevated()
}
