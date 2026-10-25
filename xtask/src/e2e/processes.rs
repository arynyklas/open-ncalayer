//! The processes of an e2e run: found by their sandbox, killed, and cleaned up when the xtask
//! is interrupted.
//!
//! Everything started for a browser carries `ONCL_DATA_DIR=<sandbox>/data` in its environment:
//! the driver (from the xtask), the browser (from the driver), the relay (from the browser) and
//! the daemon (from the relay). [`sweep`] finds and kills them by that alone, also those of an
//! earlier run that was killed.
//!
//! Drivers run in their own process group, so a Ctrl+C in the terminal reaches only the xtask.
//! [`cleanup_on_signals`] catches SIGINT, SIGTERM and SIGHUP: a handler thread kills the
//! tracked driver groups, sweeps the tracked sandboxes, removes their temporary directories and
//! exits. The signal mask is left alone, and caught signals revert to their default in exec'd
//! children, so drivers, browsers, relays and daemons keep the usual signal behaviour.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// How long [`sweep`] waits for the processes it killed to disappear.
const SWEEP_PATIENCE: Duration = Duration::from_secs(10);

/// What an interrupted run must clean up.
#[derive(Default)]
struct Tracked {
    groups: Vec<u32>,
    sandboxes: Vec<(PathBuf, PathBuf)>, // (data dir, temporary dir)
}

static TRACKED: Mutex<Tracked> = Mutex::new(Tracked {
    groups: Vec::new(),
    sandboxes: Vec::new(),
});

fn tracked() -> MutexGuard<'static, Tracked> {
    TRACKED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Kills process group `group` on interruption, until [`untrack_group`].
pub fn track_group(group: u32) {
    tracked().groups.push(group);
}

pub fn untrack_group(group: u32) {
    tracked().groups.retain(|&g| g != group);
}

/// Sweeps the sandbox of `data` and removes `tmp` on interruption while the guard lives.
pub fn track_sandbox(data: &Path, tmp: &Path) -> SandboxGuard {
    let entry = (data.to_owned(), tmp.to_owned());
    tracked().sandboxes.push(entry.clone());
    SandboxGuard(entry)
}

pub struct SandboxGuard((PathBuf, PathBuf));

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        tracked().sandboxes.retain(|entry| entry != &self.0);
    }
}

/// Held by the handler thread from the signal until the process exits; [`finish`] takes it.
static CLEANUP: Mutex<()> = Mutex::new(());

/// Waits for an interruption's cleanup, which ends the process: call before reporting results,
/// so that scenarios failing because their browser was just killed are not reported.
pub fn finish() {
    drop(CLEANUP.lock().unwrap_or_else(PoisonError::into_inner));
}

/// Catches SIGINT, SIGTERM and SIGHUP; on the first one, kills what is tracked and exits with
/// 128 + the signal.
pub fn cleanup_on_signals() {
    #[cfg(target_os = "linux")]
    signals::install(|signal| {
        let _held = CLEANUP.lock().unwrap_or_else(PoisonError::into_inner);
        let (groups, sandboxes) = {
            let tracked = tracked();
            (tracked.groups.clone(), tracked.sandboxes.clone())
        };
        for group in groups {
            kill_group(group);
        }
        for (data, tmp) in sandboxes {
            sweep(&data);
            let _ = fs::remove_dir_all(tmp);
        }
        eprintln!("ext-e2e interrupted: its drivers, browsers, relays and daemons are stopped");
        std::process::exit(128 + signal);
    });
}

/// A self-pipe: the signal handler only writes the signal number to a pipe, a thread reads it
/// and runs the cleanup.
#[cfg(target_os = "linux")]
mod signals {
    use std::sync::atomic::{AtomicI32, Ordering};

    static PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);

    extern "C" fn on_signal(signal: libc::c_int) {
        let byte = signal as u8;
        // SAFETY: write(2) is async-signal-safe; `byte` lives for the call. A full pipe
        // only means a signal is already pending.
        unsafe {
            libc::write(
                PIPE_WRITE.load(Ordering::Relaxed),
                (&raw const byte).cast(),
                1,
            )
        };
    }

    pub fn install(cleanup: fn(i32)) {
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for the two descriptors.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            eprintln!("cannot catch signals: {}", std::io::Error::last_os_error());
            return;
        }
        PIPE_WRITE.store(fds[1], Ordering::Relaxed);
        let read = fds[0];
        std::thread::spawn(move || {
            let mut byte = 0u8;
            loop {
                // SAFETY: reads one byte into `byte`.
                match unsafe { libc::read(read, (&raw mut byte).cast(), 1) } {
                    1 => return cleanup(i32::from(byte)),
                    -1 if std::io::Error::last_os_error().kind()
                        == std::io::ErrorKind::Interrupted => {}
                    _ => return,
                }
            }
        });
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: a zeroed `sigaction` with an empty mask and a handler that only calls
            // write(2); SA_RESTART keeps the other threads' system calls going.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = on_signal as *const () as libc::sighandler_t;
                libc::sigemptyset(&mut action.sa_mask);
                action.sa_flags = libc::SA_RESTART;
                libc::sigaction(signal, &action, std::ptr::null_mut());
            }
        }
    }
}

/// Kills every process of the sandbox of `data` (see the module docs) and waits until they
/// are gone, at most [`SWEEP_PATIENCE`].
pub fn sweep(data: &Path) {
    let deadline = Instant::now() + SWEEP_PATIENCE;
    loop {
        let pids = sandbox_pids(data);
        if pids.is_empty() || Instant::now() >= deadline {
            return;
        }
        for pid in pids {
            kill(pid);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Live processes other than this one with `ONCL_DATA_DIR=<data>` in their environment.
pub fn sandbox_pids(data: &Path) -> Vec<u32> {
    let needles = data_dir_vars(data);
    let own = std::process::id();
    proc_entries()
        .filter(|(pid, dir)| *pid != own && has_any_var(dir, &needles))
        .map(|(pid, _)| pid)
        .collect()
}

/// Live `openncalayer` processes (`daemon`'s file name, also once the binary was rebuilt
/// under them) of the sandbox of `data`.
pub fn daemon_pids(daemon: &Path, data: &Path) -> Vec<u32> {
    let Some(name) = daemon.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let needles = data_dir_vars(data);
    proc_entries()
        .filter(|(_, dir)| {
            // A zombie has no `exe`.
            fs::read_link(dir.join("exe"))
                .ok()
                .is_some_and(|exe| exe_name(&exe) == Some(name))
                && has_any_var(dir, &needles)
        })
        .map(|(pid, _)| pid)
        .collect()
}

/// `ONCL_DATA_DIR=<data>` as given and canonicalized.
fn data_dir_vars(data: &Path) -> Vec<Vec<u8>> {
    let mut vars = vec![format!("ONCL_DATA_DIR={}", data.display()).into_bytes()];
    if let Ok(canonical) = fs::canonicalize(data) {
        vars.push(format!("ONCL_DATA_DIR={}", canonical.display()).into_bytes());
    }
    vars
}

/// `(pid, /proc/<pid>)` of every process.
fn proc_entries() -> impl Iterator<Item = (u32, PathBuf)> {
    fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_str()?.parse().ok()?;
            Some((pid, entry.path()))
        })
}

/// The environment of the process at `dir` (`/proc/<pid>`) has one of `vars`. Unreadable
/// (gone, another user's) and zombie (empty) environments have none.
fn has_any_var(dir: &Path, vars: &[Vec<u8>]) -> bool {
    fs::read(dir.join("environ")).is_ok_and(|environ| {
        environ
            .split(|&b| b == 0)
            .any(|var| vars.iter().any(|v| var == v.as_slice()))
    })
}

/// The file name of a `/proc/<pid>/exe` target, without the ` (deleted)` the kernel appends
/// once the file was replaced.
fn exe_name(exe: &Path) -> Option<&str> {
    let name = exe.file_name()?.to_str()?;
    Some(name.strip_suffix(" (deleted)").unwrap_or(name))
}

/// SIGKILL to `pid`.
pub fn kill(pid: u32) {
    #[cfg(unix)]
    if let Ok(pid) = libc::pid_t::try_from(pid) {
        // SAFETY: kill(2) with a positive pid has no memory effects.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    let _ = pid;
}

/// SIGKILL to every process of group `group`.
pub fn kill_group(group: u32) {
    #[cfg(unix)]
    if let Ok(group) = libc::pid_t::try_from(group)
        && group > 1
    {
        // SAFETY: kill(2) with a negative pid signals a process group; no memory effects.
        unsafe { libc::kill(-group, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    let _ = group;
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[cfg(target_os = "linux")]
    #[test]
    fn sweep_kills_any_process_of_the_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .env("ONCL_DATA_DIR", &data)
            .spawn()
            .unwrap();
        let mut other = std::process::Command::new("sleep")
            .arg("60")
            .env("ONCL_DATA_DIR", dir.path().join("elsewhere"))
            .spawn()
            .unwrap();
        let pid = child.id();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !sandbox_pids(&data).contains(&pid) {
            assert!(Instant::now() < deadline, "the child never showed up");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(sandbox_pids(&data), [pid]);

        // The child stays a zombie until waited for: it has an empty environment by then.
        sweep(&data);
        assert!(sandbox_pids(&data).is_empty());
        assert!(child.wait().is_ok());
        assert!(
            other.try_wait().unwrap().is_none(),
            "another sandbox was swept"
        );
        other.kill().unwrap();
        other.wait().unwrap();
    }
}
