//! OS-level measurement of the processes under test: peak working set and peak private
//! (commit) bytes taken from the operating system after the process exits (Windows:
//! `GetProcessMemoryInfo` on the child's handle and the job object's peak counters; Linux:
//! `/proc/<pid>/status` `VmHWM`, sampled), never a counter inside the measured program.
//! Also the scratch-directory watcher (peak temporary bytes), the drive preflight and the
//! machine description for the report.

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

/// Cap of the captured stdout/stderr of one measured process (the rest is drained and dropped).
const CAPTURE_LIMIT: usize = 8 << 20;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Peaks {
    /// Peak working set (includes file-mapped pages) as the OS reports it.
    pub peak_working_set: u64,
    /// Peak private/commit bytes (Windows `PeakPagefileUsage`; Linux sampled `RssAnon`).
    pub peak_private: u64,
    /// Largest `max(working set, private)` the polling sampler saw, a cross-check only.
    pub sampled_max: u64,
}

impl Peaks {
    /// The stricter of the two peaks: what the 1 GiB criterion is judged against.
    pub fn criterion(&self) -> u64 {
        self.peak_working_set.max(self.peak_private)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TempUse {
    pub peak_bytes: u64,
    pub peak_files: u64,
    pub final_bytes: u64,
    pub final_files: u64,
}

#[derive(Debug)]
pub struct Measured {
    pub exit: Option<i32>,
    pub success: bool,
    pub wall: Duration,
    pub peaks: Peaks,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub temp: Option<TempUse>,
    pub timed_out: bool,
    pub interrupted: bool,
}

impl Measured {
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Feed for the child's stdin.
pub enum Feed {
    None,
    /// The file's bytes in 1 MiB writes, with no length ever declared (unknown-length input).
    File(PathBuf),
    /// `n` bytes of a repeating pattern (limit+1 probes, no file needed).
    Pattern { byte: u8, len: u64 },
}

pub struct RunOptions {
    pub timeout: Duration,
    pub feed: Feed,
    /// A directory whose total file size is sampled for the temporary peak.
    pub watch: Option<PathBuf>,
    /// Deliver CTRL_BREAK (Windows) / SIGINT (Unix) when this returns true; polled every 100 ms.
    pub interrupt_when: Option<Box<dyn FnMut() -> bool + Send>>,
    /// Keep stdin open and silent after the feed (a held connection) until the process ends.
    pub stdin_piped: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(6 * 3600),
            feed: Feed::None,
            watch: None,
            interrupt_when: None,
            stdin_piped: false,
        }
    }
}

/// Sum of the sizes of all regular files below `root` and their count (missing root is 0/0).
pub fn tree_usage(root: &Path) -> (u64, u64) {
    let (mut bytes, mut files) = (0u64, 0u64);
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                // `DirEntry::metadata` is the directory's cached size, 0 for a file that is still
                // being written on Windows: stat the file itself.
                bytes += std::fs::metadata(entry.path()).map_or(meta.len(), |m| m.len());
                files += 1;
            }
        }
    }
    (bytes, files)
}

struct Watcher {
    stop: Arc<AtomicBool>,
    peak_bytes: Arc<AtomicU64>,
    peak_files: Arc<AtomicU64>,
    join: Option<thread::JoinHandle<()>>,
    root: PathBuf,
}

impl Watcher {
    fn start(root: PathBuf) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let peak_bytes = Arc::new(AtomicU64::new(0));
        let peak_files = Arc::new(AtomicU64::new(0));
        let (s, b, f, r) = (stop.clone(), peak_bytes.clone(), peak_files.clone(), root.clone());
        let join = thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let (bytes, files) = tree_usage(&r);
                b.fetch_max(bytes, Ordering::Relaxed);
                f.fetch_max(files, Ordering::Relaxed);
                thread::sleep(Duration::from_millis(200));
            }
        });
        Self {
            stop,
            peak_bytes,
            peak_files,
            join: Some(join),
            root,
        }
    }

    fn finish(mut self) -> TempUse {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
        let (final_bytes, final_files) = tree_usage(&self.root);
        TempUse {
            peak_bytes: self.peak_bytes.load(Ordering::Relaxed).max(final_bytes),
            peak_files: self.peak_files.load(Ordering::Relaxed).max(final_files),
            final_bytes,
            final_files,
        }
    }
}

type Shared = Arc<std::sync::Mutex<Vec<u8>>>;

fn drain(mut reader: impl Read + Send + 'static, into: Shared) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; 64 * 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut captured = into.lock().unwrap();
                    let room = CAPTURE_LIMIT.saturating_sub(captured.len());
                    captured.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
    })
}

fn feed_stdin(mut stdin: std::process::ChildStdin, feed: Feed) -> Option<thread::JoinHandle<()>> {
    match feed {
        Feed::None => None,
        Feed::File(path) => Some(thread::spawn(move || {
            let Ok(mut file) = std::fs::File::open(path) else {
                return;
            };
            let mut buf = vec![0u8; 1 << 20];
            loop {
                match file.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stdin.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                }
            }
            drop(stdin);
        })),
        Feed::Pattern { byte, len } => Some(thread::spawn(move || {
            let chunk = vec![byte; 1 << 20];
            let mut left = len;
            while left > 0 {
                let n = left.min(chunk.len() as u64) as usize;
                if stdin.write_all(&chunk[..n]).is_err() {
                    return;
                }
                left -= n as u64;
            }
            drop(stdin);
        })),
    }
}

/// A spawned, measured process. `wait` returns the OS-measured result.
pub struct Running {
    child: std::process::Child,
    started: Instant,
    job: os::Job,
    sampler: os::Sampler,
    out: Shared,
    err: Shared,
    out_thread: thread::JoinHandle<()>,
    err_thread: thread::JoinHandle<()>,
    feeder: Option<thread::JoinHandle<()>>,
    held_stdin: Option<std::process::ChildStdin>,
    watcher: Option<Watcher>,
    interrupt_when: Option<Box<dyn FnMut() -> bool + Send>>,
    timeout: Duration,
}

impl Running {
    pub fn spawn(mut command: Command, options: RunOptions) -> anyhow::Result<Self> {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let wants_stdin = !matches!(options.feed, Feed::None) || options.stdin_piped;
        command.stdin(if wants_stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // CREATE_NEW_PROCESS_GROUP: lets CTRL_BREAK be delivered to this child only.
            command.creation_flags(0x0000_0200);
        }
        let started = Instant::now();
        let mut child = command.spawn().context("spawning the measured process")?;
        let job = os::Job::attach(&child);
        let out: Shared = Arc::default();
        let err: Shared = Arc::default();
        let out_thread = drain(child.stdout.take().context("stdout")?, out.clone());
        let err_thread = drain(child.stderr.take().context("stderr")?, err.clone());
        let stdin = child.stdin.take();
        let (feeder, held_stdin) = match stdin {
            Some(stdin) if matches!(options.feed, Feed::None) => (None, Some(stdin)),
            Some(stdin) => (feed_stdin(stdin, options.feed), None),
            None => (None, None),
        };
        let sampler = os::Sampler::new(child.id());
        Ok(Self {
            child,
            started,
            job,
            sampler,
            out,
            err,
            out_thread,
            err_thread,
            feeder,
            held_stdin,
            watcher: options.watch.map(Watcher::start),
            interrupt_when: options.interrupt_when,
            timeout: options.timeout,
        })
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Everything the process wrote to stdout so far.
    pub fn stdout_so_far(&self) -> String {
        String::from_utf8_lossy(&self.out.lock().unwrap()).into_owned()
    }

    /// Polls stdout until a line starting with `prefix` appears (returns it) or the process ends.
    pub fn wait_for_line(&mut self, prefix: &str, timeout: Duration) -> anyhow::Result<String> {
        let until = Instant::now() + timeout;
        loop {
            if let Some(line) = self
                .stdout_so_far()
                .lines()
                .find(|l| l.starts_with(prefix))
            {
                return Ok(line.to_owned());
            }
            if let Some(status) = self.child.try_wait()? {
                bail!(
                    "the process ended ({status}) before printing `{prefix}`: stdout={} stderr={}",
                    self.stdout_so_far(),
                    String::from_utf8_lossy(&self.err.lock().unwrap())
                );
            }
            if Instant::now() > until {
                bail!("no `{prefix}` line within {timeout:?}");
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Writes to a stdin that was opened with `stdin_piped` and no feed.
    pub fn write_stdin(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        let stdin = self.held_stdin.as_mut().context("stdin is not held open")?;
        stdin.write_all(bytes)?;
        stdin.flush()?;
        Ok(())
    }

    pub fn close_stdin(&mut self) {
        self.held_stdin = None;
    }

    /// Waits for the process (up to its timeout), delivering the interrupt when asked.
    pub fn wait(mut self) -> anyhow::Result<Measured> {
        let pid = self.child.id();
        let mut sampled_max = 0u64;
        let mut timed_out = false;
        let mut interrupted = false;
        let status: ExitStatus = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            sampled_max = sampled_max.max(self.sampler.sample());
            if !interrupted
                && let Some(test) = &mut self.interrupt_when
                && test()
            {
                interrupted = true;
                os::interrupt(pid);
            }
            if self.started.elapsed() > self.timeout {
                timed_out = true;
                let _ = self.child.kill();
                break self.child.wait()?;
            }
            thread::sleep(Duration::from_millis(100));
        };
        let wall = self.started.elapsed();
        let mut peaks = os::peaks(&self.child, &self.sampler, &self.job);
        peaks.sampled_max = sampled_max.max(peaks.sampled_max);
        let _ = self.out_thread.join();
        let _ = self.err_thread.join();
        if let Some(feeder) = self.feeder
            && feeder.is_finished()
        {
            let _ = feeder.join();
        }
        let temp = self.watcher.map(Watcher::finish);
        let stdout = std::mem::take(&mut *self.out.lock().unwrap());
        let stderr = std::mem::take(&mut *self.err.lock().unwrap());
        Ok(Measured {
            exit: status.code(),
            success: status.success(),
            wall,
            peaks,
            stdout,
            stderr,
            temp,
            timed_out,
            interrupted,
        })
    }
}

/// Runs `command` to completion and returns the OS-measured peaks.
pub fn run_measured(command: Command, options: RunOptions) -> anyhow::Result<Measured> {
    Running::spawn(command, options)?.wait()
}

#[cfg(windows)]
mod os {
    use super::Peaks;
    use std::{ffi::c_void, os::windows::io::AsRawHandle, process::Child};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent},
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                QueryInformationJobObject, SetInformationJobObject,
            },
            ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX},
        },
    };

    /// A kill-on-close job: the process tree cannot outlive `platform-proof`.
    pub struct Job(HANDLE);
    unsafe impl Send for Job {}

    impl Job {
        pub fn attach(child: &Child) -> Self {
            // SAFETY: plain Win32 calls on handles this function owns or borrows.
            unsafe {
                let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if job.is_null() {
                    return Self(std::ptr::null_mut());
                }
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&raw const info).cast::<c_void>(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                AssignProcessToJobObject(job, child.as_raw_handle());
                Self(job)
            }
        }

        /// `(peak process commit, peak job commit)` from the job's counters.
        fn peaks(&self) -> (u64, u64) {
            if self.0.is_null() {
                return (0, 0);
            }
            // SAFETY: `info` is a correctly sized out-parameter.
            unsafe {
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                let ok = QueryInformationJobObject(
                    self.0,
                    JobObjectExtendedLimitInformation,
                    (&raw mut info).cast::<c_void>(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                );
                if ok == 0 {
                    return (0, 0);
                }
                (info.PeakProcessMemoryUsed as u64, info.PeakJobMemoryUsed as u64)
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: closing the handle this value owns (kills any survivors).
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    pub struct Sampler {
        handle: HANDLE,
        max: u64,
    }

    impl Sampler {
        pub fn new(pid: u32) -> Self {
            use windows_sys::Win32::System::Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            };
            // SAFETY: OpenProcess with query rights only.
            let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x0010, 0, pid) };
            Self { handle, max: 0 }
        }

        pub fn sample(&mut self) -> u64 {
            if self.handle.is_null() {
                return self.max;
            }
            if let Some(c) = counters(self.handle) {
                self.max = self
                    .max
                    .max(c.WorkingSetSize as u64)
                    .max(c.PrivateUsage as u64);
            }
            self.max
        }
    }

    impl Drop for Sampler {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                // SAFETY: closing the handle this value owns.
                unsafe { CloseHandle(self.handle) };
            }
        }
    }

    fn counters(handle: HANDLE) -> Option<PROCESS_MEMORY_COUNTERS_EX> {
        // SAFETY: `c` is a correctly sized out-parameter for the extended counters.
        unsafe {
            let mut c: PROCESS_MEMORY_COUNTERS_EX = std::mem::zeroed();
            c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
            (GetProcessMemoryInfo(handle, (&raw mut c).cast(), c.cb) != 0).then_some(c)
        }
    }

    /// Peaks from the OS after exit: the child's own handle stays valid (and its counters
    /// final) until the `Child` is dropped; the job counters cover descendants.
    pub fn peaks(child: &Child, sampler: &Sampler, job: &Job) -> Peaks {
        let mut peaks = Peaks::default();
        if let Some(c) = counters(child.as_raw_handle()) {
            peaks.peak_working_set = c.PeakWorkingSetSize as u64;
            peaks.peak_private = c.PeakPagefileUsage as u64;
        }
        let (process_commit, job_commit) = job.peaks();
        peaks.peak_private = peaks.peak_private.max(process_commit).max(job_commit);
        peaks.sampled_max = sampler.max;
        peaks
    }

    pub fn interrupt(pid: u32) {
        // SAFETY: the child was created with CREATE_NEW_PROCESS_GROUP, so its pid is a group id.
        unsafe {
            GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid);
        }
    }
}

#[cfg(unix)]
mod os {
    use super::Peaks;
    use std::process::Child;

    pub struct Job;
    impl Job {
        pub fn attach(_: &Child) -> Self {
            Self
        }
    }

    pub struct Sampler {
        pid: u32,
        hwm: u64,
        anon: u64,
    }

    impl Sampler {
        pub fn new(pid: u32) -> Self {
            Self {
                pid,
                hwm: 0,
                anon: 0,
            }
        }

        pub fn sample(&mut self) -> u64 {
            if let Ok(text) = std::fs::read_to_string(format!("/proc/{}/status", self.pid))
                && let Some(s) = super::parse_proc_status(&text)
            {
                self.hwm = self.hwm.max(s.vm_hwm);
                self.anon = self.anon.max(s.rss_anon);
            }
            self.hwm.max(self.anon)
        }
    }

    pub fn peaks(_: &Child, sampler: &Sampler, _: &Job) -> Peaks {
        Peaks {
            peak_working_set: sampler.hwm,
            peak_private: sampler.anon,
            sampled_max: sampler.hwm.max(sampler.anon),
        }
    }

    pub fn interrupt(pid: u32) {
        // SAFETY: plain signal delivery to the child's pid.
        unsafe {
            libc::kill(pid as i32, libc::SIGINT);
        }
    }
}

/// What `/proc/<pid>/status` says about memory, in bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct ProcStatus {
    pub vm_hwm: u64,
    pub vm_rss: u64,
    pub rss_anon: u64,
}

/// Parses the `VmHWM`/`VmRSS`/`RssAnon` lines (kB) of a Linux `/proc/<pid>/status`.
pub fn parse_proc_status(text: &str) -> Option<ProcStatus> {
    let field = |name: &str| -> Option<u64> {
        text.lines().find_map(|line| {
            let rest = line.strip_prefix(name)?.strip_prefix(':')?;
            let kb: u64 = rest.trim().strip_suffix("kB")?.trim().parse().ok()?;
            kb.checked_mul(1024)
        })
    };
    Some(ProcStatus {
        vm_hwm: field("VmHWM")?,
        vm_rss: field("VmRSS")?,
        rss_anon: field("RssAnon").unwrap_or(0),
    })
}

/// A drive or directory that can hold the proof's scratch data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Storage {
    pub path: String,
    pub free_bytes: u64,
    pub total_bytes: u64,
    pub kind: String,
    pub filesystem: String,
}

/// Preflight: the volume of `dir` must be a fixed local drive with at least `needed` free bytes.
pub fn preflight_storage(dir: &Path, needed: u64) -> anyhow::Result<Storage> {
    let storage = storage_of(dir)?;
    if storage.kind != "fixed" {
        bail!(
            "BLOCKED: {} is on a {} volume; the proof needs a fixed local drive",
            dir.display(),
            storage.kind
        );
    }
    if storage.free_bytes < needed {
        bail!(
            "BLOCKED: {} has {} free bytes, the scratch preflight needs {needed}",
            dir.display(),
            storage.free_bytes
        );
    }
    Ok(storage)
}

#[cfg(windows)]
pub fn storage_of(dir: &Path) -> anyhow::Result<Storage> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        GetDiskFreeSpaceExW, GetDriveTypeW, GetVolumePathNameW, GetVolumeInformationW,
    };
    let absolute = std::path::absolute(dir)?;
    let wide: Vec<u16> = absolute.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut root = [0u16; 261];
    // SAFETY: wide is NUL terminated; root is a MAX_PATH+1 buffer.
    let ok = unsafe { GetVolumePathNameW(wide.as_ptr(), root.as_mut_ptr(), root.len() as u32) };
    if ok == 0 {
        bail!("GetVolumePathNameW failed for {}", dir.display());
    }
    let (mut free, mut total, mut avail) = (0u64, 0u64, 0u64);
    // SAFETY: out-parameters are valid u64 locations.
    let ok = unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut avail, &mut total, &mut free) };
    if ok == 0 {
        bail!("GetDiskFreeSpaceExW failed for {}", dir.display());
    }
    // SAFETY: root is NUL terminated.
    let kind = match unsafe { GetDriveTypeW(root.as_ptr()) } {
        2 => "removable",
        3 => "fixed",
        4 => "network",
        5 => "optical",
        6 => "ramdisk",
        _ => "unknown",
    };
    let mut fs = [0u16; 64];
    // SAFETY: fs is a valid buffer of the stated length.
    let ok = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs.as_mut_ptr(),
            fs.len() as u32,
        )
    };
    let filesystem = if ok == 0 {
        "unknown".into()
    } else {
        String::from_utf16_lossy(&fs[..fs.iter().position(|c| *c == 0).unwrap_or(fs.len())])
    };
    let root_len = root.iter().position(|c| *c == 0).unwrap_or(root.len());
    Ok(Storage {
        path: String::from_utf16_lossy(&root[..root_len]),
        free_bytes: avail,
        total_bytes: total,
        kind: kind.into(),
        filesystem,
    })
}

#[cfg(unix)]
pub fn storage_of(dir: &Path) -> anyhow::Result<Storage> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let c = CString::new(dir.as_os_str().as_bytes())?;
    // SAFETY: c is NUL terminated; stat is an out-parameter.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut stat) } != 0 {
        bail!("statvfs failed for {}", dir.display());
    }
    Ok(Storage {
        path: dir.display().to_string(),
        free_bytes: stat.f_bavail as u64 * stat.f_frsize as u64,
        total_bytes: stat.f_blocks as u64 * stat.f_frsize as u64,
        kind: "fixed".into(),
        filesystem: "unknown".into(),
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Machine {
    pub os: String,
    pub cpu: String,
    pub logical_cpus: String,
    pub physical_memory_bytes: u64,
    pub arch: String,
    pub drive_media: String,
}

#[cfg(windows)]
fn physical_memory() -> u64 {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    // SAFETY: out-parameter with its length field set.
    unsafe {
        let mut status: MEMORYSTATUSEX = std::mem::zeroed();
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut status) != 0 {
            status.ullTotalPhys
        } else {
            0
        }
    }
}

#[cfg(unix)]
fn physical_memory() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("MemTotal:")?.trim().strip_suffix("kB")?.trim().parse::<u64>().ok())
        })
        .map_or(0, |kb| kb * 1024)
}

/// Describes this machine; `drive` names the volume the proof data lives on.
pub fn machine(drive: &Storage) -> Machine {
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let os = if cfg!(windows) {
        Command::new("cmd")
            .args(["/C", "ver"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default()
    } else {
        std::fs::read_to_string("/etc/os-release")
            .unwrap_or_default()
            .lines()
            .find_map(|l| l.strip_prefix("PRETTY_NAME="))
            .unwrap_or_default()
            .trim_matches('"')
            .to_owned()
    };
    let drive_media = if cfg!(windows) {
        let letter = drive.path.chars().next().unwrap_or('C');
        Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "$p=Get-Partition -DriveLetter {letter} -ErrorAction SilentlyContinue; if($p){{$d=Get-Disk -Number $p.DiskNumber; $pd=Get-PhysicalDisk | Where-Object DeviceId -eq $p.DiskNumber; \"$($d.FriendlyName) $($pd.MediaType) $($pd.BusType)\"}}"
                ),
            ])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default()
    } else {
        String::new()
    };
    Machine {
        os,
        cpu: env("PROCESSOR_IDENTIFIER"),
        logical_cpus: std::thread::available_parallelism()
            .map(|n| n.get().to_string())
            .unwrap_or_default(),
        physical_memory_bytes: physical_memory(),
        arch: std::env::consts::ARCH.into(),
        drive_media,
    }
}

/// The last line of `text` that starts with `marker`, parsed as JSON after the marker.
pub fn parse_result_line(text: &str, marker: &str) -> Option<serde_json::Value> {
    text.lines()
        .rev()
        .find_map(|line| line.strip_prefix(marker))
        .and_then(|rest| serde_json::from_str(rest.trim()).ok())
}
