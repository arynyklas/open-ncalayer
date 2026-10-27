//! Who listens on a TCP port of this machine ([`port_owner`]), whether it looks like the
//! original NCALayer, and stopping exactly that process ([`stop`]).
//!
//! - Windows: `GetExtendedTcpTable` (listeners with their PIDs), then the process's image
//!   path (`QueryFullProcessImageNameW`), creation time and command line;
//! - Linux: the listening sockets of `/proc/net/tcp{,6}`, the process whose `/proc/*/fd`
//!   holds one, then its `/proc/<pid>/{exe,stat,cmdline}`;
//! - macOS: `lsof -nP -iTCP:<port> -sTCP:LISTEN`, then `proc_pidpath`, `proc_pidinfo` and
//!   `ps`.
//!
//! [`stop`] checks again, right before ending the process, that the PID still is the same
//! program started at the same time, so a PID reused by another process is not ended.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use std::{fmt, io};

/// How long [`stop`] waits for the process to end, after asking and again after forcing.
const STOP_WAIT: Duration = Duration::from_secs(5);

/// The process listening on a port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortOwner {
    pub pid: u32,
    /// Its program.
    pub exe: PathBuf,
    /// When it started: with `pid` and `exe`, which process it is.
    pub started: SystemTime,
    /// Whether it looks like the original NCALayer: `NCALayer.exe`, `ncalayer.sh`, or Java
    /// running NCALayer.
    pub looks_original: bool,
}

/// What is known of a process.
struct Process {
    exe: PathBuf,
    started: SystemTime,
    /// Its command line with the arguments separated by spaces; empty if unknown.
    command_line: String,
}

/// The process listening on TCP `port` (on any local address, IPv4 or IPv6), if any is
/// visible to this user.
///
/// # Errors
///
/// The listeners cannot be listed (on macOS, `lsof` cannot run), or the listening process
/// cannot be inspected (another user's or a system process on Windows).
pub fn port_owner(port: u16) -> io::Result<Option<PortOwner>> {
    // The PID is looked up again after the process is inspected: one that ended and was
    // reused in between is not taken for the listener.
    for _ in 0..3 {
        let Some(pid) = sys::listener(port)? else {
            return Ok(None);
        };
        let process = match sys::inspect(pid) {
            Ok(process) => process,
            // Ended meanwhile.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if sys::listener(port)? == Some(pid) {
            return Ok(Some(PortOwner {
                pid,
                looks_original: looks_original(&process.exe, &process.command_line),
                exe: process.exe,
                started: process.started,
            }));
        }
    }
    Ok(None)
}

/// Ends the process `owner` (found by [`port_owner`]) and waits until it is gone. Right
/// before, its PID is checked to still be the program `owner.exe` started at
/// `owner.started`, and that program to look like the original NCALayer: nothing else is
/// ever ended, whatever `owner.looks_original` says. On Unix it is asked to end (`SIGTERM`)
/// and forced (`SIGKILL`) after a few seconds, checked again right before each signal; on
/// Windows it is ended at once (`TerminateProcess`). Blocks for up to 5 s after each signal:
/// call it off the event loop.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidInput`] for this process or one that does not look like the
/// original (nothing is ended); [`io::ErrorKind::NotFound`] if the process is gone or its
/// PID is another process now (nothing is ended); [`io::ErrorKind::TimedOut`] if it does
/// not end; any error ending it.
pub fn stop(owner: &PortOwner) -> io::Result<()> {
    if owner.pid == std::process::id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to stop this process",
        ));
    }
    sys::stop(owner)
}

/// `Ok` if `now` is the process `owner` describes, and it looks like the original.
fn check_target(owner: &PortOwner, now: &Process) -> io::Result<()> {
    if now.exe != owner.exe || now.started != owner.started {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            Changed {
                pid: owner.pid,
                exe: now.exe.clone(),
            },
        ));
    }
    if !looks_original(&now.exe, &now.command_line) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to stop process {} ({}): it does not look like the original NCALayer",
                owner.pid,
                now.exe.display()
            ),
        ));
    }
    Ok(())
}

/// The process found on the port is gone and its PID is another program's.
#[derive(Debug)]
struct Changed {
    pid: u32,
    exe: PathBuf,
}

impl fmt::Display for Changed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "process {} is not the one found on the port any more (now {})",
            self.pid,
            self.exe.display()
        )
    }
}

impl std::error::Error for Changed {}

/// Whether the program `exe` run with `command_line` looks like the original NCALayer:
/// `NCALayer.exe` or `ncalayer.sh`, or Java with NCALayer in its arguments or path (the
/// launcher's `javaw.exe -jar …\NCALayer.exe`, `jre8_ncalayer/bin/java -jar ncalayer.sh`).
fn looks_original(exe: &Path, command_line: &str) -> bool {
    let path = exe.to_string_lossy();
    // Either separator, so the rules read the same on every system.
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match name.as_str() {
        "ncalayer.exe" | "ncalayer.sh" => true,
        "java" | "javaw" | "java.exe" | "javaw.exe" => {
            names_ncalayer(command_line) || names_ncalayer(&path)
        }
        _ => false,
    }
}

/// Whether `text` names NCALayer, but not as part of OpenNCALayer.
fn names_ncalayer(text: &str) -> bool {
    text.to_lowercase()
        .replace("openncalayer", "")
        .contains("ncalayer")
}

#[cfg(windows)]
mod sys {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::ptr;
    use std::time::{Duration, SystemTime};
    use std::{io, mem};

    use windows_sys::Wdk::System::Threading::{
        NtQueryInformationProcess, ProcessCommandLineInformation,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE, NO_ERROR, UNICODE_STRING,
        WAIT_OBJECT_0,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess,
        WaitForSingleObject,
    };

    use super::{PortOwner, Process, STOP_WAIT, check_target};

    /// An open process handle, closed when dropped.
    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle was opened by `open` and is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    fn open(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> io::Result<Handle> {
        // SAFETY: plain call; a null handle is failure.
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            let e = io::Error::last_os_error();
            // ERROR_INVALID_PARAMETER: no such process.
            return Err(if e.raw_os_error() == Some(87) {
                io::Error::new(io::ErrorKind::NotFound, format!("no process {pid}"))
            } else {
                io::Error::new(e.kind(), format!("process {pid}: {e}"))
            });
        }
        Ok(Handle(handle))
    }

    /// The table of TCP listeners of address family `family`, as `GetExtendedTcpTable`
    /// fills it.
    fn listeners(family: u16) -> io::Result<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let mut size = u32::try_from(buf.len()).unwrap_or(u32::MAX);
            let data = if buf.is_empty() {
                ptr::null_mut()
            } else {
                buf.as_mut_ptr().cast()
            };
            // SAFETY: `data` is null (size query) or `buf`, whose size `size` holds.
            let status = unsafe {
                GetExtendedTcpTable(
                    data,
                    &mut size,
                    0,
                    u32::from(family),
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                )
            };
            match status {
                NO_ERROR if !buf.is_empty() => return Ok(buf),
                // The size query, or the table grew since it.
                NO_ERROR | ERROR_INSUFFICIENT_BUFFER => buf = vec![0; size as usize + 1024],
                status => return Err(io::Error::from_raw_os_error(status as i32)),
            }
        }
    }

    /// The rows of type `R` of a table holding their count as its first `u32`.
    fn rows<R: Copy>(table: &[u8]) -> impl Iterator<Item = R> + '_ {
        let count = table
            .get(..4)
            .map_or(0, |c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as usize);
        // The rows follow the count, aligned to 4 like it.
        let rows = table.get(4..).unwrap_or_default();
        rows.chunks_exact(mem::size_of::<R>())
            .take(count)
            // SAFETY: each chunk holds `size_of::<R>()` bytes of a plain C row of integers.
            .map(|chunk| unsafe { ptr::read_unaligned(chunk.as_ptr().cast::<R>()) })
    }

    pub fn listener(port: u16) -> io::Result<Option<u32>> {
        // The port is in network byte order in the low 16 bits.
        let ours = |local: u32| u16::from_be(local as u16) == port;
        let v4 = listeners(AF_INET)?;
        if let Some(row) =
            rows::<MIB_TCPROW_OWNER_PID>(&v4).find(|r| ours(r.dwLocalPort) && r.dwOwningPid != 0)
        {
            return Ok(Some(row.dwOwningPid));
        }
        let v6 = listeners(AF_INET6)?;
        Ok(rows::<MIB_TCP6ROW_OWNER_PID>(&v6)
            .find(|r| ours(r.dwLocalPort) && r.dwOwningPid != 0)
            .map(|r| r.dwOwningPid))
    }

    pub fn inspect(pid: u32) -> io::Result<Process> {
        process(&open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?)
    }

    fn process(handle: &Handle) -> io::Result<Process> {
        Ok(Process {
            exe: image(handle)?,
            started: created(handle)?,
            command_line: command_line(handle).unwrap_or_default(),
        })
    }

    fn image(handle: &Handle) -> io::Result<PathBuf> {
        let mut buf = vec![0u16; 32_768];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` holds `len` UTF-16 units; on success `len` is the length written.
        if unsafe { QueryFullProcessImageNameW(handle.0, 0, buf.as_mut_ptr(), &mut len) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PathBuf::from(OsString::from_wide(&buf[..len as usize])))
    }

    fn created(handle: &Handle) -> io::Result<SystemTime> {
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        // SAFETY: the four FILETIMEs are written by the call.
        if unsafe { GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        // 100 ns intervals since 1601-01-01.
        let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;
        let since_1601 = Duration::from_nanos(ticks.saturating_mul(100));
        let epoch_offset = Duration::from_nanos(UNIX_EPOCH_TICKS * 100);
        Ok(match since_1601.checked_sub(epoch_offset) {
            Some(after) => SystemTime::UNIX_EPOCH + after,
            None => SystemTime::UNIX_EPOCH - (epoch_offset - since_1601),
        })
    }

    /// The process's command line (`NtQueryInformationProcess`, Windows 8.1 and later).
    fn command_line(handle: &Handle) -> Option<String> {
        const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
        let mut needed = 0u32;
        // SAFETY: a size query with an empty buffer.
        let status = unsafe {
            NtQueryInformationProcess(
                handle.0,
                ProcessCommandLineInformation,
                ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        if status != STATUS_INFO_LENGTH_MISMATCH || needed == 0 {
            return None;
        }
        // u64 units: the UNICODE_STRING at its start is aligned.
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        let size = u32::try_from(buf.len() * 8).ok()?;
        // SAFETY: `buf` holds `size` bytes.
        let status = unsafe {
            NtQueryInformationProcess(
                handle.0,
                ProcessCommandLineInformation,
                buf.as_mut_ptr().cast(),
                size,
                &mut needed,
            )
        };
        if status < 0 || (size as usize) < mem::size_of::<UNICODE_STRING>() {
            return None;
        }
        // SAFETY: on success the buffer starts with a UNICODE_STRING.
        let text = unsafe { ptr::read(buf.as_ptr().cast::<UNICODE_STRING>()) };
        let start = buf.as_ptr() as usize;
        let end = start + size as usize;
        let at = text.Buffer as usize;
        let len = usize::from(text.Length);
        // Its characters follow it in the same buffer.
        if text.Buffer.is_null() || at < start || at + len > end || !at.is_multiple_of(2) {
            return None;
        }
        // SAFETY: the range was checked to lie in `buf`, aligned for u16.
        let units = unsafe { std::slice::from_raw_parts(text.Buffer, len / 2) };
        Some(String::from_utf16_lossy(units))
    }

    pub fn stop(owner: &PortOwner) -> io::Result<()> {
        // The handle keeps the process's identity: checked and ended through it.
        let handle = open(
            owner.pid,
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
        )?;
        // Ended, but kept by a handle of someone else: its PID is not reused yet.
        // SAFETY: the handle is open with SYNCHRONIZE.
        if unsafe { WaitForSingleObject(handle.0, 0) } == WAIT_OBJECT_0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("process {} has ended", owner.pid),
            ));
        }
        check_target(owner, &process(&handle)?)?;
        // SAFETY: the handle is open with PROCESS_TERMINATE.
        if unsafe { TerminateProcess(handle.0, 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let wait = u32::try_from(STOP_WAIT.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: the handle is open with SYNCHRONIZE.
        if unsafe { WaitForSingleObject(handle.0, wait) } != WAIT_OBJECT_0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("process {} did not end", owner.pid),
            ));
        }
        Ok(())
    }
}

/// Signals and waiting on Unix.
#[cfg(unix)]
mod unix {
    use std::io;
    use std::time::{Duration, Instant};

    use super::{PortOwner, Process, STOP_WAIT, check_target};

    /// Sends `signal` to `pid` (`kill`).
    pub fn kill(pid: u32, signal: libc::c_int) -> io::Result<()> {
        let pid = libc::pid_t::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "no such PID"))?;
        // SAFETY: plain system call.
        if unsafe { libc::kill(pid, signal) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Whether `pid` has ended within `timeout`, polled with `alive` (which must count a
    /// zombie as ended: `kill(pid, 0)` alone does not).
    fn gone_within(
        pid: u32,
        alive: fn(u32) -> io::Result<bool>,
        timeout: Duration,
    ) -> io::Result<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            if !alive(pid)? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// `ESRCH` as "the process is gone".
    pub fn gone(pid: u32, e: io::Error) -> io::Error {
        if e.raw_os_error() == Some(libc::ESRCH) {
            io::Error::new(io::ErrorKind::NotFound, format!("no process {pid}"))
        } else {
            e
        }
    }

    /// Ends `owner` through its bare PID: `SIGTERM`, then `SIGKILL` if it is still there
    /// after [`STOP_WAIT`], each sent only after `inspect` shows the same process right
    /// before it. Once `SIGTERM` was sent, the process gone (or its PID another's) is
    /// success. A PID reused between the check and the signal is not excluded, only made
    /// unlikely: PIDs are handed out in sequence.
    pub fn stop_by_pid(
        owner: &PortOwner,
        inspect: fn(u32) -> io::Result<Process>,
        alive: fn(u32) -> io::Result<bool>,
    ) -> io::Result<()> {
        let pid = owner.pid;
        for (n, sig) in [libc::SIGTERM, libc::SIGKILL].into_iter().enumerate() {
            let asked = n > 0;
            match inspect(pid).and_then(|now| check_target(owner, &now)) {
                Ok(()) => {}
                Err(e) if asked && e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            }
            match kill(pid, sig) {
                Ok(()) => {}
                Err(e) if asked && e.raw_os_error() == Some(libc::ESRCH) => return Ok(()),
                Err(e) => return Err(gone(pid, e)),
            }
            if gone_within(pid, alive, STOP_WAIT)? {
                return Ok(());
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("process {pid} did not end"),
        ))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod sys {
    use std::fs;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::PathBuf;
    use std::time::{Duration, Instant, SystemTime};

    use super::unix::{gone, stop_by_pid};
    use super::{PortOwner, Process, STOP_WAIT, check_target};

    /// The inodes of the sockets listening on `port` in the `/proc/net/tcp` format `table`.
    fn listening_inodes(table: &str, port: u16) -> impl Iterator<Item = u64> + '_ {
        // `sl local_address rem_address st … inode`; `st` 0A is LISTEN.
        table.lines().skip(1).filter_map(move |line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let local_port = fields.get(1)?.rsplit_once(':')?.1;
            let listening = *fields.get(3)? == "0A";
            let inode: u64 = fields.get(9)?.parse().ok()?;
            (listening && u16::from_str_radix(local_port, 16).ok()? == port && inode != 0)
                .then_some(inode)
        })
    }

    pub fn listener(port: u16) -> io::Result<Option<u32>> {
        let mut sockets = Vec::new();
        for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
            match fs::read_to_string(table) {
                Ok(text) => {
                    sockets.extend(listening_inodes(&text, port).map(|i| format!("socket:[{i}]")))
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        if sockets.is_empty() {
            return Ok(None);
        }
        for entry in fs::read_dir("/proc")? {
            let Some(pid) = entry?
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            // Another user's process, or ended: not visible.
            let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                if let Ok(target) = fs::read_link(fd.path())
                    && sockets.iter().any(|s| target.as_os_str() == s.as_str())
                {
                    return Ok(Some(pid));
                }
            }
        }
        Ok(None)
    }

    fn not_found(pid: u32, e: io::Error) -> io::Error {
        if e.kind() == io::ErrorKind::NotFound {
            io::Error::new(io::ErrorKind::NotFound, format!("no process {pid}"))
        } else {
            e
        }
    }

    pub fn inspect(pid: u32) -> io::Result<Process> {
        let dir = PathBuf::from(format!("/proc/{pid}"));
        let exe = fs::read_link(dir.join("exe")).map_err(|e| not_found(pid, e))?;
        let stat = fs::read_to_string(dir.join("stat")).map_err(|e| not_found(pid, e))?;
        let command_line = fs::read(dir.join("cmdline"))
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .split('\0')
                    .filter(|a| !a.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        Ok(Process {
            exe,
            started: started(&stat)?,
            command_line,
        })
    }

    /// The start time in `/proc/<pid>/stat`: its 22nd field, in clock ticks since boot
    /// (`btime` of `/proc/stat`).
    fn started(stat: &str) -> io::Result<SystemTime> {
        let invalid = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_owned());
        // The fields after the command's name in parentheses start with the 3rd.
        let ticks: u64 = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(19))
            .and_then(|t| t.parse().ok())
            .ok_or_else(|| invalid("no start time in /proc/<pid>/stat"))?;
        let boot: u64 = fs::read_to_string("/proc/stat")?
            .lines()
            .find_map(|l| l.strip_prefix("btime ")?.trim().parse().ok())
            .ok_or_else(|| invalid("no btime in /proc/stat"))?;
        // SAFETY: plain call.
        let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
            .ok()
            .filter(|&hz| hz > 0)
            .ok_or_else(|| invalid("no clock tick rate"))?;
        let since_boot = Duration::from_secs(ticks / hz)
            + Duration::from_nanos((ticks % hz) * 1_000_000_000 / hz);
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(boot) + since_boot)
    }

    /// A pidfd of `pid` (Linux 5.3 and later), or `None` if the kernel has none.
    fn pidfd(pid: u32) -> io::Result<Option<OwnedFd>> {
        // SAFETY: plain system call; a non-negative result is a new descriptor.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::c_long::from(pid), 0) };
        if fd >= 0 {
            let fd = libc::c_int::try_from(fd).map_err(io::Error::other)?;
            // SAFETY: `fd` is a new descriptor owned by nobody else.
            return Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }));
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::ENOSYS) => Ok(None),
            _ => Err(gone(pid, e)),
        }
    }

    fn signal(fd: &OwnedFd, signal: libc::c_int) -> io::Result<()> {
        // SAFETY: plain system call on an open pidfd.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Whether the process of `fd` ends within `timeout` (the pidfd turns readable when it
    /// ends, before its parent waits for it).
    fn ended_within(fd: &OwnedFd, timeout: Duration) -> io::Result<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut poll = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let left = deadline.saturating_duration_since(Instant::now());
            let ms = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
            // SAFETY: one valid pollfd.
            match unsafe { libc::poll(&mut poll, 1, ms) } {
                -1 => {
                    let e = io::Error::last_os_error();
                    // A signal of this process: poll is not restarted by itself.
                    if e.kind() != io::ErrorKind::Interrupted {
                        return Err(e);
                    }
                }
                n => return Ok(n > 0),
            }
        }
    }

    /// Whether `pid` exists and has not ended: a zombie, which ended but waits for its
    /// parent, has ended (`kill(pid, 0)` still succeeds for it).
    pub fn alive(pid: u32) -> io::Result<bool> {
        match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => Ok(!matches!(state(&stat), Some('Z' | 'X' | 'x'))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// The state letter of `/proc/<pid>/stat`: the field after the name in parentheses.
    fn state(stat: &str) -> Option<char> {
        stat.rsplit_once(')')?.1.trim_start().chars().next()
    }

    pub fn stop(owner: &PortOwner) -> io::Result<()> {
        match pidfd(owner.pid)? {
            Some(fd) => stop_by_pidfd(owner, &fd),
            None => stop_by_pid(owner, inspect, alive),
        }
    }

    /// The pidfd `fd` of `owner.pid` keeps the process's identity: checked once after it
    /// was opened, every signal goes to that process.
    fn stop_by_pidfd(owner: &PortOwner, fd: &OwnedFd) -> io::Result<()> {
        let pid = owner.pid;
        check_target(owner, &inspect(pid)?)?;
        for (n, sig) in [libc::SIGTERM, libc::SIGKILL].into_iter().enumerate() {
            match signal(fd, sig) {
                Ok(()) => {}
                // Ended after SIGTERM.
                Err(e) if n > 0 && e.raw_os_error() == Some(libc::ESRCH) => return Ok(()),
                Err(e) => return Err(gone(pid, e)),
            }
            if ended_within(fd, STOP_WAIT)? {
                return Ok(());
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("process {pid} did not end"),
        ))
    }

    #[cfg(test)]
    #[test]
    fn proc_net_tcp_is_read() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
           0: 0100007F:3483 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 100 0 0 10 0\n\
           1: 0100007F:3483 0100007F:A000 01 00000000:00000000 00:00000000 00000000  1000        0 4243 1 0000000000000000 100 0 0 10 0\n\
           2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 17 1 0000000000000000 100 0 0 10 0\n";
        assert_eq!(listening_inodes(table, 0x3483).collect::<Vec<_>>(), [4242]);
        assert_eq!(listening_inodes(table, 22).collect::<Vec<_>>(), [17]);
        assert!(listening_inodes(table, 13579).next().is_none());
        // The name may hold `)`; the start time is the 22nd field.
        let stat = |ticks: u64| {
            format!("123 (a) b) c) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 {ticks} 20")
        };
        // SAFETY: plain call.
        let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).unwrap();
        let after = started(&stat(3 * hz)).unwrap();
        let at_boot = started(&stat(0)).unwrap();
        assert_eq!(
            after.duration_since(at_boot).unwrap(),
            Duration::from_secs(3)
        );
    }
}

#[cfg(target_os = "macos")]
mod sys {
    use std::io;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{Duration, SystemTime};

    use super::unix::{gone, kill, stop_by_pid};
    use super::{PortOwner, Process};

    pub fn listener(port: u16) -> io::Result<Option<u32>> {
        let output = Command::new("lsof")
            .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-Fp"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        // `p<pid>` lines; nothing (and exit status 1) when nobody listens.
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|l| l.strip_prefix('p')?.parse().ok()))
    }

    pub fn inspect(pid: u32) -> io::Result<Process> {
        let c_pid = libc::c_int::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "no such PID"))?;
        let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: `path` holds the given number of bytes.
        let len = unsafe { libc::proc_pidpath(c_pid, path.as_mut_ptr().cast(), path.len() as u32) };
        if len <= 0 {
            return Err(gone(pid, io::Error::last_os_error()));
        }
        path.truncate(len as usize);
        let exe = PathBuf::from(String::from_utf8_lossy(&path).into_owned());
        // SAFETY: an all-zero proc_bsdinfo is valid; the call fills it.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: `info` holds `size` bytes.
        let got = unsafe {
            libc::proc_pidinfo(
                c_pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&raw mut info).cast(),
                size,
            )
        };
        if got != size {
            return Err(gone(pid, io::Error::last_os_error()));
        }
        let started = SystemTime::UNIX_EPOCH
            + Duration::from_secs(info.pbi_start_tvsec)
            + Duration::from_micros(info.pbi_start_tvusec);
        let command_line = Command::new("ps")
            .args(["-o", "args=", "-p", &pid.to_string()])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default();
        Ok(Process {
            exe,
            started,
            command_line,
        })
    }

    /// Whether `pid` exists and is not a zombie: XNU's `kill(pid, 0)` succeeds for a zombie
    /// (POSIX), which ended already but waits for its parent.
    pub fn alive(pid: u32) -> io::Result<bool> {
        let Ok(c_pid) = libc::c_int::try_from(pid) else {
            return Ok(false);
        };
        // SAFETY: an all-zero proc_bsdinfo is valid; the call fills it.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: `info` holds `size` bytes.
        let got = unsafe {
            libc::proc_pidinfo(
                c_pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&raw mut info).cast(),
                size,
            )
        };
        if got == size {
            return Ok(info.pbi_status != libc::SZOMB);
        }
        // No information: gone or a zombie (`ESRCH`), or not ours to read (`kill` tells).
        if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return Ok(false);
        }
        match kill(pid, 0) {
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(false),
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => Ok(true),
            Err(e) => Err(e),
            Ok(()) => Ok(true),
        }
    }

    pub fn stop(owner: &PortOwner) -> io::Result<()> {
        stop_by_pid(owner, inspect, alive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::process::{Child, Command, Stdio};

    const CHILD: &str = "ONCL_TEST_PORT_LISTENER";

    /// Run by [`Listener::spawn`] in a process of its own: listens on a free port of
    /// 127.0.0.1, prints it and waits until its standard input closes. Does nothing
    /// otherwise.
    #[test]
    fn listener_process() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        println!("PORT={}", listener.local_addr().unwrap().port());
        let _ = std::io::stdin().read_to_end(&mut Vec::new());
    }

    /// This test program run again as [`listener_process`], killed when dropped if it is
    /// still running (only that child).
    struct Listener {
        child: Child,
        port: u16,
        /// The copy of the test program it runs, if any; removed after the child ends.
        _copy: Option<tempfile::TempDir>,
    }

    impl Listener {
        /// The test program itself.
        fn spawn() -> Listener {
            Listener::run(std::env::current_exe().unwrap(), None)
        }

        /// A copy of the test program named like the original NCALayer's program on this
        /// system, in a directory under `target/`.
        fn spawn_as_original() -> Listener {
            let exe = std::env::current_exe().unwrap();
            let dir = tempfile::Builder::new()
                .prefix("oncl-port-owner-")
                .tempdir_in(exe.parent().unwrap())
                .unwrap();
            let name = if cfg!(windows) {
                "NCALayer.exe"
            } else {
                "ncalayer.sh"
            };
            let copy = dir.path().join(name);
            std::fs::copy(&exe, &copy).unwrap();
            Listener::run(copy, Some(dir))
        }

        fn run(program: PathBuf, copy: Option<tempfile::TempDir>) -> Listener {
            let mut child = Command::new(program)
                .args([
                    "--exact",
                    "port_owner::tests::listener_process",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let stdout = BufReader::new(child.stdout.take().unwrap());
            let port = stdout
                .lines()
                .map_while(Result::ok)
                // After libtest's `test … ... ` on the same line.
                .find_map(|l| {
                    l.split_once("PORT=")
                        .and_then(|(_, p)| p.trim().parse().ok())
                })
                .expect("the listener tells its port");
            Listener {
                child,
                port,
                _copy: copy,
            }
        }

        /// Whether the child still runs (reaps it if it ended).
        fn running(&mut self) -> bool {
            self.child.try_wait().unwrap().is_none()
        }

        /// Its owner on the port, checked to be the child.
        fn owner(&self) -> PortOwner {
            let owner = port_owner(self.port).unwrap().expect("the child listens");
            assert_eq!(owner.pid, self.child.id());
            owner
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn same_file(a: &Path, b: &Path) -> bool {
        std::fs::canonicalize(a).unwrap() == std::fs::canonicalize(b).unwrap()
    }

    /// The child is not waited for until `stop` returns: it stays a zombie meanwhile on
    /// Unix, which `stop` must count as ended.
    #[test]
    fn owner_of_a_listening_child_and_stopping_only_it() {
        let mut listener = Listener::spawn_as_original();
        let owner = listener.owner();
        let copy = listener._copy.as_ref().unwrap().path();
        assert_eq!(
            std::fs::canonicalize(owner.exe.parent().unwrap()).unwrap(),
            std::fs::canonicalize(copy).unwrap(),
            "{owner:?}"
        );
        assert!(owner.looks_original, "{owner:?}");
        let age = SystemTime::now().duration_since(owner.started).unwrap();
        assert!(age < Duration::from_secs(120), "{age:?}");

        // The PID reused by another process: another start time or program.
        let later = PortOwner {
            started: owner.started + Duration::from_secs(1),
            ..owner.clone()
        };
        let other = PortOwner {
            exe: owner.exe.with_file_name("other.exe"),
            ..owner.clone()
        };
        for changed in [later, other] {
            assert_eq!(stop(&changed).unwrap_err().kind(), io::ErrorKind::NotFound);
            assert!(listener.running(), "a changed process is not ended");
        }

        let asked = std::time::Instant::now();
        stop(&owner).unwrap();
        // Ended by SIGTERM, not after waiting for the SIGKILL.
        assert!(asked.elapsed() < STOP_WAIT, "{:?}", asked.elapsed());
        let status = listener.child.wait().unwrap();
        assert!(!status.success());
        assert_eq!(port_owner(listener.port).unwrap(), None);
        // Gone now: nothing to end.
        assert_eq!(stop(&owner).unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn what_does_not_look_original_is_never_stopped() {
        let mut listener = Listener::spawn();
        let owner = listener.owner();
        assert!(
            same_file(&owner.exe, &std::env::current_exe().unwrap()),
            "{owner:?}"
        );
        assert!(!owner.looks_original);
        // Even when the caller says it does.
        let claimed = PortOwner {
            looks_original: true,
            ..owner
        };
        assert_eq!(
            stop(&claimed).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(listener.running());
    }

    /// Linux without a pidfd (before 5.3): the identity is checked before each signal.
    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn stopping_by_bare_pid() {
        let mut listener = Listener::spawn_as_original();
        let owner = listener.owner();
        let later = PortOwner {
            started: owner.started + Duration::from_secs(1),
            ..owner.clone()
        };
        let by_pid = |o: &PortOwner| unix::stop_by_pid(o, sys::inspect, sys::alive);
        assert_eq!(by_pid(&later).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(listener.running());
        let asked = std::time::Instant::now();
        by_pid(&owner).unwrap();
        assert!(asked.elapsed() < STOP_WAIT, "{:?}", asked.elapsed());
        assert!(!listener.child.wait().unwrap().success());
    }

    /// A child that ended but is not waited for yet: `kill(pid, 0)` succeeds, yet it has
    /// ended.
    #[cfg(unix)]
    #[test]
    fn zombie_has_ended() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let pid = child.id();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while sys::alive(pid).unwrap() {
            assert!(std::time::Instant::now() < deadline, "the child never ends");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            unix::kill(pid, 0).is_ok(),
            "a zombie until it is waited for"
        );
        assert!(child.wait().unwrap().success());
        assert!(!sys::alive(pid).unwrap());
    }

    #[test]
    fn own_process_is_found_but_never_stopped() {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let owner = port_owner(socket.local_addr().unwrap().port())
            .unwrap()
            .expect("this process listens");
        assert_eq!(owner.pid, std::process::id());
        assert_eq!(
            stop(&owner).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn free_port_has_no_owner() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert_eq!(port_owner(port).unwrap(), None);
    }

    #[test]
    fn what_looks_like_the_original() {
        let original = [
            (r"C:\Program Files\NCALayer\NCALayer.exe", ""),
            ("/home/u/NCALayer/ncalayer.sh", ""),
            (
                r"C:\Program Files\NCALayer\jre\bin\javaw.exe",
                r#""C:\Program Files\NCALayer\jre\bin\javaw.exe" -Dfile.encoding=UTF-8 -jar "C:\Program Files\NCALayer\NCALayer.exe""#,
            ),
            (
                "/home/u/NCALayer/jre8_ncalayer/bin/java",
                "jre8_ncalayer/bin/java -jar ncalayer.sh",
            ),
            ("/usr/bin/java", "java -jar /opt/x/ncalayer.sh"),
        ];
        for (exe, args) in original {
            assert!(looks_original(Path::new(exe), args), "{exe}");
        }
        let others = [
            ("/usr/bin/java", "java -jar /opt/other/app.jar"),
            ("/usr/bin/java", "java -jar /opt/openncalayer/x.jar"),
            (r"C:\OpenNCALayer\openncalayer.exe", "openncalayer run"),
            ("/usr/bin/python3", "python3 ncalayer.py"),
        ];
        for (exe, args) in others {
            assert!(!looks_original(Path::new(exe), args), "{exe}");
        }
    }
}
