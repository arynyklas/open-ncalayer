//! Named pipe transport. Uses only kernel32/advapi32 functions present on Windows 7 SP1.

use std::ffi::c_void;
use std::fmt;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::pin::Pin;
use std::ptr;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
};
use tokio::time::Instant;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, FALSE, HANDLE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::endpoint::hex16;

/// How long [`connect`] retries while every pipe instance is busy: the server creates the
/// next instance right after each connection, so the window is short.
const BUSY_TIMEOUT: Duration = Duration::from_secs(2);
const BUSY_RETRY: Duration = Duration::from_millis(20);

/// The pipe name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Address {
    name: String,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// The address of the current user and session for the absolute `data_dir`.
pub(crate) fn endpoint(data_dir: &Path) -> io::Result<Address> {
    Ok(address(data_dir, &current_user_sid()?, current_session()?))
}

/// The address for `data_dir`, the user `sid` and the `session`, without asking the OS.
fn address(data_dir: &Path, sid: &str, session: u32) -> Address {
    Address {
        name: format!(
            r"\\.\pipe\OpenNCALayer-{}",
            hex16(&format!("{sid}|{session}|"), data_dir)
        ),
    }
}

/// The current pipe instance waiting for a client, and what it takes to create the next.
#[derive(Debug)]
pub(crate) struct Listener {
    name: String,
    /// `D:P(A;;GA;;;<SID>)(A;;GA;;;SY)` as NUL-terminated UTF-16.
    sddl: Vec<u16>,
    next: NamedPipeServer,
}

pub(crate) async fn bind(addr: &Address) -> io::Result<Listener> {
    let sid = current_user_sid()?;
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid})(A;;GA;;;SY)")
        .encode_utf16()
        .chain([0])
        .collect();
    let next = create_instance(&addr.name, &sddl, true).map_err(|e| {
        if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("pipe {} already exists", addr.name),
            )
        } else {
            e
        }
    })?;
    Ok(Listener {
        name: addr.name.clone(),
        sddl,
        next,
    })
}

impl Listener {
    pub(crate) async fn accept(&mut self) -> io::Result<Stream> {
        if let Err(e) = self.next.connect().await {
            // The instance may be unusable now: wait on a fresh one next time.
            self.next = create_instance(&self.name, &self.sddl, false)?;
            return Err(e);
        }
        let next = create_instance(&self.name, &self.sddl, false)?;
        Ok(Stream::Server(std::mem::replace(&mut self.next, next)))
    }
}

/// Creates a byte-mode pipe instance protected by the SDDL `sddl`, local clients only.
fn create_instance(name: &str, sddl: &[u16], first: bool) -> io::Result<NamedPipeServer> {
    let mut descriptor = ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated; on success `descriptor` receives a LocalAlloc'ed
    // security descriptor, freed by the guard.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if ok == FALSE {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalBox(descriptor);
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).expect("small struct"),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: FALSE,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .pipe_mode(PipeMode::Byte);
    // SAFETY: `attributes` and the descriptor it points to outlive the call, which only
    // reads them.
    unsafe {
        options.create_with_security_attributes_raw(name, (&raw mut attributes).cast::<c_void>())
    }
}

pub(crate) async fn connect(addr: &Address) -> io::Result<Stream> {
    let deadline = Instant::now() + BUSY_TIMEOUT;
    let client = loop {
        match ClientOptions::new().open(&addr.name) {
            Ok(client) => break client,
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && Instant::now() < deadline =>
            {
                tokio::time::sleep(BUSY_RETRY).await;
            }
            Err(e) => return Err(e),
        }
    };
    check_server(&client, &addr.name)?;
    Ok(Stream::Client(client))
}

/// Fails with `PermissionDenied` unless the process serving `client` runs as the current
/// user.
fn check_server(client: &NamedPipeClient, name: &str) -> io::Result<()> {
    let untrusted = |reason: String| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("pipe {name}: {reason}"),
        )
    };
    let mut pid = 0;
    // SAFETY: the handle is a live pipe client handle; `pid` is a valid out pointer.
    if unsafe { GetNamedPipeServerProcessId(client.as_raw_handle(), &mut pid) } == FALSE {
        return Err(untrusted(format!(
            "cannot get the server process: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY: plain call; a null result is checked below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
    if process.is_null() {
        return Err(untrusted(format!(
            "cannot open server process {pid}: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY: `process` is a fresh handle owned by nobody else.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let server_sid = process_user_sid(process.as_raw_handle())
        .map_err(|e| untrusted(format!("cannot read the user of process {pid}: {e}")))?;
    let sid = current_user_sid()?;
    if server_sid != sid {
        return Err(untrusted(format!(
            "served by {server_sid} (process {pid}), not by {sid}"
        )));
    }
    Ok(())
}

fn current_user_sid() -> io::Result<String> {
    // SAFETY: the pseudo handle of the current process needs no closing.
    process_user_sid(unsafe { GetCurrentProcess() })
}

fn current_session() -> io::Result<u32> {
    let mut session = 0;
    // SAFETY: `session` is a valid out pointer.
    if unsafe { ProcessIdToSessionId(std::process::id(), &mut session) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    Ok(session)
}

/// The string SID (`S-1-5-…`) of the user `process` runs as.
fn process_user_sid(process: HANDLE) -> io::Result<String> {
    let mut token = ptr::null_mut();
    // SAFETY: `process` is a process handle with query access; `token` is a valid out pointer.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `token` is a fresh handle owned by nobody else.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };

    let mut len = 0;
    // SAFETY: a size query: no buffer, `len` receives the required size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut len,
        )
    };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    // `u64` elements keep the buffer aligned for `TOKEN_USER`.
    let mut buffer = vec![0u64; usize::try_from(len).expect("u32 fits usize").div_ceil(8)];
    // SAFETY: `buffer` holds at least `len` writable bytes.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    };
    if ok == FALSE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points into it.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_string(user.User.Sid)
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut wide = ptr::null_mut();
    // SAFETY: `sid` is a valid SID; on success `wide` receives a LocalAlloc'ed string.
    if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    let wide = LocalBox(wide.cast());
    // SAFETY: the string is NUL-terminated and stays alive while `wide` is.
    let units = unsafe {
        let start = wide.0.cast::<u16>();
        let len = (0..).take_while(|&i| *start.add(i) != 0).count();
        std::slice::from_raw_parts(start, len)
    };
    String::from_utf16(units).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Memory allocated by the system with `LocalAlloc`, freed on drop.
struct LocalBox(*mut c_void);

impl Drop for LocalBox {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a system call that allocates with LocalAlloc.
        unsafe { LocalFree(self.0) };
    }
}

/// A connection: the server or the client end of a pipe.
#[derive(Debug)]
pub(crate) enum Stream {
    Server(NamedPipeServer),
    Client(NamedPipeClient),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Server(pipe) => Pin::new(pipe).poll_read(cx, buf),
            Stream::Client(pipe) => Pin::new(pipe).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Server(pipe) => Pin::new(pipe).poll_write(cx, buf),
            Stream::Client(pipe) => Pin::new(pipe).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Server(pipe) => Pin::new(pipe).poll_flush(cx),
            Stream::Client(pipe) => Pin::new(pipe).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Server(pipe) => Pin::new(pipe).poll_shutdown(cx),
            Stream::Client(pipe) => Pin::new(pipe).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_hashes_sid_session_and_dir() {
        let addr = address(Path::new(r"C:\Data\OpenNCALayer"), "S-1-5-21-1-2-3-1001", 1);
        // python: hashlib.sha256(b"S-1-5-21-1-2-3-1001|1|C:\\Data\\OpenNCALayer").hexdigest()[:16]
        assert_eq!(addr.name, r"\\.\pipe\OpenNCALayer-356959c9f04071d3");
        assert_ne!(
            address(Path::new(r"C:\Data\OpenNCALayer"), "S-1-5-21-1-2-3-1001", 2),
            addr
        );
        assert_ne!(
            address(Path::new(r"C:\Data\OpenNCALayer"), "S-1-5-21-1-2-3-1002", 1),
            addr
        );
    }

    #[test]
    fn current_user_has_a_sid() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-"), "{sid}");
        current_session().unwrap();
    }
}
