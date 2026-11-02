//! Borrowed streaming sources and explicitly published document artifacts.
//!
//! Temporary storage is for documents, never passwords or private keys. Each
//! store creates an unpredictable, owner-only child of the supplied parent.
//! Cleanup unlinks only its own files and removes an empty owned directory; it
//! never recursively traverses a parent, directory link, or reparse target.
//!
//! On Unix the supplied parent must be owned by this user or root, with no
//! group/other write access unless the sticky bit protects child names. Child
//! operations use pinned directory descriptors; final empty-root removal also
//! checks device/inode identity under that parent-security invariant. Same-user
//! or privileged mutations are outside the security boundary: a renamed own
//! root may remain, but an observed foreign replacement is never removed or
//! searched recursively. Windows retains its protective DELETE-capable root
//! handle through handle-bound disposition and close, never path-deleting after
//! releasing that protection. Failed setup/OS cleanup can leave own empty
//! directories rather than risk deleting an unidentified object.
use crate::resource::{IO_CHUNK_BYTES, ProcessingError, ResourceReservation, ResourceScope};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
#[path = "io/byte_string.rs"]
mod byte_string;
pub use byte_string::{decode_pdf_byte_string, padded_der_sequence};
#[path = "io/frozen.rs"]
mod frozen;
pub use frozen::{DerivedInput, FrozenInput, FrozenReader, SnapshotEncoding};

pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek + ?Sized> ReadSeek for T {}

enum Reader<'a> {
    Sequential(&'a mut dyn Read),
    Seekable(&'a mut dyn ReadSeek),
}
/// A source starts at the reader's current position; length is an optional
/// admission hint, never a substitute for counting bytes actually consumed.
pub struct Source<'a> {
    reader: Reader<'a>,
    len: Option<u64>,
    admitted: Option<ResourceScope>,
}
impl<'a> Source<'a> {
    pub fn sequential(reader: &'a mut dyn Read, len: Option<u64>) -> Self {
        Self {
            reader: Reader::Sequential(reader),
            len,
            admitted: None,
        }
    }
    pub fn seekable(reader: &'a mut dyn ReadSeek, len: Option<u64>) -> Self {
        Self {
            reader: Reader::Seekable(reader),
            len,
            admitted: None,
        }
    }
    pub fn known_len(&self) -> Option<u64> {
        self.len
    }
    /// True only for an immutable captured source view from this exact operation.
    pub fn is_snapshot_for(&self, scope: &ResourceScope) -> Result<bool, ProcessingError> {
        match &self.admitted {
            Some(original) if !original.same_operation(scope) => Err(
                ProcessingError::InvalidInput("snapshot belongs to another operation"),
            ),
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }
    pub fn as_seekable(&mut self) -> Option<&mut dyn ReadSeek> {
        match &mut self.reader {
            Reader::Sequential(_) => None,
            Reader::Seekable(reader) => Some(&mut **reader),
        }
    }
}
impl Read for Source<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match &mut self.reader {
            Reader::Sequential(reader) => reader.read(buffer),
            Reader::Seekable(reader) => reader.read(buffer),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub offset: u64,
    pub len: u64,
}
impl Region {
    pub fn end(self) -> Result<u64, ProcessingError> {
        self.offset
            .checked_add(self.len)
            .ok_or(ProcessingError::InvalidInput("region overflows u64"))
    }
}

/// An owner-only private namespace. Artifacts retain the store even if its
/// caller drops this handle, and retain their original operation's budget.
#[derive(Clone)]
pub struct TemporaryStore {
    root: Arc<platform::Root>,
}
impl std::fmt::Debug for TemporaryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TemporaryStore { host-configured }")
    }
}
impl TemporaryStore {
    pub fn new(parent: &Path) -> Result<Self, ProcessingError> {
        Ok(Self {
            root: Arc::new(platform::Root::new(parent)?),
        })
    }
    pub fn stage(&self, scope: &mut ResourceScope) -> Result<StagedArtifact, ProcessingError> {
        self.stage_role(scope, false)
    }
    /// Internal document snapshot. Replay is uncharged internal I/O; this artifact
    /// cannot be published or copied to an external writer, even when empty.
    pub fn stage_source(
        &self,
        scope: &mut ResourceScope,
    ) -> Result<StagedArtifact, ProcessingError> {
        self.stage_role(scope, true)
    }
    fn stage_role(
        &self,
        scope: &mut ResourceScope,
        source: bool,
    ) -> Result<StagedArtifact, ProcessingError> {
        scope.checkpoint()?;
        let metadata =
            scope.reserve_metadata(std::mem::size_of::<StagedArtifact>() as u64 + 512)?;
        let temp = scope.reserve_temp(0)?;
        let name = random_name()?;
        scope.checkpoint()?;
        let file = self.root.create_file(&name)?;
        Ok(StagedArtifact {
            root: self.root.clone(),
            name,
            file: Some(file),
            scope: scope.retain(),
            temp,
            _metadata: metadata,
            failed: false,
            source,
        })
    }
}

/// Unpublished output. Drop deletes scratch; it never commits. Writes reserve
/// temporary disk and cumulative output capacity before touching the file.
/// `commit` is a no-clobber hard-link publication on the same filesystem;
/// unsupported/cross-filesystem links fail without creating a partial destination.
/// The published file retains private permissions. Destination ownership transfers
/// to the caller on success and its persistent disk is no longer SDK scratch.
pub struct StagedArtifact {
    root: Arc<platform::Root>,
    name: String,
    file: Option<File>,
    scope: ResourceScope,
    temp: ResourceReservation,
    _metadata: ResourceReservation,
    failed: bool,
    source: bool,
}
impl StagedArtifact {
    pub(crate) fn check_sign_output(&self, scope: &ResourceScope) -> Result<(), ProcessingError> {
        scope.checkpoint()?;
        if !self.scope.same_operation(scope) || self.source || self.failed || !self.is_empty() {
            return Err(ProcessingError::InvalidInput(
                "sign output requires an empty live output artifact from this operation",
            ));
        }
        Ok(())
    }
    pub(crate) fn fail_sign_output(&mut self) {
        self.failed = true;
    }
    pub fn len(&self) -> u64 {
        self.temp.bytes()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn lease(&self) -> crate::resource::OperationLease {
        self.scope.lease()
    }
    /// Replay at most one bounded chunk without exposing the spool file or
    /// changing its append position. Internal replay is not new document I/O.
    pub fn read_region(
        &mut self,
        region: Region,
        output: &mut [u8],
    ) -> Result<usize, ProcessingError> {
        self.scope.checkpoint()?;
        if self.failed {
            return Err(ProcessingError::InvalidInput(
                "artifact has an incomplete write",
            ));
        }
        if region.end()? > self.len() {
            return Err(ProcessingError::InvalidInput("region exceeds artifact"));
        }
        let count = region
            .len
            .min(output.len() as u64)
            .min(IO_CHUNK_BYTES as u64) as usize;
        if count == 0 {
            self.scope.checkpoint()?;
            return Ok(0);
        }
        let file = self
            .file
            .as_mut()
            .ok_or(ProcessingError::InvalidInput("artifact closed"))?;
        let position = file.stream_position()?;
        let result = (|| {
            self.scope.checkpoint()?;
            file.seek(SeekFrom::Start(region.offset))?;
            let mut read = 0;
            while read < count {
                self.scope.checkpoint()?;
                let n = match file.read(&mut output[read..count]) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                self.scope.checkpoint()?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short staged region",
                    )
                    .into());
                }
                read += n;
            }
            self.scope.checkpoint()?;
            Ok(read)
        })();
        // Restore even when the operation was interrupted. If restoration is
        // ambiguous, neither future append nor publication is safe.
        if let Err(error) = file.seek(SeekFrom::Start(position)) {
            self.failed = true;
            return Err(error.into());
        }
        if result.is_ok() {
            self.scope.checkpoint()?;
        }
        result
    }
    pub fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), ProcessingError> {
        self.scope.checkpoint()?;
        if self.failed {
            return Err(ProcessingError::InvalidInput(
                "artifact has an incomplete write",
            ));
        }
        let count = u64::try_from(bytes.len()).map_err(|_| ProcessingError::TempLimit)?;
        self.temp.grow(count)?;
        if !self.source
            && let Err(error) = self.scope.account_output(count)
        {
            self.temp.shrink(count)?;
            return Err(error);
        }
        // Keep the full reservation on I/O failure: a partial file still occupies
        // scratch. Never let that incomplete file be committed subsequently.
        let result = write_controlled(
            self.file
                .as_mut()
                .ok_or(ProcessingError::InvalidInput("artifact closed"))?,
            bytes,
            &self.scope,
        );
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn commit(self, destination: &Path) -> Result<(), ProcessingError> {
        self.scope.checkpoint()?;
        if self.source {
            return Err(ProcessingError::InvalidInput(
                "source snapshot cannot be published",
            ));
        }
        if self.failed {
            return Err(ProcessingError::InvalidInput(
                "artifact has an incomplete write",
            ));
        }
        self.file
            .as_ref()
            .ok_or(ProcessingError::InvalidInput("artifact closed"))?
            .sync_all()?;
        self.scope.checkpoint()?;
        // No fallible SDK work follows publication: reporting failure after this
        // point would misrepresent an already visible, complete destination.
        self.root.publish(&self.name, destination)?;
        Ok(())
    }
    /// Explicit streaming delivery. The caller's writer can receive a partial
    /// result on I/O/cancel/deadline failure; use `commit` for atomic publication.
    /// Output was already charged when staged, and is not double-counted here.
    pub fn copy_to(mut self, output: &mut dyn Write) -> Result<u64, ProcessingError> {
        self.scope.checkpoint()?;
        if self.source {
            return Err(ProcessingError::InvalidInput(
                "source snapshot cannot be delivered",
            ));
        }
        if self.failed {
            return Err(ProcessingError::InvalidInput(
                "artifact has an incomplete write",
            ));
        }
        let capacity = self.scope.available_memory().min(IO_CHUNK_BYTES as u64) as usize;
        if capacity == 0 {
            return Err(ProcessingError::MemoryLimit);
        }
        let _memory = self.scope.reserve_memory(capacity as u64)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(capacity)
            .map_err(|_| ProcessingError::MemoryLimit)?;
        buffer.resize(capacity, 0);
        let file = self
            .file
            .as_mut()
            .ok_or(ProcessingError::InvalidInput("artifact closed"))?;
        self.scope.checkpoint()?;
        file.seek(SeekFrom::Start(0))?;
        let mut copied = 0u64;
        loop {
            self.scope.checkpoint()?;
            let n = match file.read(&mut buffer) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            self.scope.checkpoint()?;
            if n == 0 {
                break;
            }
            write_controlled(output, &buffer[..n], &self.scope)?;
            copied = copied
                .checked_add(n as u64)
                .ok_or(ProcessingError::OutputLimit)?;
        }
        self.scope.checkpoint()?;
        output.flush()?;
        self.scope.checkpoint()?;
        Ok(copied)
    }
}
impl Drop for StagedArtifact {
    fn drop(&mut self) {
        // Close before unlink on Windows. Reservations are released only after
        // cleanup has run, not when the original context/connection disappears.
        drop(self.file.take());
        self.root.remove_file(&self.name);
    }
}

fn write_controlled(
    output: &mut dyn Write,
    mut bytes: &[u8],
    scope: &ResourceScope,
) -> Result<(), ProcessingError> {
    while !bytes.is_empty() {
        scope.checkpoint()?;
        let request = bytes.len().min(IO_CHUNK_BYTES);
        let n = match output.write(&bytes[..request]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        scope.checkpoint()?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "artifact write made no progress",
            )
            .into());
        }
        if n > request {
            return Err(ProcessingError::InvalidInput(
                "writer exceeded its supplied buffer",
            ));
        }
        bytes = &bytes[n..];
    }
    Ok(())
}

fn random_name() -> io::Result<String> {
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    use std::fmt::Write as _;
    let mut name = String::with_capacity(37);
    name.push_str("oncl-");
    for byte in random {
        let _ = write!(name, "{byte:02x}");
    }
    Ok(name)
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    pub(super) struct Root {
        parent: File,
        directory: File,
        name: CString,
    }
    fn cpath(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
    }
    impl Root {
        pub(super) fn new(parent: &Path) -> io::Result<Self> {
            let parent = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(parent)?;
            let parent_metadata = parent.metadata()?;
            // Sticky directories (e.g. root-owned /tmp) protect our entries from
            // other writers. A writable non-sticky parent does not, even when we
            // own it. Only this user or root may control the parent itself.
            // SAFETY: geteuid is a parameterless identity query.
            let uid = unsafe { libc::geteuid() };
            if (parent_metadata.uid() != uid && parent_metadata.uid() != 0)
                || (parent_metadata.mode() & 0o022 != 0 && parent_metadata.mode() & 0o1000 == 0)
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "temporary parent permits foreign name replacement",
                ));
            }
            let name = CString::new(random_name()?).map_err(io::Error::other)?;
            // SAFETY: parent is an open directory and name is a single NUL-terminated
            // component. mkdirat creates a new directory, never follows an existing link.
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: same pinned parent; O_NOFOLLOW refuses a replaced final link.
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = io::Error::last_os_error();
                // No pinned child identity exists to authorize cleanup. Leave a
                // possible own empty child rather than unlink an unknown entry.
                return Err(error);
            }
            // SAFETY: successful openat returns one newly owned descriptor.
            let directory = unsafe { File::from_raw_fd(fd) };
            let metadata = directory.metadata()?;
            // An untrusted writable parent can rename a new child before it is
            // opened. Refuse a substituted directory owned by another identity
            // or exposing group/other access. Descriptor-relative I/O then stays
            // in this pinned namespace even if the parent is renamed later.
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "temporary root is not owner-only",
                ));
            }
            Ok(Self {
                parent,
                directory,
                name,
            })
        }
        pub(super) fn create_file(&self, name: &str) -> io::Result<File> {
            let name = CString::new(name).map_err(io::Error::other)?;
            // SAFETY: directory is pinned, name is generated internally, and the
            // exclusive create does not open any existing file or final symlink.
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful openat returns one newly owned descriptor.
            Ok(unsafe { File::from_raw_fd(fd) })
        }
        pub(super) fn remove_file(&self, name: &str) {
            if let Ok(name) = CString::new(name) {
                // SAFETY: unlinkat removes only this exact component relative to
                // the pinned directory; even a substituted symlink is not followed.
                unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
            }
        }
        pub(super) fn publish(&self, name: &str, destination: &Path) -> io::Result<()> {
            let name = CString::new(name).map_err(io::Error::other)?;
            let destination = cpath(destination)?;
            // SAFETY: source is relative to our pinned private directory. linkat
            // without AT_SYMLINK_FOLLOW does not dereference a final source link;
            // the kernel creates the destination exclusively, including dangling links.
            if unsafe {
                libc::linkat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::AT_FDCWD,
                    destination.as_ptr(),
                    0,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let mut identity = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: live pinned directory descriptor and writable stat output.
            if unsafe { libc::fstat(self.directory.as_raw_fd(), identity.as_mut_ptr()) } != 0 {
                return;
            }
            // SAFETY: successful fstat initialized the complete identity.
            let identity = unsafe { identity.assume_init() };
            let mut entry = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: pinned parent, single name, writable stat output; no final
            // link is followed. The parent invariant excludes another identity
            // racing a rename between this check and removal.
            if unsafe {
                libc::fstatat(
                    self.parent.as_raw_fd(),
                    self.name.as_ptr(),
                    entry.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return;
            }
            // SAFETY: successful fstatat initialized the complete stat value.
            let entry = unsafe { entry.assume_init() };
            if identity.st_dev != entry.st_dev || identity.st_ino != entry.st_ino {
                return;
            }
            // Same-user mutations are outside the trust boundary, but an already
            // replaced name is still never removed. Do not search for a moved root.
            // SAFETY: same pinned parent and identity-checked directory name;
            // AT_REMOVEDIR only removes an empty directory, never recursively.
            unsafe {
                libc::unlinkat(
                    self.parent.as_raw_fd(),
                    self.name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            };
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::PathBuf;
    use std::ptr;
    use windows_sys::Win32::Foundation::{FALSE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid,
        GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorOwner, GetTokenInformation,
        OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, DELETE, FILE_ALL_ACCESS, FILE_DISPOSITION_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FileDispositionInfo, SetFileInformationByHandle,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub(super) struct Root {
        path: PathBuf,
        directory: File,
    }
    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }
    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut result: Vec<u16> = path.as_os_str().encode_wide().collect();
        if result.contains(&0) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"));
        }
        result.push(0);
        Ok(result)
    }
    fn owner_descriptor() -> io::Result<Local> {
        let mut token = ptr::null_mut();
        // SAFETY: current process pseudo-handle is valid and token is an out pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: OpenProcessToken returned one owned token handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut length = 0;
        // SAFETY: initial size query uses a null buffer of zero length.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut length,
            )
        };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u64; (length as usize).div_ceil(8)];
        // SAFETY: u64 storage is aligned and holds at least length bytes.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        } == FALSE
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful TokenUser query starts with TOKEN_USER.
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut sid = ptr::null_mut();
        // SAFETY: SID points into the live token information buffer.
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        let sid = Local(sid.cast());
        let start = sid.0.cast::<u16>();
        // SAFETY: ConvertSidToStringSidW returns a NUL-terminated UTF-16 string.
        let sid = unsafe {
            let length = (0..).take_while(|&i| *start.add(i) != 0).count();
            String::from_utf16(std::slice::from_raw_parts(start, length))
                .map_err(io::Error::other)?
        };
        // Protected DACL: only the actual current user; inherited by both files
        // and subdirectories. No inherited ACEs from a permissive supplied parent.
        let sddl: Vec<u16> = format!("O:{sid}D:P(A;OICI;FA;;;{sid})")
            .encode_utf16()
            .chain([0])
            .collect();
        let mut descriptor = ptr::null_mut();
        // SAFETY: SDDL is terminated and descriptor is a writable out pointer.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == FALSE
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Local(descriptor))
    }
    fn verify_private_directory(directory: &File, expected: &Local) -> io::Result<()> {
        let denied = || {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "filesystem did not preserve owner-only temporary ACL",
            )
        };
        let mut descriptor = ptr::null_mut();
        let mut owner = ptr::null_mut();
        let mut acl = ptr::null_mut();
        // SAFETY: live file handle and writable outputs; returned owner/ACL
        // pointers are owned by the returned LocalAlloc security descriptor.
        let status = unsafe {
            GetSecurityInfo(
                directory.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let descriptor = Local(descriptor);
        if descriptor.0.is_null() || owner.is_null() || acl.is_null() {
            return Err(denied());
        }
        let mut expected_owner = ptr::null_mut();
        let mut defaulted = FALSE;
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: both descriptors were produced by successful Windows APIs.
        if unsafe { GetSecurityDescriptorOwner(expected.0, &mut expected_owner, &mut defaulted) }
            == FALSE
            || unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) }
                == FALSE
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful descriptor query returned valid SID/ACL storage.
        if expected_owner.is_null()
            || control & SE_DACL_PROTECTED == 0
            || unsafe { EqualSid(owner, expected_owner) } == FALSE
            || unsafe { (*acl).AceCount } != 1
        {
            return Err(denied());
        }
        let mut ace = ptr::null_mut();
        // SAFETY: the OS-owned ACL has exactly one ACE and ace is an out pointer.
        if unsafe { GetAce(acl, 0, &mut ace) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        if ace.is_null() {
            return Err(denied());
        }
        // SAFETY: GetAce returns a valid ACE beginning with ACE_HEADER.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        // ACCESS_ALLOWED_ACE_TYPE is 0. Only this one inheritable allow entry is
        // accepted; null/permissive/synthetic ACLs (e.g. FAT) fail closed.
        if header.AceType != 0
            || u32::from(header.AceFlags) != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
        {
            return Err(denied());
        }
        // SAFETY: a type-0 ACE has the ACCESS_ALLOWED_ACE layout and trailing SID.
        let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = ptr::addr_of!(ace.SidStart).cast_mut().cast();
        // SAFETY: both SIDs remain inside the live OS descriptors.
        if ace.Mask != FILE_ALL_ACCESS || unsafe { EqualSid(sid, owner) } == FALSE {
            return Err(denied());
        }
        Ok(())
    }
    impl Root {
        pub(super) fn new(parent: &Path) -> io::Result<Self> {
            let parent = fs::canonicalize(parent)?;
            let path = parent.join(random_name()?);
            let descriptor = owner_descriptor()?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: FALSE,
            };
            // SAFETY: path and explicit protected owner-only descriptor live
            // through this exclusive directory creation call.
            if unsafe { CreateDirectoryW(wide(&path)?.as_ptr(), &attributes) } == FALSE {
                return Err(io::Error::last_os_error());
            }
            let directory = fs::OpenOptions::new()
                .read(true)
                .access_mode(FILE_GENERIC_READ | DELETE)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path)?;
            use std::os::windows::fs::MetadataExt;
            if directory.metadata()?.file_attributes() & 0x400 != 0 {
                // Refuse every reparse kind, not merely recognized symlinks.
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "temporary root is a reparse point",
                ));
            }
            verify_private_directory(&directory, &descriptor)?;
            Ok(Self { path, directory })
        }
        pub(super) fn create_file(&self, name: &str) -> io::Result<File> {
            // The root handle denies delete sharing: the private directory cannot
            // be renamed/replaced by a link while artifacts use its child paths.
            // Files inherit only the explicitly protected root's owner-only ACE.
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(self.path.join(name))
        }
        pub(super) fn remove_file(&self, name: &str) {
            let _ = fs::remove_file(self.path.join(name));
        }
        pub(super) fn publish(&self, name: &str, destination: &Path) -> io::Result<()> {
            fs::hard_link(self.path.join(name), destination)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            // SAFETY: retain the original DELETE-capable, non-delete-shared
            // directory handle throughout disposition and close. This Vista+
            // FileDispositionInfo API preserves the Windows 7 floor. A nonempty
            // directory fails disposition without deleting unrelated contents.
            unsafe {
                SetFileInformationByHandle(
                    self.directory.as_raw_handle(),
                    FileDispositionInfo,
                    (&raw const disposition).cast(),
                    std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
                )
            };
            // File's field destructor closes this exact handle; no path deletion
            // occurs after protection is released, even if the old name changes.
        }
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!("owner-only temporary stores require a supported Unix or Windows target");
