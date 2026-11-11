//! Persistent owner-only filesystem namespace, separate from document spooling.
//! Existing objects are verified, never repaired or chmodded. Names are bounded
//! single ASCII components. Application ownership headers remain the caller's job.
use std::{fs::File, io, path::Path};
#[cfg(windows)]
pub(crate) mod windows_security;

pub struct PrivateDirectory {
    inner: platform::Directory,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamespaceSync {
    Synced,
    Unsupported,
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "private filesystem policy rejected object",
    )
}
fn component(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 64
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(denied());
    }
    Ok(())
}
impl PrivateDirectory {
    pub fn create(path: &Path) -> io::Result<Self> {
        Ok(Self {
            inner: platform::Directory::new(path, true)?,
        })
    }
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            inner: platform::Directory::new(path, false)?,
        })
    }
    pub fn create_file(&self, name: &str) -> io::Result<File> {
        component(name)?;
        self.inner.file(name, true)
    }
    pub fn open_file(&self, name: &str) -> io::Result<File> {
        component(name)?;
        self.inner.file(name, false)
    }
    /// Remove only an existing verified private regular single-link file. The
    /// caller must additionally verify its application header before authorizing.
    pub fn remove_file(&self, name: &str) -> io::Result<()> {
        component(name)?;
        self.inner.remove(name)
    }
    /// Bounded namespace enumeration; refuses >65538 entries rather than allocating
    /// unbounded metadata. Foreign entries are returned but never modified.
    pub fn names(&self) -> io::Result<Vec<String>> {
        self.inner.names()
    }
    /// Unix synchronizes directory metadata. Windows explicitly reports the
    /// unavailable directory barrier; callers must synchronize WRITE_THROUGH files.
    pub fn sync(&self) -> io::Result<NamespaceSync> {
        self.inner.sync()
    }
}
#[cfg(unix)]
mod platform {
    use super::*;
    use std::{
        ffi::{CStr, CString},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, OpenOptionsExt},
            },
        },
    };
    pub struct Directory {
        directory: File,
    }
    fn cstring(value: &[u8]) -> io::Result<CString> {
        CString::new(value).map_err(|_| denied())
    }
    fn verify(file: &File, directory: bool) -> io::Result<()> {
        let m = file.metadata()?;
        // SAFETY: parameterless effective identity query.
        if m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
            || (directory && !m.is_dir())
            || (!directory && (!m.is_file() || m.nlink() != 1))
        {
            return Err(denied());
        }
        Ok(())
    }
    impl Directory {
        pub fn new(path: &Path, create: bool) -> io::Result<Self> {
            let leaf = path.file_name().ok_or_else(denied)?;
            let parent = path.parent().ok_or_else(denied)?;
            let parent = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(parent)?;
            let m = parent.metadata()?;
            // SAFETY: parameterless effective identity query. Sticky root-owned
            // parents such as /tmp protect names from other identities.
            let uid = unsafe { libc::geteuid() };
            if (m.uid() != uid && m.uid() != 0) || (m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0)
            {
                return Err(denied());
            }
            let leaf = cstring(leaf.as_bytes())?;
            if create {
                // SAFETY: pinned parent descriptor and NUL-terminated component.
                if unsafe { libc::mkdirat(parent.as_raw_fd(), leaf.as_ptr(), 0o700) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                parent.sync_all()?;
            }
            // SAFETY: openat refuses the final symlink; parent is pinned.
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    leaf.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: newly owned descriptor from successful openat.
            let directory = unsafe { File::from_raw_fd(fd) };
            verify(&directory, true)?;
            Ok(Self { directory })
        }
        pub fn file(&self, name: &str, create: bool) -> io::Result<File> {
            let name = cstring(name.as_bytes())?;
            let flags = libc::O_RDWR
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | if create {
                    libc::O_CREAT | libc::O_EXCL
                } else {
                    0
                };
            // SAFETY: pinned directory and bounded validated single component.
            let fd =
                unsafe { libc::openat(self.directory.as_raw_fd(), name.as_ptr(), flags, 0o600) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful openat returns a new owned descriptor.
            let file = unsafe { File::from_raw_fd(fd) };
            verify(&file, false)?;
            Ok(file)
        }
        pub fn remove(&self, name: &str) -> io::Result<()> {
            let file = self.file(name, false)?;
            let original = file.metadata()?;
            let name = cstring(name.as_bytes())?;
            let mut current = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: pinned directory, bounded component and valid output storage.
            if unsafe {
                libc::fstatat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    current.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fstatat succeeded and initialized output.
            let current = unsafe { current.assume_init() };
            // `MetadataExt::dev()` is `st_dev as u64`; `libc::stat.st_dev` is `i32` on macOS.
            #[allow(clippy::unnecessary_cast)]
            let same_device = current.st_dev as u64 == original.dev();
            if current.st_ino != original.ino() || !same_device {
                return Err(denied());
            }
            // SAFETY: unlinkat never follows the final component. Namespace is
            // owner-only; same-user malicious mutation is outside ACL protection.
            if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        pub fn names(&self) -> io::Result<Vec<String>> {
            // SAFETY: duplicate live descriptor for fdopendir ownership transfer.
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    c".".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: valid directory descriptor; closedir assumes ownership.
            let ptr = unsafe { libc::fdopendir(fd) };
            if ptr.is_null() {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }
            struct Dir(*mut libc::DIR);
            impl Drop for Dir {
                fn drop(&mut self) {
                    unsafe { libc::closedir(self.0) };
                }
            }
            let dir = Dir(ptr);
            let mut names = Vec::new();
            loop {
                // SAFETY: errno is thread-local. Clear it before readdir so EOF
                // cannot hide a directory read error on supported Unix hosts.
                #[cfg(any(target_os = "linux", target_os = "android"))]
                unsafe {
                    *libc::__errno_location() = 0;
                }
                #[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
                unsafe {
                    *libc::__error() = 0;
                }
                // SAFETY: readdir returns a directory-owned, NUL-terminated name
                // valid until the next call; copied immediately.
                let entry = unsafe { libc::readdir(dir.0) };
                if entry.is_null() {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(0) {
                        return Err(error);
                    }
                    break;
                }
                let value = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
                    .to_str()
                    .map_err(|_| denied())?;
                if value == "." || value == ".." {
                    continue;
                }
                if names.len() >= 65538 {
                    return Err(denied());
                }
                names.push(value.to_owned());
            }
            Ok(names)
        }
        pub fn sync(&self) -> io::Result<NamespaceSync> {
            self.directory.sync_all()?;
            Ok(NamespaceSync::Synced)
        }
    }
}
#[cfg(windows)]
mod platform {
    use super::windows_security::{owner_descriptor, verify_private_directory};
    use super::*;
    use std::{
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::{AsRawHandle, FromRawHandle},
        },
        path::PathBuf,
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{FALSE, INVALID_HANDLE_VALUE},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE,
            FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, FileDispositionInfo, GetFileInformationByHandle, OPEN_EXISTING,
            SetFileInformationByHandle,
        },
    };
    pub struct Directory {
        path: PathBuf,
        _directory: File,
    }
    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut value: Vec<_> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(denied());
        }
        value.push(0);
        Ok(value)
    }
    fn verify(file: &File, directory: bool) -> io::Result<()> {
        let m = file.metadata()?;
        if m.file_attributes() & 0x400 != 0 || m.is_dir() != directory {
            return Err(denied());
        }
        verify_private_directory(file, &owner_descriptor()?)?;
        if !directory {
            let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
            // SAFETY: live regular-file handle and valid writable output.
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) }
                == FALSE
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful API initialized structure.
            if unsafe { info.assume_init() }.nNumberOfLinks != 1 {
                return Err(denied());
            }
        }
        Ok(())
    }
    impl Directory {
        pub fn new(path: &Path, create: bool) -> io::Result<Self> {
            let parent = std::fs::canonicalize(path.parent().ok_or_else(denied)?)?;
            let path = parent.join(path.file_name().ok_or_else(denied)?);
            let descriptor = owner_descriptor()?;
            if create {
                let attributes = SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: descriptor.0,
                    bInheritHandle: FALSE,
                };
                // SAFETY: explicit owner-only protected DACL, exclusive creation.
                if unsafe { CreateDirectoryW(wide(&path)?.as_ptr(), &attributes) } == FALSE {
                    return Err(io::Error::last_os_error());
                }
            }
            // Deny delete sharing for the lifetime of this pinned root, refusing
            // junctions/reparse points without following them.
            let directory = std::fs::OpenOptions::new()
                .read(true)
                .access_mode(FILE_GENERIC_READ)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path)?;
            verify(&directory, true)?;
            Ok(Self {
                path,
                _directory: directory,
            })
        }
        fn open(&self, name: &str, create: bool, delete: bool) -> io::Result<File> {
            let descriptor = owner_descriptor()?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: FALSE,
            };
            // SAFETY: pinned non-delete-shared root, validated single component,
            // protected explicit file DACL, and create_new never follows links.
            let handle = unsafe {
                CreateFileW(
                    wide(&self.path.join(name))?.as_ptr(),
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE | if delete { DELETE } else { 0 },
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    &attributes,
                    if create { CREATE_NEW } else { OPEN_EXISTING },
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                    ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful CreateFileW returned one owned file handle.
            let file = unsafe { File::from_raw_handle(handle) };
            verify(&file, false)?;
            Ok(file)
        }
        pub fn file(&self, name: &str, create: bool) -> io::Result<File> {
            self.open(name, create, false)
        }
        pub fn remove(&self, name: &str) -> io::Result<()> {
            let file = self.open(name, false, true)?;
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            // SAFETY: verified exact file handle owns DELETE, no pathname race.
            if unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    FileDispositionInfo,
                    (&raw const disposition).cast(),
                    std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
                )
            } == FALSE
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        pub fn names(&self) -> io::Result<Vec<String>> {
            let mut names = Vec::new();
            for entry in std::fs::read_dir(&self.path)? {
                if names.len() >= 65538 {
                    return Err(denied());
                }
                names.push(entry?.file_name().into_string().map_err(|_| denied())?);
            }
            Ok(names)
        }
        pub fn sync(&self) -> io::Result<NamespaceSync> {
            // No successful directory-fsync claim on Win32. All files created by
            // this module use WRITE_THROUGH and callers still MUST sync_all them.
            Ok(NamespaceSync::Unsupported)
        }
    }
}
#[cfg(not(any(unix, windows)))]
compile_error!("owner-only persistent directories require Unix or Windows");
