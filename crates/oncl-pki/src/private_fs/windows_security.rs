//! Shared protected owner-only DACL construction and verification.
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::{ffi::c_void, fs::File, io, ptr};
use windows_sys::Win32::Foundation::{FALSE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid,
    GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorOwner, GetTokenInformation,
    OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
pub(crate) struct Local(pub(crate) *mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}
pub(crate) fn owner_descriptor() -> io::Result<Local> {
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
        String::from_utf16(std::slice::from_raw_parts(start, length)).map_err(io::Error::other)?
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
pub(crate) fn verify_private_directory(directory: &File, expected: &Local) -> io::Result<()> {
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
