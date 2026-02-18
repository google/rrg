// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::path::Path;
use windows_sys::Win32::{
    Foundation::{
        HANDLE,
    },
    Security::{
        ACL, ACCESS_ALLOWED_ACE,
        SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
        TOKEN_USER,
    },
};

pub fn create_dir_private_all<P>(path: P) -> std::io::Result<()>
where
    P: AsRef<Path>,
{
    // We use capacity of 2: one for the current user and one for the admin
    // group.
    let mut acl = Acl::with_capacity(2)?;

    let token_current_process = AccessToken::current_process()?;
    let token_current_user = AccessTokenInfo::user(token_current_process)?;

    // SAFETY: We call add an user ACE to the ACL as described in the docs [1]
    // on a valid instance using SID of a valid user. We verify the result of
    // the call below.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-addaccessallowedace
    let status = unsafe {
        windows_sys::Win32::Security::AddAccessAllowedAce(
            &mut *acl,
            windows_sys::Win32::Security::ACL_REVISION,
            windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS,
            token_current_user.User.Sid,
        )
    };
    if status == 0 {
        let error = std::io::Error::last_os_error();
        return Err(std::io::Error::new(error.kind(), format! {
            "could not add current user ACE to ACL: {error}",
        }));
    }

    let mut admin_user_sid = {
        [0; windows_sys::Win32::Security::SECURITY_MAX_SID_SIZE as usize]
    };
    let mut admin_user_sid_len = {
        windows_sys::Win32::Security::SECURITY_MAX_SID_SIZE
    };
    // SAFETY: We call get SID for the admin group as described in the docs [1]
    // on a buffer large enough to contain the largest possible SID. We verify
    // the result of the call below.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createwellknownsid
    let status = unsafe {
        windows_sys::Win32::Security::CreateWellKnownSid(
            windows_sys::Win32::Security::WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            &mut admin_user_sid as *mut _ as *mut std::ffi::c_void,
            &mut admin_user_sid_len,
        )
    };
    if status == 0 {
        let error = std::io::Error::last_os_error();
        return Err(std::io::Error::new(error.kind(), format! {
            "could not create builtin admin group SID: {error}",
        }));
    }

    // SAFETY: We call add an admin ACE to the ACL as described in the docs [1]
    // on a just retrieved and verified SID. We verify the result of the call
    // below.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-addaccessallowedace
    let status = unsafe {
        windows_sys::Win32::Security::AddAccessAllowedAce(
            &mut *acl,
            windows_sys::Win32::Security::ACL_REVISION,
            windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS,
            &mut admin_user_sid as *mut _ as *mut std::ffi::c_void,
        )
    };
    if status == 0 {
        let error = std::io::Error::last_os_error();
        return Err(std::io::Error::new(error.kind(), format! {
            "could not add admins ACE to ACL: {error}",
        }));
    }

    let mut sec_desc = std::mem::MaybeUninit::<SECURITY_DESCRIPTOR>::uninit();
    // SAFETY: We initialize the security descriptor as described in the docs
    // for it [1]. We verify the result of that below.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-initializesecuritydescriptor
    let status = unsafe {
        windows_sys::Win32::Security::InitializeSecurityDescriptor(
            sec_desc.as_mut_ptr().cast::<std::ffi::c_void>(),
            windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION,
        )
    };
    if status == 0 {
        let error = std::io::Error::last_os_error();
        return Err(std::io::Error::new(error.kind(), format! {
            "could not initialize security descriptor: {error}",
        }));
    }
    // SAFETY: We initialized the security descriptor and verified that it suc-
    // ceeded.
    let mut sec_desc = unsafe {
        sec_desc.assume_init()
    };

    // SAFETY: We set the control bits as described in the docs [1] using valid
    // security descriptor and constant-defined bits. We verify the result of
    // the call below.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-setsecuritydescriptorcontrol
    let status = unsafe {
        windows_sys::Win32::Security::SetSecurityDescriptorControl(
            &mut sec_desc as *mut _ as *mut std::ffi::c_void,
            windows_sys::Win32::Security::SE_DACL_PROTECTED,
            windows_sys::Win32::Security::SE_DACL_PROTECTED,
        )
    };
    if status == 0 {
        let error = std::io::Error::last_os_error();
        return Err(std::io::Error::new(error.kind(), format! {
            "could not enable security descriptor DACL protection: {error}",
        }));
    }

    // SAFETY: We call `SetSecurityDescriptorDacl` as described in the docs [1]
    // on a valid security descriptor (initialized and verified above) and a
    // valid instance of `ACL`. We verify the result of the call below.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-setsecuritydescriptordacl
    let status = unsafe {
        windows_sys::Win32::Security::SetSecurityDescriptorDacl(
            &mut sec_desc as *mut _ as *mut std::ffi::c_void,
            windows_sys::Win32::Foundation::TRUE,
            &*acl,
            windows_sys::Win32::Foundation::FALSE,
        )
    };
    if status == 0 {
        let error = std::io::Error::last_os_error();
        return Err(std::io::Error::new(error.kind(), format! {
            "could not set security descriptor DACL: {error}",
        }));
    }

    // See [1] for the details on invididual fields.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ns-wtypesbase-security_attributes
    let sec_attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: &mut sec_desc as *mut _ as *mut std::ffi::c_void,
        bInheritHandle: windows_sys::Win32::Foundation::FALSE,
    };

    // SAFETY: Security attributes were properly initialized now.
    unsafe {
        create_dir_with_sec_attrs_all(path.as_ref(), &sec_attrs)
    }
}

/// Recursively creates a directory at the given path with the given security
/// attributes.
///
/// # Safety
///
/// `sec_attrs` must be a valid instance of [`SECURTITY_ATTRIBUTES`].
unsafe fn create_dir_with_sec_attrs_all(
    path: &Path,
    sec_attrs: &SECURITY_ATTRIBUTES,
) -> std::io::Result<()>
{
    if let Some(path_parent) = path.parent() {
        // SAFETY: `sec_attrs` is required to be a valid instance.
        unsafe {
            create_dir_with_sec_attrs_all(path_parent, sec_attrs)?
        }
    }

    // SAFETY: `sec_attrs` is required to be a valid instance.
    unsafe {
        create_dir_with_sec_attrs(path, sec_attrs)
    }
}

/// Creates a directory at the given path with the given security attributes.
///
/// # Safety
///
/// `sec_attrs` must be a valid instance of [`SECURTITY_ATTRIBUTES`].
unsafe fn create_dir_with_sec_attrs(
    path: &Path,
    sec_attrs: &SECURITY_ATTRIBUTES,
) -> std::io::Result<()>
{
    use std::os::windows::ffi::OsStrExt as _;
    let mut path_wide = path.as_os_str().encode_wide()
        .collect::<Vec<u16>>();
    path_wide.push(0);

    // SAFETY: We call the function as descrined in the docs [1] on a valid wide
    // null-terminated path with a valid security attributes object.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw
    let status = unsafe {
        windows_sys::Win32::Storage::FileSystem::CreateDirectoryW(
            path_wide.as_ptr(),
            sec_attrs,
        )
    };
    if status == 0 {
        // SAFETY: `GetLastError` is always safe to call.
        //
        // We use it over the standard `Error::last_os_error` to match on error
        // code specifically mentioned in `CreateDirectoryW` documentation in-
        // stead of `ErrorKind::AlreadyExists` that is not guaranteed to corres-
        // pond to it (but it almost certainly will).
        match unsafe { windows_sys::Win32::Foundation::GetLastError() } {
            windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS => (),
            error => return Err(std::io::Error::from_raw_os_error(error as i32)),
        }
    }

    Ok(())
}

/// RAII wrapper for an [access token][1].
///
/// [1]: https://learn.microsoft.com/en-us/windows/win32/secgloss/a-gly#_SECURITY_ACCESS_TOKEN_GLY
struct AccessToken {
    handle: HANDLE,
}

impl AccessToken {

    /// Opens a security access token for the current process.
    fn current_process() -> std::io::Result<AccessToken> {
        let mut handle = std::mem::MaybeUninit::uninit();
        // SAFETY: We call `OpenProcessToken` as described in the docs [1] for
        // the current process and verify the result of the call below.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        let status = unsafe {
            windows_sys::Win32::System::Threading::OpenProcessToken(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                windows_sys::Win32::Security::TOKEN_QUERY,
                handle.as_mut_ptr(),
            )
        };
        if status == 0 {
            let error = std::io::Error::last_os_error();
            return Err(std::io::Error::new(error.kind(), format! {
                "could not open access token for the current process: {error}",
            }));
        }
        // SAFETY: We verified that the call above succeeded, so `handle` should
        // now be properly initialized.
        let handle = unsafe {
            handle.assume_init()
        };

        Ok(AccessToken {
            handle
        })
    }
}

impl Drop for AccessToken {

    fn drop(&mut self) {
        // SAFETY: `self.handle` is guaranteed to be a valid token handle, so we
        // can close it when we are done as described in the docs for opening
        // it [1].
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        let _ = unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle)
        };
    }
}

/// RAII wrapper for information about an [access token][1].
///
/// [1]: https://learn.microsoft.com/en-us/windows/win32/secgloss/a-gly#_SECURITY_ACCESS_TOKEN_GLY
struct AccessTokenInfo<T> {
    layout: std::alloc::Layout,
    buf: *mut u8,
    phantom: std::marker::PhantomData<T>,
}

impl AccessTokenInfo<TOKEN_USER> {

    /// Retrieves [user information][1] for the given access token
    ///
    /// [1]: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_user
    fn user(token: AccessToken) -> std::io::Result<AccessTokenInfo<TOKEN_USER>> {
        let layout = std::alloc::Layout::from_size_align(
            // Instead of doing a separate call to `GetTokenInformation` to get
            // the exact size of the buffer needed we just use the biggest pos-
            // sible size.
            std::mem::size_of::<TOKEN_USER>() +
            windows_sys::Win32::Security::SECURITY_MAX_SID_SIZE as usize,
            std::mem::align_of::<TOKEN_USER>(),
        ).expect("invalid layout");

        let mut buf_len = layout.size() as u32;
        // SAFETY: The layout size is guaranteed to non-zero, so allocation is
        // fine.
        let buf = unsafe {
            std::alloc::alloc(layout)
        };

        // We create the result here already to trigger RAII deallocation of the
        // buffer in case the call below does not succeed.
        let result = AccessTokenInfo {
            layout,
            buf,
            phantom: std::marker::PhantomData,
        };

        // SAFETY: We call `GetTokenInformation` as described in the docs [1]
        // and verify the result below. The buffer is allocated beforehand with
        // maximum possible capacity and layout to hold the `TOKEN_USER` data.
        // We correctly pass its length along.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
        let status = unsafe {
            windows_sys::Win32::Security::GetTokenInformation(
                token.handle,
                windows_sys::Win32::Security::TokenUser,
                result.buf.cast::<std::ffi::c_void>(),
                buf_len,
                &mut buf_len,
            )
        };
        if status == 0 {
            let error = std::io::Error::last_os_error();
            return Err(std::io::Error::new(error.kind(), format! {
                "could not get access token user information: {error}",
            }));
        }

        // The call above succeeded, so the buffer now contains valid instance
        // of `TOKEN_USER`.
        Ok(result)
    }
}

impl<T> Drop for AccessTokenInfo<T> {

    fn drop(&mut self) {
        // SAFETY: `self.buf` is guaranteed to be a valid allocation allocated
        // with the `self.layout` layout so it is fine to deallocate it once it
        // is no longer needed.
        unsafe {
            std::alloc::dealloc(self.buf, self.layout);
        }
    }
}

impl std::ops::Deref for AccessTokenInfo<TOKEN_USER> {

    type Target = TOKEN_USER;

    fn deref(&self) -> &TOKEN_USER {
        // SAFETY: `self.buf` is guaranteed to contain a valid instance of
        // `TOKEN_USER` (and was allocated with correct alignment for it).
        unsafe {
            &*self.buf.cast::<TOKEN_USER>()
        }
    }
}

/// RAII wrapper for an [ACL][1].
///
/// [1]: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl
struct Acl {
    layout: std::alloc::Layout,
    buf: *mut u8,
}

impl Acl {

    /// Initializes the ACL wrapper able hold `cap` [access control entries][1].
    ///
    /// [1]: https://learn.microsoft.com/en-us/windows/win32/secgloss/a-gly#_SECURITY_ACCESS_CONTROL_ENTRY_GLY
    fn with_capacity(cap: usize) -> std::io::Result<Acl> {
        let layout = std::alloc::Layout::from_size_align(
            // As per [1], we need size that can hold the ACL metadata, metadata
            // for each ACE and a SID for each ACE. Instead of querying length
            // of each SID, we just make the size the upper bound by assuming
            // the longest posible SID size fo each.
            //
            // [1]: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-initializeacl#remarks
            std::mem::size_of::<ACL>() +
            std::mem::size_of::<ACCESS_ALLOWED_ACE>() * cap +
            windows_sys::Win32::Security::SECURITY_MAX_SID_SIZE as usize * cap,
            std::mem::align_of::<ACL>(),
        ).expect("invalid layout");

        // SAFETY: The layout size is guaranteed to non-zero, so allocation is
        // fine.
        let buf = unsafe {
            std::alloc::alloc(layout)
        };

        // We create the result here already to trigger RAII deallocation of the
        // buffer in case the call below does not succeed.
        let result = Acl {
            layout,
            buf,
        };

        // SAFETY: We initialize the ACL as described in the docs [1] with the
        // pre-allocated buffer aligned to hold `ACL` data. We correctly pass
        // its length along and verify the result blow.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-initializeacl
        let status = unsafe {
            windows_sys::Win32::Security::InitializeAcl(
                result.buf.cast::<ACL>(),
                layout.size() as u32,
                windows_sys::Win32::Security::ACL_REVISION,
            )
        };
        if status == 0 {
            let error = std::io::Error::last_os_error();
            return Err(std::io::Error::new(error.kind(), format! {
                "could not initialize ACL: {error}",
            }));
        }

        // The call above succeeded, so the buffer now contains valid instance
        // of `ACL`.
        Ok(result)
    }
}

impl Drop for Acl {

    fn drop(&mut self) {
        // SAFETY: `self.buf` is guaranteed to be a valid allocation allocated
        // with the `self.layout` layout so it is fine to deallocate it once it
        // is no longer needed.
        unsafe {
            std::alloc::dealloc(self.buf, self.layout);
        }
    }
}

impl std::ops::Deref for Acl {

    type Target = ACL;

    fn deref(&self) -> &ACL {
        // SAFETY: `self.buf` is guaranteed to contain a valid instance of `ACL`
        // (and was allocated with correct alignment for it).
        unsafe {
            &*self.buf.cast::<ACL>()
        }
    }
}

impl std::ops::DerefMut for Acl {

    fn deref_mut(&mut self) -> &mut ACL {
        // SAFETY: `self.buf` is guaranteed to contain a valid instance of `ACL`
        // (and was allocated with correct alignment for it).
        unsafe {
            &mut *self.buf.cast::<ACL>()
        }
    }
}
