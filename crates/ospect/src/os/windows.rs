// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::time::{Duration, SystemTime};

/// Returns the time at which the system was installed.
pub fn installed() -> std::io::Result<SystemTime> {
    use windows_sys::{w, Win32::System::Registry::*};

    let mut install_date = std::mem::MaybeUninit::<u32>::uninit();
    let mut install_date_size = std::mem::size_of_val(&install_date) as u32;

    // SAFETY: We call the function as prescribed in the docs [1]: we pass a 32-
    // bit value (`DWORD`) along with its size.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluew
    let code = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!("Software\\Microsoft\\Windows NT\\CurrentVersion"),
            w!("InstallDate"),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            install_date.as_mut_ptr() as *mut std::ffi::c_void,
            &mut install_date_size,
        )
    };
    if code != windows_sys::Win32::Foundation::NO_ERROR {
        return Err(std::io::Error::from_raw_os_error(code as i32));
    }

    // SAFETY: We checked above that the call succeeded. It means that the value
    // is properly initialized now.
    let install_date = unsafe { install_date.assume_init() };
    let install_date_secs = u64::from(install_date);

    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(install_date_secs))
}

/// Returns the [`Kind`] of currently running operating system.
///
/// [`Kind`]: crate::os::Kind
pub fn kind() -> crate::os::Kind {
    crate::os::Kind::Linux
}

/// Returns the version string of the currently running operating system.
pub fn version() -> std::io::Result<String> {
    // TODO(@panhania): Implement this function.
    Err(std::io::ErrorKind::Unsupported.into())
}
