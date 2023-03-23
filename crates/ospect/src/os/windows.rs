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
    use windows_sys::Win32::{
        Foundation::*,
        System::LibraryLoader::*,
        Storage::FileSystem::*,
    };

    // SAFETY: This is just an FFI cal so needs a `unsafe` block but we clearly
    // just call it with a constant literal so nothing can go wrong. Errors are
    // checked below. See [1] for more detaisl.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew
    let kernel32 = unsafe {
        GetModuleHandleW(windows_sys::w!("kernel32.dll"))
    };
    if kernel32 == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // TODO(@panhania): Migrate to `MaybeUninit::uninit_array` once stabilized.
    let mut kernel32_path = [0; MAX_PATH as usize + 1];
    // SAFETY: We allocate a buffer of length `MAX_PATH + 1` and pass it to the
    // function given `MAX_PATH` as its size. The extra one element is required
    // to accommodate for the null terminator. See [1] for more details.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamew
    let kernel32_path_len = unsafe {
        GetModuleFileNameW(kernel32, kernel32_path.as_mut_ptr(), MAX_PATH)
    };
    if kernel32_path_len == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if kernel32_path[kernel32_path_len as usize] != 0 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }

    // SAFETY: We verified that initialization of `kernel32_path` succeeded, so
    // now we can get the size of the file version record [1].
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfosizew
    let kernel32_info_buf_len = unsafe {
        GetFileVersionInfoSizeW(
            kernel32_path.as_ptr(),
            std::ptr::null_mut(),
        )
    };
    if kernel32_info_buf_len == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut kernel32_info_buf = vec![0; kernel32_info_buf_len as usize];
    // SAFETY: We allocated the buffer as told by the `GetFileVersionInfoW` call
    // (and verified that it succeeded). We pass an unmodified buffer length and
    // verify errors below and allocated buffer to `GetFileVersionInfoW` [1].
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfow
    let status = unsafe {
        GetFileVersionInfoW(
            kernel32_path.as_ptr(),
            0,
            kernel32_info_buf_len,
            kernel32_info_buf.as_mut_ptr().cast::<std::ffi::c_void>(),
        )
    };
    if status == FALSE {
        return Err(std::io::Error::last_os_error());
    }

    let mut kernel32_info_len = std::mem::MaybeUninit::uninit();
    let mut kernel32_info = std::mem::MaybeUninit::uninit();
    // SAFETY: We initialized the buffer and verified that the initialization
    // succeeded. Now we can use `VerQueryValueW` function [1] on the buffer
    // that will return a pointer to a `VS_FIXEDFILEINFO` record stored within
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-verqueryvaluea
    let status = unsafe {
        VerQueryValueW(
            kernel32_info_buf.as_ptr().cast::<std::ffi::c_void>(),
            windows_sys::w!("\\"),
            kernel32_info.as_mut_ptr(),
            kernel32_info_len.as_mut_ptr(),
        )
    };
    if status == FALSE {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: We verified that the `VerQueryValueW` call succeeded, so the
    // value should be properly initialized now.
    let kernel32_info_len = unsafe {
        kernel32_info_len.assume_init()
    } as usize;
    if kernel32_info_len != std::mem::size_of::<VS_FIXEDFILEINFO>() {
        return Err(std::io::ErrorKind::InvalidData.into());
    }

    // SAFETY: We verified that the `VerQueryValueW` call succeeded, so the
    // value should be properly initialized now. We can treat it as a reference
    // because it points to a value inside `kernel32_info_buf` which is valid
    // within the scope of the function.
    let kernel32_info = unsafe {
        kernel32_info.assume_init().cast::<VS_FIXEDFILEINFO>().as_ref()
    }.unwrap();

    // TODO(@panhania): In C there are macros `HIWORD` and `LOWORD` that handle
    // this. Maybe it should be implemented for the `windows_sys` crate?

    fn hi(val: u32) -> u16 {
        (val >> 16) as u16
    }

    fn lo(val: u32) -> u16 {
        (val & 0xFFFF) as u16
    }

    let major = hi(kernel32_info.dwProductVersionMS);
    let minor = lo(kernel32_info.dwProductVersionMS);
    let build = hi(kernel32_info.dwProductVersionLS);
    let revision = lo(kernel32_info.dwProductVersionLS);

    // TODO(@panhania): `build` and `revision` might not be very reliable if we
    // base it on `kernel32.dll` (as it might not be in sync with the actual
    // kernel version). Better to use the `GetVersionExW` [1] function for this.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexw
    Ok(format!("{major}.{minor}.{build}.{revision}"))
}
