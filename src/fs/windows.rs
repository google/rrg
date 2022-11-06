// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Windows-specific utilities for working with the filesystem.

use std::ptr;
use windows::{
    core::{Error, PCWSTR},
    w,
    Win32::{
        Foundation::MAX_PATH,
        Storage::FileSystem::{
            GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
        },
        System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW},
    },
};

/// Retrieves the specified fileinfo version of a module.
///
/// The module must have been loaded by the current process.
pub fn dll_module_fileinfo(dll_name: PCWSTR) -> Result<VS_FIXEDFILEINFO, Error> {
    let module_handle = unsafe { GetModuleHandleW(dll_name) }?;

    let module_file_path = {
        let mut filename = vec![0_u16; MAX_PATH as usize];
        unsafe { GetModuleFileNameW(module_handle, &mut filename) };
        PCWSTR::from_raw(filename.as_ptr() as *const _)
    };

    let mut file_version_info_size =
        unsafe { GetFileVersionInfoSizeW(module_file_path.clone(), None) };

    let mut file_version_info = vec![0_u16; file_version_info_size as usize];
    unsafe {
        GetFileVersionInfoW(
            module_file_path,
            0,
            file_version_info_size,
            file_version_info.as_mut_ptr() as _,
        )
    }
    .ok()?;

    unsafe {
        file_version_info.set_len(file_version_info_size as usize);
    }

    let mut version_info: *mut VS_FIXEDFILEINFO = ptr::null_mut();
    unsafe {
        VerQueryValueW(
            file_version_info.as_ptr() as _,
            w!("\\"),
            &mut version_info as *mut *mut _ as _,
            &mut file_version_info_size,
        )
    }
    .ok()?;

    Ok(unsafe { version_info.as_ref() }.unwrap().to_owned())
}
