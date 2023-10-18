// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Windows-specific filesystem inspection functionalities.

use std::ffi::{OsStr, OsString};
use std::path::Path;

use super::*;

/// Collects names of all extended attributes for the specified file.
pub fn ext_attr_names<P>(_path: P) -> std::io::Result<Vec<OsString>>
where
    P: AsRef<Path>,
{
    // Windows does not support extended file attributes, so we just error out.
    Err(std::io::ErrorKind::Unsupported.into())
}

/// Collects value of a file extended attribute with the specified name.
pub fn ext_attr_value<P, S>(_path: P, _name: S) -> std::io::Result<Vec<u8>>
where
    P: AsRef<Path>,
    S: AsRef<OsStr>,
{
    // Windows does not support extended file attributes, so we just error out.
    Err(std::io::ErrorKind::Unsupported.into())
}

/// Returns an iterator over mounted filesystems information.
pub fn mounts() -> std::io::Result<impl Iterator<Item = std::io::Result<Mount>>> {
    use std::os::windows::ffi::OsStringExt as _;

    use windows_sys::Win32::{
        Foundation::{
            GetLastError, ERROR_MORE_DATA, ERROR_NO_MORE_FILES,
            MAX_PATH,
            INVALID_HANDLE_VALUE,
        },
        Storage::FileSystem::{
            FindFirstVolumeW, FindNextVolumeW, FindVolumeClose,
            GetVolumeInformationW, GetVolumePathNamesForVolumeNameW,
        },
    };

    // TODO(rust-lang/rust#96097): Refactor with `MaybeUninit` once support for
    // arrays is stabilized.
    let mut name_buf: [u16; MAX_PATH as usize] = [0; MAX_PATH as usize];

    // SAFETY: This is just a call to the unsafe function as described in the
    // documentation [1]. We pass the buffer and its size and verify the result
    // of the call below.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstvolumew
    let handle = unsafe {
        FindFirstVolumeW(name_buf.as_mut_ptr(), name_buf.len() as u32)
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    // TODO(@panhania): Rewrite this code to return an iterator that yields
    // results on demand.
    let mut results = Vec::new();

    loop {
        let name_len = name_buf.iter().position(|tchar| *tchar == 0)
            .expect("volume name not null-terminated");

        let mut fs_type_buf: [u16; MAX_PATH as usize] = [0; MAX_PATH as usize];

        // SAFETY: This is just a call to the unsafe function as described in
        // the documentation [1]. As root path we pass the volume name and then
        // only the buffer for filesystem type along with its size. All other
        // values we leave empty (they are optional) as we are not interested.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw
        let status = unsafe {
            GetVolumeInformationW(
                name_buf.as_ptr(),
                std::ptr::null_mut(), 0, // Volume name.
                std::ptr::null_mut(), // Volume serial number.
                std::ptr::null_mut(), // Component length limit.
                std::ptr::null_mut(), // Filesystem flags.
                fs_type_buf.as_mut_ptr(), fs_type_buf.len() as u32,
            )
        };
        if status == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let fs_type_len = fs_type_buf.iter().position(|tchar| *tchar == 0)
            .expect("volume filesystem name not null-terminated");

        let mut mounts_buf_len = std::mem::MaybeUninit::uninit();

        // SAFETY: This is the first call to `GetVolumePathNamesForVolumeNameW`
        // (see [1] for its documentation) where we query for the size of the
        // buffer needed to hold the actual result. We expect this call to fail
        // and verify this below.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumepathnamesforvolumenamew
        let status = unsafe {
            GetVolumePathNamesForVolumeNameW(
                name_buf.as_ptr(),
                std::ptr::null_mut(), 0, mounts_buf_len.as_mut_ptr(),
            )
        };
        if status != 0 {
            // This should never happen because the call with no buffer should
            // not succeed. But just to be on the safe side, we verify that.
            return Err(std::io::ErrorKind::Other.into());
        }

        // SAFETY: We verified that the previous call failed (as expected),
        // so we can read the error code. It should return `ERROR_MORE_DATA`,
        // otherwise we rethrow the error.
        let code = unsafe { GetLastError() };
        if code != ERROR_MORE_DATA {
            // TODO(rust-lang/rust#107792): Migrate cast to `as RawOsError`
            // once it is stable.
            return Err(std::io::Error::from_raw_os_error(code as i32));
        }

        // SAFETY: Call to `GetVolumePathNamesForVolumeNameW` failed with
        // `ERROR_MORE_DATA`, so `mounts_buf_len` should now be set to the value
        // of the needed buffer, we can assume it is initialized.
        let mut mounts_buf_len = unsafe { mounts_buf_len.assume_init() };
        let mut mounts_buf = Vec::with_capacity(mounts_buf_len as usize);

        // SAFETY: We call `GetVolumePathNamesForVolumeNameW` again, this time
        // with a real buffer. The buffer has been initialized to the expected
        // size (returned by the previous call). We pass it along with its real
        // length. It is hypothetically possible that in between calls the size
        // of the needed buffer changed (although the chances are close to 0),
        // but in this case the call will just fail and not cause any unsafety.
        // We verify the call below.
        let status = unsafe {
            GetVolumePathNamesForVolumeNameW(
                name_buf.as_ptr(),
                mounts_buf.as_mut_ptr(), mounts_buf_len, &mut mounts_buf_len)
        };
        if status == 0 {
            return Err(std::io::Error::last_os_error());
        }

        // SAFETY: The second call to `GetVolumePathNamesForVolumeNameW` and so
        // the `mounts_buf_len` should be initialized to the length of the
        // returned buffer. Note that this value might be hypothetically smaller
        // than the value of this variable after the first call. We can set the
        // length of the vector to this value.
        unsafe {
            mounts_buf.set_len(mounts_buf_len as usize);
        }

        // `mounts_buf` is now a null-terminated list of mount point where each
        // mount point is also null-terminated itself. We iterate over subslices
        // delimited by the null character.
        //
        // Note that in case there are no known mount points, the buffer will
        // only have a single null character. We still want to yield a mount
        // point (for volume name and filesystem type), so we use a loop that
        // is guaranteed to have at least one iteration.
        let mut mounts_slice = &mounts_buf[..];
        loop {
            let mount_len = mounts_slice.iter().position(|tchar| *tchar == 0)
                .expect("volume mount point is not null-terminated");

            results.push(Mount {
                source: OsString::from_wide(&name_buf[0..name_len])
                    .to_string_lossy().into_owned(),
                target: OsString::from_wide(&mounts_slice[..mount_len])
                    .into(),
                fs_type: OsString::from_wide(&fs_type_buf[0..fs_type_len])
                    .to_string_lossy().into_owned(),
            });

            mounts_slice = &mounts_slice[mount_len + 1..];

            // There are two end conditions:
            //
            // * If there were no mount points, the slice at this point should
            //   be empty.
            // * If there are and we are at the end it means that the slice must
            //   point to the null character.
            if mounts_slice.is_empty() || mounts_slice[0] == 0 {
                break;
            }
        }

        // SAFETY: This is just a call to the unsafe function as described in
        // the documentation [1]. We pass the handle that is guaranteed to be
        // valid and buffer along with its size and verify the result of the
        // call below.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextvolumew
        let status = unsafe {
            FindNextVolumeW(handle, name_buf.as_mut_ptr(), name_buf.len() as u32)
        };
        if status == 0 {
            // SAFETY: If `FindNextVolumeW` fails, it returns 0 and sets the
            // last error to some value that we need to inspect.
            let code = unsafe { GetLastError() };
            if code != ERROR_NO_MORE_FILES {
                // TODO(rust-lang/rust#107792): Migrate cast to `as RawOsError`
                // once it is stable.
                return Err(std::io::Error::from_raw_os_error(code as i32));
            }

            // SAFETY: This is just a call to the unsafe function as described
            // in the documentation [1]. We pass the handle that is guaranteed
            // to be valid and verify the result of the call below.
            //
            // [1]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findvolumeclose
            let status = unsafe {
                FindVolumeClose(handle)
            };
            if status == 0 {
                return Err(std::io::Error::last_os_error());
            }

            // TODO(@panhania): Improve error handling once iterator approach
            // is implemented.
            return Ok(results.into_iter().map(Ok));
        }
    }
}
