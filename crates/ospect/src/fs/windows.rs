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

type VolumeNameBuf = [u16; (windows_sys::Win32::Foundation::MAX_PATH + 1) as usize];
type VolumeMountPointBuf = [u16];
type VolumeFsTypeBuf = [u16; (windows_sys::Win32::Foundation::MAX_PATH + 1) as usize];

/// An iterator over Windows volume names.
struct VolumeNames {
    /// Error to return next time the iterator is polled (if set).
    error: Option<std::io::Error>,
    /// Buffer with null-terminated volume name to be yielded.
    name_buf: VolumeNameBuf,
    /// Active handle for the underlying Windows API iterator.
    handle: Option<windows_sys::Win32::Storage::FileSystem::FindVolumeHandle>,
}

impl VolumeNames {

    /// Creates a new instance of the iterator.
    fn new() -> std::io::Result<VolumeNames> {
        // TODO(rust-lang/rust#96097): Refactor with `MaybeUninit` once support
        // for arrays is stabilized.
        let mut name_buf: VolumeNameBuf = [0; (windows_sys::Win32::Foundation::MAX_PATH + 1) as usize];

        // SAFETY: This is just a call to the unsafe function as described in
        // the documentation [1]. We pass the buffer and its size and verify the
        // result of the call below.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstvolumew
        let handle = unsafe {
            windows_sys::Win32::Storage::FileSystem::FindFirstVolumeW(
                name_buf.as_mut_ptr(), name_buf.len() as u32,
            )
        };
        if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }

        Ok(VolumeNames {
            error: None,
            name_buf,
            handle: Some(handle),
        })
    }

    /// Closes the iterator.
    ///
    /// This is similar to `drop` but makes it possible to handle errors.
    fn close(&mut self) -> std::io::Result<()> {
        let Some(handle) = self.handle else {
            return Ok(());
        };

        // We need to set the handle to `None` explicitly because this function
        // is used in the `drop` implementation but `drop` is also implicitly
        // called at the end of this function, ending with an endless loop
        // otherwise. We also don't want to allow multiple calls of `close` in
        // case closing fails.
        self.handle = None;

        // SAFETY: This is just a call to the unsafe function as described
        // in the documentation [1]. We pass the handle that is guaranteed
        // to be valid and verify the result of the call below.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findvolumeclose
        let status = unsafe {
            windows_sys::Win32::Storage::FileSystem::FindVolumeClose(handle)
        };
        if status == 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }
}

impl Drop for VolumeNames {

    fn drop(&mut self) {
        // Like with `drop` for `std::fs::File`, there is no way to handle
        // errors and they have to be swallowed. If one has to handle errors,
        // `close` can be used.
        let _ = self.close();
    }
}

impl Iterator for VolumeNames {

    type Item = std::io::Result<VolumeNameBuf>;

    fn next(&mut self) -> Option<std::io::Result<VolumeNameBuf>> {
        // If we have a pending error to return, we do it. An error also means
        // that further iteration makes no sense and we close the iterator.
        if let Some(error) = self.error.take() {
            match self.close() {
                Ok(()) => (),
                Err(error) => self.error = Some(error),
            }
            return Some(Err(error));
        }

        let Some(handle) = self.handle else {
            return None;
        };

        let old_name_buf = self.name_buf;

        // SAFETY: This is just a call to the unsafe function as described in
        // the documentation [1]. We pass the handle that is guaranteed to be
        // valid and buffer along with its size and verify the result of the
        // call below.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextvolumew
        let status = unsafe {
            windows_sys::Win32::Storage::FileSystem::FindNextVolumeW(
                handle,
                self.name_buf.as_mut_ptr(), self.name_buf.len() as u32,
            )
        };
        if status == 0 {
            // SAFETY: If `FindNextVolumeW` fails, it returns 0 and sets the
            // last error to some value that we need to inspect.
            let code = unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            };
            if code == windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES {
                match self.close() {
                    Ok(()) => (),
                    Err(error) => self.error = Some(error),
                }
            } else {
                // TODO(rust-lang/rust#107792): Migrate cast to `as RawOsError`
                // once it is stable.
                let error = std::io::Error::from_raw_os_error(code as i32);
                self.error = Some(error);
            }
        }

        Some(Ok(old_name_buf))
    }
}

/// An iterator over Windows volume mount points.
///
/// In case there are no mount points the iterator will yield a single result
/// with empty mount point.
///
/// Note that because of borrowing limitations, this type does not implement
/// the [`Iterator`] trait directly but can be converted to one using its
/// [`IntoIterator`] implementation.
struct VolumeMountPoints {
    /// Buffer with null-terminated mount points list.
    mounts_buf: Vec<u16>,
}

impl VolumeMountPoints {

    /// Creates a new instance of the iterator for the given volume name.
    fn new(name_buf: &VolumeNameBuf) -> std::io::Result<VolumeMountPoints> {
        let mut mounts_buf_len = std::mem::MaybeUninit::uninit();

        // SAFETY: This is the first call to `GetVolumePathNamesForVolumeNameW`
        // (see [1] for its documentation) where we query for the size of the
        // buffer needed to hold the actual result. We expect this call to fail
        // and verify this below.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumepathnamesforvolumenamew
        let status = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetVolumePathNamesForVolumeNameW(
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
        let code = unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        };
        if code != windows_sys::Win32::Foundation::ERROR_MORE_DATA {
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
            windows_sys::Win32::Storage::FileSystem::GetVolumePathNamesForVolumeNameW(
                name_buf.as_ptr(),
                mounts_buf.as_mut_ptr(), mounts_buf_len, &mut mounts_buf_len,
            )
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

        Ok(VolumeMountPoints {
            mounts_buf,
        })
    }
}

impl<'a> IntoIterator for &'a VolumeMountPoints {

    type Item = &'a VolumeMountPointBuf;
    type IntoIter = VolumeMountPointsIter<'a>;

    fn into_iter(self) -> VolumeMountPointsIter<'a> {
        VolumeMountPointsIter {
            mounts_buf: &self.mounts_buf[..],
        }
    }

}

/// An iterator over Windows volume mount points.
///
/// In case there are no mount points the iterator will yield a single result
/// with empty mount point.
///
/// This iterator can be created by using implementation of the [`IntoIterator`]
/// trait for the [`VolumeMountPoints`] type.`
struct VolumeMountPointsIter<'a> {
    /// Subslice of the null-terminated buffer with mount points list.
    mounts_buf: &'a [u16],
}

impl<'a> Iterator for VolumeMountPointsIter<'a> {

    type Item = &'a VolumeMountPointBuf;

    fn next(&mut self) -> Option<&'a VolumeMountPointBuf> {
        // `self.mounts_buf` is empty only if we have nothing else to yield
        // (and after we yielded an empty slice in case of empty mount list).
        if self.mounts_buf.is_empty() {
            return None;
        }

        // `self.mounts_buf` is a null-terminated list of mount point where each
        // mount point is also null-terminated itself. We iterate over subslices
        // delimited by the null character.
        //
        // Note that in case there are no known mount points, the buffer will
        // only have a single null character. We still want to yield a mount
        // point (empty one) in that case.
        let mount_len = self.mounts_buf.iter().position(|tchar| *tchar == 0)
            .expect("volume mount point is not null-terminated");

        let mount_buf = &self.mounts_buf[..mount_len];

        // We advance past the null character. In case we are at the end, the
        // slice should point to a singular null character marking the end of
        // the list. In such scenario, we advance further to empty the slice to
        // avoid yielding empty result in next iteration (since this iteration
        // is already guaranteed to yield a result).
        self.mounts_buf = &self.mounts_buf[mount_len + 1..];
        if self.mounts_buf.len() == 1 {
            assert! {
                self.mounts_buf[0] == 0,
                "volume mount point list is not null-terminated"
            };

            self.mounts_buf = &self.mounts_buf[1..];
        }

        Some(mount_buf)
    }
}

/// Returns filesystem type for the given volume name.
fn volume_fs_type(name_buf: &VolumeNameBuf) -> std::io::Result<VolumeFsTypeBuf> {
    // TODO(rust-lang/rust#96097): Refactor with `MaybeUninit` once support
    // for arrays is stabilized.
    let mut fs_type_buf: VolumeFsTypeBuf = [0; (windows_sys::Win32::Foundation::MAX_PATH + 1) as usize];

    // SAFETY: This is just a call to the unsafe function as described in
    // the documentation [1]. As root path we pass the volume name and then
    // only the buffer for filesystem type along with its size. All other
    // values we leave empty (they are optional) as we are not interested.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw
    let status = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW(
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

    Ok(fs_type_buf)
}

/// Returns an iterator over mounted filesystems information.
pub fn mounts() -> std::io::Result<impl Iterator<Item = std::io::Result<Mount>>> {
    use std::os::windows::ffi::OsStringExt as _;

    // TODO(@panhania): We collect all mount points into a vector and then make
    // an iterator out of it. However, all individual methods return iterators
    // so it should be possible to combine them. Ideally, this should be very
    // easy to do with generators.
    //
    // One option is to use `itertools::flatten_ok` but that does not play nice
    // with the iterator over volume mount points that creates self-references.
    let mut results = Vec::new();

    for name_buf in VolumeNames::new()? {
        let name_buf = match name_buf {
            Ok(name_buf) => name_buf,
            Err(error) => {
                results.push(Err(error));
                continue;
            }
        };
        let name_len = name_buf.iter().position(|tchar| *tchar == 0)
            .expect("volume name not null-terminated");

        let fs_type_buf = match volume_fs_type(&name_buf) {
            Ok(name_buf) => name_buf,
            Err(error) => {
                results.push(Err(error));
                continue;
            }
        };
        let fs_type_len = fs_type_buf.iter().position(|tchar| *tchar == 0)
            .expect("volume filesystem name not null-terminated");

        match VolumeMountPoints::new(&name_buf) {
            Ok(mount_points) => {
                for mount_buf in &mount_points {
                    results.push(Ok(Mount {
                        source: OsString::from_wide(&name_buf[0..name_len])
                            .to_string_lossy().into_owned(),
                        target: OsString::from_wide(mount_buf)
                            .into(),
                        fs_type: OsString::from_wide(&fs_type_buf[0..fs_type_len])
                            .to_string_lossy().into_owned(),
                    }));
                }
            }
            Err(error) => {
                results.push(Err(error));
                continue;
            }
        }
    }

    Ok(results.into_iter())
}
