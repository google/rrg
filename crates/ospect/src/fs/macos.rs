// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! macOS-specific filesystem inspection functionalities.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::path::{Path, PathBuf};

use super::*;

/// Collects names of all extended attributes for the specified file.
pub fn ext_attr_names<P>(path: P) -> std::io::Result<Vec<OsString>>
where
    P: AsRef<Path>,
{
    use std::os::unix::ffi::OsStrExt as _;

    let os_str_path = path.as_ref().as_os_str();
    let c_str_path = CString::new(os_str_path.as_bytes())
        // Unlike on Linux where a null bytes in paths are not possible, HFS+
        // does allow such characters [1]. Thus, we have to handle such cases
        // gracefully.
        //
        // [1]: https://en.wikipedia.org/wiki/HFS_Plus
        .map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
        })?;

    // SAFETY: The correctness of the path is guaranteed by conversion to the
    // `CString` type above. The rest is just is a FFI call respecting the spec.
    let len = unsafe {
        // First we call `listxattr` with empty buffer to get the size of the
        // buffer that will collect the actual results.
        libc::listxattr(
            c_str_path.as_ptr(),
            std::ptr::null_mut(), 0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut buf = vec![0; len as usize];

    // SAFETY: The correctness of the path is guaranteed by conversion to the
    // `CString` type above. For remaining parameters we provide a buffer with
    // length obtained through the previous call and we explicitly supply its
    // length as well. In case the result length increases between the calls the
    // system will report an error but will not cause memory issues.
    let len = unsafe {
        // Now we can call `listxattr` with the actual buffer of the size we
        // determined by the previous call.
        libc::listxattr(
            c_str_path.as_ptr(),
            buf.as_mut_ptr(), buf.len(),
            libc::XATTR_NOFOLLOW,
        )
    };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // It is possible that the `len` value is smaller than as returned by the
    // first `listxattr` call if somebody tampered with the file in the mean-
    // time. To avoid having spurious empty slices (as each following null byte
    // would cause the `split_inclusive` iterator to yield one), we trim the
    // buffer to the acutally returned length.
    //
    // Note that it is impossible for the `len` value to increase, as otherwise
    // the `listxattr` would fail.
    let result = buf[..len as usize]
        .split_inclusive(|byte| *byte == 0)
        .map(|slice| {
            // SAFETY: The slice is guaranteed to be terminated with a null byte
            // and not contain any null bytes elsewhere because of the splitting
            // above. This holds true also for the last slice provided by the
            // iterator.
            let c_str = unsafe {
                CStr::from_ptr(slice.as_ptr())
            };

            OsStr::from_bytes(c_str.to_bytes()).to_os_string()
        })
        .collect();

    Ok(result)
}

/// Collects value of a file extended attribute with the specified name.
pub fn ext_attr_value<P, S>(path: P, name: S) -> std::io::Result<Vec<u8>>
where
    P: AsRef<Path>,
    S: AsRef<OsStr>,
{
    use std::os::unix::ffi::OsStrExt as _;

    let os_str_path = path.as_ref().as_os_str();
    let c_str_path = CString::new(os_str_path.as_bytes())
        // Unlike on Linux where a null bytes in paths are not possible, HFS+
        // does allow such characters [1]. Thus, we have to handle such cases
        // gracefully.
        //
        // [1]: https://en.wikipedia.org/wiki/HFS_Plus
        .map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
        })?;

    let c_str_name = CString::new(name.as_ref().as_bytes())
        // While `name` as returned by the `ext_attr_names` function cannot have
        // null bytes inside, we cannot guarantee that the user doesn't supply
        // a bogus string here. Thus, we have to do proper error handling here.
        .map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
        })?;

    // SAFETY: The correctness of the path and name is guaranteed by conversion
    // to the `CString` type above. The rest is just is a FFI call respecting
    // the spec.
    let len = unsafe {
        // First we call `getxattr` with empty buffer to get the size of the
        // buffer that will collect the actual results.
        libc::getxattr(
            c_str_path.as_ptr(),
            c_str_name.as_ptr(),
            std::ptr::null_mut(), 0,
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut buf = vec![0; len as usize];
    let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;

    // SAFETY: The correctness of the path and name is guaranteed by conversion
    // to the `CString` type above. For remaining parameters we provide a buffer
    // with length obtained through the previous call and we explicitly supply
    // its length as well. In case the result length increases between the calls
    // the system will report an error but will not cause memory issues.
    let len = unsafe {
        // Now we can call `getxattr` with the actual buffer of the size we
        // determined by the previous call.
        libc::getxattr(
            c_str_path.as_ptr(),
            c_str_name.as_ptr(),
            buf_ptr, buf.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // In very rare cases (if the users tampers with the file inbetween calls to
    // the `getxattr`), the length value can decrease. To avoid returning any
    // garbage at the end, we have to truncate the buffer to its real length.
    buf.truncate(len as usize);
    Ok(buf)
}

/// Returns an iterator over mounted filesystems information.
pub fn mounts() -> std::io::Result<impl Iterator<Item = std::io::Result<Mount>>> {
    // We slap a lock on this function to at least partially mitigate issues
    // mentioned in multiple comments below. Note however, thay this lock does
    // not magically mean that there are no issues with the code below. Because
    // we cannot ensure that nobody else calls `getmntinfo` directly, all the
    // concerns are still valid, this only prevents users of the safe library
    // from shooting themselves in the foot.
    static MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let mutex = MUTEX.lock()
        .unwrap();

    let mut buf = std::mem::MaybeUninit::<*mut libc::statfs>::uninit();

    // SAFETY: This is actually not safe as the `getmntinfo` is most likely not
    // thread-safe (the documentation is pretty vague on this but since it works
    // through a reusable buffer, it almost certainly is not unless thread-local
    // storage is involved). But since possible issue happens not on the Rust
    // side, the worst can happen is we will get garbage data. So as long as we
    // put limited trust in the string buffers we parse later we should be good.
    let len = unsafe {
        libc::getmntinfo(buf.as_mut_ptr(), libc::MNT_NOWAIT)
    };
    if len == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: We verified that the function call succeeded, so the pointer to
    // the buffer is now initialized but the content of the buffer itself should
    // not be trusted. This is why we stay with the pointer and not convert it
    // to a Rust reference (that has to adhere to non-aliasing principles).
    let buf = unsafe {
        buf.assume_init()
    };

    let mut mounts = Vec::with_capacity(len as usize);
    for i in 0..(len as usize) {
        // SAFETY: This is the tricky part as we dereference pointer that can be
        // theoretically invalid at this point if another thread did call the
        // `getmntinfo` function. We treat this function as a black box and
        // consider two cases (we know for a fact that the first one is the real
        // one from studying the source code but since it is not documented, we
        // should not rely on that).
        //
        // In the first case there is a static buffer that is shared among all
        // threads. This is the reason why we don't convert the pointer to slice
        // ealier and continue to work with raw pointers. And this is also the
        // source of data race: by the time we do the dereference below another
        // thread might have already overriden the data. But the buffer itself
        // is static and all entries have constant size so in the worst case we
        // read some garbage data but we will not cause any buffer overflow (as
        // the pointer before was valid and the buffer is of the same length).
        //
        // In the second case, buffers are dynamically allocated (which should
        // not be the case because we are explicitly told not to free the memory
        // allocated for the buffer). But then we have no issue as each call to
        // `getmntinfo` gets different buffer.
        //
        // Theoretically there is a possibility of a third option: there is a
        // static pointer to a dynamically allocated buffer that is shrunk or
        // grown depending on how much results are going to take. We ignore that
        // this is possible as it means that such an operating system is beyond
        // any salvation anyway and we should let the bad guys roam there free.
        let mut statfs = unsafe {
            *buf.offset(i as isize)
        };

        // As mentioned before, the strings can contain garbage data, i.e. they
        // do not have to be properly null-terminated. For this reason we patch
        // them up by putting an artificial zero at the end. This means that we
        // can still return garbage names from this function but at leats there
        // is no memory safety issue.
        *statfs.f_fstypename.last_mut().unwrap() = 0;
        *statfs.f_mntonname.last_mut().unwrap() = 0;
        *statfs.f_mntfromname.last_mut().unwrap() = 0;

        // SAFETY: Because we patch the strings above we are sure that all the
        // safety invariants required by the `from_ptr` call are met. Note that
        // `statfs` is now on the stack, so the lifetime of this reference is
        // valid until the end of this scope.
        let source = unsafe {
            std::ffi::CStr::from_ptr(statfs.f_mntonname.as_ptr())
        }.to_string_lossy();
        // SAFETY: Same as above.
        let target = unsafe {
            std::ffi::CStr::from_ptr(statfs.f_mntfromname.as_ptr())
        }.to_bytes();
        // SAFETY: Same as above.
        let fs_type = unsafe {
            std::ffi::CStr::from_ptr(statfs.f_fstypename.as_ptr())
        }.to_string_lossy();

        use std::os::unix::ffi::OsStrExt as _;

        mounts.push(Mount {
            source: source.into_owned(),
            target: PathBuf::from(OsStr::from_bytes(target)),
            fs_type: fs_type.into_owned(),
        });
    }

    // All the relevant buffer data is already copied to our vector, we can
    // release the lock now and the buffer can be safely overridden.
    // TODO(@panhania): Replace with `Mutex::unlock` once it is stabilized [1].
    //
    // [1]: https://github.com/rust-lang/rust/issues/81872
    drop(mutex);

    Ok(mounts.into_iter().map(Ok))
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*;

    #[test]
    fn ext_attr_names_none() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();

        let ext_attr_names = ext_attr_names(tempfile.path()).unwrap();
        assert!(ext_attr_names.is_empty());
    }

    #[test]
    fn ext_attr_names_single() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        xattr(tempfile.path(), "user.foo", b"");

        let ext_attr_names = ext_attr_names(tempfile.path()).unwrap();
        assert_eq!(ext_attr_names, vec!["user.foo"]);
    }

    #[test]
    fn ext_attr_names_multiple() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        xattr(tempfile.path(), "user.abc", b"");
        xattr(tempfile.path(), "user.def", b"");
        xattr(tempfile.path(), "user.ghi", b"");

        let mut ext_attr_names = ext_attr_names(tempfile.path()).unwrap();
        ext_attr_names.sort();

        assert_eq!(ext_attr_names, vec!["user.abc", "user.def", "user.ghi"]);
    }

    #[test]
    fn ext_attr_value_not_existing() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();

        let error = ext_attr_value(tempfile.path(), "user.foo").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOATTR));
    }

    #[test]
    fn ext_attr_value_single() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        xattr(tempfile.path(), "user.foo", b"bar");

        let value = ext_attr_value(tempfile.path(), "user.foo").unwrap();
        assert_eq!(value, b"bar");
    }

    #[test]
    fn ext_attr_value_single_not_unicode() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        xattr(tempfile.path(), "user.foo", b"\xff\xfe\xff");

        let value = ext_attr_value(tempfile.path(), "user.foo").unwrap();
        assert_eq!(value, b"\xff\xfe\xff");
    }

    #[test]
    fn ext_attr_value_multiple() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        xattr(tempfile.path(), "user.foo", b"quux");
        xattr(tempfile.path(), "user.bar", b"norf");

        let foo_value = ext_attr_value(tempfile.path(), "user.foo").unwrap();
        assert_eq!(foo_value, b"quux");

        let bar_value = ext_attr_value(tempfile.path(), "user.bar").unwrap();
        assert_eq!(bar_value, b"norf");
    }

    pub(crate) fn xattr<P, S>(path: P, name: S, value: &[u8])
    where
        P: AsRef<Path>,
        S: AsRef<OsStr>,
    {
        use std::os::unix::ffi::OsStrExt as _;

        assert! {
            std::process::Command::new("xattr")
                .arg("-w")
                .arg(name)
                .arg(OsStr::from_bytes(value))
                .arg(path.as_ref().as_os_str())
                .status()
                .unwrap()
                .success()
        };
    }
}
