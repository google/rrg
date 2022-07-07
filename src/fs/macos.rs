//! macOS-specific utilities for working with the filesystem.

/// Collects names of all extended attributes for the specified file.
///
/// This function is a wrapper around the `listxattr` macOS call.
///
/// See [`ext_attr_names`] from the Unix module for more details.
///
/// [`ext_attr_names`]: super::unix::ext_attr_names
pub fn ext_attr_names<P>(path: P) -> std::io::Result<Vec<std::ffi::OsString>>
where
    P: AsRef<std::path::Path>,
{
    extern "C" {
        // https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/listxattr.2.html
        fn listxattr(
            path: *const libc::c_char,
            namebuf: *mut libc::c_char,
            size: libc::size_t,
            options: libc::c_int,
        ) -> libc::ssize_t;
    }

    use std::os::unix::ffi::OsStrExt as _;

    let os_str_path = path.as_ref().as_os_str();
    let c_str_path = std::ffi::CString::new(os_str_path.as_bytes())
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
        listxattr(
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
        listxattr(
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
                std::ffi::CStr::from_ptr(slice.as_ptr())
            };

            std::ffi::OsStr::from_bytes(c_str.to_bytes()).to_os_string()
        })
        .collect();

    Ok(result)
}

/// Collects value of a file extended attribute with the specified name.
///
/// This function is a wrapper around the `getxattr` macOS call.
///
/// See [`ext_attr_value`] from the Unix module for more details.
///
/// [`ext_attr_value`]: super::unix::ext_attr_names
pub fn ext_attr_value<P, S>(path: P, name: S) -> std::io::Result<Vec<u8>>
where
    P: AsRef<std::path::Path>,
    S: AsRef<std::ffi::OsStr>,
{
    extern "C" {
        // https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getxattr.2.html#//apple_ref/doc/man/2/getxattr
        fn getxattr(
            path: *const libc::c_char,
            name: *const libc::c_char,
            value: *mut libc::c_void,
            size: libc::size_t,
            position: u32,
            options: libc::c_int,
        ) -> libc::ssize_t;
    }

    use std::os::unix::ffi::OsStrExt as _;

    let os_str_path = path.as_ref().as_os_str();
    let c_str_path = std::ffi::CString::new(os_str_path.as_bytes())
        // Unlike on Linux where a null bytes in paths are not possible, HFS+
        // does allow such characters [1]. Thus, we have to handle such cases
        // gracefully.
        //
        // [1]: https://en.wikipedia.org/wiki/HFS_Plus
        .map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
        })?;

    let c_str_name = std::ffi::CString::new(name.as_ref().as_bytes())
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
        getxattr(
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
        getxattr(
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

#[cfg(test)]
mod tests {

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
        xattr(tempfile.path(), "user.foo", b"");
        xattr(tempfile.path(), "user.bar", b"");
        xattr(tempfile.path(), "user.baz", b"");

        let ext_attr_names = ext_attr_names(tempfile.path()).unwrap();
        assert_eq!(ext_attr_names, vec!["user.foo", "user.bar", "user.baz"]);
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

    fn xattr<P, S>(path: P, name: S, value: &[u8])
    where
        P: AsRef<std::path::Path>,
        S: AsRef<std::ffi::OsStr>,
    {
        use std::os::unix::ffi::OsStrExt as _;

        assert! {
            std::process::Command::new("xattr")
                .arg("-w")
                .arg(name)
                .arg(std::ffi::OsStr::from_bytes(value))
                .arg(path.as_ref().as_os_str())
                .status()
                .unwrap()
                .success()
        };
    }
}
