// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Linux-specific utilities for working with the filesystem.

use std::path::Path;

// TODO: Document behaviour for symlinks.
/// Collects extended flags of the specified file.
///
/// The returned mask represents file attributes specific to the Linux extended
/// file system. Normally, they can be inspected using the `lsattr` command and
/// can be set through the `chattr` command.
///
/// See the [Wikipedia] article and the [man] page for more details.
///
/// [Wikipedia]: https://en.wikipedia.org/wiki/Chattr
/// [man]: https://linux.die.net/man/1/chattr
///
/// # Examples
///
/// ```no_run
/// const FS_FL_USER_VISIBLE: u32 = 0x0003DFFF;
///
/// let flags = rrg::fs::linux::flags("/tmp/foo").unwrap();
/// assert_eq!(flags & FS_FL_USER_VISIBLE, 0);
/// ```
pub fn flags<P>(path: P) -> std::io::Result<u32> where
    P: AsRef<Path>
{
    let file = std::fs::File::open(path)?;

    let mut flags = 0;
    let code = unsafe {
        // This block is safe: we simply pass a raw file descriptor (that is
        // valid until the end of the scope of this function) because this is
        // what the low-level API expects.
        use std::os::unix::io::AsRawFd as _;
        ioctls::fs_ioc_getflags(file.as_raw_fd(), &mut flags)
    };

    if code == 0 {
        Ok(flags as u32)
    } else {
        Err(std::io::Error::from_raw_os_error(code))
    }
}

pub fn ext_attr_names<P>(path: P) -> std::io::Result<Vec<std::ffi::OsString>>
where
    P: AsRef<Path>,
{
    extern "C" {
        // https://linux.die.net/man/2/llistxattr
        fn llistxattr(
            path: *const libc::c_char,
            list: *mut libc::c_char,
            size: libc::size_t,
        ) -> libc::ssize_t;
    }

    use std::os::unix::ffi::OsStrExt as _;

    let os_str_path = path.as_ref().as_os_str();
    let c_str_path = std::ffi::CString::new(os_str_path.as_bytes())
        // It is not possible to have a null byte in a Linux path.
        .expect("path with a null character");

    // SAFETY: The correctness of the path is guaranteed by conversion to the
    // `CString` type above. The rest is just is a FFI call respecting the spec.
    let len = unsafe {
        // First we call `llistxattr` with empty buffer to get the size of the
        // buffer that will collect the actual results.
        llistxattr(c_str_path.as_ptr(), std::ptr::null_mut(), 0)
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
        // Now we can call `llistxattr` with the actual buffer of the size we
        // determined by the previous call.
        llistxattr(c_str_path.as_ptr(), buf.as_mut_ptr(), buf.len())
    };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // It is possible that the `len` value is smaller than as returned by the
    // first `llistxattr` call if somebody tampered with the file in the mean-
    // time. To avoid having spurious empty slices (as each following null byte
    // would cause the `split_inclusive` iterator to yield one), we trim the
    // buffer to the acutally returned length.
    //
    // Note that it is impossible for the `len` value to increase, as otherwise
    // the `llistxattr` would fail.
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

#[cfg(test)]
mod tests {

    use std::fs::File;

    use super::*;

    // TODO: Write tests for symlinks.

    #[test]
    fn test_flags_non_existing() {
        let tempdir = tempfile::tempdir().unwrap();

        assert!(flags(tempdir.path().join("foo")).is_err());
    }

    #[test]
    fn test_flags_noatime() {
        // https://elixir.bootlin.com/linux/v5.8.14/source/include/uapi/linux/fs.h#L245
        const FS_NOATIME_FL: std::os::raw::c_long = 0x00000080;

        let tempdir = tempfile::tempdir().unwrap();
        let tempfile = File::create(tempdir.path().join("foo")).unwrap();

        unsafe {
            use std::os::unix::io::AsRawFd as _;
            let fd = tempfile.as_raw_fd();

            assert_eq!(ioctls::fs_ioc_setflags(fd, &FS_NOATIME_FL), 0);
        }

        let flags = flags(tempdir.path().join("foo")).unwrap();
        assert_eq!(flags & FS_NOATIME_FL as u32, FS_NOATIME_FL as u32);
    }

    #[test]
    fn ext_attr_names_none() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();

        let ext_attr_names = ext_attr_names(tempfile.path()).unwrap();
        assert!(ext_attr_names.is_empty());
    }

    #[cfg(feature = "test-setfattr")]
    #[test]
    fn ext_attr_names_single() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        setfattr(tempfile.path(), "user.foo", b"");

        let ext_attr_names = ext_attr_names(tempfile.path()).unwrap();
        assert_eq!(ext_attr_names, vec!["user.foo"]);
    }

    #[cfg(feature = "test-setfattr")]
    #[test]
    fn ext_attr_names_multiple() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        setfattr(tempfile.path(), "user.foo", b"");
        setfattr(tempfile.path(), "user.bar", b"");
        setfattr(tempfile.path(), "user.baz", b"");

        let ext_attr_names = ext_attr_names(tempfile.path()).unwrap();
        assert_eq!(ext_attr_names, vec!["user.foo", "user.bar", "user.baz"]);
    }

    #[cfg(feature = "test-setfattr")]
    fn setfattr<P, S>(path: P, name: S, value: &[u8])
    where
        P: AsRef<std::path::Path>,
        S: AsRef<std::ffi::OsStr>,
    {
        use std::os::unix::ffi::OsStrExt as _;

        assert! {
            std::process::Command::new("setfattr")
                .arg("--name").arg(name)
                .arg("--value").arg(std::ffi::OsStr::from_bytes(value))
                .arg(path.as_ref().as_os_str())
                .status()
                .unwrap()
                .success()
        };
    }
}
