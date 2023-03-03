// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Linux-specific filesystem inspection functionalities.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::path::Path;

use super::*;

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
/// let flags = ospect::fs::linux::flags("/tmp/foo").unwrap();
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

/// Collects names of all extended attributes for the specified file.
pub fn ext_attr_names<P>(path: P) -> std::io::Result<Vec<OsString>>
where
    P: AsRef<Path>,
{
    use std::os::unix::ffi::OsStrExt as _;

    let os_str_path = path.as_ref().as_os_str();
    let c_str_path = CString::new(os_str_path.as_bytes())
        // It is not possible to have a null byte in a Linux path.
        .expect("path with a null character");

    // SAFETY: The correctness of the path is guaranteed by conversion to the
    // `CString` type above. The rest is just is a FFI call respecting the spec.
    let len = unsafe {
        // First we call `llistxattr` with empty buffer to get the size of the
        // buffer that will collect the actual results.
        libc::llistxattr(c_str_path.as_ptr(), std::ptr::null_mut(), 0)
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
        libc::llistxattr(c_str_path.as_ptr(), buf.as_mut_ptr(), buf.len())
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
        // It is not possible to have a null byte in a Linux path.
        .expect("path with a null character");

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
        // First we call `lgetxattr` with empty buffer to get the size of the
        // buffer that will collect the actual results.
        libc::lgetxattr(
            c_str_path.as_ptr(),
            c_str_name.as_ptr(),
            std::ptr::null_mut(),
            0,
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
        // Now we can call `lgetxattr` with the actual buffer of the size we
        // determined by the previous call.
        libc::lgetxattr(
            c_str_path.as_ptr(),
            c_str_name.as_ptr(),
            buf_ptr,
            buf.len(),
        )
    };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // In very rare cases (if the users tampers with the file inbetween calls to
    // the `lgetxattr`), the length value can decrease. To avoid returning any
    // garbage at the end, we have to truncate the buffer to its real length.
    buf.truncate(len as usize);
    Ok(buf)
}

/// Returns an iterator over mounted filesystems information.
pub fn mounts() -> std::io::Result<impl Iterator<Item = std::io::Result<Mount>>> {
    // We try to parse `/proc/mounts`, but if it does not exist we fallback to
    // `/etc/mtab` (which often is nowadays just a symlink to the former).
    let file = match std::fs::File::open("/proc/mounts") {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::File::open("/etc/mtab")?
        }
        Err(error) => return Err(error),
    };

    Ok(Mounts::new(file))
}

/// An iterator over mounted filesystems information.
struct Mounts<R: std::io::Read> {
    /// An mtab-like file to parse for mount information.
    reader: std::io::BufReader<R>,
    /// A reusable line buffer where mount entries are fed to.
    buf: String,
}

impl<R: std::io::Read> Mounts<R> {

    /// Creates a new instance of the iterator.
    fn new(reader: R) -> Mounts<R> {
        Mounts {
            reader: std::io::BufReader::new(reader),
            buf: String::new(),
        }
    }

    /// Parses data stored in the line buffer.
    fn parse_buf(&self) -> std::io::Result<Mount> {
        let mut cols = self.buf.split(' ');

        // There is more data in the file but we don't care for the time being
        // and only "parse" the first three columns.
        let source = cols.next()
            .ok_or_else(|| std::io::ErrorKind::InvalidData)?;
        let target = cols.next()
            .ok_or_else(|| std::io::ErrorKind::InvalidData)?;
        let fs_type = cols.next()
            .ok_or_else(|| std::io::ErrorKind::InvalidData)?;

        Ok(Mount {
            source: source.into(),
            target: target.into(),
            fs_type: fs_type.into(),
        })
    }
}

impl<R: std::io::Read> Iterator for Mounts<R> {

    type Item = std::io::Result<Mount>;

    fn next(&mut self) -> Option<std::io::Result<Mount>> {
        use std::io::BufRead as _;

        loop {
            self.buf.clear();
            match self.reader.read_line(&mut self.buf) {
                Ok(0) => return None,
                Ok(_) => (),
                Err(error) => return Some(Err(error)),
            }

            // We want to parse the buffer only if it is not blank. In general
            // blank lines should not happen but better safe then sorry.
            if !self.buf.trim().is_empty() {
                return Some(self.parse_buf())
            } else {
                continue;
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {

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
        setfattr(tempfile.path(), "user.abc", b"");
        setfattr(tempfile.path(), "user.def", b"");
        setfattr(tempfile.path(), "user.ghi", b"");

        let mut ext_attr_names = ext_attr_names(tempfile.path()).unwrap();
        ext_attr_names.sort();

        assert_eq!(ext_attr_names, vec!["user.abc", "user.def", "user.ghi"]);
    }

    #[test]
    fn ext_attr_value_not_existing() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();

        let error = ext_attr_value(tempfile.path(), "user.foo").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENODATA));
    }

    #[cfg(feature = "test-setfattr")]
    #[test]
    fn ext_attr_value_single() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        setfattr(tempfile.path(), "user.foo", b"bar");

        let value = ext_attr_value(tempfile.path(), "user.foo").unwrap();
        assert_eq!(value, b"bar");
    }

    #[cfg(feature = "test-setfattr")]
    #[test]
    fn ext_attr_value_single_not_unicode() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        setfattr(tempfile.path(), "user.foo", b"\xff\xfe\xff");

        let value = ext_attr_value(tempfile.path(), "user.foo").unwrap();
        assert_eq!(value, b"\xff\xfe\xff");
    }

    #[cfg(feature = "test-setfattr")]
    #[test]
    fn ext_attr_value_multiple() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        setfattr(tempfile.path(), "user.foo", b"quux");
        setfattr(tempfile.path(), "user.bar", b"norf");

        let foo_value = ext_attr_value(tempfile.path(), "user.foo").unwrap();
        assert_eq!(foo_value, b"quux");

        let bar_value = ext_attr_value(tempfile.path(), "user.bar").unwrap();
        assert_eq!(bar_value, b"norf");
    }

    #[cfg(feature = "test-setfattr")]
    pub(crate) fn setfattr<P, S>(path: P, name: S, value: &[u8])
    where
        P: AsRef<Path>,
        S: AsRef<OsStr>,
    {
        use std::os::unix::ffi::OsStrExt as _;

        assert! {
            std::process::Command::new("setfattr")
                .arg("--no-dereference")
                .arg("--name").arg(name)
                .arg("--value").arg(OsStr::from_bytes(value))
                .arg(path.as_ref().as_os_str())
                .status()
                .unwrap()
                .success()
        };
    }
}
