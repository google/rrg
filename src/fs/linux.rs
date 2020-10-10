// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Linux-specific utilities for working with the filesystem.

use std::path::Path;

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
        use std::os::unix::io::AsRawFd as _;
        ioctls::fs_ioc_getflags(file.as_raw_fd(), &mut flags)
    };

    if code == 0 {
        Ok(flags as u32)
    } else {
        Err(std::io::Error::from_raw_os_error(code))
    }
}

#[cfg(test)]
mod tests {

    use std::fs::File;

    use super::*;

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
}
