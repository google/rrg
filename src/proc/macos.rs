// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Returns an iterator yielding identifiers of all processes on the system.
pub fn ids() -> std::io::Result<impl Iterator<Item = std::io::Result<u32>>> {
    Ids::new()
}

/// A macOS-specific implementation of the iterator over process identifiers.
struct Ids {
    /// An iterator over the process metadata returned by a `sysctl` call.
    iter: std::vec::IntoIter<crate::libc::kinfo_proc>,
}

impl Ids {

    /// Creates a new iterator over system process identifiers.
    fn new() -> std::io::Result<Ids> {
        const KINFO_PROC_SIZE: usize = {
            std::mem::size_of::<crate::libc::kinfo_proc>()
        };

        let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ALL];

        let mut buf_size = std::mem::MaybeUninit::uninit();

        // SAFETY: We call the `sysctl` function as described in the FreeBSD
        // documentation [1] (macOS's kernel derives from FreeBSD). We check for
        // errors afterwards.
        //
        // This is the first call where we don't pass any buffer and we just
        // want to estimate the size of the buffer to hold the data. It should
        // be returned thought the fourth (`oldlenp`) argument.
        //
        // Note that the `namelen` parameter (second argument) is the _length_
        // of the array passed as the `name` argument (not size in bytes), while
        // the remaining two expect size in bytes.
        //
        // [1]: https://man.freebsd.org/cgi/man.cgi?sysctl(3)
        let code = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(), mib.len() as libc::c_uint,
                std::ptr::null_mut(), buf_size.as_mut_ptr(),
                std::ptr::null_mut(), 0,
            )
        };
        if code != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // SAFETY: If the call to `sysctl` succeeded, we can assume that the
        // `buf_size` no is filled with the expected size of the buffer.
        let mut buf_size = unsafe {
            buf_size.assume_init()
        } as usize;

        let mut buf_len = buf_size / KINFO_PROC_SIZE;
        if buf_size % KINFO_PROC_SIZE != 0 {
            buf_len += 1;
        }

        let mut buf = Vec::<crate::libc::kinfo_proc>::with_capacity(buf_len);

        // SAFETY: We create a buffer of the size specified by the previous call
        // to `sysctl`. Note that between the two calls the required buffer size
        // might have changed in which case `ENOMEM` ought to be returned. The
        // operating system should round up the required buffer size to handle
        // such cases. We verify whether the call succeeded below.
        //
        // The rest is as with the `sysctl` call above (not the comment about
        // the length parameters).
        let code = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(), mib.len() as libc::c_uint,
                buf.as_mut_ptr().cast::<libc::c_void>(), &mut buf_size,
                std::ptr::null_mut(), 0,
            )
        };
        if code != 0 {
            return Err(std::io::Error::last_os_error());
        }

        if buf_size % KINFO_PROC_SIZE != 0 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }

        let buf_len = buf_size / KINFO_PROC_SIZE;

        // SAFETY: The `syctl` call succeeded and we calculated the length of
        // the buffer above.
        unsafe {
            buf.set_len(buf_len);
        }

        Ok(Ids {
            iter: buf.into_iter(),
        })
    }
}

impl Iterator for Ids {

    type Item = std::io::Result<u32>;

    fn next(&mut self) -> Option<std::io::Result<u32>> {
        use std::convert::TryFrom as _;

        let proc = self.iter.next()?;

        let pid = match u32::try_from(proc.kp_proc.p_pid) {
            Ok(pid) => pid,
            Err(error) => {
                use std::io::{Error, ErrorKind};
                return Some(Err(Error::new(ErrorKind::InvalidData, error)));
            },
        };

        Some(Ok(pid))
    }
}
