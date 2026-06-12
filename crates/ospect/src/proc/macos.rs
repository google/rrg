// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Returns an iterator yielding identifiers of all processes on the system.
pub fn ids() -> std::io::Result<impl Iterator<Item = std::io::Result<u32>>> {
    Ok(sysctl_kern_proc()?.into_iter().map(|proc| {
        u32::try_from(proc.kp_proc.p_pid)
            .map_err(|error| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error,
            ))
    }))
}

/// Returns an iterator yielding metadata for all processes on the system.
pub fn all() -> std::io::Result<impl Iterator<Item = std::io::Result<Metadata>>> {
    Ok(sysctl_kern_proc()?.into_iter().map(|proc| Ok(Metadata {
        proc,
        proc_args: sysctl_kern_procargs2(proc.kp_proc.p_pid),
    })))
}

/// Metadata about the process (specific to macOS).
pub struct Metadata {
    proc: crate::libc::kinfo_proc,
    proc_args: std::io::Result<Vec<u8>>,
}

impl Metadata {

    /// PID of the process this metadata corresponds to.
    pub fn id(&self) -> u32 {
        u32::try_from(self.proc.kp_proc.p_pid)
            // PID for a live process should never be negative and sign is used
            // only for special return values or arguments.
            .unwrap_or(0)
    }

    /// PID of the parent of the process this metadata corresponds to.
    pub fn parent_id(&self) -> u32 {
        u32::try_from(self.proc.kp_eproc.e_ppid)
            // PID for a live process should never be negative and sign is used
            // only for special return values or arguments.
            .unwrap_or(0)
    }

    /// Returns name of the process.
    pub fn name(&self) -> std::ffi::OsString {
        use std::os::unix::ffi::OsStrExt as _;

        let name_bytes = self.proc.kp_proc.p_comm.map(|byte| byte as u8);
        // Name is null-terminated so we need to take it only until the null
        // byte.
        let name_bytes = match name_bytes.iter().position(|byte| *byte == 0) {
            Some(idx) => &name_bytes[..idx],
            // This should not happen as the string has to be null-terminated
            // but just to be on the safe side, we don't panic and just take the
            // full string.
            None => &name_bytes[..],
        };

        std::ffi::OsStr::from_bytes(name_bytes).to_os_string()
    }

    pub fn args(&self) -> std::io::Result<Args<'_>> {
        let proc_args = self.proc_args.as_ref()
            // `std::io::Error` does not implement `Clone` so we have to do the
            // little dance below.
            .map_err(|error| match error.raw_os_error() {
                Some(error) => std::io::Error::from_raw_os_error(error),
                None => std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "unexpected error",
                ),
            })?;

        let argc_bytes = <[u8; 4]>::try_from(&proc_args[0..4])
            .map_err(|error| std::io::Error::new(
                std::io::ErrorKind::Other,
                error,
            ))?;
        let argc = usize::try_from(libc::c_int::from_ne_bytes(argc_bytes))
            .map_err(|error| std::io::Error::new(
                std::io::ErrorKind::Other,
                error,
            ))?;

        // We start at index `4` because of the argc placed at the beginning
        // which we parsed already.
        let mut buf_index = 4;
        // Then we need to skip the executable path that is placed in the
        // buffer. The executable path is null-terminated.
        buf_index += &proc_args[buf_index..].iter().position(|byte| *byte == 0)
            .unwrap_or(0);
        // The executable path is not only null-terminated but also null-padded,
        // so we need to skip this padding as well.
        buf_index += &proc_args[buf_index..].iter().position(|byte| *byte != 0)
            .unwrap_or(0);

        Ok(Args {
            argv: &proc_args[buf_index..],
            argc_left: argc,
        })
    }
}

/// Iterator over the arguments of the process.
pub struct Args<'m> {
    /// Slice of the buffer with process argument data as returned by the kernel
    /// from the `KERN_PROCARGS2` system call.
    argv: &'m [u8],
    /// Number of arguments left to yield.
    ///
    /// This is needed because the buffer might be actually bigger than the
    /// data it holds, so we would not know where to end otherwise. Moreover, it
    /// allows as to implement `ExactSizeIterator` for the type.
    argc_left: usize,
}

impl<'m> Iterator for Args<'m> {

    type Item = std::ffi::OsString;

    fn next(&mut self) -> Option<std::ffi::OsString> {
        if self.argc_left == 0 {
            return None;
        }

        dbg!(String::from_utf8_lossy(&self.argv));

        let Some(index) = self.argv.iter().position(|byte| *byte == 0) else {
            // This should generally never happen as all arguments should be
            // null-terminated.
            return None;
        };

        use std::os::unix::ffi::OsStrExt as _;
        let result = std::ffi::OsStr::from_bytes(&self.argv[..index])
            .to_os_string();

        // `+ 1` because we want to skip the null byte.
        self.argv = &self.argv[index + 1..];
        self.argc_left -= 1;

        Some(result)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.argc_left, Some(self.argc_left))
    }
}

impl<'m> ExactSizeIterator for Args<'m> {
}

fn sysctl_kern_proc() -> std::io::Result<Vec<crate::libc::kinfo_proc>> {
    const KINFO_PROC_SIZE: usize = {
        std::mem::size_of::<crate::libc::kinfo_proc>()
    };

    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_ALL,
    ];

    let mut buf_size = std::mem::MaybeUninit::uninit();

    // SAFETY: We call the `sysctl` function as described in the FreeBSD
    // documentation [1] (macOS's kernel derives from FreeBSD). We check for
    // errors afterwards.
    //
    // This is the first call where we don't pass any buffer and we just want
    // to estimate the size of the buffer to hold the data. It should be
    // returned thought the fourth (`oldlenp`) argument.
    //
    // Note that the `namelen` parameter (second argument) is the _length_ of
    // the array passed as the `name` argument (not size in bytes), while the
    // remaining two expect size in bytes.
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

    // SAFETY: We create a buffer of the size specified by the previous call to
    // `sysctl`. Note that between the two calls the required buffer size might
    // have changed in which case `ENOMEM` ought to be returned. The operating
    // system should round up the required buffer size to handle such cases. We
    // verify whether the call succeeded below.
    //
    // The rest is as with the `sysctl` call above (note the comment about the
    // length parameters).
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

    Ok(buf)
}

fn sysctl_kern_procargs2(pid: libc::pid_t) -> std::io::Result<Vec<u8>> {
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROCARGS2,
        pid as libc::c_int,
    ];

    let mut buf_size = std::mem::MaybeUninit::uninit();

    // SAFETY: We call the `sysctl` function as described in the FreeBSD
    // documentation [1] (macOS's kernel derives from FreeBSD). We check for
    // errors afterwards.
    //
    // Note that the `KERN_PROCARGS2` sytem call that we use here is not
    // documented in the official documentation [2] but we can see how it
    // works in the kernel source [3].
    //
    // Despite the call being undocumented this code should not cause any
    // undefined behaviour: we pass input and output buffers along with its
    // size. In the worst case we will get back garbage data but we will
    // only access memory that we explicitly allocated and own.
    //
    // This is the first call where we don't pass any buffer and we just
    // want to estimate the size of the buffer to hold the data. It should
    // be returned thought the fourth (`oldlenp`) argument.
    //
    // [1]: https://man.freebsd.org/cgi/man.cgi?sysctl(3)
    // [2]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/sysctl.3.html
    // [3]: https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_sysctl.c#L1300-L1326
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
    // `buf_size` is now filled with the expected size of the buffer.
    let mut buf_size = unsafe {
        buf_size.assume_init()
    };
    // Note that we do not need to worry about any alignment issues (the
    // kernel writes an `i32` with the argument count to the beginning of
    // the buffer) as it is not used directly but instead the kernel makes
    // its copy in the kernel space and uses that instead.
    let mut buf = vec![0u8; buf_size as usize];

    // SAFETY: We create a buffer of the size specified by the previous call
    // to `sysctl`. We verify whether the call succeeded below.
    //
    // The rest is as with the `sysctl` call above.
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

    Ok(buf)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn all_self_exists() {
        let metadata = all()
            .unwrap().filter_map(Result::ok)
            .find(|metadata| metadata.id() == std::process::id())
            .unwrap();

        assert_eq!(metadata.parent_id(), std::os::unix::process::parent_id());

        let mut args = metadata.args().unwrap();
        let mut args_env = std::env::args_os();

        for (arg, arg_env) in args.by_ref().zip(args_env.by_ref()) {
            assert_eq!(arg, arg_env);
        }
        assert_eq!(args.next(), None);
        assert_eq!(args_env.next(), None);
    }

    #[test]
    fn all_launchd_exists() {
        let metadata = all()
            .unwrap().filter_map(Result::ok)
            .find(|metadata| metadata.id() == 1)
            .unwrap();

        assert_eq!(metadata.parent_id(), 0);
        assert_eq!(metadata.name(), "launchd");
    }

    #[test]
    fn all_subprocess() {
        // TODO(rust-lang/rust#144426): Simplify once `drop_guard` is stable.
        struct ChildDropGuard(std::process::Child);
        impl Drop for ChildDropGuard {
            fn drop(&mut self) {
                // We ignore errors as there is not much we can do when
                // dropping.
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let cat = std::process::Command::new("cat")
            // We want to have some argument to verify that argument retrival
            // works and we want to block until the stdin is not closed. `-`
            // strikes both.
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn().unwrap();

        // We need to use a guard because `std::process::Command` does not end
        // on its own at the end of the scope unless we `wait`.
        let cat = ChildDropGuard(cat);

        let metadata = all().unwrap().filter_map(Result::ok)
            .find(|metadata| metadata.id() == cat.0.id()).unwrap();

        assert_eq!(metadata.parent_id(), std::process::id());
        assert_eq!(metadata.name(), "cat");

        let mut args = metadata.args().unwrap();
        assert_eq!(args.next().unwrap(), "cat");
        assert_eq!(args.next().unwrap(), "-");
        assert_eq!(args.next(), None);
    }
}
