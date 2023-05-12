// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Returns the time at which the system was installed.
pub fn installed() -> std::io::Result<std::time::SystemTime> {
    let root_metadata = std::fs::metadata("/")?;
    root_metadata.created()
}

/// Returns the version string of the currently running operating system.
pub fn version() -> std::io::Result<String> {
    let uname = uname()?;

    // SAFETY: All strings in `utsname` are guaranteed to be null-terminated. As
    // mentioned, the buffer is valid for the entire scope of the function and
    // we create an owned copy before we return, so the call is safe.
    Ok(unsafe {
        std::ffi::CStr::from_ptr(uname.version.as_ptr())
    }.to_string_lossy().into_owned())
}

/// Returns the hostname of the currently running operating system.
pub fn hostname() -> std::io::Result<String> {
    let uname = uname()?;

    // SAFETY: All strings in `utsname` are guaranteed to be null-terminated. As
    // mentioned, the buffer is valid for the entire scope of the function and
    // we create an owned copy before we return, so the call is safe.
    Ok(unsafe {
        std::ffi::CStr::from_ptr(uname.nodename.as_ptr())
    }.to_string_lossy().into_owned())
}

/// Returns the FQDN of the currently running operating system.
pub fn fqdn() -> std::io::Result<String> {
    let uname = uname()?;

    let hints = libc::addrinfo {
        ai_family: libc::AF_UNSPEC, // `AF_UNSPEC` means "any family".
        ai_socktype: 0, // 0 means "any type".
        ai_protocol: 0, // 0 means "any protocol".
        ai_flags: libc::AI_CANONNAME,
        // The following fields are irrelevant for `getaddrinfo` call.
        ai_addrlen: 0,
        ai_addr: std::ptr::null_mut(),
        ai_canonname: std::ptr::null_mut(),
        ai_next: std::ptr::null_mut(),
    };

    let mut info = std::mem::MaybeUninit::uninit();

    // SAFETY: We call the function as described in the documentation [1] and
    // verify the return code below. In case of success, we free the memory at
    // the end of the function.
    //
    // [1]: https://man7.org/linux/man-pages/man3/getaddrinfo.3.html
    let code = unsafe {
        libc::getaddrinfo(
            uname.nodename.as_ptr(),
            std::ptr::null(),
            &hints,
            info.as_mut_ptr(),
        )
    };
    if code != 0 {
        // Ideally, we should use `gai_strerror` to get a human-friendly message
        // of the error. Unfortunately, it is not clear whether this function is
        // or is not thread-safe so we just return a generic error.
        use std::io::{Error, ErrorKind::Other};
        return Err(Error::new(Other, "`getaddrinfo` failure"))
    }

    // SAFETY: We verified that the call succeeded. It means that the call has
    // initialized the pointer and we can read from it.
    let info = unsafe {
        info.assume_init()
    };

    // SAFETY: We have verified that the call for which we specified the
    // `AI_CANONNAME` flag succeeded, to the `ai_canonname` is pointing to the
    // name of the host. We create an owned copy of the value and free the
    // memory afterwards.
    let fqdn = unsafe {
        std::ffi::CStr::from_ptr((*info).ai_canonname)
    }.to_string_lossy().into_owned();

    // SAFETY: `fqdn` has been copied and no references are kept around, so we
    // can release the memory now.
    unsafe {
        libc::freeaddrinfo(info);
    }

    Ok(fqdn)
}

/// Returns `uname` information of the currently running operating system.
fn uname() -> std::io::Result<libc::utsname> {
    let mut uname = std::mem::MaybeUninit::uninit();

    // SAFETY: We just pass the buffer we allocated. The buffer is valid for the
    // entire scope of this function.
    let code = unsafe {
        libc::uname(uname.as_mut_ptr())
    };
    if code < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: We verified that the call succeeded. It means that the call has
    // initialized the buffer and we can read from it.
    let uname = unsafe {
        uname.assume_init()
    };

    Ok(uname)
}
