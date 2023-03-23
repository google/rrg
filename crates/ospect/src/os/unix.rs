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
    let mut utsname = std::mem::MaybeUninit::uninit();

    // SAFETY: We just pass the buffer we allocated. The buffer is valid for the
    // entire scope of this function.
    let code = unsafe {
        libc::uname(utsname.as_mut_ptr())
    };
    if code < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: We verified that the call succeeded. It means that the call has
    // initialized the buffer and we can read from it.
    let utsname = unsafe {
        utsname.assume_init()
    };

    // SAFETY: All strings in `utsname` are guaranteed to be null-terminated. As
    // mentioned, the buffer is valid for the entire scope of the function and
    // we create an owned copy before we return, so the call is safe.
    Ok(unsafe {
        std::ffi::CStr::from_ptr(utsname.version.as_ptr())
    }.to_string_lossy().into_owned())
}
