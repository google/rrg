// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Returns the time at which the system was installed.
pub fn installed() -> std::io::Result<std::time::SystemTime> {
    crate::os::unix::installed()
}

/// Returns the [`Kind`] of currently running operating system.
///
/// [`Kind`]: crate::os::Kind
pub fn kind() -> crate::os::Kind {
    crate::os::Kind::Linux
}

/// Returns the version string of the currently running operating system.
pub fn version() -> std::io::Result<String> {
    crate::os::unix::version()
}

/// Returns the CPU architecture of the currently running operating system.
pub fn arch() -> std::io::Result<String> {
    crate::os::unix::arch()
}

/// Returns the hostname of the currently running operating system.
pub fn hostname() -> std::io::Result<std::ffi::OsString> {
    crate::os::unix::hostname()
}

/// Returns the FQDN of the currently running operating system.
pub fn fqdn() -> std::io::Result<std::ffi::OsString> {
    crate::os::unix::fqdn()
}
