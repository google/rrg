// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_family = "unix")]
mod unix;

#[cfg(target_os = "windows")]
mod windows;

mod sys {
    #[cfg(target_os = "linux")]
    pub use crate::os::linux::*;

    #[cfg(target_os = "macos")]
    pub use crate::os::macos::*;

    #[cfg(target_os = "windows")]
    pub use crate::os::windows::*;
}

// TODO(@panhania): Enable the example to run once the method is supported on
// platforms.
/// Returns the time at which the system was installed.
///
/// Note that this function uses various heuristics to estimate the installation
/// time and they might not really be be accurate. Very often various system
/// updates can "bump" the timestamps that this function considers.
///
/// # Errors
///
/// This function will return an error in case there was some error when trying
/// to query data from the system.
///
/// # Examples
///
/// ```no_run
/// let time = ospect::os::installed()
///     .unwrap();
///
/// assert!(time < std::time::SystemTime::now());
/// ```
pub fn installed() -> std::io::Result<std::time::SystemTime> {
    self::sys::installed()
}

/// A list of operating systems that the library is guaranteed to run on.
pub enum Kind {
    Linux,
    Macos,
    Windows,
}

/// Returns the [`Kind`] of currently running operating system.
///
/// [`Kind`]: crate::os::Kind
pub fn kind() -> Kind {
    self::sys::kind()
}

/// Returns the version string of the currently running operating system.
///
/// No assumptions on the specific format of this string should be made and the
/// output can vary between operating system versions, distributions and even
/// `ospect` releases.
///
/// # Errors
///
/// This function will return an error in case there was some issue when trying
/// to query data from the system.
pub fn version() -> std::io::Result<String> {
    self::sys::version()
}

/// Returns the CPU architecture of the currently running operating system.
///
/// No assumptions on the specific format of this string should be made. Even
/// the same architecture can be reported in different ways depending on the
/// operating system or even its version (e.g. a 64-bit ARM-based architecture
/// can be reported as `arm64` or `aarch64`).
pub fn arch() -> std::io::Result<String> {
    self::sys::arch()
}

/// Returns the hostname of the currently running operating system.
///
/// # Errors
///
/// This function will return an error in case there was some issue when trying
/// to query data from the system.
pub fn hostname() -> std::io::Result<std::ffi::OsString> {
    self::sys::hostname()
}

/// Returns the FQDN of the currently running operating system.
///
/// Note that FQDN retrival is not reliable on all operating systems and in some
/// cases just a hostname can be returned instead (depending on the configration
/// of the sepcific system).
///
/// # Errors
///
/// This function will return an error in case there was some issue when trying
/// to query data from the system.
pub fn fqdn() -> std::io::Result<std::ffi::OsString> {
    self::sys::fqdn()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn version_not_empty() {
        assert!(!version().unwrap().is_empty());
    }

    #[test]
    // TODO(@panhania): Enable onc `arch` is implemented on Windows.
    #[cfg_attr(target_os = "windows", ignore)]
    fn arch_not_empty() {
        assert!(!arch().unwrap().is_empty());
    }

    #[test]
    fn hostname_not_empty() {
        assert!(!hostname().unwrap().is_empty());
    }

    #[test]
    fn fqdn_not_empty() {
        assert!(!fqdn().unwrap().is_empty());
    }
}
