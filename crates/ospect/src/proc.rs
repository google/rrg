// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

mod sys {
    #[cfg(target_os = "linux")]
    pub use crate::proc::linux::*;

    #[cfg(target_os = "macos")]
    pub use crate::proc::macos::*;

    #[cfg(target_os = "windows")]
    pub use crate::proc::windows::*;
}

/// Returns an iterator yielding identifiers of all processes on the system.
///
/// The order in which the identifiers are yield is not defined.
///
/// # Errors
///
/// The function will return an error if the operating system does not allow
/// get the required information (e.g. in case of insufficient permissions).
///
/// # Examples
///
/// ```
/// let mut pids = ospect::proc::ids()
///     .unwrap();
///
/// assert! {
///     pids.find(|pid| *pid.as_ref().unwrap() == std::process::id()).is_some()
/// };
/// ```
pub fn ids() -> std::io::Result<impl Iterator<Item = std::io::Result<u32>>> {
    self::sys::ids()
}
