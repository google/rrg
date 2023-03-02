// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Filesystem inspection functionalities.

use std::ffi::{OsStr, OsString};
use std::path::Path;

// TODO(@panhania): Define common interface for all platforms and hide these
// modules.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

mod sys {
    #[cfg(target_os = "linux")]
    pub use crate::fs::linux::*;

    #[cfg(target_os = "macos")]
    pub use crate::fs::macos::*;

    #[cfg(target_os = "windows")]
    pub use crate::fs::windows::*;
}

#[cfg(target_family = "unix")]
pub mod unix;

/// Collects names of all extended attributes for the specified file.
///
/// The exact behaviour is system-specific:
///
///   * On Linux it uses the [`llistxattr`] call.
///   * On macOS it uses the [`listxattr`] call.
///   * On Windows there are no extended file attributes and the call fails.
///
/// In case of a symlink this function returns the extended attributes of the
/// link itself and not the file pointed by it.
///
/// [`llistxattr`]: https://man7.org/linux/man-pages/man2/listxattr.2.html
/// [`listxattr`]:https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/listxattr.2.html
///
/// # Errors
///
/// This function will fail if the specified file does not exist, the process
/// does not have permission to access the file, the operation is not supported
/// by the platform or if any other system error is raised.
///
/// # Examples
///
/// ```no_run
/// let names = ospect::fs::ext_attr_names("/tmp/foo")
///     .unwrap();
///
/// println!("{} attributes found", names.len());
/// for name in names {
///     println!("'{}'", name.to_string_lossy());
/// }
/// ```
pub fn ext_attr_names<P>(path: P) -> std::io::Result<Vec<OsString>>
where
    P: AsRef<Path>,
{
    self::sys::ext_attr_names(path)
}

/// Collects value of a file extended attribute with the specified name.
///
/// The exact behaviour is system-specific:
///
///   * On Linux it uses the [`lgetxattr`] call.
///   * On macOS it uses the [`getxattr`] call.
///   * On Windows there are no extended attributes and the call fails.
///
/// In case of a symlink this function returns the extended attributes of the
/// link itself and not the file pointed by it.
///
/// [`lgetxattr`]: https://man7.org/linux/man-pages/man2/getxattr.2.html
/// [`getxattr`]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getxattr.2.html#//apple_ref/doc/man/2/getxattr
///
/// # Errors
///
/// This function will fail if the specified file or the attribute do not exist,
/// the process does not have permission to access the file, the opreation is
/// supported by the platform or if any other system error is raised.
///
/// # Examples
///
/// ```no_run
/// let value = ospect::fs::ext_attr_value("/tmp/foo", "user.bar")
///     .unwrap();
///
/// println!("'user.bar': '{}'", String::from_utf8_lossy(&value));
/// ```
pub fn ext_attr_value<P, S>(path: P, name: S) -> std::io::Result<Vec<u8>>
where
    P: AsRef<Path>,
    S: AsRef<OsStr>
{
    self::sys::ext_attr_value(path, name)
}
