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
pub fn ext_attr_names<P>(path: P) -> std::io::Result<Vec<OsString>>
where
    P: AsRef<Path>,
{
    self::sys::ext_attr_names(path)
}

/// Collects value of a file extended attribute with the specified name.
pub fn ext_attr_value<P, S>(path: P, name: S) -> std::io::Result<Vec<u8>>
where
    P: AsRef<Path>,
    S: AsRef<OsStr>
{
    self::sys::ext_attr_value(path, name)
}
