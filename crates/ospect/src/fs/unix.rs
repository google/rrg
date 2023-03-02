// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Unix-specific utilities for working with the filesystem.

use std::path::Path;

/// Collects names of all extended attributes for the specified file.
pub fn ext_attr_names<P>(path: P) -> std::io::Result<Vec<std::ffi::OsString>>
where
    P: AsRef<Path>,
{
    #[cfg(target_os = "linux")]
    use super::linux::ext_attr_names;

    #[cfg(target_os = "macos")]
    use super::macos::ext_attr_names;

    ext_attr_names(path)
}

/// Collects value of a file extended attribute with the specified name.
pub fn ext_attr_value<P, S>(path: P, name: S) -> std::io::Result<Vec<u8>>
where
    P: AsRef<Path>,
    S: AsRef<std::ffi::OsStr>,
{
    #[cfg(target_os = "linux")]
    use super::linux::ext_attr_value;

    #[cfg(target_os = "macos")]
    use super::macos::ext_attr_value;

    ext_attr_value(path, name)
}
