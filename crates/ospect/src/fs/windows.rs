// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Windows-specific filesystem inspection functionalities.

use std::ffi::{OsStr, OsString};
use std::path::Path;

use super::*;

/// Collects names of all extended attributes for the specified file.
pub fn ext_attr_names<P>(_path: P) -> std::io::Result<Vec<OsString>>
where
    P: AsRef<Path>,
{
    // Windows does not support extended file attributes, so we just error out.
    Err(std::io::ErrorKind::Unsupported.into())
}

/// Collects value of a file extended attribute with the specified name.
pub fn ext_attr_value<P, S>(_path: P, _name: S) -> std::io::Result<Vec<u8>>
where
    P: AsRef<Path>,
    S: AsRef<OsStr>,
{
    // Windows does not support extended file attributes, so we just error out.
    Err(std::io::ErrorKind::Unsupported.into())
}

/// Returns an iterator over mounted filesystems information.
pub fn mounts() -> std::io::Result<impl Iterator<Item = std::io::Result<Mount>>> {
    // TODO(@panhania): Implement this. See [1] for details how it can be done.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/fileio/enumerating-volume-mount-points
    let error = std::io::ErrorKind::Unsupported.into();
    Err::<std::iter::Empty<std::io::Result<Mount>>, _>(error)
}
