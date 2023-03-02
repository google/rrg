// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::ffi::{OsStr, OsString};
use std::path::Path;

/// Collects names of all extended attributes for the specified file.
pub fn ext_attr_names<P>(_path: P) -> std::io::Result<Vec<OsString>>
where
    P: AsRef<Path>,
{
    // Windows does not support extended attributes, so we just do not yield any
    // results. Alternatively we could return an error, but `std` functions tend
    // no to do that (I think).
    Ok(Vec::new())
}

/// Collects value of a file extended attribute with the specified name.
pub fn ext_attr_value<P, S>(_path: P, _name: S) -> std::io::Result<Vec<u8>>
where
    P: AsRef<Path>,
    S: AsRef<OsStr>
{
    // Windows does not support extended attributes, so we return an error. Note
    // that this might seem to contradict with the behaviour of the previous
    // function where an empty result is returned. However, this function is a
    // bit different: we are asked to provide an attribute for the given name.
    // And since there is no attribute for the given name (or any in general),
    // we return an error.
    Err(std::io::ErrorKind::Unsupported.into())
}
