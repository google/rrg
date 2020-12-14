// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::path::PathBuf;

#[cfg(target_family = "unix")]
pub fn from_bytes(bytes: Vec<u8>) -> PathBuf {
    use std::os::unix::ffi::OsStringExt as _;
    std::ffi::OsString::from_vec(bytes).into()
}

#[cfg(target_family = "windows")]
pub fn from_bytes(bytes: Vec<u8>) -> PathBuf {
    // TODO: This is just a quick hack that treats UTF-8-encoded strings as
    // UTF-16. This works for trivial cases but should be reworked once the GRR
    // protocol for paths is defined.
    let bytes_u16 = bytes.iter().map(|byte| *byte as u16).collect::<Vec<_>>();

    use std::os::windows::ffi::OsStringExt as _;
    std::ffi::OsString::from_wide(&bytes_u16).into()
}
