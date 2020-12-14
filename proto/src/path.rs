// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::path::PathBuf;

/// Interprets given bytes as an operating system path.
///
/// On Linux, the path is constructed from bytes as is since system paths can
/// be made of arbitrary sequence of bytes.
///
/// On Windows, the behaviour is unspecified (for now).
///
/// # Examples
///
/// ```
/// use std::ffi::OsStr;
///
/// let path = rrg_proto::path::from_bytes(b"foo/bar/baz".to_vec());
///
/// let mut components = path.components()
///     .map(|component| component.as_os_str());
///
/// assert_eq!(components.next(), Some(OsStr::new("foo")));
/// assert_eq!(components.next(), Some(OsStr::new("bar")));
/// assert_eq!(components.next(), Some(OsStr::new("baz")));
/// assert_eq!(components.next(), None);
/// ```
pub fn from_bytes(bytes: Vec<u8>) -> PathBuf {
    from_bytes_impl(bytes)
}

/// Serializes given path to a byte sequence.
///
/// On Linux, the path is emitted as is since system paths can consist of
/// arbitrary bytes.
///
/// On Windows, the behaviour is unspecified (for now).
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
///
/// let path = PathBuf::from("foo/bar/baz");
/// assert_eq!(rrg_proto::path::to_bytes(path), b"foo/bar/baz");
/// ```
pub fn to_bytes(path: PathBuf) -> Vec<u8> {
    to_bytes_impl(path)
}

#[cfg(target_family = "unix")]
fn from_bytes_impl(bytes: Vec<u8>) -> PathBuf {
    use std::os::unix::ffi::OsStringExt as _;
    std::ffi::OsString::from_vec(bytes).into()
}

#[cfg(target_family = "windows")]
fn from_bytes_impl(bytes: Vec<u8>) -> PathBuf {
    // TODO: This is just a quick hack that treats UTF-8-encoded strings as
    // UTF-16. This works for trivial cases but should be reworked once the GRR
    // protocol for paths is defined.
    let bytes_u16 = bytes.iter().map(|byte| *byte as u16).collect::<Vec<_>>();

    use std::os::windows::ffi::OsStringExt as _;
    std::ffi::OsString::from_wide(&bytes_u16).into()
}

#[cfg(target_family = "unix")]
fn to_bytes_impl(path: PathBuf) -> Vec<u8> {
    use std::os::unix::ffi::OsStringExt as _;
    std::ffi::OsString::from(path).into_vec()
}

#[cfg(target_family = "windows")]
fn to_bytes_impl(path: PathBuf) -> Vec<u8> {
    let string = std::ffi::OsString::from(path);

    // TODO: See explanation in `from_bytes_impl` on Windows.
    use std::os::windows::ffi::OsStrExt as _;
    string.as_os_str().encode_wide().map(|byte| byte as u8).collect()
}
