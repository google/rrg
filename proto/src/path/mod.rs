// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#[cfg(any(target_os = "windows", test))]
mod wtf8;

use std::path::PathBuf;

/// Interprets given bytes as an operating system path.
///
/// On Linux, the path is constructed from bytes as is since system paths can
/// be made of arbitrary sequence of bytes.
///
/// On Windows, the [WTF-8][wtf8] encoding is used.
///
/// [wtf8]: https://simonsapin.github.io/wtf-8
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
/// On Windows, the [WTF-8][wtf8] encoding is used.
///
/// [wtf8]: https://simonsapin.github.io/wtf-8
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
///
/// let path = PathBuf::from("foo/bar/baz");
/// assert_eq!(rrg_proto::path::into_bytes(path), b"foo/bar/baz");
/// ```
pub fn into_bytes(path: PathBuf) -> Vec<u8> {
    into_bytes_impl(path)
}

#[cfg(target_family = "unix")]
fn from_bytes_impl(bytes: Vec<u8>) -> PathBuf {
    use std::os::unix::ffi::OsStringExt as _;
    std::ffi::OsString::from_vec(bytes).into()
}

#[cfg(target_family = "windows")]
fn from_bytes_impl(bytes: Vec<u8>) -> PathBuf {
    let bytes_u16 = wtf8::into_ill_formed_utf16(bytes)
        .unwrap(); // TODO: Add proper error handling.

    use std::os::windows::ffi::OsStringExt as _;
    std::ffi::OsString::from_wide(&bytes_u16).into()
}

#[cfg(target_family = "unix")]
fn into_bytes_impl(path: PathBuf) -> Vec<u8> {
    use std::os::unix::ffi::OsStringExt as _;
    std::ffi::OsString::from(path).into_vec()
}

#[cfg(target_family = "windows")]
fn into_bytes_impl(path: PathBuf) -> Vec<u8> {
    let string = std::ffi::OsString::from(path);

    use std::os::windows::ffi::OsStrExt as _;
    wtf8::from_ill_formed_utf16(string.as_os_str().encode_wide())
}
