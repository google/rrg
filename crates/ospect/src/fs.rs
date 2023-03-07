// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Filesystem inspection functionalities.

use std::ffi::{OsStr, OsString};
use std::path::Path;

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

/// An extended attribute of a file.
///
/// On Linux, extended attributes can be obtained using [`getfattr`] and set
/// with [`setfattr`] utilities. On macOS, they can be manipulated through the
/// [`xattr`] utility.
///
/// See the [Wikipedia] article for more details.
///
/// [`getfattr`]: https://man7.org/linux/man-pages/man1/getfattr.1.html
/// [`setfattr`]: https://man7.org/linux/man-pages/man1/setfattr.1.html
/// [`xattr`]: https://ss64.com/osx/xattr.html
///
/// [Wikipedia]: https://en.wikipedia.org/wiki/Extended_file_attributes
#[derive(Debug)]
pub struct ExtAttr {
    /// A name of the extended attribute.
    pub name: OsString,
    /// A value of the extended attribute.
    pub value: Vec<u8>,
}

/// Returns an iterator over [extended attributes] of the specified file.
///
/// In case of a symlink this function returns the extended attributes of the
/// link itself and not the file pointed by it.
///
/// [extended attributes]: crate::fs::ExtAttr
///
/// # Errors
///
/// This function will fail if the specified file does not exist, the process
/// does not have permission to access the file, the operation is not supported
/// by the platform or if any other system error is raised.
///
/// Each iterator element is a result itself and errors are possible e.g. when
/// an attribute has been deleted since it was first listed.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
///
/// let ext_attrs = ospect::fs::ext_attrs(Path::new("/tmp/foo"))
///     .unwrap()
///     .map(Result::unwrap);
///
/// for ext_attr in ext_attrs {
///     let name = ext_attr.name.to_string_lossy();
///     let value = String::from_utf8_lossy(&ext_attr.value);
///     println!("{}: {}", name, value);
/// }
/// ```
pub fn ext_attrs<'p>(path: &'p Path) -> std::io::Result<ExtAttrs<'p>> {
    let names = ext_attr_names(path)?;

    Ok(ExtAttrs {
        path: path.as_ref(),
        names: names.into_iter(),
    })
}

/// Iterator over extended attributes of a file.
///
/// The iterator can be constructed with the [`ext_attrs`] function.
///
/// [`ext_attrs`]: crate::fs::ext_attrs
pub struct ExtAttrs<'p> {
    path: &'p Path,
    names: std::vec::IntoIter<OsString>,
}

impl<'p> Iterator for ExtAttrs<'p> {

    type Item = std::io::Result<ExtAttr>;

    fn next(&mut self) -> Option<std::io::Result<ExtAttr>> {
        let name = self.names.next()?;
        let value = match ext_attr_value(self.path, &name) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };

        Some(Ok(ExtAttr { name, value }))
    }
}

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

/// Information about a mounted filesystem.
pub struct Mount {
    /// Name of the mounted device.
    pub source: String,
    /// Mount point, i.e., where the mounted filesystem is available.
    pub target: std::path::PathBuf,
    /// Type of the mounted filesystem (e.g. `ext4`, `ramfs`, `proc`).
    pub fs_type: String,
}

// TODO(@panhania): Add information about Windows once it is supported.
/// Returns an iterator over mounted filesystems information.
///
/// The exact behaviour is system specific:
///
///   * On Linux it parses `/proc/mounts` entries (or alternatives).
///   * On macOS it uses the [`getmntinfo`] call.
///
/// [`getmntinfo`]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getmntinfo.3.html
pub fn mounts() -> std::io::Result<impl Iterator<Item = std::io::Result<Mount>>> {
    self::sys::mounts()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn ext_attrs_non_existing() {
        let tempdir = tempfile::tempdir().unwrap();

        assert!(ext_attrs(&tempdir.path().join("foo")).is_err());
    }

    #[cfg(all(target_os = "linux", feature = "test-setfattr"))]
    #[test]
    fn ext_attrs_multiple_values() {
        use crate::fs::linux::tests::setfattr;

        let tempfile = tempfile::NamedTempFile::new().unwrap();
        setfattr(tempfile.path(), "user.abc", b"quux");
        setfattr(tempfile.path(), "user.def", b"norf");

        let mut results = ext_attrs(&tempfile.path()).unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        results.sort_by_key(|attr| attr.name.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].name, "user.abc");
        assert_eq!(results[0].value, b"quux");

        assert_eq!(results[1].name, "user.def");
        assert_eq!(results[1].value, b"norf");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ext_attrs_multiple_values() {
        use crate::fs::macos::tests::xattr;

        let tempfile = tempfile::NamedTempFile::new().unwrap();
        xattr(tempfile.path(), "user.abc", b"quux");
        xattr(tempfile.path(), "user.def", b"norf");

        let mut results = ext_attrs(&tempfile.path()).unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        results.sort_by_key(|attr| attr.name.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].name, "user.abc");
        assert_eq!(results[0].value, b"quux");

        assert_eq!(results[1].name, "user.def");
        assert_eq!(results[1].value, b"norf");
    }

    #[cfg(all(target_os = "linux", feature = "test-setfattr"))]
    #[test]
    fn ext_attrs_empty_value() {
        use crate::fs::linux::tests::setfattr;

        let tempfile = tempfile::NamedTempFile::new().unwrap();
        setfattr(tempfile.path(), "user.abc", b"");

        let results = ext_attrs(&tempfile.path()).unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        assert_eq!(results.len(), 1);

        assert_eq!(results[0].name, "user.abc");
        assert_eq!(results[0].value, b"");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ext_attrs_empty_value() {
        use crate::fs::macos::tests::xattr;

        let tempfile = tempfile::NamedTempFile::new().unwrap();
        xattr(tempfile.path(), "user.abc", b"");

        let results = ext_attrs(&tempfile.path()).unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        assert_eq!(results.len(), 1);

        assert_eq!(results[0].name, "user.abc");
        assert_eq!(results[0].value, b"");
    }

    #[cfg(all(target_os = "linux", feature = "test-setfattr"))]
    #[test]
    fn ext_attrs_bytes_value() {
        use crate::fs::linux::tests::setfattr;

        let tempfile = tempfile::NamedTempFile::new().unwrap();
        setfattr(tempfile.path(), "user.abc", b"\xff\xfe\xff\xfe\xff");

        let results = ext_attrs(&tempfile.path()).unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        assert_eq!(results.len(), 1);

        assert_eq!(results[0].name, "user.abc");
        assert_eq!(results[0].value, b"\xff\xfe\xff\xfe\xff");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ext_attrs_bytes_value() {
        use crate::fs::macos::tests::xattr;

        let tempfile = tempfile::NamedTempFile::new().unwrap();
        xattr(tempfile.path(), "user.abc", b"\xff\xfe\xff\xfe\xff");

        let results = ext_attrs(&tempfile.path()).unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        assert_eq!(results.len(), 1);

        assert_eq!(results[0].name, "user.abc");
        assert_eq!(results[0].value, b"\xff\xfe\xff\xfe\xff");
    }

    // Ideally, we would like to have tests for symlinks but turns out that it
    // is not possible (at least currently) to have extended attributes on them
    // as the kernel simply does not allow that [1].
    //
    // [1]: https://unix.stackexchange.com/questions/16537/extended-attribute-on-symbolic-link

    #[cfg(target_family = "unix")]
    #[test]
    fn mounts_root_exists() {
        let mut mounts = mounts()
            .unwrap()
            .map(Result::unwrap);

        assert!(mounts.find(|mount| mount.target == Path::new("/")).is_some());
    }
}
