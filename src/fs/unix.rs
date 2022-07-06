// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Unix-specific utilities for working with the filesystem.

use std::ffi::OsString;
use std::path::Path;

/// An extended attribute of a file.
///
/// On Linux, extended attributes can be obtained using `getfattr` and set with
/// `setfattr` utilities. On macOS, they can be manipulated through the `xattr`
/// utility.
///
/// See the [Wikipedia] article for more details.
///
/// [Wikipedia]: https://en.wikipedia.org/wiki/Extended_file_attributes
#[derive(Debug)]
pub struct ExtAttr {
    /// A name of the extended attribute.
    pub name: OsString,
    /// A value of the extended attribute.
    pub value: Vec<u8>,
}

/// Returns an iterator over extended attributes of the specified file.
///
/// # Errors
///
/// The function will fail if a list of extended attributes of the file cannot
/// be obtained (e.g. when the file doesn't exist). Each iterator element is a
/// result itself and errors are possible e.g. when the attribute has been dele-
/// ted since we first listed it.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
///
/// for attr in rrg::fs::unix::ext_attrs(Path::new("/tmp/foo")).unwrap() {
///     let attr = attr.unwrap();
///     let name = attr.name.to_string_lossy();
///     let value = String::from_utf8_lossy(&attr.value);
///     println!("{}: {}", name, value);
/// }
/// ```
pub fn ext_attrs<'p>(path: &'p std::path::Path) -> std::io::Result<ExtAttrs<'p>> {
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
/// [`ext_attrs`]: fn.ext_attrs.html
pub struct ExtAttrs<'p> {
    path: &'p Path,
    names: std::vec::IntoIter<std::ffi::OsString>,
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
/// This function is an idiomatic wrapper over lower-level system calls (like
/// `llistxattr` on Linux or `listxattr` on macOS).
///
/// # Errors
///
/// This function will fail if the specified file does not exist, the process
/// does not have permission to access the file or any other system error is
/// raised.
///
/// # Examples
///
/// ```no_run
/// let names = rrg::fs::unix::ext_attr_names("/tmp/foo").unwrap();
///
/// println!("{} attributes found", names.len());
/// for name in names {
///     println!("'{}'", name.to_string_lossy());
/// }
/// ```
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
///
/// This function is an idiomatic wrapper over lower-level system calls (like
/// `lgetxattr` on Linux or `getxattr` or macOS).
///
/// # Errors
///
/// This function will fail if the specified file or the attribute do not exist,
/// the process does not have permission to access the file or any other system
/// error is raised.
///
/// # Examples
///
/// ```no_run
/// let value = rrg::fs::unix::ext_attr_value("/tmp/foo", "user.bar").unwrap();
/// println!("'user.bar': '{}'", String::from_utf8_lossy(&value));
/// ```
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
    fn ext_attrs_with_multiple_values() {
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
    fn ext_attrs_with_multiple_values() {
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
    fn ext_attrs_with_empty_value() {
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
    fn ext_attrs_with_empty_value() {
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
    fn ext_attrs_with_bytes_value() {
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
    fn ext_attrs_with_bytes_value() {
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        xattr(tempfile.path(), "user.abc", b"\xff\xfe\xff\xfe\xff");

        let results = ext_attrs(&tempfile.path()).unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        assert_eq!(results.len(), 1);

        assert_eq!(results[0].name, "user.abc");
        assert_eq!(results[0].value, b"\xff\xfe\xff\xfe\xff");
    }

    #[cfg(all(target_os = "linux", feature = "test-setfattr"))]
    fn setfattr<P, S>(path: P, name: S, value: &[u8])
    where
        P: AsRef<std::path::Path>,
        S: AsRef<std::ffi::OsStr>,
    {
        use std::os::unix::ffi::OsStrExt as _;

        assert! {
            std::process::Command::new("setfattr")
                .arg("--name").arg(name)
                .arg("--value").arg(std::ffi::OsStr::from_bytes(value))
                .arg(path.as_ref().as_os_str())
                .status()
                .unwrap()
                .success()
        };
    }

    #[cfg(target_os = "macos")]
    fn xattr<P, S>(path: P, name: S, value: &[u8])
    where
        P: AsRef<std::path::Path>,
        S: AsRef<std::ffi::OsStr>,
    {
        use std::os::unix::ffi::OsStrExt as _;

        assert! {
            std::process::Command::new("xattr")
                .arg(name)
                .arg(std::ffi::OsStr::from_bytes(value))
                .arg(path.as_ref().as_os_str())
                .status()
                .unwrap()
                .success()
        };
    }

    // TODO: Document and add tests for collecting attributes of a symlink.
}

// TODO: Move this into the `rrg-proto` crate once generic purpose utilities are
// moved to a separate crate.
impl Into<rrg_proto::jobs::StatEntry_ExtAttr> for ExtAttr {

    fn into(self) -> rrg_proto::jobs::StatEntry_ExtAttr {
        use std::os::unix::ffi::OsStringExt as _;

        let mut proto = rrg_proto::jobs::StatEntry_ExtAttr::new();
        proto.set_name(self.name.into_vec());
        proto.set_value(self.value);

        proto
    }
}
