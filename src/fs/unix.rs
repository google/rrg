// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Unix-specific utilities for working with the filesystem.

use std::ffi::{OsStr, OsString};
use std::path::Path;

use log::warn;

/// An extended attribute of a file.
///
/// On Linux, extended attributes can be obtained using `getfattr` and set with
/// `setfattr` utilities. On macOS, they can be manipulated through `getxattr`
/// and `setxattr` utilities.
///
/// See the [Wikipedia] article for more details.
///
/// [Wikipedia]: https://en.wikipedia.org/wiki/Extended_file_attributes
#[derive(Debug)]
pub struct ExtAttr {
    /// A name of the extended attribute.
    pub name: OsString,
    /// A value of the extended attribute.
    pub value: Option<Vec<u8>>,
}

/// Returns an iterator over extended attributes of the specified file.
///
/// # Errors
///
/// The function will fail if a list of extended attributes of the file cannot
/// be obtained (e.g. when the file doesn't exist). However, all errors when
/// that can occur when inspecting values for particular attribute are logged
/// and forgotten.
///
/// # Examples
///
/// ```no_run
/// for attr in rrg::fs::unix::ext_attrs(&"/tmp/foo").unwrap() {
///     let name = attr.name.to_string_lossy();
///     match attr.value {
///         Some(value) => println!("{}: {:?}", name, value),
///         None => println!("{}", name),
///     }
/// }
/// ```
pub fn ext_attrs<'p, P>(path: &'p P) -> std::io::Result<ExtAttrs<'p>>
where
    P: AsRef<Path>,
{
    let iter = xattr::list(&path)?;

    Ok(ExtAttrs {
        path: path.as_ref(),
        iter: iter,
    })
}

/// Iterator over extended attributes of a file.
///
/// Note that this iterator always returns an attribute. All errors that can
/// occur when obtaining values for particular attributes are swallowed.
///
/// The iterator can be constructed with the [`ext_attrs`] function.
///
/// [`ext_attrs`]: fn.ext_attrs.html
pub struct ExtAttrs<'p> {
    path: &'p Path,
    iter: xattr::XAttrs,
}

impl<'p> Iterator for ExtAttrs<'p> {

    type Item = ExtAttr;

    fn next(&mut self) -> Option<ExtAttr> {
        for name in &mut self.iter {
            let value = match ext_attr_value(self.path, &name) {
                Ok(value) => value,
                Err(()) => continue,
            };

            return Some(ExtAttr {
                name: name,
                value: value,
            });
        }

        None
    }
}

/// Collects value of an extended attribute with the specified name.
///
/// This is a tiny wrapper around `xattr::get`, but logs and forgets the error
/// (if occurs).
fn ext_attr_value<P>(path: P, name: &OsStr) -> Result<Option<Vec<u8>>, ()>
where
    P: AsRef<Path>,
{
    xattr::get(&path, name).map_err(|error| warn! {
        "failed to collect attribute '{:?}' of '{path}': {cause}",
        name = name,
        path = path.as_ref().display(),
        cause = error,
    })
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_ext_attrs_non_existing() {
        let tempdir = tempfile::tempdir().unwrap();

        assert!(ext_attrs(&tempdir.path().join("foo")).is_err());
    }

    #[cfg(all(target_os = "linux", feature = "test-setfattr"))]
    #[test]
    fn test_ext_attrs_with_multiple_values() {
        let tempdir = tempfile::tempdir().unwrap();
        let tempfile = tempdir.path().join("foo");
        std::fs::File::create(&tempfile).unwrap();

        assert! {
            std::process::Command::new("setfattr")
                .arg("--name").arg("user.abc")
                .arg("--value").arg("quux")
                .arg(&tempfile)
                .status()
                .unwrap()
                .success()
        };

        assert! {
            std::process::Command::new("setfattr")
                .arg("--name").arg("user.def")
                .arg("--value").arg("norf")
                .arg(&tempfile)
                .status()
                .unwrap()
                .success()
        };

        let mut results = ext_attrs(&tempfile).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|attr| attr.name.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].name, "user.abc");
        assert_eq!(results[0].value, Some("quux".into()));

        assert_eq!(results[1].name, "user.def");
        assert_eq!(results[1].value, Some("norf".into()));
    }

    #[cfg(all(target_os = "linux", feature = "test-setfattr"))]
    #[test]
    fn test_ext_attrs_with_empty_value() {
        let tempdir = tempfile::tempdir().unwrap();
        let tempfile = tempdir.path().join("foo");
        std::fs::File::create(&tempfile).unwrap();

        assert! {
            std::process::Command::new("setfattr")
                .arg("--name").arg("user.abc")
                .arg(&tempfile)
                .status()
                .unwrap()
                .success()
        };

        let mut iter = ext_attrs(&tempfile).unwrap();

        let attr = iter.next().unwrap();
        assert_eq!(attr.name, "user.abc");
        assert_eq!(attr.value, Some("".into()));

        assert!(iter.next().is_none());
    }

    #[cfg(all(target_os = "linux", feature = "test-setfattr"))]
    #[test]
    fn test_ext_attrs_with_bytes_value() {
        use std::os::unix::ffi::OsStrExt as _;

        let tempdir = tempfile::tempdir().unwrap();
        let tempfile = tempdir.path().join("foo");
        std::fs::File::create(&tempfile).unwrap();

        assert! {
            std::process::Command::new("setfattr")
                .arg("--name").arg("user.abc")
                .arg("--value").arg(OsStr::from_bytes(b"\xff\xfe\xff\xfe\xff"))
                .arg(&tempfile)
                .status()
                .unwrap()
                .success()
        };

        let mut iter = ext_attrs(&tempfile).unwrap();

        let attr = iter.next().unwrap();
        assert_eq!(attr.name, "user.abc");
        assert_eq!(attr.value, Some(b"\xff\xfe\xff\xfe\xff".to_vec()));

        assert!(iter.next().is_none());
    }

    // TODO: Add macOS tests.
    // TODO: Document and add tests for collecting attributes of a symlink.
}

// TODO: Move this into the `rrg-proto` crate once generic purpose utilities are
// moved to a separate crate.
impl Into<rrg_proto::stat_entry::ExtAttr> for ExtAttr {

    fn into(self) -> rrg_proto::stat_entry::ExtAttr {
        use std::os::unix::ffi::OsStringExt as _;

        rrg_proto::stat_entry::ExtAttr {
            name: Some(self.name.into_vec()),
            value: self.value,
        }
    }
}
