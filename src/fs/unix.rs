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
/// let attrs = rrg::fs::unix::ext_attrs(&"/tmp/foo")
///     .expect("failed to collect extended attributes");
///
/// for attr in attrs {
///     let name = attr.name.to_string_lossy();
///     match attr.value {
///         Some(value) => {
///             let value = std::str::from_utf8(&value)
///                 .expect("failed to convert attribute value");
///
///             println!("{}: {}", name, value);
///         },
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
    xattr::get(&path, name).map_err(|error| {
        warn! {
            "failed to collect attribute '{:?}' of '{path}': {cause}",
            name = name,
            path = path.as_ref().display(),
            cause = error,
        };
    })
}
