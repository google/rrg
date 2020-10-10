use std::ffi::{OsStr, OsString};
use std::path::Path;

use log::warn;

pub struct ExtAttr {
    pub key: OsString,
    pub value: Option<Vec<u8>>,
}

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

pub struct ExtAttrs<'p> {
    path: &'p Path,
    iter: xattr::XAttrs,
}

impl<'p> Iterator for ExtAttrs<'p> {

    type Item = ExtAttr;

    fn next(&mut self) -> Option<ExtAttr> {
        for key in &mut self.iter {
            let value = match ext_attr_value(self.path, &key) {
                Ok(value) => value,
                Err(()) => continue,
            };

            return Some(ExtAttr {
                key: key,
                value: value,
            });
        }

        None
    }
}

fn ext_attr_value<P>(path: P, key: &OsStr) -> Result<Option<Vec<u8>>, ()>
where
    P: AsRef<Path>,
{
    xattr::get(&path, key).map_err(|error| {
        warn! {
            "failed to collect {key:?} of '{path}': {cause}",
            key = key,
            path = path.as_ref().display(),
            cause = error,
        };
    })
}
