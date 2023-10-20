// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::path::{Path, PathBuf};

/// Arguments of the `get_file_metadata` action.
pub struct Args {
    /// Path the file to get the metadata of.
    path: PathBuf,
}

/// Result of the `get_file_metadata` action.
struct Item {
    /// Canonical path to the file we retrieve the metadata of.
    path: PathBuf,
    /// Retrieved metadata of the file we retrieved.
    metadata: std::fs::Metadata,
    /// Extended attributes of the file.
    #[cfg(target_family = "unix")]
    ext_attrs: Vec<ospect::fs::ExtAttr>,
    // TODO(@panhania): Add support for file flags (also known as attributes).
    //
    // Collection of them is already implemented in the `ospect` crate, but it
    // is no clear which protobuf message should include them and whether we
    // should have separate fields for each platform or to cram everything into
    // one.
    //
    // It is also not clear how the field should be named as on Linux this
    // feature is called "attributes" (not to be confused with file extended
    // attributes!) and on macOS it is called "flags".
    /// Path to the file pointed by a symlink (if available).
    symlink: Option<PathBuf>,
}

/// Handles invocations of the `get_file_metadata` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    if args.path.is_relative() {
        use std::io::{Error, ErrorKind};

        let error = Error::new(ErrorKind::InvalidInput, "relative path");
        return Err(crate::session::Error::action(error));
    }

    let metadata = args.path.symlink_metadata()
        .map_err(crate::session::Error::action)?;

    #[cfg(target_family = "unix")]
    let ext_attrs = || -> std::io::Result<Vec<ospect::fs::ExtAttr>> {
        ospect::fs::ext_attrs(args.path.as_ref())?
            .collect()
    }().map_err(crate::session::Error::action)?;

    // Canonicalization of a symlink would yield a path that is fully resolved
    // (including the symlink) which is not what we want as we return metadata
    // of the symlink itself and not the data it points to. Thus, we want only
    // to canonicalize the parent part of the path.
    let path;
    let symlink;

    if metadata.is_symlink() {
        path = canonicalize_parent(&args.path);
        symlink = Some(std::fs::read_link(&args.path));
    } else {
        path = args.path.canonicalize();
        symlink = None;
    };

    let path = path.map_err(crate::session::Error::action)?;
    let symlink = symlink.transpose().map_err(crate::session::Error::action)?;

    session.reply(Item {
        path,
        metadata,
        #[cfg(target_family = "unix")]
        ext_attrs,
        symlink,
    })?;

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_file_metadata::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let path = PathBuf::try_from(proto.take_path())
            .map_err(|error| ParseArgsError::invalid_field("path", error))?;

        Ok(Args {
            path,
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_file_metadata::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = rrg_proto::get_file_metadata::Result::default();
        proto.set_path(self.path.into());
        proto.set_metadata(self.metadata.into());

        #[cfg(target_family = "unix")]
        {
            for ext_attr in self.ext_attrs {
                proto.mut_ext_attrs().push(ext_attr.into());
            }
        }

        if let Some(symlink) = self.symlink {
            proto.set_symlink(symlink.into());
        }

        proto
    }
}

/// Returns the canonical, absolute form of the path.
///
/// This is similar to [`std::fs::canonicalize`] but modifies only the dirname
/// part of the path. This might be important for symlinks, because we want to
/// return the canonical path to the symlink itself, not the file it points to.
fn canonicalize_parent<P>(path: P) -> std::io::Result<PathBuf>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();

    let parent = match path.parent() {
        Some(parent) => parent,
        None => {
            // There is no parent, we are at root so there is no need to do any
            // canonicalization.
            return Ok(PathBuf::from(path));
        }
    };

    let mut canonicalized = parent.canonicalize()?;

    match path.file_name() {
        Some(file_name) => canonicalized.push(file_name),
        None => {
            // This should never happen: if we are not a root path, there always
            // should be a file name as long as we don't end with something like
            // `..` or `.`. But then the behaviour is not well defined anyway
            // (and we use this function on something we are sure is a symlink).
            return Err(std::io::ErrorKind::InvalidInput.into());
        },
    }

    Ok(canonicalized)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn handle_non_existent() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let args = Args {
            path: tempdir.path().join("foo"),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_err());
    }

    #[test]
    fn handle_relative() {
        let args = Args {
            path: PathBuf::from("foo/bar/baz")
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_err());
    }

    #[test]
    fn handle_regular_file() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path().canonicalize()
            .unwrap();

        std::fs::File::create(tempdir.join("foo"))
            .unwrap();

        let args = Args {
            path: tempdir.join("foo").to_path_buf(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempdir.join("foo"));
        assert_eq!(item.metadata.is_file(), true);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn handle_symlink() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path().canonicalize()
            .unwrap();

        std::fs::File::create(tempdir.join("file"))
            .unwrap();
        std::os::unix::fs::symlink(tempdir.join("file"), tempdir.join("link"))
            .unwrap();

        let args = Args {
            path: tempdir.join("link"),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempdir.join("link"));
        assert_eq!(item.metadata.is_symlink(), true);
        assert_eq!(item.symlink, Some(tempdir.join("file")));
    }

    #[cfg(feature = "test-setfattr")]
    #[cfg(target_os = "linux")]
    #[test]
    fn handle_ext_attrs() {
        let tempfile = tempfile::NamedTempFile::new()
            .unwrap();

        assert! {
            std::process::Command::new("setfattr")
                .arg("--no-dereference")
                .arg("--name").arg("user.foo")
                .arg("--value").arg("bar")
                .arg(tempfile.path().as_os_str())
                .status().unwrap()
                .success()
        };

        let args = Args {
            path: tempfile.path().to_path_buf(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempfile.path());
        assert_eq!(item.ext_attrs.len(), 1);
        assert_eq!(item.ext_attrs[0].name, "user.foo");
        assert_eq!(item.ext_attrs[0].value, b"bar");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn handle_ext_attrs() {
        let tempfile = tempfile::NamedTempFile::new()
            .unwrap();

        assert! {
            std::process::Command::new("xattr")
                .arg("-w")
                .arg("user.foo")
                .arg("bar")
                .arg(tempfile.path().to_path_buf())
                .status().unwrap()
                .success()
        };

        let args = Args {
            path: tempfile.path().to_owned(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempfile.path().canonicalize().unwrap());
        assert_eq!(item.ext_attrs.len(), 1);
        assert_eq!(item.ext_attrs[0].name, "user.foo");
        assert_eq!(item.ext_attrs[0].value, b"bar");
    }

    macro_rules! path {
        ($root:expr) => {{
            ::std::path::PathBuf::from($root)
        }};
        ($root:expr, $($comp:expr),*) => {{
            let mut path = ::std::path::PathBuf::from($root);
            $(path.push($comp);)*

            path
        }};
    }

    #[test]
    fn canonicalize_parent_empty() {
        let canonical = canonicalize_parent("")
            .unwrap();

        assert_eq!(canonical, path!(""));
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn canonicalize_parent_root() {
        let canonical = canonicalize_parent("/")
            .unwrap();

        assert_eq!(canonical, path!("/"));
    }

    #[test]
    fn canonicalize_parent_simple() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = &tempdir.path().canonicalize()
            .unwrap();

        std::fs::File::create(path!(tempdir, "foo.txt"))
            .unwrap();

        assert_eq! {
            canonicalize_parent(path!(tempdir, "foo.txt"))
                .unwrap(),
            path!(tempdir, "foo.txt")
        }
    }

    #[test]
    fn canonicalize_parent_dots() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = &tempdir.path().canonicalize()
            .unwrap();

        std::fs::create_dir_all(path!(tempdir, "a", "b"))
            .unwrap();
        std::fs::File::create(path!(tempdir, "foo.txt"))
            .unwrap();
        std::fs::File::create(path!(tempdir, "a", "bar.txt"))
            .unwrap();

        assert_eq! {
            canonicalize_parent(path!(tempdir, "a", ".", "foo.txt"))
                .unwrap(),
            path!(tempdir, "a", "foo.txt")
        }
        assert_eq! {
            canonicalize_parent(path!(tempdir, "a", "b", "..", "foo.txt"))
                .unwrap(),
            path!(tempdir, "a", "foo.txt")
        }
        assert_eq! {
            canonicalize_parent(path!(tempdir, "a", "b", ".", "bar.txt"))
                .unwrap(),
            path!(tempdir, "a", "b", "bar.txt")
        }
        assert_eq! {
            canonicalize_parent(path!(tempdir, "a", ".", ".", "b", "..", ".", "foo.txt"))
                .unwrap(),
            path!(tempdir, "a", "foo.txt")
        }
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn canonicalize_parent_symlinks() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = &tempdir.path().canonicalize()
            .unwrap();

        std::fs::create_dir_all(path!(tempdir, "dir"))
            .unwrap();
        std::fs::File::create(path!(tempdir, "dir", "file"))
            .unwrap();

        use std::os::unix::fs::symlink;
        symlink(path!(tempdir, "dir"), path!(tempdir, "dir.l"))
            .unwrap();
        symlink(path!(tempdir, "dir", "file"), path!(tempdir, "dir", "file.l"))
            .unwrap();

        assert_eq! {
            canonicalize_parent(path!(tempdir, "dir", "file.l"))
                .unwrap(),
            path!(tempdir, "dir", "file.l")
        }
        assert_eq! {
            canonicalize_parent(path!(tempdir, "dir.l", "file"))
                .unwrap(),
            path!(tempdir, "dir", "file")
        }
        assert_eq! {
            canonicalize_parent(path!(tempdir, "dir.l", "file.l"))
                .unwrap(),
            path!(tempdir, "dir", "file.l")
        }
    }
}
