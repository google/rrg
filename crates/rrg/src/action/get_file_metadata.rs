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

    // Canonicalization of a symlink would yield a path that is fully resolved
    // (including the symlink) which is not what we want as we return metadata
    // of the symlink itself and not the data it points to. Thus, we want only
    // to canonicalize the parent part of the path.
    let path = if metadata.is_symlink() {
        canonicalize_parent(args.path)
    } else {
        args.path.canonicalize()
    }.map_err(crate::session::Error::action)?;

    session.reply(Item {
        path,
        metadata,
    })?;

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::v2::get_file_metadata::Args;

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

    type Proto = rrg_proto::v2::get_file_metadata::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = rrg_proto::v2::get_file_metadata::Result::default();
        proto.set_path(self.path.into());
        proto.set_metadata(self.metadata.into());

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
        let tempdir = tempdir.path();

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
        let tempdir = tempdir.path();

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
        let tempdir = tempdir.path();

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
