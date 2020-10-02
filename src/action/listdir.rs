// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the list directory action.
//!
//! A list directory action collects basic metadata for all files in the
//! provided directory.
//!
//! Note that this includes only entries directly under the specified directory.
//! For more sophisticated recursive traversals, please look into the [timeline]
//! action.
//!
//! [timeline]: ../timeline/index.html

use crate::session::{self, Session};

use std::fs::{Metadata};
use std::path::{PathBuf};

/// A request type for the list directory action.
pub struct Request {
    /// A path to the directory ought to be listed.
    path: PathBuf,
}

/// A response type for the list directory action.
pub struct Response {
    /// A full path to a particular file within the listed directory.
    path: PathBuf,
    /// Metadata about a particular file within the listed directory.
    metadata: Metadata,
}

/// An error type for failures that can occur during the list directory action.
#[derive(Debug)]
enum Error {
    /// A failure occurred during the attempt to list a directory.
    ListDir(std::io::Error),
}

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            ListDir(ref error) => Some(error),
        }
    }
}

impl std::fmt::Display for Error {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use Error::*;

        match *self {
            ListDir(ref error) => {
                write!(fmt, "unable to list directory: {}", error)
            }
        }
    }
}

impl From<Error> for session::Error {

    fn from(error: Error) -> session::Error {
        session::Error::action(error)
    }
}

/// Handles requests for the list directory action.
pub fn handle<S>(session: &mut S, request: Request) -> session::Result<()>
where
    S: Session,
{
    let entries = crate::fs::list_dir(&request.path)
        .map_err(Error::ListDir)?;

    for entry in entries {
        session.reply(Response {
            path: entry.path,
            metadata: entry.metadata,
        })?;
    }

    Ok(())
}

impl super::Request for Request {

    type Proto = rrg_proto::ListDirRequest;

    fn from_proto(proto: Self::Proto) -> Result<Request, session::ParseError> {
        use std::convert::TryInto as _;

        let path = proto.pathspec
            .ok_or(session::MissingFieldError::new("path spec"))?
            .try_into().map_err(session::ParseError::malformed)?;

        Ok(Request {
            path: path,
        })
    }
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("StatEntry");

    type Proto = rrg_proto::StatEntry;

    fn into_proto(self) -> Self::Proto {
        use rrg_proto::convert::IntoLossy as _;

        rrg_proto::StatEntry {
            pathspec: Some(self.path.into()),
            ..self.metadata.into_lossy()
        }
    }
}

#[cfg(test)]
mod tests {

    use std::fs::File;

    use super::*;

    #[test]
    fn test_non_existent_dir() {
        let tempdir = tempfile::tempdir().unwrap();

        let request = Request {
            path: tempdir.path().join("foo").to_path_buf(),
        };

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_err());
    }

    #[test]
    fn test_empty_dir() {
        let tempdir = tempfile::tempdir().unwrap();

        let request = Request {
            path: tempdir.path().to_path_buf(),
        };

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());

        assert_eq!(session.reply_count(), 0);
    }

    #[test]
    fn test_dir_with_files() {
        let tempdir = tempfile::tempdir().unwrap();
        File::create(tempdir.path().join("abc")).unwrap();
        File::create(tempdir.path().join("def")).unwrap();
        File::create(tempdir.path().join("ghi")).unwrap();

        let request = Request {
            path: tempdir.path().to_path_buf(),
        };

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());

        let mut replies = session.replies().collect::<Vec<&Response>>();
        replies.sort_by_key(|reply| reply.path.clone());

        assert_eq!(replies.len(), 3);

        assert_eq!(replies[0].path, tempdir.path().join("abc"));
        assert!(replies[0].metadata.is_file());

        assert_eq!(replies[1].path, tempdir.path().join("def"));
        assert!(replies[1].metadata.is_file());

        assert_eq!(replies[2].path, tempdir.path().join("ghi"));
        assert!(replies[2].metadata.is_file());
    }

    #[test]
    fn test_dir_with_dirs() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::create_dir(tempdir.path().join("abc")).unwrap();
        std::fs::create_dir(tempdir.path().join("def")).unwrap();

        let request = Request {
            path: tempdir.path().to_path_buf(),
        };

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());

        let mut replies = session.replies().collect::<Vec<&Response>>();
        replies.sort_by_key(|reply| reply.path.clone());

        assert_eq!(replies.len(), 2);

        assert_eq!(replies[0].path, tempdir.path().join("abc"));
        assert!(replies[0].metadata.is_dir());

        assert_eq!(replies[1].path, tempdir.path().join("def"));
        assert!(replies[1].metadata.is_dir());
    }

    #[test]
    fn test_dir_with_nested_dirs() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("abc").join("def").join("ghi");

        std::fs::create_dir_all(path).unwrap();

        let request = Request {
            path: tempdir.path().to_path_buf(),
        };

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());

        assert_eq!(session.reply_count(), 1);
    }

    // Symlinking is supported only on Unix-like systems.
    #[cfg(target_family = "unix")]
    #[test]
    fn test_list_dir_with_links() {
        let tempdir = tempfile::tempdir().unwrap();
        let source = tempdir.path().join("abc");
        let target = tempdir.path().join("def");

        File::create(&source).unwrap();
        std::os::unix::fs::symlink(&source, &target).unwrap();

        let request = Request {
            path: tempdir.path().to_path_buf(),
        };

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());

        let mut replies = session.replies().collect::<Vec<&Response>>();
        replies.sort_by_key(|reply| reply.path.clone());

        assert_eq!(replies.len(), 2);

        assert_eq!(replies[0].path, tempdir.path().join("abc"));
        assert!(replies[0].metadata.file_type().is_file());

        assert_eq!(replies[1].path, tempdir.path().join("def"));
        assert!(replies[1].metadata.file_type().is_symlink());
    }

    // macOS mangles Unicode-specific characters in filenames.
    #[cfg_attr(target_os = "macos", ignore)]
    #[test]
    fn test_dir_with_unicode_files() {
        let tempdir = tempfile::tempdir().unwrap();
        File::create(tempdir.path().join("zażółć gęślą jaźń")).unwrap();
        File::create(tempdir.path().join("што й па мору")).unwrap();

        let request = Request {
            path: tempdir.path().to_path_buf(),
        };

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());

        let mut replies = session.replies().collect::<Vec<&Response>>();
        replies.sort_by_key(|reply| reply.path.clone());

        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0].path, tempdir.path().join("zażółć gęślą jaźń"));
        assert_eq!(replies[1].path, tempdir.path().join("што й па мору"));
    }
}
