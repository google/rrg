// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the file stat action.
//!
//! A file stat action collects filesystem metadata associated with a particular
//! file.
//!
//! Note that the gathered bits of information differ across platforms, e.g. on
//! Linux there is a notion of symlinks whereas on Windows no such thing exists.
//! Therefore, on Linux the results might include additional information about
//! the symlink (like the file it points to).

use std::fs::Metadata;
use std::path::PathBuf;

use rrg_macro::ack;

use crate::session::{self, Session};

/// A request type for the stat action.
#[derive(Debug)]
pub struct Request {
    /// A path to the file to stat.
    path: PathBuf,
    /// Whether to collect extended file attributes.
    collect_ext_attrs: bool,
    /// Whether, in case of a symlink, to collect data about the linked file.
    follow_symlink: bool,
}

impl Request {

    /// Obtains a (potentially expanded) path that this request corresponds to.
    ///
    /// In case of requests that wish to follow symlinks, it will return a path
    /// to the symlink target (in case there is such). Otherwise, it will just
    /// return the requested path unchanged.
    ///
    /// # Errors
    ///
    /// This method will return an error if the path needs to be expanded but
    /// the expansion fails for some reason (e.g. the requested path does not
    /// exist).
    fn target(&self) -> std::io::Result<std::borrow::Cow<PathBuf>> {
        use std::borrow::Cow::*;

        if self.follow_symlink {
            self.path.canonicalize().map(Owned)
        } else {
            Ok(Borrowed(&self.path))
        }
    }
}

/// A response type for the stat action.
#[derive(Debug)]
pub struct Response {
    /// A path to the file that the result corresponds to.
    path: PathBuf,
    /// Metadata about the file.
    metadata: Metadata,
    /// A path to the pointed file (in case of a symlink).
    symlink: Option<PathBuf>,
    /// Extended attributes of the file.
    ext_attrs: Vec<ospect::fs::ExtAttr>,
    /// Additional Linux-specific file flags.
    #[cfg(target_os = "linux")]
    flags_linux: Option<u32>,
    // TODO: Add support for collecting file flags on macOS.
}

/// An error type for failures that can occur during the stat action.
#[derive(Debug)]
enum Error {
    /// A failure occurred during the attempt to collect file metadata.
    Metadata(std::io::Error),
}

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            Metadata(ref error) => Some(error),
        }
    }
}

impl std::fmt::Display for Error {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use Error::*;

        match *self {
            Metadata(ref error) => {
                write!(fmt, "unable to collect metadata: {}", error)
            }
        }
    }
}

impl From<Error> for session::Error {

    fn from(error: Error) -> session::Error {
        session::Error::action(error)
    }
}

/// Handles requests for the file stat action.
pub fn handle<S>(session: &mut S, request: Request) -> session::Result<()>
where
    S: Session,
{
    let metadata = if request.follow_symlink {
        std::fs::metadata(&request.path)
    } else {
        std::fs::symlink_metadata(&request.path)
    }.map_err(Error::Metadata)?;

    let symlink = if metadata.file_type().is_symlink() {
        ack! {
            std::fs::read_link(&request.path),
            warn: "failed to read symlink for '{}'", request.path.display()
        }
    } else {
        None
    };

    let ext_attrs = if request.collect_ext_attrs {
        ext_attrs(&request)
    } else {
        vec!()
    };

    #[cfg(target_os = "linux")]
    let flags_linux = if !metadata.file_type().is_symlink() {
        ack! {
            ospect::fs::linux::flags(&request.path),
            warn: "failed to collect flags for '{}'", request.path.display()
        }
    } else {
        // Flags are available only for non-symlinks. For symlinks, the function
        // would return flags mask for the target file, which can look confusing
        // in the results.
        None
    };

    let response = Response {
        path: request.path,
        metadata: metadata,
        symlink: symlink,
        ext_attrs: ext_attrs,
        #[cfg(target_os = "linux")]
        flags_linux: flags_linux,
    };

    session.reply(response)?;

    Ok(())
}

impl crate::request::Args for Request {

    type Proto = rrg_proto::jobs::GetFileStatRequest;

    fn from_proto(mut proto: Self::Proto) -> Result<Self, crate::request::ParseArgsError> {
        let path = proto.take_pathspec().try_into()
            .map_err(crate::request::ParseArgsError::invalid_field)?;

        Ok(Request {
            path: path,
            follow_symlink: proto.get_follow_symlink(),
            collect_ext_attrs: proto.get_collect_ext_attrs(),
        })
    }
}

impl crate::response::Item for Response {

    type Proto = rrg_proto::jobs::StatEntry;

    fn into_proto(self) -> Self::Proto {
        use rrg_proto::convert::FromLossy as _;

        let mut proto = rrg_proto::jobs::StatEntry::from_lossy(self.metadata);
        proto.set_pathspec(self.path.into());

        if let Some(symlink) = self.symlink {
            proto.set_symlink(symlink.to_string_lossy().into_owned());
        }

        proto.set_ext_attrs(self.ext_attrs.into_iter().map(Into::into).collect());

        #[cfg(target_os = "linux")]
        if let Some(flags_linux) = self.flags_linux {
            proto.set_st_flags_linux(flags_linux);
        }

        proto
    }
}

/// Collects extended attributes of a file specified by the request.
fn ext_attrs(request: &Request) -> Vec<ospect::fs::ExtAttr> {
    let path = match request.target() {
        Ok(path) => path,
        Err(error) => {
            rrg_macro::warn! {
                "failed to expand '{path}': {cause}",
                path = request.path.display(),
                cause = error
            };
            return vec!();
        }
    };

    let ext_attrs = match ospect::fs::ext_attrs(&path) {
        Ok(ext_attrs) => ext_attrs,
        Err(error) => {
            rrg_macro::warn! {
                "failed to collect extended attributes for '{path}': {cause}",
                path = request.path.display(),
                cause = error
            };
            return vec!();
        }
    };

    ext_attrs.filter_map(|ext_attr| match ext_attr {
        Ok(ext_attr) => Some(ext_attr),
        Err(error) => {
            rrg_macro::warn! {
                "failed to collect an extended attribute for '{path}': {cause}",
                path = request.path.display(),
                cause = error
            };

            None
        }
    }).collect()
}

#[cfg(test)]
mod tests {

    use std::fs::File;

    use super::*;

    #[test]
    fn test_handle_with_non_existent_file() {
        let tempdir = tempfile::tempdir().unwrap();

        let request = Request {
            path: tempdir.path().join("foo").to_path_buf(),
            follow_symlink: false,
            collect_ext_attrs: false,
        };

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, request).is_err());
    }

    #[test]
    fn test_handle_with_regular_file() {
        let tempdir = tempfile::tempdir().unwrap();
        File::create(tempdir.path().join("foo")).unwrap();

        let request = Request {
            path: tempdir.path().join("foo").to_path_buf(),
            follow_symlink: false,
            collect_ext_attrs: false,
        };

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        assert_eq!(session.reply_count(), 1);

        let reply = session.reply::<Response>(0);
        assert_eq!(reply.path, tempdir.path().join("foo"));
        assert!(reply.metadata.is_file());
    }

    // Symlinking is supported only on Unix-like systems.
    #[cfg(target_family = "unix")]
    #[test]
    fn test_handle_with_link() {
        let tempdir = tempfile::tempdir().unwrap();
        let symlink = tempdir.path().join("foo");
        let target = tempdir.path().join("bar");

        File::create(&target).unwrap();
        std::os::unix::fs::symlink(&target, &symlink).unwrap();

        let request = Request {
            path: symlink.clone(),
            follow_symlink: false,
            collect_ext_attrs: false,
        };

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        assert_eq!(session.reply_count(), 1);

        let reply = session.reply::<Response>(0);
        assert_eq!(reply.path, symlink);
        assert_eq!(reply.symlink, Some(target));
        assert!(reply.metadata.file_type().is_symlink());
    }

    // Symlinking is supported only on Unix-like systems.
    #[cfg(target_family = "unix")]
    #[test]
    fn test_handle_with_two_links() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().unwrap();
        let symlink_to_symlink = tempdir.path().join("foo");
        let symlink_to_target = tempdir.path().join("bar");
        let target = tempdir.path().join("baz");

        File::create(&target).unwrap();
        symlink(&target, &symlink_to_target).unwrap();
        symlink(&symlink_to_target, &symlink_to_symlink).unwrap();

        let request = Request {
            path: symlink_to_symlink.clone(),
            follow_symlink: false,
            collect_ext_attrs: false,
        };

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        assert_eq!(session.reply_count(), 1);

        let reply = session.reply::<Response>(0);
        assert_eq!(reply.path, symlink_to_symlink);
        assert_eq!(reply.symlink, Some(symlink_to_target));
        assert!(reply.metadata.file_type().is_symlink());
    }

    // Symlinking is supported only on Unix-like systems.
    #[cfg(target_family = "unix")]
    #[test]
    fn test_handle_with_link_and_follow_symlink() {
        let tempdir = tempfile::tempdir().unwrap();
        let symlink = tempdir.path().join("foo");
        let target = tempdir.path().join("bar");

        File::create(&target).unwrap();
        std::os::unix::fs::symlink(&target, &symlink).unwrap();

        let request = Request {
            path: symlink.clone(),
            follow_symlink: true,
            collect_ext_attrs: false,
        };

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        assert_eq!(session.reply_count(), 1);

        let reply = session.reply::<Response>(0);
        assert_eq!(reply.path, symlink);
        assert_eq!(reply.symlink, None);
        assert!(reply.metadata.is_file());
    }

    // Symlinking is supported only on Unix-like systems.
    #[cfg(target_family = "unix")]
    #[test]
    fn test_handle_with_two_links_and_follow_symlink() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().unwrap();
        let symlink_to_symlink = tempdir.path().join("foo");
        let symlink_to_target = tempdir.path().join("bar");
        let target = tempdir.path().join("baz");

        File::create(&target).unwrap();
        symlink(&target, &symlink_to_target).unwrap();
        symlink(&symlink_to_target, &symlink_to_symlink).unwrap();

        let request = Request {
            path: symlink_to_symlink.clone(),
            follow_symlink: true,
            collect_ext_attrs: false,
        };

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        let reply = session.reply::<Response>(0);
        assert_eq!(reply.path, symlink_to_symlink);
        assert_eq!(reply.symlink, None);
        assert!(reply.metadata.is_file());
    }

    #[cfg(all(target_os = "linux", feature = "test-setfattr"))]
    #[test]
    fn test_handle_with_file_ext_attrs_on_linux() {
        let tempdir = tempfile::tempdir().unwrap();
        let tempfile = tempdir.path().join("foo");
        std::fs::File::create(&tempfile).unwrap();

        assert! {
            std::process::Command::new("setfattr")
                .arg("--name").arg("user.norf")
                .arg("--value").arg("quux")
                .arg(&tempfile)
                .status()
                .unwrap()
                .success()
        };

        let request = Request {
            path: tempfile.clone(),
            follow_symlink: false,
            collect_ext_attrs: true,
        };

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        assert_eq!(session.reply_count(), 1);

        let reply = session.reply::<Response>(0);
        assert_eq!(reply.ext_attrs.len(), 1);
        assert_eq!(reply.ext_attrs[0].name, "user.norf");
        assert_eq!(reply.ext_attrs[0].value, b"quux");
    }

    #[cfg(all(target_os = "linux", feature = "test-setfattr"))]
    #[test]
    fn test_handle_with_symlink_ext_attrs_on_linux() {
        let tempdir = tempfile::tempdir().unwrap();
        let symlink = tempdir.path().join("foo");
        let target = tempdir.path().join("bar");

        std::fs::File::create(&target).unwrap();
        std::os::unix::fs::symlink(&target, &symlink).unwrap();

        // Turns out, the kernel disallows setting extended attributes on a
        // symlink [1]. However, the kernel itself can hypothetically set such
        // bits.
        //
        // In order to verify that we really collect attributes for the symlink
        // and no for the target, we set some attributes for the target and then
        // we collect attributes of the symlink. Then, the expected result is to
        // have a reply with no extended attributes.
        //
        // [1]: https://man7.org/linux/man-pages/man7/xattr.7.html

        assert! {
            std::process::Command::new("setfattr")
                .arg("--name").arg("user.norf")
                .arg("--value").arg("quux")
                .arg("--no-dereference")
                .arg(&target)
                .status()
                .unwrap()
                .success()
        };

        let request = Request {
            path: symlink,
            follow_symlink: false,
            collect_ext_attrs: true,
        };

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        assert_eq!(session.reply_count(), 1);

        let reply = session.reply::<Response>(0);
        assert!(reply.ext_attrs.is_empty());
    }

    #[cfg(all(target_os = "linux", feature = "test-setfattr"))]
    #[test]
    fn test_handle_with_symlink_ext_attrs_and_follow_symlink_on_linux() {
        let tempdir = tempfile::tempdir().unwrap();
        let symlink = tempdir.path().join("foo");
        let target = tempdir.path().join("bar");

        std::fs::File::create(&target).unwrap();
        std::os::unix::fs::symlink(&target, &symlink).unwrap();

        assert! {
            std::process::Command::new("setfattr")
                .arg("--name").arg("user.norf")
                .arg("--value").arg("quux")
                .arg(&target)
                .status()
                .unwrap()
                .success()
        };

        let request = Request {
            path: symlink.clone(),
            follow_symlink: true,
            collect_ext_attrs: true,
        };

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        assert_eq!(session.reply_count(), 1);

        let reply = session.reply::<Response>(0);
        assert_eq!(reply.ext_attrs.len(), 1);
        assert_eq!(reply.ext_attrs[0].name, "user.norf");
        assert_eq!(reply.ext_attrs[0].value, b"quux");
    }

    #[cfg(all(target_os = "linux", feature = "test-chattr"))]
    #[test]
    fn test_handle_with_file_flags_on_linux() {
        // https://elixir.bootlin.com/linux/v5.8.14/source/include/uapi/linux/fs.h#L245
        const FS_NOATIME_FL: std::os::raw::c_long = 0x00000080;

        let tempdir = tempfile::tempdir().unwrap();
        let tempfile = tempdir.path().join("foo");
        std::fs::File::create(&tempfile).unwrap();

        assert! {
            std::process::Command::new("chattr")
                .arg("+A").arg(&tempfile)
                .status()
                .unwrap()
                .success()
        };

        let request = Request {
            path: tempfile,
            follow_symlink: false,
            collect_ext_attrs: false,
        };

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        assert_eq!(session.reply_count(), 1);

        let reply = session.reply::<Response>(0);
        let flags = reply.flags_linux.unwrap();
        assert_eq!(flags & FS_NOATIME_FL as u32, FS_NOATIME_FL as u32);
    }

    #[cfg(all(target_os = "linux", feature = "test-chattr"))]
    #[test]
    fn test_handle_with_symlink_flags_on_linux() {
        let tempdir = tempfile::tempdir().unwrap();
        let symlink = tempdir.path().join("foo");
        let target = tempdir.path().join("bar");

        std::fs::File::create(&target).unwrap();
        std::os::unix::fs::symlink(&target, &symlink).unwrap();

        assert! {
            std::process::Command::new("chattr")
                .arg("+d").arg(&target)
                .status()
                .unwrap()
                .success()
        };

        let request = Request {
            path: symlink,
            follow_symlink: false,
            collect_ext_attrs: false,
        };

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        assert_eq!(session.reply_count(), 1);

        let reply = session.reply::<Response>(0);
        assert_eq!(reply.flags_linux, None);
    }

    #[cfg(all(target_os = "linux", feature = "test-chattr"))]
    #[test]
    fn test_handle_with_symlink_flags_and_follow_symlink_on_linux() {
        // https://elixir.bootlin.com/linux/v5.8.14/source/include/uapi/linux/fs.h#L245
        const FS_NODUMP_FL: std::os::raw::c_long = 0x00000040;

        let tempdir = tempfile::tempdir().unwrap();
        let symlink = tempdir.path().join("foo");
        let target = tempdir.path().join("bar");

        std::fs::File::create(&target).unwrap();
        std::os::unix::fs::symlink(&target, &symlink).unwrap();

        assert! {
            std::process::Command::new("chattr")
                .arg("+d").arg(&target)
                .status()
                .unwrap()
                .success()
        };

        let request = Request {
            path: symlink,
            follow_symlink: true,
            collect_ext_attrs: false,
        };

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        assert_eq!(session.reply_count(), 1);

        let reply = session.reply::<Response>(0);
        let flags = reply.flags_linux.unwrap();
        assert_eq!(flags & FS_NODUMP_FL as u32, FS_NODUMP_FL as u32);
    }
}
