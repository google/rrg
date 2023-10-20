// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the filesystems action.
//!
//! The filesystems action lists all mounted filesystems on the client,
//! collecting device name, mount point, filesystem type and its options.
//! Current implementation works only in Linux systems.

use crate::session::{self, Session};

use std::fmt::{Display, Formatter};

/// Enum of possible errors, which can occur during collecting filesystems data.
#[derive(Debug)]
enum Error {
    /// Missing mtab-like file error.
    MissingFile(std::io::Error),
    /// Parsing mtab-like file error.
    MountInfoParse(std::io::Error),
}

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            MissingFile(ref error) => Some(error),
            MountInfoParse(ref error) => Some(error),
        }
    }
}

impl Display for Error {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        use Error::*;

        match *self {
            MissingFile(ref error) => {
                write!(fmt, "missed file error: {}", error)
            },
            MountInfoParse(ref error) => {
                write!(fmt, "failed to obtain mount information: {}", error)
            },
        }
    }
}

impl From<Error> for session::Error {

    fn from(error: Error) -> session::Error {
        session::Error::action(error)
    }
}

/// A response type for the filesystems action.
pub struct Response {
    /// Information about the filesystem.
    mount_info: ospect::fs::Mount,
}

/// Handles requests for the filesystems action.
///
/// Initially searches in `/proc/mounts`. If it's missing, falls back to
/// `/etc/mtab`.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    let mounts = ospect::fs::mounts()
        .map_err(Error::MissingFile)?;

    for mount_info in mounts {
        let mount_info = mount_info.map_err(Error::MountInfoParse)?;
        session.reply(Response {
           mount_info,
        })?;
    }

    Ok(())
}

impl crate::response::Item for Response {

    type Proto = rrg_proto::sysinfo::Filesystem;

    fn into_proto(self) -> rrg_proto::sysinfo::Filesystem {
        // TODO: Remove lossy conversion of `PathBuf` to `String`
        // when `mount_point` and `device` fields of `Filesystem` message
        // will have `bytes` type instead of `string`.
        let mut proto = rrg_proto::sysinfo::Filesystem::new();
        proto.set_device(self.mount_info.name);
        proto.set_mount_point(self.mount_info.path.to_string_lossy().into_owned());
        proto.set_field_type(self.mount_info.fs_type);

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_if_any_filesystem_exists() {
        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());
        assert_ne!(session.reply_count(), 0);
    }

    #[cfg(feature = "test-fuse")]
    #[test]
    fn test_fuse_filesystem() {
        /// Unit-like struct, representing a filesystem for testing with `fuse`.
        struct FuseFilesystem;

        impl fuse::Filesystem for FuseFilesystem {}

        let fs_name = "fuse-test-fs";

        let tmp_dir = tempfile::tempdir().unwrap();
        let mountpoint = tmp_dir.path();

        let fs_name_option = format!("fsname={}", fs_name);
        let options = [
            "-o", "ro",
            "-o", "nosuid",
            "-o", "nodev",
            "-o", "relatime",
            "-o", "subtype=custom-type",
            "-o", &fs_name_option,
        ];
        let options = options.iter().map(|opt| opt.as_ref())
            .collect::<Vec<&std::ffi::OsStr>>();

        // Spawn a background thread to handle filesystem operations.
        // When `_background_session` is dropped, filesystem will be unmounted.
        let background_session = unsafe {
            fuse::spawn_mount(FuseFilesystem, &mountpoint, &options).unwrap()
        };

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());

        let fuse_mounted_fs = session.replies::<Response>()
            .find(|reply| reply.mount_info.source == fs_name)
            .expect("no reply with a mounted FUSE filesystem");

        let mount_info = &fuse_mounted_fs.mount_info;
        assert_eq!(mount_info.source, fs_name);
        assert_eq!(mount_info.target, tmp_dir.path());
        assert_eq!(mount_info.fs_type, "fuse.custom-type");

        drop(background_session);
    }
}
