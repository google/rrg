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

use log::error;
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
    mount_info: proc_mounts::MountInfo,
}

/// Handles requests for the filesystems action.
///
/// Initially searches in `/proc/mounts`. If it's missing, falls back to
/// `/etc/mtab`.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    use proc_mounts::MountIter;

    // Check whether `/proc/mounts` exists.
    let mount_iter = match MountIter::new() {
        Ok(mount_iter) => mount_iter,
        Err(_) => {
            // `/proc/mounts` doesn't exist. Try to fall back to `/etc/mtab`.
            MountIter::new_from_file("/etc/mtab").map_err(Error::MissingFile)?
        },
    };

    for mount_info in mount_iter {
        let mount_info = mount_info.map_err(Error::MountInfoParse)?;
        session.reply(Response {
           mount_info,
        })?;
    }

    Ok(())
}

/// Converts filesystem mount option in `String` representation to
/// GRR's `KeyValue` protobuf struct representation.
fn option_to_key_value(option: String) -> rrg_proto::jobs::KeyValue {
    match &option.split('=').collect::<Vec<&str>>()[..] {
        &[key] => rrg_proto::jobs::KeyValue::key(String::from(key)),
        &[key, value] => rrg_proto::jobs::KeyValue::pair(String::from(key), String::from(value)),
        _ => {
            error!("invalid mount option syntax: {}", option);
            // TODO: It's better not to send any key-value in this case.
            rrg_proto::jobs::KeyValue::new()
        },
    }
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("Filesystem");

    type Proto = rrg_proto::sysinfo::Filesystem;

    fn into_proto(self) -> rrg_proto::sysinfo::Filesystem {
        let options: rrg_proto::jobs::AttributedDict = self.mount_info.options.into_iter()
            .map(option_to_key_value)
            .collect();

        // TODO: Remove lossy conversion of `PathBuf` to `String`
        // when `mount_point` and `device` fields of `Filesystem` message
        // will have `bytes` type instead of `string`.
        let mut proto = rrg_proto::sysinfo::Filesystem::new();
        proto.set_device(self.mount_info.source.to_string_lossy().into_owned());
        proto.set_mount_point(self.mount_info.dest.to_string_lossy().into_owned());
        proto.set_field_type(self.mount_info.fstype);
        proto.set_options(options);

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_if_any_filesystem_exists() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());
        assert_ne!(session.reply_count(), 0);
    }

    /// Unit-like struct, representing a filesystem for testing with `fuse`.
    struct FuseFilesystem;

    impl fuse::Filesystem for FuseFilesystem {}

    #[test]
    fn test_fuse_filesystem() {
        let fs_name = PathBuf::from("fuse-test-fs");

        let tmp_dir = tempfile::tempdir().unwrap();
        let mountpoint = tmp_dir.path();

        let fs_name_option = format!("fsname={}", fs_name.to_str().unwrap());
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

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        let fuse_mounted_fs = session.replies::<Response>()
            .find(|reply| reply.mount_info.source == fs_name)
            .expect("no reply with a mounted FUSE filesystem");

        let mount_info = &fuse_mounted_fs.mount_info;
        assert_eq!(mount_info.source, fs_name);
        assert_eq!(mount_info.dest, tmp_dir.path());
        assert_eq!(mount_info.fstype, "fuse.custom-type");

        let options = &mount_info.options;
        assert!(options.iter().any(|opt| opt == "ro"));
        assert!(options.iter().any(|opt| opt == "nosuid"));
        assert!(options.iter().any(|opt| opt == "nodev"));
        assert!(options.iter().any(|opt| opt == "relatime"));

        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        // `user_id` and `group_id` are set by libfuse.
        // http://man7.org/linux/man-pages/man8/mount.fuse.8.html
        let current_uid_option = format!("user_id={}", uid);
        assert!(options.iter().any(|opt| *opt == current_uid_option));

        let current_gid_option = format!("group_id={}", gid);
        assert!(options.iter().any(|opt| *opt == current_gid_option));

        drop(background_session);
    }
}
