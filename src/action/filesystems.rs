// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the filesystems action.
//!
//! The filesystems action lists all mounted filesystems on the client,
//! collecting device name, mount point, filesystem type and its options.
//! Current implementation works only in Linux systems.

use rrg_proto::{Filesystem, KeyValue, AttributedDict, DataBlob};
use crate::session::{self, Session};

use log::error;
use std::fmt::{Display, Formatter};

/// Enum of possible errors, which can occur during collecting filesystems data.
#[derive(Debug)]
enum Error {
    /// Missed mtab-like file error.
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
/// Initially searches in `/proc/mounts`. If it's missed, falls back to
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
fn option_to_key_value(option: String) -> KeyValue {
    match &option.split('=').collect::<Vec<&str>>()[..] {
        &[key] => {
            KeyValue {
                k: Some(DataBlob {
                    string: Some(String::from(key)),
                    ..Default::default()
                }),
                v: None,
            }
        },
        &[key, value] => {
            KeyValue {
                k: Some(DataBlob {
                    string: Some(String::from(key)),
                    ..Default::default()
                }),
                v: Some(DataBlob {
                    string: Some(String::from(value)),
                    ..Default::default()
                }),
            }
        },
        _ => {
            error!("invalid mount option syntax: {}", option);
            KeyValue {
                k: None,
                v: None,
            }
        },
    }
}

/// Converts a `Vec` of filesystem mount options in `String` representation to
/// GRR's `AttributedDict` protobuf struct representation.
fn options_to_dict(options: Vec<String>) -> AttributedDict {
    AttributedDict {
        dat: options.into_iter().map(option_to_key_value).collect(),
    }
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("Filesystem");

    type Proto = rrg_proto::Filesystem;

    fn into_proto(self) -> Filesystem {
        // TODO: Remove lossy conversion of `PathBuf` to `String`
        // when `mount_point` and `device` fields of `Filesystem` message
        // will have `bytes` type instead of `string`.
        Filesystem {
            device: Some(self.mount_info.source.to_string_lossy()
                .into_owned()),
            mount_point: Some(self.mount_info.dest.to_string_lossy()
                .into_owned()),
            r#type: Some(self.mount_info.fstype),
            label: None,
            options: Some(options_to_dict(self.mount_info.options)),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_if_any_filesystem_exist() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());
        assert_ne!(session.reply_count(), 0);
    }

    /// Returns all responses whose `source` is equal to `fs_name`.
    fn find_filesystems_by_name<'a>(
        session: &'a session::test::Fake,
        fs_name: &'a PathBuf,
    ) -> Vec<&'a Response> {
        let mut responses = Vec::new();

        for i in 0..session.reply_count() {
            let response: &Response = session.reply(i);
            if response.mount_info.source == *fs_name {
                responses.push(response);
            }
        }

        responses
    }

    /// Unit-like struct, representing a filesystem for testing with `fuse`.
    #[cfg(target_os = "linux")]
    struct FuseFilesystem;

    #[cfg(target_os = "linux")]
    impl fuse::Filesystem for FuseFilesystem {}

    #[test]
    #[cfg(target_os = "linux")]
    fn test_fuse_filesystem() {
        use users::{get_current_uid, get_current_gid};

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

        let fuse_mounted_fs = find_filesystems_by_name(&session, &fs_name);
        assert_eq!(fuse_mounted_fs.len(), 1);

        let mount_info = &fuse_mounted_fs[0].mount_info;
        assert_eq!(mount_info.source, fs_name);
        assert_eq!(mount_info.dest, tmp_dir.path());
        assert_eq!(mount_info.fstype, "fuse.custom-type");

        let options = &mount_info.options;
        assert!(options.iter().any(|opt| opt == "ro"));
        assert!(options.iter().any(|opt| opt == "nosuid"));
        assert!(options.iter().any(|opt| opt == "nodev"));
        assert!(options.iter().any(|opt| opt == "relatime"));

        // `user_id` and `group_id` are set by libfuse.
        // http://man7.org/linux/man-pages/man8/mount.fuse.8.html
        let current_uid_option = format!("user_id={}", get_current_uid());
        assert!(options.iter().any(|opt| *opt == current_uid_option));

        let current_gid_option = format!("group_id={}", get_current_gid());
        assert!(options.iter().any(|opt| *opt == current_gid_option));

        drop(background_session);
    }
}
