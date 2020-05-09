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
    MissedFile(std::io::Error),
    /// Parsing mtab-like file error.
    MountInfoError(std::io::Error),
}

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            MissedFile(ref error) => Some(error),
            MountInfoError(ref error) => Some(error),
        }
    }
}

impl Display for Error {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        use Error::*;

        match *self {
            MissedFile(ref error) => {
                write!(fmt, "missed file error: {}", error)
            },
            MountInfoError(ref error) => {
                write!(fmt, "failed to obtain MountInfo: {}", error)
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
            match MountIter::new_from_file("/etc/mtab") {
                Ok(mount_iter) => mount_iter,
                Err(error) => {
                    return Err(session::Error::from(Error::MissedFile(error)))
                },
            }
        },
    };

    for mount_info in mount_iter {
        match mount_info {
            Ok(mount_info) => {
                session.reply(Response {
                    mount_info,
                })?;
            },
            Err(error) => {
                return Err(session::Error::from(Error::MountInfoError(error)))
            },
        }

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
