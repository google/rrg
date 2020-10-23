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

use log::warn;

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
    #[cfg(target_family = "unix")]
    ext_attrs: Vec<crate::fs::unix::ExtAttr>,
    /// Additional Linux-specific file flags.
    #[cfg(target_os = "linux")]
    flags_linux: Option<u32>,
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
        std::fs::read_link(&request.path).map_err(|error| {
            // TODO: Make the `ack!` macro more expressive and rewrite it.
            warn! {
                "failed to read symlink for '{path}': {cause}",
                path = request.path.display(),
                cause = error,
            }
        }).ok()
    } else {
        None
    };

    #[cfg(target_family = "unix")]
    let ext_attrs = if request.collect_ext_attrs {
        // TODO: Make the `ack!` macro more expressive and then simplify it.
        match crate::fs::unix::ext_attrs(&request.path) {
            Ok(ext_attrs) => ext_attrs.collect(),
            Err(error) => {
                warn! {
                    "failed to collect attributes for '{path}': {cause}",
                    path = request.path.display(),
                    cause = error,
                };
                vec!()
            },
        }
    } else {
        vec!()
    };

    #[cfg(target_os = "linux")]
    let flags_linux = crate::fs::linux::flags(&request.path).map_err(|error| {
        // TODO: Make the `ack!` macro more expressive and rewrite it.
        warn! {
            "failed to collect flags for '{path}': {cause}",
            path = request.path.display(),
            cause = error,
        }
    }).ok();

    let response = Response {
        path: request.path,
        metadata: metadata,
        symlink: symlink,
        #[cfg(target_family = "unix")]
        ext_attrs: ext_attrs,
        #[cfg(target_os = "linux")]
        flags_linux: flags_linux,
    };

    session.reply(response)?;

    Ok(())
}

impl super::Request for Request {

    type Proto = rrg_proto::GetFileStatRequest;

    fn from_proto(proto: Self::Proto) -> Result<Self, session::ParseError> {
        use std::convert::TryInto as _;

        let path = proto.pathspec
            .ok_or(session::MissingFieldError::new("path spec"))?
            .try_into().map_err(session::ParseError::malformed)?;

        Ok(Request {
            path: path,
            follow_symlink: proto.follow_symlink.unwrap_or(false),
            collect_ext_attrs: proto.collect_ext_attrs.unwrap_or(false),
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
            #[cfg(target_family = "unix")]
            ext_attrs: self.ext_attrs.into_iter().map(Into::into).collect(),
            #[cfg(target_os = "linux")]
            st_flags_linux: self.flags_linux,
            ..self.metadata.into_lossy()
        }
    }
}

#[cfg(test)]
mod tests {
}
