// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::path::PathBuf;

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
    let metadata = args.path.symlink_metadata()
        .map_err(crate::session::Error::action)?;

    session.reply(Item {
        path: args.path, // TODO(@panhania): This should be canonicalized.
        metadata,
    })?;

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::v2::get_file_metadata::Args;

    fn from_proto(proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError::*;

        let path = PathBuf::try_from(proto.path)
            .map_err(|error| invalid_field("path", error))?;

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
