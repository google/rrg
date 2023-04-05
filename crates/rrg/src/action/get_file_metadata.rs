// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::path::PathBuf;

/// Arguments of the `get_file_metadata` action.
pub struct Args {
    /// Path the file to get the metadata of.
    path: std::path::PathBuf,
}

/// Result of the `get_file_metadata` action.
struct Item {
    /// Canonical path to the file we retrieve the metadata of.
    path: std::path::PathBuf,
    /// Retrieved metadata of the file we retrieved.
    metadata: std::fs::Metadata,
}

/// Handles invocations of the `get_file_metadata` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    todo!()
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::v2::get_file_metadata::Args;

    fn from_proto(proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        todo!()
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::v2::get_file_metadata::Result;

    fn into_proto(self) -> Self::Proto {
        todo!()
    }
}
