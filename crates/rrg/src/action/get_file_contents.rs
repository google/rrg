// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::path::PathBuf;

/// Arguments of the `get_file_contents` action.
pub struct Args {
    /// Path to the file to get the contents of.
    path: PathBuf,
    /// Offset from which to read the file contents.
    offset: u64,
    /// Number of bytes to read from the file.
    len: u64,
}

/// Result of the `get_file_contents` action.
pub struct Item {
    /// Byte offset of the file part sent to the blob sink.
    offset: u64,
    /// Number of bytes of the file part sent to the blob sink.
    len: u64,
    /// SHA-256 digest of the file part sent to the blob sink.
    blob_sha256: sha2::Sha256,
}

pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    todo!()
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::v2::get_file_contents::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        todo!()
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::v2::get_file_contents::Result;

    fn into_proto(self) -> Self::Proto {
        todo!()
    }
}
