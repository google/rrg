// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::path::PathBuf;

/// Arguments of the `grep_file_contents` action.
pub struct Args {
    /// Path to the file to grep the contents of.
    path: PathBuf,
    /// Regular expression to search for in the file contents.
    regex: regex::Regex,
}

/// Result of the `grep_file_contents` action.
pub struct Item {
    /// Byte offset within the file from which the content matched.
    offset: u64,
    /// Content that matched the specified regular expression.
    content: String,
}

/// Handles invocations of the `grep_file_contents` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    todo!()
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::grep_file_contents::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let path = PathBuf::try_from(proto.take_path())
            .map_err(|error| ParseArgsError::invalid_field("path", error))?;

        let regex = regex::Regex::new(proto.regex())
            .map_err(|error| ParseArgsError::invalid_field("regex", error))?;

        Ok(Args {
            path,
            regex,
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::grep_file_contents::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = Self::Proto::default();
        proto.set_offset(self.offset);
        proto.set_content(self.content);

        proto
    }
}
