// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Arguments of the `grep_file_contents` action.
pub struct Args {
}

/// Result of the `grep_file_contents` action.
pub struct Item {
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

    fn from_proto(proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        todo!()
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::grep_file_contents::Result;

    fn into_proto(self) -> Self::Proto {
        todo!()
    }
}
