// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Arguments of the `get_tcp_response` action.
pub struct Args {
}

/// Result of the `get_tcp_response` action.
pub struct Item {
}

pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    todo!()
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_tcp_response::Args;

    fn from_proto(proto: Self::Proto) -> Result<Self, crate::request::ParseArgsError> {
        todo!()
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_tcp_response::Result;

    fn into_proto(self) -> Self::Proto {
        todo!()
    }
}
