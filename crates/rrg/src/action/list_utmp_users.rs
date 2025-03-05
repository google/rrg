// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Arguments of the `list_utmp_users` action.
pub struct Args {
    // TODO.
}

/// Result of the `list_utmp_users` action.
pub struct Item {
    // TODO.
}

/// Handles invocations of the `list_utmp_users` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    todo!()
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::list_utmp_users::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        todo!()
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::list_utmp_users::Result;

    fn into_proto(self) -> Self::Proto {
        todo!()
    }
}
