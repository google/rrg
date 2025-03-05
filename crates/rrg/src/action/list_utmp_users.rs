// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Arguments of the `list_utmp_users` action.
#[cfg(target_os = "linux")]
pub struct Args {
    // TODO.
}

/// Result of the `list_utmp_users` action.
#[cfg(target_os = "linux")]
pub struct Item {
    // TODO.
}

/// Handles invocations of the `list_utmp_users` action.
#[cfg(target_os = "linux")]
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    todo!()
}

#[cfg(not(target_os = "linux"))]
pub fn handle<S>(_: &mut S, _: ()) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use std::io::{Error, ErrorKind};
    Err(crate::session::Error::action(Error::from(ErrorKind::Unsupported)))
}

#[cfg(target_os = "linux")]
impl crate::request::Args for Args {

    type Proto = rrg_proto::list_utmp_users::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        todo!()
    }
}

#[cfg(target_os = "linux")]
impl crate::response::Item for Item {

    type Proto = rrg_proto::list_utmp_users::Result;

    fn into_proto(self) -> Self::Proto {
        todo!()
    }
}
