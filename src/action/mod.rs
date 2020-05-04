// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

pub mod metadata;
pub mod startup;
pub mod timeline;

use crate::session::{self, Session, Task};

pub trait Request: Sized {
    type Proto: prost::Message + Default;
    fn from_proto(proto: Self::Proto) -> Result<Self, session::ParseError>;
}

pub trait Response: Sized {
    const RDF_NAME: Option<&'static str>;
    type Proto: prost::Message + Default;
    fn into_proto(self) -> Self::Proto;
}

impl Request for () {

    type Proto = ();

    fn from_proto(unit: ()) -> Result<(), session::ParseError> {
        Ok(unit)
    }
}

impl Response for () {

    const RDF_NAME: Option<&'static str> = None;

    type Proto = ();

    fn into_proto(self) {
    }
}

/// Dispatches `task` to a handler appropriate for the given `action`.
///
/// This method is a mapping between action names (as specified in the protocol)
/// and action handlers (implemented on the agent).
///
/// If the given action is unknown (or not yet implemented), this function will
/// return an error.
pub fn dispatch<'s, S>(action: &str, task: Task<'s, S>) -> session::Result<()>
where
    S: Session,
{
    match action {
        "SendStartupInfo" => task.execute(self::startup::handle),
        "GetClientInfo" => task.execute(self::metadata::handle),
        "Timeline" => task.execute(self::timeline::handle),
        action => return Err(session::Error::Dispatch(String::from(action))),
    }
}
