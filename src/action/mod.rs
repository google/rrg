// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Handlers and types for agent's actions.
//!
//! The basic functionality that a GRR agent exposes is called an _action_.
//! Actions are invoked by the server (when running a _flow_), should gather
//! requested information and report back to the server.
//!
//! In RRG each action consists of three components: a request type, a response
//! type and an action handler. Request and response types wrap lower-level
//! Protocol Buffer messages sent by and to the GRR server. Handlers accept one
//! instance of the corresponding request type and send some (zero or more)
//! instances of the corresponding response type.

#[cfg(target_os = "linux")]
pub mod filesystems;

pub mod metadata;
pub mod startup;
pub mod network;

use crate::session::{self, Session, Task};

/// Abstraction for action-specific requests.
///
/// Protocol Buffer messages received from the GRR server are not necessarily
/// easy to work with and are hardly idiomatic to Rust. For this reason, actions
/// should define more structured data types to represent their input and should
/// be able to parse raw messages into them.
pub trait Request: Sized {

    /// A type of the corresponding raw proto message.
    type Proto: prost::Message + Default;

    /// A method for converting raw proto messages into structured requests.
    fn from_proto(proto: Self::Proto) -> Result<Self, session::ParseError>;
}

/// Abstraction for action-specific responses.
///
/// Like with the [`Request`] type, Protocol Buffer messages sent to the GRR
/// server are very idiomatic to Rust. For this reason, actions should define
/// more structured data types to represent responses and provide a way to
/// convert them into the wire format.
///
/// Note that because of the design flaws in the protocol, actions also need to
/// specify a name of the wrapper RDF class from the Python implementation.
/// Hopefully, one day this issue would be fixed and class names will not leak
/// into the specification.
///
/// [`Request`]: trait.Request.html
pub trait Response: Sized {

    /// A name of the corresponding RDF class.
    const RDF_NAME: Option<&'static str>;

    /// A type of the corresponding raw proto message.
    type Proto: prost::Message + Default;

    /// A method for converting structured responses into raw proto messages.
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
        "ListNetworkConnections" => task.execute(self::network::handle),

        #[cfg(target_os = "linux")]
        "EnumerateFilesystems" => task.execute(self::filesystems::handle),

        action => return Err(session::Error::Dispatch(String::from(action))),
    }
}
