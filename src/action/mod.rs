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

#[cfg(feature = "action-filesystems")]
#[cfg(target_os = "linux")]
pub mod filesystems;

#[cfg(feature = "action-interfaces")]
#[cfg(target_family = "unix")]
pub mod interfaces;

#[cfg(feature = "action-metadata")]
pub mod metadata;

#[cfg(feature = "action-listdir")]
pub mod listdir;

#[cfg(feature = "action-timeline")]
pub mod timeline;

#[cfg(feature = "action-network")]
pub mod network;

#[cfg(feature = "action-stat")]
pub mod stat;

#[cfg(feature = "action-insttime")]
pub mod insttime;

#[cfg(feature = "action-memsize")]
pub mod memsize;

#[cfg(feature = "action-finder")]
pub mod finder;

use crate::session::{self, Session, Task};

/// Abstraction for action-specific requests.
///
/// Protocol Buffer messages received from the GRR server are not necessarily
/// easy to work with and are hardly idiomatic to Rust. For this reason, actions
/// should define more structured data types to represent their input and should
/// be able to parse raw messages into them.
pub trait Request: Sized {

    /// A type of the corresponding raw proto message.
    type Proto: protobuf::Message + Default;

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
    type Proto: protobuf::Message + Default;

    /// A method for converting structured responses into raw proto messages.
    fn into_proto(self) -> Self::Proto;
}

impl Request for () {

    type Proto = protobuf::well_known_types::Empty;

    fn from_proto(_: protobuf::well_known_types::Empty) -> Result<(), session::ParseError> {
        Ok(())
    }
}

impl Response for () {

    const RDF_NAME: Option<&'static str> = None;

    type Proto = protobuf::well_known_types::Empty;

    fn into_proto(self) -> protobuf::well_known_types::Empty {
        protobuf::well_known_types::Empty::new()
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
        #[cfg(feature = "action-metadata")]
        "GetClientInfo" => task.execute(self::metadata::handle),

        #[cfg(feature = "action-listdir")]
        "ListDirectory" => task.execute(self::listdir::handle),

        #[cfg(feature = "action-timeline")]
        "Timeline" => task.execute(self::timeline::handle),

        #[cfg(feature = "action-network")]
        "ListNetworkConnections" => task.execute(self::network::handle),

        #[cfg(feature = "action-stat")]
        "GetFileStat" => task.execute(self::stat::handle),

        #[cfg(feature = "action-insttime")]
        "GetInstallDate" => task.execute(self::insttime::handle),

        #[cfg(feature = "action-interfaces")]
        #[cfg(target_family = "unix")]
        "EnumerateInterfaces" => task.execute(self::interfaces::handle),

        #[cfg(feature = "action-filesystems")]
        #[cfg(target_os = "linux")]
        "EnumerateFilesystems" => task.execute(self::filesystems::handle),

        #[cfg(feature = "action-memsize")]
        "GetMemorySize" => task.execute(self::memsize::handle),

        action => return Err(session::Error::Dispatch(String::from(action))),
    }
}

// TODO(panhania@): Remove all usages of the `Request` trait and replace it with
// `Args`.
pub trait Args: Sized {
    /// Low-level Protocol Buffers type representing the action arguments.
    type Proto: protobuf::Message + Default;

    /// Converts a low-level type to a structured request arguments.
    fn from_proto(proto: Self::Proto) -> Result<Self, ParseArgsError>;
}

impl Args for () {

    type Proto = protobuf::well_known_types::Empty;

    fn from_proto(_: protobuf::well_known_types::Empty) -> Result<(), ParseArgsError> {
        Ok(())
    }
}

pub trait Item: Sized {
    /// Low-level Protocol Buffers type representing the action results.
    type Proto: protobuf::Message + Default;

    /// A name of the corresponding RDF class in GRR.
    const RDF_NAME: &'static str;

    /// Converts an action result ot its low-level representation.
    fn into_proto(self) -> Self::Proto;
}

impl Item for () {

    // This implementation is intended to be used only in tests and we do not
    // really care about the `RDF_NAME` field there. And since GRR does not have
    // any RDF wrapper for empty type (except maybe `EmptyFlowArgs`, but this is
    // semantically different), we just leave it blank.
    const RDF_NAME: &'static str = "";

    type Proto = protobuf::well_known_types::Empty;

    fn into_proto(self) -> protobuf::well_known_types::Empty {
        protobuf::well_known_types::Empty::new()
    }
}

/// The error type for cases when action argument parsing fails.
#[derive(Debug)]
pub struct ParseArgsError {
    /// A corresponding [`ParseArgsErrorKind`] of this error.
    kind: ParseArgsErrorKind,
    /// A detailed payload associated with the error.
    error: Box<dyn std::error::Error + Send + Sync>,
}

impl ParseArgsError {

    /// Creates a new error instance caused by some invalid field error.
    fn invalid_field<E>(error: E) -> ParseArgsError
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        ParseArgsError {
            kind: ParseArgsErrorKind::InvalidField,
            error: Box::new(error),
        }
    }
}

/// Kinds of errors that can happen when parsing action arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParseArgsErrorKind {
    /// The serialized message with arguments was impossible to deserialize.
    InvalidProto,
    // TODO(panhania@): Augment with field name.
    /// One of the fields of the arguments struct is invalid.
    InvalidField,
}

impl ParseArgsErrorKind {

    fn as_str(&self) -> &'static str {
        use ParseArgsErrorKind::*;

        match *self {
            InvalidProto => "invalid serialized protobuf message",
            InvalidField => "invalid argument field",
        }
    }
}

impl std::fmt::Display for ParseArgsError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}: {}", self.kind.as_str(), self.error)
    }
}

impl std::error::Error for ParseArgsError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

impl From<protobuf::ProtobufError> for ParseArgsError {

    fn from(error: protobuf::ProtobufError) -> Self {
        ParseArgsError {
            kind: ParseArgsErrorKind::InvalidProto,
            error: Box::new(error),
        }
    }
}
