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

mod error;

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

pub use error::{
    ParseArgsError, ParseArgsErrorKind,
    DispatchError, DispatchErrorKind,
};
use crate::session::{self, Session};

/// Dispatches the given `request` to an appropriate action handler.
///
/// This method is a mapping between action names (as specified in the protocol)
/// and action handlers (implemented on the agent).
///
/// # Errors
///
/// This function will return an error if the given action is unknown (or not
/// yet implemented).
///
/// It will also error out if the action execution itself fails for whatever
/// reason.
pub fn dispatch<'s, S>(session: &mut S, request: crate::message::Request) -> session::Result<()>
where
    S: Session,
{
    match request.action_name() {
        #[cfg(feature = "action-metadata")]
        "GetClientInfo" => handle(session, request, self::metadata::handle),

        #[cfg(feature = "action-listdir")]
        "ListDirectory" => handle(session, request, self::listdir::handle),

        #[cfg(feature = "action-timeline")]
        "Timeline" => handle(session, request, self::timeline::handle),

        #[cfg(feature = "action-network")]
        "ListNetworkConnections" => handle(session, request, self::network::handle),

        #[cfg(feature = "action-stat")]
        "GetFileStat" => handle(session, request, self::stat::handle),

        #[cfg(feature = "action-insttime")]
        "GetInstallDate" => handle(session, request, self::insttime::handle),

        #[cfg(feature = "action-interfaces")]
        #[cfg(target_family = "unix")]
        "EnumerateInterfaces" => handle(session, request, self::interfaces::handle),

        #[cfg(feature = "action-filesystems")]
        #[cfg(target_os = "linux")]
        "EnumerateFilesystems" => handle(session, request, self::filesystems::handle),

        #[cfg(feature = "action-memsize")]
        "GetMemorySize" => handle(session, request, self::memsize::handle),

        action => return Err(session::Error::Dispatch(String::from(action))),
    }
}

/// Handles a `request` using the specified `handler`.
///
/// This method will attempt to interpret request arguments for the specific
/// action and execute the handler with them.
///
/// # Errors
///
/// This function will return an error if the request arguments cannot be parsed
/// for the specific action or if the action execution fails.
fn handle<S, A, H>(session: &mut S, request: crate::message::Request, handler: H) -> session::Result<()>
where
    S: crate::session::Session,
    A: Args,
    H: FnOnce(&mut S, A) -> session::Result<()>,
{
    let args = request.parse_args()?;
    handler(session, args)
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
