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

#[allow(dead_code)]
pub mod deprecated; // TODO(@panhania): Unexpose this module.

// TODO(@panhania): Hide this module behind a feature.
pub mod get_system_metadata;

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
pub fn dispatch<'s, S>(session: &mut S, request: crate::Request) -> Result<(), crate::session::Error>
where
    S: crate::session::Session,
{
    use crate::request::Action::*;

    match request.action() {
        GetSystemMetadata => {
            handle(session, request, self::get_system_metadata::handle)
        }
    }

    /*
    match request.action {
        #[cfg(feature = "action-listdir")]
        "ListDirectory" => {
            handle(session, request, self::listdir::handle)
        }

        #[cfg(feature = "action-timeline")]
        "Timeline" => {
            handle(session, request, self::timeline::handle)
        }

        #[cfg(feature = "action-network")]
        "ListNetworkConnections" => {
            handle(session, request, self::network::handle)
        }

        #[cfg(feature = "action-stat")]
        "GetFileStat" => {
            handle(session, request, self::stat::handle)
        }

        #[cfg(feature = "action-insttime")]
        "GetInstallDate" => {
            handle(session, request, self::insttime::handle)
        }

        #[cfg(feature = "action-interfaces")]
        #[cfg(target_family = "unix")]
        "EnumerateInterfaces" => {
            handle(session, request, self::interfaces::handle)
        }

        #[cfg(feature = "action-filesystems")]
        #[cfg(target_os = "linux")]
        "EnumerateFilesystems" => {
            handle(session, request, self::filesystems::handle)
        }

        action_name => {
            return Err(error::UnknownActionError::new(action_name).into())
        }
    }
    */
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
fn handle<S, A, H>(session: &mut S, request: crate::Request, handler: H) -> crate::session::Result<()>
where
    S: crate::session::Session,
    A: crate::request::Args,
    H: FnOnce(&mut S, A) -> crate::session::Result<()>,
{
    Ok(handler(session, request.args()?)?)
}
