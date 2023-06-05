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

#[cfg(feature = "action-get_system_metadata")]
pub mod get_system_metadata;

#[cfg(feature = "action-get_file_metadata")]
pub mod get_file_metadata;

#[cfg(feature = "action-get_file_contents")]
pub mod get_file_contents;

#[cfg(feature = "action-get_filesystem_timeline")]
pub mod get_filesystem_timeline;

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

    let action = match request.action() {
        Ok(action) => action,
        Err(action) => {
            return Err(crate::session::Error::unknown_action(action));
        }
    };

    match action {
        #[cfg(feature = "action-get_system_metadata")]
        GetSystemMetadata => {
            handle(session, request, self::get_system_metadata::handle)
        }
        #[cfg(feature = "action-get_file_metadata")]
        GetFileMetadata => {
            handle(session, request, self::get_file_metadata::handle)
        }
        #[cfg(feature = "action-get_file_contents")]
        GetFileContents => {
            handle(session, request, self::get_file_contents::handle)
        }
        #[cfg(feature = "action-get_filesystem_timeline")]
        GetFilesystemTimeline => {
            handle(session, request, self::get_filesystem_timeline::handle)
        }
        // We allow `unreachable_patterns` because otherwise we get a warning if
        // we compile with all the actions enabled.
        #[allow(unreachable_patterns)]
        action => {
            return Err(crate::session::Error::unsupported_action(action));
        },
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
fn handle<S, A, H>(session: &mut S, request: crate::Request, handler: H) -> crate::session::Result<()>
where
    S: crate::session::Session,
    A: crate::request::Args,
    H: FnOnce(&mut S, A) -> crate::session::Result<()>,
{
    Ok(handler(session, request.args()?)?)
}
