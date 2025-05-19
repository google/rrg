// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

// TODO: Hide irrelevant modules.

pub mod action;
pub mod fs;
pub mod io;
pub mod log;
pub mod args;
pub mod session;

mod blob;
mod filter;
mod request;
mod response;

mod ping;
mod startup;

// TODO(@panhania): Consider moving these to a separate submodule.
#[cfg(feature = "action-get_filesystem_timeline")]
pub mod chunked;
#[cfg(feature = "action-get_filesystem_timeline")]
pub mod gzchunked;

pub use ping::Ping;
pub use startup::Startup;

pub use request::{ParseRequestError, Request, RequestId};
pub use response::{LogBuilder, Parcel, ResponseBuilder, ResponseId, Sink};

/// Initializes the RRG subsystems.
///
/// This function should be called only once (at the very beginning of the
/// process lifetime).
pub fn init(args: &crate::args::Args) {
    log::init(args)
}

/// Enters the agent's main loop and waits for messages.
///
/// It will poll for messages from the GRR server and should consume very few
/// resources when idling. Once it picks a message, it dispatches it to an
/// appropriate action handler (which should take care of sending heartbeat
/// signals if expected to be long-running) and goes back to idling when action
/// execution is finished.
///
/// This function never terminates and panics only if something went very wrong
/// (e.g. the Fleetspeak connection has been broken). All non-critical errors
/// are going to be handled carefully, notifying the server about the failure if
/// appropriate.
pub fn listen(args: &crate::args::Args) {
    loop {
        let request = Request::receive(args.heartbeat_rate);
        session::FleetspeakSession::dispatch(args, request);
    }
}
