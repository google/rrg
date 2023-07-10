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
mod request;
mod response;

pub mod startup; // TODO(@panhania): Hide this module.

// TODO(@panhania): Consider moving these to a separate submodule.
#[cfg(feature = "action-get_filesystem_timeline")]
pub mod chunked;
#[cfg(feature = "action-get_filesystem_timeline")]
pub mod gzchunked;

pub use request::{Request, RequestId};
pub use response::{ResponseBuilder, ResponseId, Sink};

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
        use ::log::{info, error};

        let request = match Request::receive(args.heartbeat_rate) {
            Ok(request) => request,
            Err(error) => {
                error!("failed to receive a request: {}", error);
                continue
            }
        };
        let request_id = request.id();
        info!("received request '{}': {:?}", request_id, request.action());

        session::FleetspeakSession::dispatch(request);
        info!("finished handling request '{}'", request_id);
    }
}

/// Sends a system message with startup information to the GRR server.
///
/// This function should be called only once at the beginning of RRG's process
/// lifetime. It communicates to the GRR server that the agent has been started
/// and sends some basic information like agent metadata.
pub fn startup() {
    startup::startup()
}
