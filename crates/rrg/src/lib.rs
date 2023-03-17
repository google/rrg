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

mod request;
// TOOD(@panhania): Hide this module once the `timeline` example is removed or
// refactored.
pub mod response;

pub mod startup; // TODO(@panhania): Hide this module.

// Consider moving these to a separate submodule.
#[cfg(feature = "action-timeline")]
pub mod chunked;
#[cfg(feature = "action-timeline")]
pub mod gzchunked;

pub use request::{Action, Args, ParseArgsError, ParseArgsErrorKind, Request, RequestId};
pub use response::{Reply, ResponseBuilder, ResponseId, Sink};

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
        let request = match Request::receive(args.heartbeat_rate) {
            Ok(request) => request,
            Err(error) => {
                rrg_macro::error!("failed to receive a request: {}", error);
                continue
            }
        };

        session::FleetspeakSession::dispatch(request);
    }
}

/// Sends a system message with startup information to the GRR server.
///
/// This function should be called only once at the beginning of RRG's process
/// lifetime. It communicates to the GRR server that the agent has been started
/// and sends some basic information like agent metadata.
///
/// # Errors
///
/// In case we fail to send startup information, this function will report an
/// error. Note that by "send" we just mean pushing the message to Fleetspeak,
/// whether Fleetspeak manages to reach the GRR server with it is a separate
/// issue. Failure to push the message to Fleetspeak means that the pipe used
/// for communication is most likely broken and we should quit.
pub fn startup() -> Result<(), fleetspeak::WriteError> {
    startup::startup()
}
