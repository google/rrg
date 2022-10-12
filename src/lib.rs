// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

pub mod action;
pub mod fs;
pub mod io;
pub mod log;
pub mod message;
pub mod metadata;
pub mod args;
pub mod session;
pub mod sink;
pub mod startup;

// Consider moving these to a separate submodule.
#[cfg(feature = "action-timeline")]
pub mod chunked;
#[cfg(feature = "action-timeline")]
pub mod gzchunked;

use crate::args::{Args};

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
pub fn listen(args: &Args) {
    loop {
        let request = match crate::message::Request::receive(args.heartbeat_rate) {
            Ok(request) => request,
            Err(error) => {
                rrg_macro::error!("failed to obtain a request: {}", error);
                continue
            }
        };

        session::FleetspeakSession::handle(request);
    }
}
