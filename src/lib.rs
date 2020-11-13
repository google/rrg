// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

pub mod action;
pub mod fs;
pub mod io;
pub mod message;
pub mod metadata;
pub mod opts;
pub mod session;

// Consider moving these to a separate submodule.
pub mod chunked;
pub mod gzchunked;

use crate::opts::{Opts};

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
pub fn listen(opts: &Opts) {
    loop {
        if let Some(message) = message::collect(&opts) {
            session::handle(message);
        }
    }
}
