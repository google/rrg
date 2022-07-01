// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use log::{error, warn};

use crate::opts::Opts;

pub fn send(message: rrg_proto::jobs::GrrMessage) {
        let data = protobuf::Message::write_to_bytes(&message)
            // Encoding can fail only if the buffer is insufficiently large. But
            // since we use growable vector this should never happen (provided
            // that we have enough memory).
            .expect("message encoding failure");

        let message = fleetspeak::Message {
            service: String::from("GRR"),
            kind: Some(String::from("GrrMessage")),
            data,
        };

        if let Err(error) = fleetspeak::send(message) {
            // If we failed to deliver the message through Fleetspeak, it means
            // that our communication is broken (e.g. the pipe was closed) and
            // the agent should be killed.
            panic!("message delivery failure: {}", error)
        };
}

// TODO: Rename this method to `receive`.
pub fn collect(opts: &Opts) -> Option<rrg_proto::jobs::GrrMessage> {
    use fleetspeak::ReadError::*;

    let message = match fleetspeak::receive_with_heartbeat(opts.heartbeat_rate) {
        Ok(message) => message,
        Err(Malformed(error)) => {
            error!("received a malformed message: {}", error);
            return None;
        }
        Err(Decode(error)) => {
            error!("failed to decode a message: {}", error);
            return None;
        }
        Err(error) => {
            // If we failed to collect the message because of I/O error or magic
            // check, it means that our communication is broken (e.g. the pipe
            // was closed) and the agent should be killed.
            panic!("failed to collect a message: {}", error)
        }
    };

    if message.service != "GRR" {
        warn!("message send by '{}' service (instead of GRR)", message.service);
    }

    match message.kind {
        Some(ref kind) if kind != "GrrMessage" => {
            warn!("message with unrecognized type '{}'", kind);
        }
        Some(_) => (),
        None => {
            warn!("message with missing type specification");
        }
    }

    match protobuf::parse_from_bytes(&message.data[..]) {
        Ok(message) => Some(message),
        Err(error) => {
            error!("failed to decode the data: {}", error);
            None
        }
    }
}
