// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use fleetspeak::Packet;
use log::{error, warn};

use crate::opts::Opts;

pub fn send(message: rrg_proto::GrrMessage) {
        let packet = Packet {
            service: String::from("GRR"),
            kind: Some(String::from("GrrMessage")),
            data: message,
        };

        if let Err(error) = fleetspeak::send(packet) {
            // If we failed to deliver the message through Fleetspeak, it means
            // that our communication is broken (e.g. the pipe was closed) and
            // the agent should be killed.
            panic!("message delivery failure: {}", error)
        };
}

pub fn collect(opts: &Opts) -> Option<rrg_proto::GrrMessage> {
    use fleetspeak::ReadError::*;

    let packet = match fleetspeak::collect(opts.heartbeat_rate) {
        Ok(packet) => packet,
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

    if packet.service != "GRR" {
        warn!("message send by '{}' service (instead of GRR)", packet.service);
    }

    match packet.kind {
        Some(ref kind) if kind != "GrrMessage" => {
            warn!("message with unrecognized type '{}'", kind);
        }
        Some(_) => (),
        None => {
            warn!("message with missing type specification");
        }
    }

    Some(packet.data)
}
