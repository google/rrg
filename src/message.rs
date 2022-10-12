// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

// TODO: Write top-level documentation for this module (and its submodules).

mod request;
mod response;

pub use request::{Request, RequestId, ReceiveRequestError};
pub use response::{Item, Status, ResponseBuilder, ResponseId};

// TODO: Unexpose this function, make it possible to only send the high-level
// types (`Item`, `Status`).
pub fn send_raw(message: rrg_proto::jobs::GrrMessage) {
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
