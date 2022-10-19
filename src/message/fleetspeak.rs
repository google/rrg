// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Awaits for the raw GRR Protocol Buffers message object from Fleetspeak.
///
/// This function will block until the message is available. While waiting, it
/// will heartbeat at the specified rate making sure that Fleetspeak does not
/// kill the agent for unresponsiveness.
///
/// # Errors
///
/// This function will return error in case of recoverable issues (e.g. the
/// message is missing some required field). However, it will panic in case
/// there is a fundamental problem (e.g. the Fleetspeak connection is broken)
/// as it makes no sense to continue running in such case.
pub fn receive_raw(heartbeat_rate: std::time::Duration) -> Result<rrg_proto::jobs::GrrMessage, super::ReceiveRequestError> {
    use fleetspeak::ReadError::*;

    // TODO(@panhania): Rework Fleetspeak errors to use kinds and delete those
    // that make no sense to catch anyway.
    let message = match fleetspeak::receive_with_heartbeat(heartbeat_rate) {
        Ok(message) => message,
        Err(error @ (Malformed(_) | Decode(_))) => return Err(error.into()),
        Err(error) => {
            // If we failed to collect the message because of I/O error or magic
            // check, it means that our communication is broken (e.g. the pipe
            // was closed) and the agent should be killed.
            panic!("failed to collect a message: {}", error)
        }
    };

    if message.service != "GRR" {
        rrg_macro::warn!("message send by '{}' service (instead of GRR)", message.service);
    }

    match message.kind {
        Some(ref kind) if kind != "GrrMessage" => {
            rrg_macro::warn!("message with unrecognized type '{}'", kind);
        }
        Some(_) => (),
        None => {
            rrg_macro::warn!("message with missing type specification");
        }
    }

    Ok(protobuf::Message::parse_from_bytes(&message.data[..])?)
}

/// Sends a raw GRR Protocol Buffers message object to Fleetspeak.
///
/// This function will block until it is possible to send the message (which
/// should always be possible if there is no problem with the underlying file
/// for communicating with Fleetspeak).
///
/// # Errors
///
/// This function never errors but may panic during an unrecoverable issue (e.g.
/// the Fleetspeak connection is broken) as running in such a state does not
/// make sense.
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
