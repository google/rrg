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
