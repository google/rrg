/// A session implementation that uses real Fleetspeak connection.
///
/// This is a normal session type that that is associated with some flow on the
/// server. It keeps track of the responses it sends and collects statistics
/// about network and runtime utilization to kill the action if it is needed.
pub struct FleetspeakSession {
    response_builder: crate::ResponseBuilder,
}

impl FleetspeakSession {

    /// Creates a new Fleetspeak session for the given `request` object.
    fn new(request_id: crate::RequestId) -> FleetspeakSession {
        FleetspeakSession {
            response_builder: crate::ResponseBuilder::new(request_id),
        }
    }

    /// Dispatches the given `request` to an appropriate action handler.
    ///
    /// This is the main entry point of the session. It processes the request
    /// and sends the execution status back to the server.
    pub fn dispatch(request: crate::Request) {
        let mut session = FleetspeakSession::new(request.id());

        let result = crate::action::dispatch(&mut session, request);
        let status = session.response_builder.status(result);

        status.send_unaccounted()
            // If we fail to send the response to Fleetspeak, our connection is
            // most likely broken and we should die. In general, this should not
            // happen.
            .expect("failed to send a status response to Fleetspeak");

        // TODO(panhania@): Consider returning the status so that the parent can
        // log appropriate message.
    }
}

impl crate::session::Session for FleetspeakSession {

    fn reply<I>(&mut self, item: I) -> crate::session::Result<()>
    where
        I: crate::action::Item,
    {
        // TODO(panhania@): Enforce limits.
        let reply = self.response_builder.reply(item);

        reply.send_unaccounted()
            // If we fail to send the response to Fleetspeak, our connection is
            // most likely broken and we should die. In general, this should not
            // happen.
            .expect("failed to send a result response to Fleetspeak");

        Ok(())
    }

    fn send<I>(&mut self, sink: crate::Sink, item: I) -> crate::session::Result<()>
    where
        I: crate::action::Item,
    {
        let parcel = crate::Parcel {
            sink,
            payload: item,
        };

        parcel.send_unaccounted()
            // If we fail to send the parcel to Fleetspeak, our connection is
            // most likely broken and we should die. In general, this should not
            // happen.
            .expect("failed to send a parcel to Fleetspeak");

        Ok(())
    }
}
