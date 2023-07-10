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

        status.send_unaccounted();
    }
}

impl crate::session::Session for FleetspeakSession {

    fn reply<I>(&mut self, item: I) -> crate::session::Result<()>
    where
        I: crate::response::Item,
    {
        // TODO(panhania@): Enforce limits.
        let reply = self.response_builder.reply(item);

        reply.send_unaccounted();

        Ok(())
    }

    fn send<I>(&mut self, sink: crate::Sink, item: I) -> crate::session::Result<()>
    where
        I: crate::response::Item,
    {
        let parcel = crate::response::Parcel::new(sink, item);

        parcel.send_unaccounted();

        Ok(())
    }
}
