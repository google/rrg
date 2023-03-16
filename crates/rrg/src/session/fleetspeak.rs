use crate::message::Sink;

/// A session implementation that uses real Fleetspeak connection.
///
/// This is a normal session type that that is associated with some flow on the
/// server. It keeps track of the responses it sends and collects statistics
/// about network and runtime utilization to kill the action if it is needed.
pub struct FleetspeakSession {
    response_builder: crate::message::ResponseBuilder,
}

impl FleetspeakSession {

    /// Creates a new Fleetspeak session for the given `request` object.
    fn new(request_id: crate::RequestId) -> FleetspeakSession {
        FleetspeakSession {
            response_builder: crate::message::ResponseBuilder::new(request_id),
        }
    }

    // TODO(panhania@): Rename this function to `dispatch`.
    //
    // Currently, the call chain looks like:
    //
    //   1. `FleetspeakSession::handle`
    //   2. `action::dispatch`
    //   3. `action::handle`
    //   4. `<action>::handle`
    //
    // This `dispatch` in the middle is a little bit charring. It would be more
    // reasonable to first have two `dispatch` calls that at some point call
    // correct `handle` function.
    pub fn handle(request: crate::Request) {
        let mut session = FleetspeakSession::new(request.id());

        let result = crate::action::dispatch(&mut session, request);
        session.response_builder.status(result).send();

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
        self.response_builder.reply(item).send();

        Ok(())
    }

    fn send<I>(&mut self, sink: Sink, item: I) -> crate::session::Result<()>
    where
        I: crate::action::Item,
    {
        // TODO(panhania@): Enforce limits.
        crate::message::Parcel::new(sink, item).send();

        Ok(())
    }
}
