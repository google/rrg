use log::{error, info};

/// A session implementation that uses real Fleetspeak connection.
///
/// This is a normal session type that that is associated with some flow on the
/// server. It keeps track of the responses it sends and collects statistics
/// about network and runtime utilization to kill the action if it is needed.
pub struct FleetspeakSession {
    response_builder: crate::ResponseBuilder,
}

impl FleetspeakSession {

    /// Dispatches the given `request` to an appropriate action handler.
    ///
    /// This is the main entry point of the session. It processes the request
    /// and sends the execution status back to the server.
    ///
    /// Note that the function accepts a `Result`. This is because we want to
    /// send the error (in case on occurred) back to the server. But this we can
    /// do only within a sesssion, so we have to create a session from a perhaps
    /// invalid request.
    pub fn dispatch(request: Result<crate::Request, crate::ParseRequestError>) {
        let request_id = match &request {
            Ok(request) => request.id(),
            Err(error) => match error.request_id() {
                Some(request_id) => request_id,
                None => {
                    error!("invalid request: {}", error);
                    return;
                }
            }
        };

        info!("received request '{request_id}'");

        let response_builder = crate::ResponseBuilder::new(request_id);

        let status = match request {
            Ok(request) => {
                let mut session = FleetspeakSession {
                    response_builder,
                };

                let result = crate::action::dispatch(&mut session, request);
                session.response_builder.status(result)
            },
            Err(error) => {
                error!("invalid request '{request_id}': {error}");
                response_builder.status(Err(error.into()))
            }
        };

        info!("finished dispatching request '{request_id}'");

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
