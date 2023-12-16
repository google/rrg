use log::{error, info};

/// A session implementation that uses real Fleetspeak connection.
///
/// This is a normal session type that that is associated with some flow on the
/// server. It keeps track of the responses it sends and collects statistics
/// about network and runtime utilization to kill the action if it is needed.
pub struct FleetspeakSession {
    /// A builder for responses sent through Fleetspeak to the GRR server.
    response_builder: crate::ResponseBuilder,
    /// Number of bytes sent since the session was created.
    network_bytes_sent: u64,
    /// Number of bytes we are allowed to send within the session.
    network_bytes_limit: Option<u64>,
    /// Time at which the session was created.
    real_time_start: std::time::Instant,
    /// Time which we are allowed to spend within the session.
    real_time_limit: Option<std::time::Duration>,
    /// List of filters to apply to result messages.
    filters: Vec<crate::request::Filter>,
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
            Ok(mut request) => {
                let mut session = FleetspeakSession {
                    response_builder,
                    network_bytes_sent: 0,
                    network_bytes_limit: request.network_bytes_limit(),
                    real_time_start: std::time::Instant::now(),
                    real_time_limit: request.real_time_limit(),
                    filters: request.take_filters(),
                };

                let result = crate::log::ResponseLogger::new(&request)
                    .context(|| crate::action::dispatch(&mut session, request));

                session.response_builder.status(result)
            },
            Err(error) => {
                error!("invalid request '{request_id}': {error}");
                response_builder.status(Err(error.into()))
            }
        };

        status.send_unaccounted();
    }
}

impl FleetspeakSession {

    /// Checks whether the network bytes limit was crossed.
    ///
    /// This function will return an error if it was.
    fn check_network_bytes_limit(&self) -> crate::session::Result<()> {
        use crate::session::error::NetworkBytesLimitExceededError;

        if let Some(network_bytes_limit) = self.network_bytes_limit {
            if self.network_bytes_sent > network_bytes_limit {
                return Err(NetworkBytesLimitExceededError {
                    network_bytes_sent: self.network_bytes_sent,
                    network_bytes_limit,
                }.into());
            }
        }

        Ok(())
    }

    /// Checks whether the real (wall) time limit was crossed.
    ///
    /// This function will return an error if it was.
    fn check_real_time_limit(&self) -> crate::session::Result<()> {
        use crate::session::error::RealTimeLimitExceededError;

        if let Some(real_time_limit) = self.real_time_limit {
            let real_time_spent = self.real_time_start.elapsed();
            if real_time_spent > real_time_limit {
                return Err(RealTimeLimitExceededError {
                    real_time_spent,
                    real_time_limit,
                }.into());
            }
        }

        Ok(())
    }

    /// Evaluates filters on the given reply.
    /// 
    /// This function returns a boolean indicating whether the reply passes the
    /// filters.
    /// 
    /// # Errors
    /// 
    /// The function will return an error if the filter cannot be evaluated on
    /// the given message (e.g. the specified field is not available on the
    /// message or there was a type issue).
    fn eval_filters<I>(&self, reply: &crate::response::PreparedReply<I>) -> crate::session::Result<bool>
    where
        I: crate::response::Item,
    {
        for filter in &self.filters {
            let item_proto = reply.item_proto();
            if !filter.eval_message(item_proto)? {
                log::debug!("result '{item_proto}' filtered out by: {filter}");
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl crate::session::Session for FleetspeakSession {

    fn reply<I>(&mut self, item: I) -> crate::session::Result<()>
    where
        I: crate::response::Item,
    {
        let reply = self.response_builder.reply(item).prepare();

        if !self.eval_filters(&reply)? {
            self.response_builder.filter_out(reply);
            return Ok(());
        }

        self.network_bytes_sent += reply.send_unaccounted() as u64;
        self.check_network_bytes_limit()?;

        // TODO(@panhania): Enforce CPU time limits.
        self.check_real_time_limit()?;

        Ok(())
    }

    fn send<I>(&mut self, sink: crate::Sink, item: I) -> crate::session::Result<()>
    where
        I: crate::response::Item,
    {
        let parcel = crate::response::Parcel::new(sink, item);

        self.network_bytes_sent += parcel.send_unaccounted() as u64;
        self.check_network_bytes_limit()?;

        // TODO(@panhania): Enforce CPU time limits.
        self.check_real_time_limit()?;

        Ok(())
    }
}
