use log::{error, info};

/// A session implementation that uses real Fleetspeak connection.
///
/// This is a normal session type that that is associated with some flow on the
/// server. It keeps track of the responses it sends and collects statistics
/// about network and runtime utilization to kill the action if it is needed.
pub struct FleetspeakSession<'a, 'fs> {
    /// Identifier of the request that spawned the session.
    request_id: crate::RequestId,
    /// Arguments passed to the agent.
    args: &'a crate::args::Args,
    /// Filestore of the current process (if available).
    filestore: Option<&'fs crate::filestore::Filestore>,
    /// The response identifier assigned to the next generated response.
    next_response_id: crate::ResponseId,
    /// Filters to apply to the results before they are sent.
    filters: crate::filter::FilterSet,
    /// Number of items that have been rejected by filters.
    filtered_out_count: u32,
    /// Number of bytes sent since the session was created.
    network_bytes_sent: u64,
    /// Number of bytes we are allowed to send within the session.
    network_bytes_limit: Option<u64>,
    /// Time at which the session was created.
    real_time_start: std::time::Instant,
    /// Time which we are allowed to spend within the session.
    real_time_limit: Option<std::time::Duration>,
}

impl<'a, 'fs> FleetspeakSession<'a, 'fs> {

    /// Dispatches the given `request` to an appropriate action handler.
    ///
    /// This is the main entry point of the session. It processes the request
    /// and sends the execution status back to the server.
    ///
    /// Note that the function accepts a `Result`. This is because we want to
    /// send the error (in case on occurred) back to the server. But this we can
    /// do only within a session, so we have to create a session from a perhaps
    /// invalid request.
    ///
    /// Long-running actions spawned by requests that need to send heartbeat
    /// signal to Fleetspeak will do so with frequency not greater than the one
    /// specified the arguments passed to the agent.
    pub fn dispatch(
        // TODO(@panhania): The list of arguments to this function starts to be
        // unwieldy, we should refeactor it through some builder pattern.
        args: &'a crate::args::Args,
        filestore: Option<&'fs crate::filestore::Filestore>,
        request: Result<crate::Request, crate::ParseRequestError>,
    ) {
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

        // Response identifiers that GRR agents use start at 1. The server
        // assumes this to determine the number of expected messages when the
        // status message is received. Thus, we have to replicate the behaviour
        // of the existing GRR agent and start at 1 as well.
        let next_response_id = crate::ResponseId(1);

        let status = match request {
            Ok(mut request) => {
                let mut session = FleetspeakSession {
                    request_id,
                    args,
                    filestore,
                    next_response_id,
                    filters: request.take_filters(),
                    filtered_out_count: 0,
                    network_bytes_sent: 0,
                    network_bytes_limit: request.network_bytes_limit(),
                    real_time_start: std::time::Instant::now(),
                    real_time_limit: request.real_time_limit(),
                };

                let result = crate::log::ResponseLogger::new(&request)
                    .context(|| crate::action::dispatch(&mut session, request));

                crate::response::Status {
                    request_id: request_id,
                    // Because status is the last response to be sent (`session`
                    // is dropped at the end of this scope), we do not need to
                    // increment the response id.
                    response_id: session.next_response_id,
                    network_bytes_sent: session.network_bytes_sent,
                    filtered_out_count: session.filtered_out_count,
                    result,
                }
            },
            Err(error) => {
                error!("invalid request '{request_id}': {error}");

                crate::response::Status {
                    request_id,
                    response_id: next_response_id,
                    network_bytes_sent: 0,
                    filtered_out_count: 0,
                    result: Err(crate::session::Error::from(error)),
                }
            }
        };

        status.send_unaccounted();
    }
}

impl<'a, 'fs> FleetspeakSession<'a, 'fs> {

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
}

impl<'a, 'fs> crate::session::Session for FleetspeakSession<'a, 'fs> {

    fn args(&self) -> &crate::args::Args {
        self.args
    }

    fn reply<I>(&mut self, item: I) -> crate::session::Result<()>
    where
        I: crate::response::Item,
    {
        let item = crate::response::PreparedItem::from(item);

        let reply = match self.filters.eval(item.as_proto()) {
            Ok(true) => {
                let response_id = self.next_response_id;
                self.next_response_id.0 += 1;

                crate::response::Reply {
                    request_id: self.request_id,
                    response_id,
                    item,
                }
            }
            Ok(false) => {
                self.filtered_out_count += 1;
                return Ok(())
            }
            Err(error) => {
                return Err(error.into())
            }
        };

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

    fn heartbeat(&mut self) {
        fleetspeak::heartbeat_with_throttle(self.args.heartbeat_rate);
    }

    fn filestore_store(
        &self,
        file_sha256: [u8; 32],
        part: crate::filestore::Part,
    ) -> crate::session::Result<crate::filestore::Status> {
        let filestore = self.filestore
            .ok_or(crate::session::FilestoreUnavailableError)?;

        filestore.store(crate::filestore::Id {
            flow_id: self.request_id.flow_id(),
            file_sha256,
        }, part)
            .map_err(|error| crate::session::Error {
                kind: crate::session::ErrorKind::FilestoreStoreFailure,
                error: Box::new(error),
            })
    }

    fn filestore_path(
        &self,
        file_sha256: [u8; 32],
    ) -> crate::session::Result<std::path::PathBuf> {
        let filestore = self.filestore
            .ok_or(crate::session::FilestoreUnavailableError)?;

        filestore.path(crate::filestore::Id {
            flow_id: self.request_id.flow_id(),
            file_sha256,
        })
            .map_err(|error| crate::session::Error {
                kind: crate::session::ErrorKind::FilestoreInvalidPath,
                error: Box::new(error),
            })
    }
}
