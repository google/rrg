// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Utilities for working with sessions.
//!
//! Sessions are created per action request and should be used as the only way
//! to communicate with the server. Sessions are responsible for handling action
//! errors (when something goes wrong) or notifying the server that the action
//! finished (by sending appropriate status signal).
//!
//! They also keep track of various statistics (such as number of transferred
//! bytes, action runtime, etc.) and stop the execution if they exceed limits
//! for a particular request.

mod demand;
mod error;
mod response;
mod sink;

use std::convert::TryInto;

use log::{error, info};

use crate::action;
use crate::message;
pub use self::demand::{Demand, Header, Payload};
pub use self::error::{Error, ParseError, MissingFieldError};
use self::response::{Response, Status};
pub use self::sink::{Sink};

/// A specialized `Result` type for sessions.
pub type Result<T> = std::result::Result<T, Error>;

/// Object associating a session with particular action request.
///
/// This is just a convenience type used to avoid threading large numbers of
/// parameters through different function calls.
///
/// Note that the payload can be quite large object, so it should not be stored
/// with the session itself. The payload should be consumed as soon as the
/// request is dispatched to a particular handler and parsed to a concrete type.
pub struct Task<'s, S: Session> {
    /// A session that this task should be run on.
    pub session: &'s mut S,
    /// Serialized data of the action request.
    pub payload: Payload,
}

impl<'s, S: Session> Task<'s, S> {

    /// Executes the task with a particular action handler.
    pub fn execute<R, H>(self, handler: H) -> Result<()>
    where
        R: action::Request,
        H: FnOnce(&mut S, R) -> Result<()>,
    {
        let request = self.payload.parse()?;
        handler(self.session, request)
    }
}

/// Processes given message, handling all errors.
///
/// This function takes a message from the GRR server and interprets it as an
/// action request. It creates a new session object and dispatches the request
/// to an appropriate action handler. Once the action finishes, the function
/// will send a final status message, informing the server about a success
/// or a failure.
///
/// Note that if action execution fails, this function deals with all the errors
/// by sending appropriate information to the server (if possible), logging them
/// and failing hard if a critical error (e.g. communication failure) occurred.
pub fn handle<M>(message: M)
where
    M: TryInto<Demand, Error=ParseError>,
{
    let demand = match message.try_into() {
        Ok(demand) => {
            info!("requested to execute the '{}' action", demand.action);
            demand
        }
        Err(error) => {
            error!("failed to parse the message: {}", error);
            return;
        }
    };

    let mut session = Action::from_demand(&demand);

    let result = action::dispatch(&demand.action, Task {
        session: &mut session,
        payload: demand.payload,
    });

    if let Err(ref error) = result {
        error!("failed to execute the '{}' action: {}", demand.action, error);
    } else {
        info!("finished executing the '{}' action", demand.action);
    }

    let message = match session.status(result).try_into() {
        Ok(message) => message,
        Err(error) => {
            // If we cannot encode the final status message, there is nothing
            // we can do to notify the server, as status is responsible for
            // reporting errors. We can only log the error and carry on.
            error!("failed to encode status message: {}", error);
            return;
        }
    };

    message::send(message);
}

/// Abstraction for various kinds of sessions.
pub trait Session {
    /// Sends a reply to the flow that call the action.
    fn reply<R>(&mut self, response: R) -> Result<()>
    where R: action::Response + 'static;

    /// Sends a message to a particular sink.
    fn send<R>(&mut self, sink: Sink, response: R) -> Result<()>
    where R: action::Response + 'static;

    /// Sends a heartbeat signal to the Fleetspeak process.
    fn heartbeat(&mut self) {
        // TODO: Create a real implementation.
    }
}

/// A session type for unrequested action executions.
///
/// Certain kind of actions are executed not only when a server flow decides to
/// do so, but also upon particular kind of events (e.g. the agent's startup).
/// In such cases, when one needs to trigger action execution manually, ad-hoc
/// sessions should be used.
pub struct Adhoc;

impl Session for Adhoc {

    // TODO: Session trait should be probably split into two traits and then
    // make the actions that do not care about the `reply` method implement the
    // simpler one.
    fn reply<R>(&mut self, response: R) -> Result<()>
    where
        R: action::Response,
    {
        error!("attempted to reply to an ad-hoc session, dropping response");
        drop(response);

        Ok(())
    }

    fn send<R>(&mut self, sink: Sink, response: R) -> Result<()>
    where
        R: action::Response,
    {
        send(sink.wrap(response))?;

        Ok(())
    }
}

/// A session type for ordinary action requests.
///
/// This is a normal session type that that is associated with some flow on the
/// server. It keeps track of the responses it sends and collects statistics
/// about network and runtime utilization to kill the action if it is needed.
pub struct Action {
    header: Header,
    next_response_id: u64,
}

impl Action {

    /// Constructs a new session for the given `demand` object.
    pub fn from_demand(demand: &Demand) -> Action {
        // Response identifiers that GRR agents use start at 1. Unfortunately,
        // the server uses this assumption (to determine the number of expected
        // responses when status message is received), so we have to follow this
        // behaviour in RRG as well.
        Action {
            header: demand.header.clone(),
            next_response_id: 1,
        }
    }

    /// Wraps an action response to a session-specific response.
    fn wrap<R>(&self, response: R) -> Response<R>
    where
        R: action::Response
    {
        Response {
            session_id: self.header.session_id.clone(),
            request_id: Some(self.header.request_id),
            response_id: Some(self.next_response_id),
            data: response,
        }
    }

    /// Wraps an action result to a session-specific status response.
    ///
    /// Note that this method consumes the session. The reason for this is that
    /// status response should be obtained as the very last response and no
    /// further replies should be possible after that.
    fn status(self, result: Result<()>) -> Status {
        Status {
            session_id: self.header.session_id,
            request_id: self.header.request_id,
            response_id: self.next_response_id,
            result: result,
        }
    }
}

impl Session for Action {

    fn reply<R: action::Response>(&mut self, response: R) -> Result<()> {
        send(self.wrap(response))?;
        self.next_response_id += 1;

        Ok(())
    }

    fn send<R>(&mut self, sink: Sink, response: R) -> Result<()>
    where
        R: action::Response,
    {
        send(sink.wrap(response))?;

        Ok(())
    }
}

/// Sends a session response to the server.
///
/// Note that this function is not exposed on purpose. Actions should send
/// responses through session objects which introduce a layer of safety. `send`
/// is a low-level utility supposed to be used internally.
fn send<R>(response: Response<R>) -> Result<()>
where
    R: action::Response,
{
    let message = response.try_into()?;
    message::send(message);

    Ok(())
}

#[cfg(test)]
pub mod test {
    use std::any::Any;
    use std::collections::HashMap;

    use super::*;

    pub struct Fake {
        replies: Vec<Box<dyn Any>>,
        responses: HashMap<Sink, Vec<Box<dyn Any>>>,
    }

    impl Fake {

        pub fn new() -> Fake {
            Fake {
                replies: Vec::new(),
                responses: std::collections::HashMap::new(),
            }
        }

        pub fn reply<R>(&self, index: usize) -> &R
        where
            R: action::Response + 'static,
        {
            let reply = match self.replies.get(index) {
                Some(reply) => reply,
                None => panic!("no reply #{}", index),
            };

            reply.downcast_ref().expect("unexpected reply type")
        }

        pub fn response<R>(&self, sink: Sink, index: usize) -> &R
        where
            R: action::Response + 'static,
        {
            let responses = match self.responses.get(&sink) {
                Some(responses) => responses,
                None => panic!("no responses for sink '{:?}'", sink),
            };

            let response = match responses.get(index) {
                Some(response) => response,
                None => panic!("no response #{} for sink '{:?}'", index, sink),
            };

            match response.downcast_ref() {
                Some(response) => response,
                None => panic!("unexpected response type in sink '{:?}'", sink),
            }
        }
    }

    impl Session for Fake {

        fn reply<R>(&mut self, response: R) -> Result<()>
        where
            R: action::Response + 'static,
        {
            self.replies.push(Box::new(response));

            Ok(())
        }

        fn send<R>(&mut self, sink: Sink, response: R) -> Result<()>
        where
            R: action::Response + 'static,
        {
            let responses = self.responses.entry(sink).or_insert_with(Vec::new);
            responses.push(Box::new(response));

            Ok(())
        }
    }
}
