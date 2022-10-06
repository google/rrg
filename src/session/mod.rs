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
mod time;

use std::convert::TryInto;

use log::{error, info};

use crate::action;
use crate::message;
pub use self::demand::{Demand, Header, Payload};
pub use self::error::{Error, ParseError, MissingFieldError, RegexParseError,
                      UnsupportedValueError, UnknownEnumValueError};
// TODO: Revisit visibility once comms refactoring is complete.
pub use self::response::{Response, Status};
pub use self::time::time_from_micros;

/// A specialized `Result` type for sessions.
pub type Result<T> = std::result::Result<T, Error>;

/// Object associating a session with particular action request.
///
/// This is just a convenience type used to avoid threading large numbers of
/// parameters through different function calls.
///
/// Note that the payload can be a quite large object, so it should not be stored
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

    message::send_raw(message);
}

/// Abstraction for various kinds of sessions.
pub trait Session {
    /// Sends a reply to the flow that call the action.
    fn reply<R>(&mut self, response: R) -> Result<()>
    where R: action::Response + 'static;

    /// Sends an adressed parcel.
    fn send<P>(&mut self, parcel: crate::sink::AddressedParcel<P>) -> Result<()>
    where P: crate::sink::Parcel + 'static;

    /// Sends a heartbeat signal to the Fleetspeak process.
    fn heartbeat(&mut self) {
        // TODO: Create a real implementation.
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
            request_id: self.header.request_id,
            response_id: self.next_response_id,
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

    fn send<P>(&mut self, parcel: crate::sink::AddressedParcel<P>) -> Result<()>
    where
        P: crate::sink::Parcel,
    {
        crate::message::send_raw(parcel.try_into()?);

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
    message::send_raw(message);

    Ok(())
}

#[cfg(test)]
pub mod test {

    use std::any::Any;
    use std::collections::HashMap;

    use super::*;
    use crate::sink::Sink;

    /// A session type intended to be used in tests.
    ///
    /// Testing actions with normal session objects can be quite hard, since
    /// they communicate with the outside world (through Fleetspeak). Since we
    /// want to keep the tests minimal and not waste resources on unneeded I/O,
    /// using real sessions is not an option.
    ///
    /// Instead, one can use a `Fake` session. It simply accumulates responses
    /// that the action sends and lets the creator inspect them later.
    pub struct Fake {
        replies: Vec<Box<dyn Any>>,
        parcels: HashMap<Sink, Vec<Box<dyn Any>>>,
    }

    impl Fake {

        /// Constructs a new fake session.
        pub fn new() -> Fake {
            Fake {
                replies: Vec::new(),
                parcels: std::collections::HashMap::new(),
            }
        }

        /// Yields the number of replies that this session sent so far.
        pub fn reply_count(&self) -> usize {
            self.replies.len()
        }

        /// Retrieves a reply corresponding to the given id.
        ///
        /// The identifier corresponding to the first response is 0, the second
        /// one is 1 and so on.
        ///
        /// This method will panic if a reply with the specified `id` does not
        /// exist or if it exists but has a wrong type.
        pub fn reply<R>(&self, id: usize) -> &R
        where
            R: action::Response + 'static,
        {
            match self.replies().nth(id) {
                Some(reply) => reply,
                None => panic!("no reply #{}", id),
            }
        }

        /// Constructs an iterator over session replies.
        ///
        /// The iterator will panic (but not immediately) if some reply has an
        /// incorrect type.
        pub fn replies<R>(&self) -> impl Iterator<Item = &R>
        where
            R: action::Response + 'static
        {
            self.replies.iter().map(|reply| {
                reply.downcast_ref().expect("unexpected reply type")
            })
        }

        /// Yields the number of parcels sent so far to the specified sink.
        pub fn parcel_count(&self, sink: Sink) -> usize {
            match self.parcels.get(&sink) {
                Some(parcels) => parcels.len(),
                None => 0,
            }
        }

        /// Retrieves a parcel with the given id sent to a particular sink.
        ///
        /// The identifier corresponding to the first parcel to the particular
        /// sink is 0, to the second one (to the same sink) is 1 and so on.
        ///
        /// This method will panic if a reply with the specified `id` to the
        /// given `sink` does not exist or if it exists but has wrong type.
        pub fn parcel<P>(&self, sink: Sink, id: usize) -> &P
        where
            P: crate::sink::Parcel + 'static,
        {
            match self.parcels(sink).nth(id) {
                Some(parcel) => parcel,
                None => panic!("no parcel #{} for sink '{:?}'", id, sink),
            }
        }

        /// Constructs an iterator over session parcels for the given sink.
        ///
        /// The iterator will panic (but not immediately) if some parcels has
        /// an incorrect type.
        pub fn parcels<P>(&self, sink: Sink) -> impl Iterator<Item = &P>
        where
            P: crate::sink::Parcel + 'static,
        {
            // Since the empty iterator (as defined in the standard library) is
            // a specific type, it cannot be returned in one branch but not in
            // another branch.
            //
            // Instead, we use the fact that `Option` is an iterator and then we
            // squash it with `Iterator::flatten`.
            let parcels = self.parcels.get(&sink).into_iter().flatten();

            parcels.map(move |parcel| match parcel.downcast_ref() {
                Some(parcel) => parcel,
                None => panic!("unexpected parcel type in sink '{:?}'", sink),
            })
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

        fn send<P>(&mut self, parcel: crate::sink::AddressedParcel<P>) -> Result<()>
        where
            P: crate::sink::Parcel + 'static,
        {
            let sink = parcel.sink();

            let parcels = self.parcels.entry(sink).or_insert_with(Vec::new);
            parcels.push(Box::new(parcel.unpack()));

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::sink;

    #[test]
    fn test_fake_reply_count() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.reply(()).unwrap();
            session.reply(()).unwrap();
            session.reply(()).unwrap();
        }

        let mut session = test::Fake::new();
        handle(&mut session, ());

        assert_eq!(session.reply_count(), 3);
    }

    #[test]
    fn test_fake_parcel_count() {

        // TODO: Extend this test with more sinks (once we have some more sinks
        // defined).

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(crate::sink::STARTUP.address(())).unwrap();
            session.send(crate::sink::STARTUP.address(())).unwrap();
        }

        let mut session = test::Fake::new();
        handle(&mut session, ());

        assert_eq!(session.parcel_count(crate::sink::STARTUP), 2);
    }

    #[test]
    fn test_fake_reply_correct_response() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.reply(StringResponse::from("foo")).unwrap();
            session.reply(StringResponse::from("bar")).unwrap();
        }

        let mut session = test::Fake::new();
        handle(&mut session, ());

        assert_eq!(session.reply::<StringResponse>(0).0, "foo");
        assert_eq!(session.reply::<StringResponse>(1).0, "bar");
    }

    #[test]
    #[should_panic(expected = "no reply #0")]
    fn test_fake_reply_incorrect_response_id() {

        fn handle<S: Session>(_: &mut S, _: ()) {
        }

        let mut session = test::Fake::new();
        handle(&mut session, ());

        session.reply::<()>(0);
    }

    #[test]
    #[should_panic(expected = "unexpected reply type")]
    fn test_fake_reply_incorrect_response_type() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.reply(StringResponse::from("quux")).unwrap();
        }

        let mut session = test::Fake::new();
        handle(&mut session, ());

        session.reply::<()>(0);
    }

    #[test]
    fn test_fake_parcel_correct_parcel() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(sink::STARTUP.address(StringResponse::from("foo")))
                .unwrap();
            session.send(sink::STARTUP.address(StringResponse::from("bar")))
                .unwrap();
        }

        let mut session = test::Fake::new();
        handle(&mut session, ());

        let response_foo = session.parcel::<StringResponse>(sink::STARTUP, 0);
        let response_bar = session.parcel::<StringResponse>(sink::STARTUP, 1);
        assert_eq!(response_foo.0, "foo");
        assert_eq!(response_bar.0, "bar");
    }

    #[test]
    #[should_panic(expected = "no parcel #42")]
    fn test_fake_parcel_incorrect_parcel_id() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(sink::STARTUP.address(()))
                .unwrap();
            session.send(sink::STARTUP.address(()))
                .unwrap();
        }

        let mut session = test::Fake::new();
        handle(&mut session, ());

        session.parcel::<()>(sink::STARTUP, 42);
    }

    #[test]
    #[should_panic(expected = "unexpected parcel type")]
    fn test_fake_parcel_incorrect_parcel_type() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(sink::STARTUP.address(StringResponse::from("quux")))
                .unwrap();
        }

        let mut session = test::Fake::new();
        handle(&mut session, ());

        session.parcel::<()>(sink::STARTUP, 0);
    }

    #[test]
    fn test_fake_replies_no_parcels() {

        fn handle<S: Session>(_: &mut S, _: ()) {
        }

        let mut session = test::Fake::new();
        handle(&mut session, ());

        let mut replies = session.replies::<()>();
        assert_eq!(replies.next(), None);
    }

    #[test]
    fn test_fake_replies_multiple_parcels() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.reply(StringResponse::from("foo")).unwrap();
            session.reply(StringResponse::from("bar")).unwrap();
            session.reply(StringResponse::from("baz")).unwrap();
        }

        let mut session = test::Fake::new();
        handle(&mut session, ());

        let mut replies = session.replies::<StringResponse>();
        assert_eq!(replies.next().unwrap().0, "foo");
        assert_eq!(replies.next().unwrap().0, "bar");
        assert_eq!(replies.next().unwrap().0, "baz");
        assert_eq!(replies.next(), None);
    }

    #[test]
    fn test_fake_parcels_no_parcels() {

        fn handle<S: Session>(_: &mut S, _: ()) {
        }

        let mut session = test::Fake::new();
        handle(&mut session, ());

        let mut parcels = session.parcels::<()>(crate::sink::STARTUP);
        assert_eq!(parcels.next(), None);
    }

    #[test]
    fn test_fake_parcels_multiple_parcels() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(sink::STARTUP.address(StringResponse::from("foo")))
                .unwrap();
            session.send(sink::STARTUP.address(StringResponse::from("bar")))
                .unwrap();
            session.send(sink::STARTUP.address(StringResponse::from("baz")))
                .unwrap();
        }

        let mut session = test::Fake::new();
        handle(&mut session, ());

        let mut parcels = session.parcels::<StringResponse>(sink::STARTUP);
        assert_eq!(parcels.next().unwrap().0, "foo");
        assert_eq!(parcels.next().unwrap().0, "bar");
        assert_eq!(parcels.next().unwrap().0, "baz");
        assert_eq!(parcels.next(), None);
    }

    #[derive(Debug, PartialEq, Eq)]
    struct StringResponse(String);

    impl<S: Into<String>> From<S> for StringResponse {

        fn from(string: S) -> StringResponse {
            StringResponse(string.into())
        }
    }

    impl action::Response for StringResponse {

        const RDF_NAME: Option<&'static str> = Some("RDFString");

        type Proto = protobuf::well_known_types::StringValue;

        fn into_proto(self) -> protobuf::well_known_types::StringValue {
            let mut proto = protobuf::well_known_types::StringValue::new();
            proto.set_value(self.0);

            proto
        }
    }

    impl crate::sink::Parcel for StringResponse {

        const RDF_NAME: &'static str = "RDFString";

        type Proto = protobuf::well_known_types::StringValue;

        fn into_proto(self) -> protobuf::well_known_types::StringValue {
            let mut proto = protobuf::well_known_types::StringValue::new();
            proto.set_value(self.0);

            proto
        }
    }
}
