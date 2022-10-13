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

mod error;
mod response;
mod time;

use crate::action;

pub use self::error::{Error, ParseError, MissingFieldError, RegexParseError,
                      UnsupportedValueError, UnknownEnumValueError};
// TODO: Revisit visibility once comms refactoring is complete.
pub use self::response::{Response, Status};
pub use self::time::time_from_micros;

/// A specialized `Result` type for sessions.
pub type Result<T> = std::result::Result<T, Error>;

/// Abstraction for various kinds of sessions.
pub trait Session {
    /// Sends a reply to the flow that call the action.
    fn reply<I>(&mut self, item: I) -> Result<()>
    where I: action::Item + 'static;

    /// Sends an item to a particular sink.
    fn send<I>(&mut self, sink: crate::message::Sink, item: I) -> Result<()>
    where I: action::Item + 'static;

    /// Sends a heartbeat signal to the Fleetspeak process.
    fn heartbeat(&mut self) {
        // TODO: Create a real implementation.
    }
}

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
    fn new(request_id: crate::message::RequestId) -> FleetspeakSession {
        FleetspeakSession {
            response_builder: crate::message::ResponseBuilder::new(request_id),
        }
    }

    pub fn handle(request: crate::message::Request) {
        let mut session = FleetspeakSession::new(request.id());

        let result = crate::action::dispatch(&mut session, request);
        session.response_builder.status(result).send();

        // TODO(panhania@): Consider returning the status so that the parent can
        // log appropriate message.
    }
}

impl Session for FleetspeakSession {

    fn reply<I: crate::action::Item>(&mut self, item: I) -> Result<()> {
        // TODO(panhania@): Enforce limits.
        self.response_builder.reply(item).send();

        Ok(())
    }

    fn send<I>(&mut self, sink: crate::message::Sink, item: I) -> Result<()>
    where
        I: crate::action::Item,
    {
        // TODO(panhania@): Enforce limits.
        crate::message::Parcel::new(sink, item).send();

        Ok(())
    }
}

#[cfg(test)]
pub mod test {

    use std::any::Any;
    use std::collections::HashMap;

    use super::*;

    /// A session implementation intended to be used in tests.
    ///
    /// Testing actions with normal session objects can be quite hard, since
    /// they communicate with the outside world (through Fleetspeak). Since we
    /// want to keep the tests minimal and not waste resources on unneeded I/O,
    /// using real sessions is not an option.
    ///
    /// Instead, one can use a `Fake` session. It simply accumulates responses
    /// that the action sends and lets the creator inspect them later.
    pub struct FakeSession {
        replies: Vec<Box<dyn Any>>,
        parcels: HashMap<crate::message::Sink, Vec<Box<dyn Any>>>,
    }

    impl FakeSession {

        /// Constructs a new fake session.
        pub fn new() -> FakeSession {
            FakeSession {
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
            R: crate::action::Item + 'static,
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
            R: crate::action::Item + 'static
        {
            self.replies.iter().map(|reply| {
                reply.downcast_ref().expect("unexpected reply type")
            })
        }

        /// Yields the number of parcels sent so far to the specified sink.
        pub fn parcel_count(&self, sink: crate::message::Sink) -> usize {
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
        pub fn parcel<I>(&self, sink: crate::message::Sink, id: usize) -> &I
        where
            I: crate::action::Item + 'static,
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
        pub fn parcels<I>(&self, sink: crate::message::Sink) -> impl Iterator<Item = &I>
        where
            I: crate::action::Item + 'static,
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

    impl Session for FakeSession {

        fn reply<I>(&mut self, item: I) -> Result<()>
        where
            I: crate::action::Item + 'static,
        {
            self.replies.push(Box::new(item));

            Ok(())
        }

        fn send<I>(&mut self, sink: crate::message::Sink, item: I) -> Result<()>
        where
            I: crate::action::Item + 'static,
        {
            let parcels = self.parcels.entry(sink).or_insert_with(Vec::new);
            parcels.push(Box::new(item));

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::message::Sink;

    #[test]
    fn test_fake_reply_count() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.reply(()).unwrap();
            session.reply(()).unwrap();
            session.reply(()).unwrap();
        }

        let mut session = test::FakeSession::new();
        handle(&mut session, ());

        assert_eq!(session.reply_count(), 3);
    }

    #[test]
    fn test_fake_parcel_count() {

        // TODO: Extend this test with more sinks (once we have some more sinks
        // defined).

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(Sink::STARTUP, ()).unwrap();
            session.send(Sink::STARTUP, ()).unwrap();
        }

        let mut session = test::FakeSession::new();
        handle(&mut session, ());

        assert_eq!(session.parcel_count(Sink::STARTUP), 2);
    }

    #[test]
    fn test_fake_reply_correct_response() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.reply(StringResponse::from("foo")).unwrap();
            session.reply(StringResponse::from("bar")).unwrap();
        }

        let mut session = test::FakeSession::new();
        handle(&mut session, ());

        assert_eq!(session.reply::<StringResponse>(0).0, "foo");
        assert_eq!(session.reply::<StringResponse>(1).0, "bar");
    }

    #[test]
    #[should_panic(expected = "no reply #0")]
    fn test_fake_reply_incorrect_response_id() {

        fn handle<S: Session>(_: &mut S, _: ()) {
        }

        let mut session = test::FakeSession::new();
        handle(&mut session, ());

        session.reply::<()>(0);
    }

    #[test]
    #[should_panic(expected = "unexpected reply type")]
    fn test_fake_reply_incorrect_response_type() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.reply(StringResponse::from("quux")).unwrap();
        }

        let mut session = test::FakeSession::new();
        handle(&mut session, ());

        session.reply::<()>(0);
    }

    #[test]
    fn test_fake_parcel_correct_parcel() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(Sink::STARTUP, StringResponse::from("foo")).unwrap();
            session.send(Sink::STARTUP, StringResponse::from("bar")).unwrap();
        }

        let mut session = test::FakeSession::new();
        handle(&mut session, ());

        let response_foo = session.parcel::<StringResponse>(Sink::STARTUP, 0);
        let response_bar = session.parcel::<StringResponse>(Sink::STARTUP, 1);
        assert_eq!(response_foo.0, "foo");
        assert_eq!(response_bar.0, "bar");
    }

    #[test]
    #[should_panic(expected = "no parcel #42")]
    fn test_fake_parcel_incorrect_parcel_id() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(Sink::STARTUP, ()).unwrap();
            session.send(Sink::STARTUP, ()).unwrap();
        }

        let mut session = test::FakeSession::new();
        handle(&mut session, ());

        session.parcel::<()>(Sink::STARTUP, 42);
    }

    #[test]
    #[should_panic(expected = "unexpected parcel type")]
    fn test_fake_parcel_incorrect_parcel_type() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(Sink::STARTUP, StringResponse::from("quux")).unwrap();
        }

        let mut session = test::FakeSession::new();
        handle(&mut session, ());

        session.parcel::<()>(Sink::STARTUP, 0);
    }

    #[test]
    fn test_fake_replies_no_parcels() {

        fn handle<S: Session>(_: &mut S, _: ()) {
        }

        let mut session = test::FakeSession::new();
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

        let mut session = test::FakeSession::new();
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

        let mut session = test::FakeSession::new();
        handle(&mut session, ());

        let mut parcels = session.parcels::<()>(Sink::STARTUP);
        assert_eq!(parcels.next(), None);
    }

    #[test]
    fn test_fake_parcels_multiple_parcels() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(Sink::STARTUP, StringResponse::from("foo")).unwrap();
            session.send(Sink::STARTUP, StringResponse::from("bar")).unwrap();
            session.send(Sink::STARTUP, StringResponse::from("baz")).unwrap();
        }

        let mut session = test::FakeSession::new();
        handle(&mut session, ());

        let mut parcels = session.parcels::<StringResponse>(Sink::STARTUP);
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

    impl action::Item for StringResponse {

        const RDF_NAME: &'static str = "RDFString";

        type Proto = protobuf::well_known_types::StringValue;

        fn into_proto(self) -> protobuf::well_known_types::StringValue {
            let mut proto = protobuf::well_known_types::StringValue::new();
            proto.set_value(self.0);

            proto
        }
    }
}
