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

#[cfg(test)]
mod fake;
mod fleetspeak;

#[cfg(test)]
pub use crate::session::fake::FakeSession;
pub use crate::session::fleetspeak::FleetspeakSession;

pub use self::error::{Error};

/// A specialized `Result` type for sessions.
pub type Result<T> = std::result::Result<T, Error>;

/// Abstraction for various kinds of sessions.
pub trait Session {
    /// Sends a reply to the flow that call the action.
    fn reply<I>(&mut self, item: I) -> Result<()>
    where I: crate::response::Item + 'static;

    /// Sends an item to a particular sink.
    fn send<I>(&mut self, sink: crate::Sink, item: I) -> Result<()>
    where I: crate::response::Item + 'static;

    /// Sends a heartbeat signal to the Fleetspeak process.
    fn heartbeat(&mut self);
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::Sink;

    #[test]
    fn test_fake_reply_count() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.reply(()).unwrap();
            session.reply(()).unwrap();
            session.reply(()).unwrap();
        }

        let mut session = FakeSession::new();
        handle(&mut session, ());

        assert_eq!(session.reply_count(), 3);
    }

    #[test]
    fn test_fake_parcel_count() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(Sink::Startup, ()).unwrap();
            session.send(Sink::Blob, ()).unwrap();
            session.send(Sink::Startup, ()).unwrap();
        }

        let mut session = FakeSession::new();
        handle(&mut session, ());

        assert_eq!(session.parcel_count(Sink::Blob), 1);
        assert_eq!(session.parcel_count(Sink::Startup), 2);
    }

    #[test]
    fn test_fake_reply_correct_response() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.reply(StringResponse::from("foo")).unwrap();
            session.reply(StringResponse::from("bar")).unwrap();
        }

        let mut session = FakeSession::new();
        handle(&mut session, ());

        assert_eq!(session.reply::<StringResponse>(0).0, "foo");
        assert_eq!(session.reply::<StringResponse>(1).0, "bar");
    }

    #[test]
    #[should_panic(expected = "no reply #0")]
    fn test_fake_reply_incorrect_response_id() {

        fn handle<S: Session>(_: &mut S, _: ()) {
        }

        let mut session = FakeSession::new();
        handle(&mut session, ());

        session.reply::<()>(0);
    }

    #[test]
    #[should_panic(expected = "unexpected reply type")]
    fn test_fake_reply_incorrect_response_type() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.reply(StringResponse::from("quux")).unwrap();
        }

        let mut session = FakeSession::new();
        handle(&mut session, ());

        session.reply::<()>(0);
    }

    #[test]
    fn test_fake_parcel_correct_parcel() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(Sink::Startup, StringResponse::from("foo")).unwrap();
            session.send(Sink::Startup, StringResponse::from("bar")).unwrap();
        }

        let mut session = FakeSession::new();
        handle(&mut session, ());

        let response_foo = session.parcel::<StringResponse>(Sink::Startup, 0);
        let response_bar = session.parcel::<StringResponse>(Sink::Startup, 1);
        assert_eq!(response_foo.0, "foo");
        assert_eq!(response_bar.0, "bar");
    }

    #[test]
    #[should_panic(expected = "no parcel #42")]
    fn test_fake_parcel_incorrect_parcel_id() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(Sink::Startup, ()).unwrap();
            session.send(Sink::Startup, ()).unwrap();
        }

        let mut session = FakeSession::new();
        handle(&mut session, ());

        session.parcel::<()>(Sink::Startup, 42);
    }

    #[test]
    #[should_panic(expected = "unexpected parcel type")]
    fn test_fake_parcel_incorrect_parcel_type() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(Sink::Startup, StringResponse::from("quux")).unwrap();
        }

        let mut session = FakeSession::new();
        handle(&mut session, ());

        session.parcel::<()>(Sink::Startup, 0);
    }

    #[test]
    fn test_fake_replies_no_parcels() {

        fn handle<S: Session>(_: &mut S, _: ()) {
        }

        let mut session = FakeSession::new();
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

        let mut session = FakeSession::new();
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

        let mut session = FakeSession::new();
        handle(&mut session, ());

        let mut parcels = session.parcels::<()>(Sink::Startup);
        assert_eq!(parcels.next(), None);
    }

    #[test]
    fn test_fake_parcels_multiple_parcels() {

        fn handle<S: Session>(session: &mut S, _: ()) {
            session.send(Sink::Startup, StringResponse::from("foo")).unwrap();
            session.send(Sink::Startup, StringResponse::from("bar")).unwrap();
            session.send(Sink::Startup, StringResponse::from("baz")).unwrap();
        }

        let mut session = FakeSession::new();
        handle(&mut session, ());

        let mut parcels = session.parcels::<StringResponse>(Sink::Startup);
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

    impl crate::response::Item for StringResponse {

        type Proto = protobuf::well_known_types::wrappers::StringValue;

        fn into_proto(self) -> protobuf::well_known_types::wrappers::StringValue {
            let mut proto = protobuf::well_known_types::wrappers::StringValue::new();
            proto.value = self.0;

            proto
        }
    }
}
