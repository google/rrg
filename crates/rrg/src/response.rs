// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use crate::RequestId;

/// A response item that can be sent to the server.
///
/// Each object that we want to sent to the server has to be serializable to a
/// Protocol Buffers message that the GRR server can interpret. In other words,
/// "items" are simply objects that can be converted to such messages.
///
/// Note that unlike `From<protobuf::Message>`, implementators of this trait can
/// include a bit of "impurity" to the conversion (e.g. logging).
pub trait Item: Sized {
    /// Low-level Protocol Buffers type representing the action results.
    type Proto: protobuf::Message + Default;

    /// Converts an action result ot its low-level representation.
    fn into_proto(self) -> Self::Proto;
}

impl Item for () {
    type Proto = protobuf::well_known_types::Empty;

    fn into_proto(self) -> protobuf::well_known_types::Empty {
        protobuf::well_known_types::Empty::new()
    }
}

/// An action reply message.
///
/// This is a message wrapper around the [`Item`] type but associates it with a
/// particular request.
///
/// [`Item`]: crate::response::Item
pub struct Reply<I: Item> {
    /// A unique request identifier for which this item was yielded.
    request_id: RequestId,
    /// A unique response identifier of this item.
    response_id: ResponseId,
    /// An actual item that the action yielded.
    item: I,
}

impl<I: Item> Reply<I> {

    /// Sends the reply message through Fleetspeak to the GRR server.
    ///
    /// This function consumes the item to ensure that it is not sent twice.
    ///
    /// Note that this function will not do any network traffic accounting and
    /// should not be used in general. One should almost always prefer to use
    /// [`Session::reply`] instead.
    ///
    /// This function returns number of bytes in the serialized reply sent to
    /// Fleetspeak.
    ///
    /// [`Session::reply`]: crate::session::Session::reply
    pub fn send_unaccounted(self) -> usize {
        use protobuf::Message as _;

        let data = rrg_proto::v2::rrg::Response::from(self).write_to_bytes()
            // This should only fail in case we are out of memory, which we are
            // almost certainly not (and if we are, we have bigger issue).
            .expect("failed to serialize a result response");

        let data_len = data.len();

        fleetspeak::send(fleetspeak::Message {
            service: String::from("GRR"),
            kind: Some(String::from("rrg.Response")),
            data,
        });

        data_len
    }
}

/// An action execution status message.
///
/// Every action execution should return a status message as the last response
/// to the server. The status should contain information if the action execution
/// succeeded and error details in case it did not.
pub struct Status {
    /// A unique request identifier for which this status is generated.
    request_id: RequestId,
    /// A unique response identifier of this status.
    response_id: ResponseId,
    /// The action execution status.
    result: Result<(), crate::session::Error>,
}

impl Status {

    /// Sends the status message through Fleetspeak to the GRR server.
    ///
    /// This function consumes the status to ensure that it is not sent twice.
    ///
    /// Note that this function will not do any network traffic accounting. For
    /// accounted version of this function see [`Session::send`].
    ///
    /// This function returns number of bytes in the serialized status sent to
    /// Fleetspeak.
    ///
    /// [`Session::send`]: crate::session::Session::send
    pub fn send_unaccounted(self) -> usize {
        use protobuf::Message as _;

        let data = rrg_proto::v2::rrg::Response::from(self).write_to_bytes()
            // This should only fail in case we are out of memory, which we are
            // almost certainly not (and if we are, we have bigger issue).
            .expect("failed to serialize a status response");

        let data_len = data.len();

        fleetspeak::send(fleetspeak::Message {
            service: String::from("GRR"),
            kind: Some(String::from("rrg.Response")),
            data,
        });

        data_len
    }
}

/// A unique identifier of a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResponseId(pub(super) u64);

/// Response factory for building many responses to a single request.
pub struct ResponseBuilder {
    /// A unique request identifier for which we build responses.
    request_id: RequestId,
    /// The response identifier assigned to the next generated response.
    next_response_id: ResponseId,
}

impl ResponseBuilder {

    /// Creates a new response builder for the specified request.
    pub fn new(request_id: RequestId) -> ResponseBuilder {
        ResponseBuilder {
            request_id,
            // Response identifiers that GRR agents use start at 1. The server
            // assumes this to determine the number of expected messages when
            // the status message is received. Thus, we have to replicate the
            // behaviour of the existing GRR agent and start at 1 as well.
            next_response_id: ResponseId(1),
        }
    }

    /// Builds a new status response for the given action outcome.
    pub fn status(self, result: crate::session::Result<()>) -> Status {
        Status {
            request_id: self.request_id,
            // Because this method consumes the builder, we do not need to
            // increment the response id.
            response_id: self.next_response_id,
            result,
        }
    }

    /// Builds a new reply response for the given action item.
    pub fn reply<I>(&mut self, item: I) -> Reply<I>
    where
        I: Item,
    {
        let response_id = self.next_response_id;
        self.next_response_id.0 += 1;

        Reply {
            request_id: self.request_id.clone(),
            response_id,
            item,
        }
    }
}

/// Handle to a specific sink.
///
/// Sinks ("well-known flows" or "message handlers" in GRR nomenclature) are
/// ever-existing data processors on the GRR server that listen for various
/// kinds of data. They are a way to break away from the usual request-response
/// workflow.
///
/// For example, sinks are used to notify the server about agent startup (which
/// is clearly not a response to a particular request) or to send file blobs to
/// a specialized storage that can handle data deduplication.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Sink {
    /// Collects records of agent startup.
    Startup,
    /// Collects binary blobs (e.g. fragments of files).
    Blob,
}

impl From<Sink> for rrg_proto::v2::rrg::Sink {

    fn from(sink: Sink) -> rrg_proto::v2::rrg::Sink {
        match sink {
            Sink::Startup => rrg_proto::v2::rrg::Sink::STARTUP,
            Sink::Blob => rrg_proto::v2::rrg::Sink::BLOB,
        }
    }
}

/// Data that should be sent to a particular [sink].
///
/// Sometimes the agent should send data to the server that is not associated
/// with any particular request. An example can be the agent startup information
/// sent to the server at the moment the agent process start. Another example is
/// file contents that are delivered to the server not as part of the action
/// results but are sent out-of-band to a sink that has logic for deduplication
/// of data that we already collected in the past.
///
/// [sink]: crate::Sink
pub struct Parcel<I: crate::response::Item> {
    /// A sink to deliver the parcel to.
    sink: Sink,
    /// The actual content of the parcel.
    payload: I,
}

impl<I: crate::response::Item> Parcel<I> {
    /// Creates a new parcel from the given `item` addressed to `sink`.
    pub fn new(sink: Sink, item: I) -> Parcel<I> {
        Parcel {
            sink,
            payload: item,
        }
    }
}

impl<I: crate::response::Item> Parcel<I> {

    /// Sends the parcel message through Fleetspeak to the GRR server.
    ///
    /// This function consumes the parcel to ensure that it is not sent twice.
    ///
    /// Note that this function should generally not be used if running as part
    /// of some [session], otherwise network usage might not be correctly
    /// accounted for. Prefer to use [`Session::send`] for such cases.
    ///
    /// This function returns number of bytes in the serialized parcel sent to
    /// Fleetspeak.
    ///
    /// [session]: crate::session::Session
    /// [`Session::send`]: crate::session::Session::send
    pub fn send_unaccounted(self) -> usize {
        use protobuf::Message as _;

        let data = rrg_proto::v2::rrg::Parcel::from(self).write_to_bytes()
            // This should only fail in case we are out of memory, which we are
            // almost certainly not (and if we are, we have bigger issue).
            .unwrap();

        let data_len = data.len();

        fleetspeak::send(fleetspeak::Message {
            service: String::from("GRR"),
            kind: Some(String::from("rrg.Parcel")),
            data,
        });

        data_len
    }
}

impl<I> From<Reply<I>> for rrg_proto::v2::rrg::Response
where
    I: Item,
{
    fn from(reply: Reply<I>) -> rrg_proto::v2::rrg::Response {
        let mut proto = rrg_proto::v2::rrg::Response::new();
        proto.set_flow_id(reply.request_id.flow_id());
        proto.set_request_id(reply.request_id.request_id());
        proto.set_response_id(reply.response_id.0);

        // TODO(@panhania): Migrate this code to use `Any::pack` once we upgrade
        // the `protobuf` package.
        use protobuf::Message as _;

        let result_proto = reply.item.into_proto();
        let result_bytes = result_proto.write_to_bytes()
            // This should only fail in case we are out of memory, which we are
            // almost certainly not (and if we are, we have bigger issue).
            .expect("failed to serialize a result");

        proto.mut_result().set_value(result_bytes);

        proto
    }
}

impl From<Status> for rrg_proto::v2::rrg::Response {

    fn from(status: Status) -> rrg_proto::v2::rrg::Response {
        let mut proto = rrg_proto::v2::rrg::Response::new();
        proto.set_flow_id(status.request_id.flow_id());
        proto.set_request_id(status.request_id.request_id());
        proto.set_response_id(status.response_id.0);
        proto.set_status(status.into());

        proto
    }
}

impl From<Status> for rrg_proto::v2::rrg::Status {

    fn from(status: Status) -> rrg_proto::v2::rrg::Status {
        let mut proto = rrg_proto::v2::rrg::Status::new();
        if let Err(error) = status.result {
            proto.set_error(error.into());
        }

        proto
    }
}

impl<I> From<Parcel<I>> for rrg_proto::v2::rrg::Parcel
where
    I: crate::response::Item,
{
    fn from(parcel: Parcel<I>) -> rrg_proto::v2::rrg::Parcel {
        let payload_proto = parcel.payload.into_proto();
        let payload_any = protobuf::well_known_types::Any::pack(&payload_proto)
            // The should not really ever fail, assumming that the protobuf
            // message we are working with is well-formed and we are not out of
            // memory.
            .unwrap();

        let mut proto = rrg_proto::v2::rrg::Parcel::new();
        proto.set_sink(parcel.sink.into());
        proto.set_payload(payload_any);

        proto
    }
}
