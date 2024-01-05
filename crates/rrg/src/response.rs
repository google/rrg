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
    type Proto: protobuf::MessageFull + Default;

    /// Converts an action result ot its low-level representation.
    fn into_proto(self) -> Self::Proto;
}

impl Item for () {
    type Proto = protobuf::well_known_types::empty::Empty;

    fn into_proto(self) -> protobuf::well_known_types::empty::Empty {
        protobuf::well_known_types::empty::Empty::new()
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

    /// Converts the reply into [`PreparedReply`].
    pub fn prepare(self) -> PreparedReply<I> {
        PreparedReply {
            request_id: self.request_id,
            response_id: self.response_id,
            item_proto: self.item.into_proto(),
        }
    }
}

/// A prepared action reply message.
///
/// This is a message wrapper around the raw Protocol Buffers message for some
/// [`Item`] type but associated with a particular request.
///
/// To create an instance of this type, use the [`Reply::prepare`] method.
///
/// [`Item`]: crate::response::Item
pub struct PreparedReply<I: Item> {
    /// A unique request identifier for which this item was yielded.
    request_id: RequestId,
    /// A unique response identifier of this item.
    response_id: ResponseId,
    /// An actual Protocol Buffers message of the item that the action yielded.
    item_proto: I::Proto,
}

impl<I: Item> PreparedReply<I> {

    /// Returns the Protocol Buffers message of the item of the reply.
    pub fn item_proto(&self) -> &I::Proto {
        &self.item_proto
    }

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

        let data = rrg_proto::rrg::Response::from(self).write_to_bytes()
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
    /// Number of items that have been rejected by filters.
    filtered_out_count: u32,
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

        let data = rrg_proto::rrg::Response::from(self).write_to_bytes()
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

/// An action execution log message.
///
/// Whenever an actions logs a message (through the [`log`] crate), all entries
/// with a level higher than the logging threshold specified in the request are
/// going to be sent to the server as responses.
///
/// These responses can be useful for debugging action behaviour but are should
/// not be used "by default" not to induce too much traffic on the server.
///
/// Note that even though log messages are responses they do not have a unique
/// identifier (unlike [`Status`] and [`Reply`] instances).
pub struct Log<'r, 'a> {
    /// A unique identifier of the request that casued the log message.
    request_id: RequestId,
    /// The time at which the message was logged.
    timestamp: std::time::SystemTime,
    /// The actual record that was logged.
    record: &'r log::Record<'a>,
}

impl<'r, 'a> Log<'r, 'a> {

    /// Sends the log message through Fleetspeak to the GRR server.
    ///
    /// This function consumes the item to ensure that it is not sent twice.
    ///
    /// Note that unlike for [`Status`] and [`Reply`], there is no corresponding
    /// "accounted" method for sending logs as they should not contribute to the
    /// network usage statistics.
    pub fn send_unaccounted(self) {
        use protobuf::Message as _;

        let data = rrg_proto::rrg::Response::from(self).write_to_bytes()
            // This should only fail in case we are out of memory, which we are
            // almost certainly not (and if we are, we have bigger issue).
            .expect("failed to serialize a log response");

        fleetspeak::send(fleetspeak::Message {
            service: String::from("GRR"),
            kind: Some(String::from("rrg.Response")),
            data,
        });
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
    /// Number of items that have been rejected by filters.
    filtered_out_count: u32,
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
            filtered_out_count: 0,
        }
    }

    /// Builds a new status response for the given action outcome.
    pub fn status(self, result: crate::session::Result<()>) -> Status {
        Status {
            request_id: self.request_id,
            // Because this method consumes the builder, we do not need to
            // increment the response id.
            response_id: self.next_response_id,
            filtered_out_count: self.filtered_out_count,
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

    /// Marks the given reply as rejected by filters.
    pub fn filter_out<I>(&mut self, reply: PreparedReply<I>)
    where
        I: Item,
    {
        drop(reply);

        self.filtered_out_count += 1;
    }
}

/// Log factory for building many log responses to a single request.
pub struct LogBuilder {
    /// A unique request identifier for which we build log responses.
    request_id: RequestId,
}

impl LogBuilder {

    /// Creates a new log response builder for the specified request.
    pub fn new(request_id: RequestId) -> LogBuilder {
        LogBuilder {
            request_id,
        }
    }

    /// Builds a new log response for the given log record.
    pub fn log<'r, 'a>(&self, record: &'r log::Record<'a>) -> Log<'r, 'a> {
        Log {
            request_id: self.request_id,
            timestamp: std::time::SystemTime::now(),
            record,
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

impl From<Sink> for rrg_proto::rrg::Sink {

    fn from(sink: Sink) -> rrg_proto::rrg::Sink {
        match sink {
            Sink::Startup => rrg_proto::rrg::Sink::STARTUP,
            Sink::Blob => rrg_proto::rrg::Sink::BLOB,
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

        let data = rrg_proto::rrg::Parcel::from(self).write_to_bytes()
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

impl<I> From<PreparedReply<I>> for rrg_proto::rrg::Response
where
    I: Item,
{
    fn from(reply: PreparedReply<I>) -> rrg_proto::rrg::Response {
        let result_proto = reply.item_proto();
        let result_any = protobuf::well_known_types::any::Any::pack(result_proto)
            // This should only fail in case we are out of memory, which we are
            // almost certainly not (and if we are, we have bigger issue).
            .expect("failed to serialize a result");

        let mut proto = rrg_proto::rrg::Response::new();
        proto.set_flow_id(reply.request_id.flow_id());
        proto.set_request_id(reply.request_id.request_id());
        proto.set_response_id(reply.response_id.0);
        proto.set_result(result_any);

        proto
    }
}

impl From<Status> for rrg_proto::rrg::Response {

    fn from(status: Status) -> rrg_proto::rrg::Response {
        let mut proto = rrg_proto::rrg::Response::new();
        proto.set_flow_id(status.request_id.flow_id());
        proto.set_request_id(status.request_id.request_id());
        proto.set_response_id(status.response_id.0);
        proto.set_status(status.into());

        proto
    }
}

impl From<Status> for rrg_proto::rrg::Status {

    fn from(status: Status) -> rrg_proto::rrg::Status {
        let mut proto = rrg_proto::rrg::Status::new();
        if let Err(error) = status.result {
            proto.set_error(error.into());
        }

        proto.set_filtered_out_count(status.filtered_out_count);

        proto
    }
}

impl<'r, 'a> From<Log<'r, 'a>> for rrg_proto::rrg::Response {

    fn from(log: Log<'r, 'a>) -> rrg_proto::rrg::Response {
        let mut proto = rrg_proto::rrg::Response::new();
        proto.set_flow_id(log.request_id.flow_id());
        proto.set_request_id(log.request_id.request_id());
        proto.set_log(log.into());

        proto
    }
}

impl<'r, 'a> From<Log<'r, 'a>> for rrg_proto::rrg::Log {

    fn from(log: Log<'r, 'a>) -> rrg_proto::rrg::Log {
        let mut proto = rrg_proto::rrg::Log::new();
        proto.set_level(log.record.level().into());
        proto.set_timestamp(rrg_proto::into_timestamp(log.timestamp));
        proto.set_message(log.record.args().to_string());

        proto
    }
}

impl<I> From<Parcel<I>> for rrg_proto::rrg::Parcel
where
    I: crate::response::Item,
{
    fn from(parcel: Parcel<I>) -> rrg_proto::rrg::Parcel {
        let payload_proto = parcel.payload.into_proto();
        let payload_any = protobuf::well_known_types::any::Any::pack(&payload_proto)
            // This should only fail in case we are out of memory, which we are
            // almost certainly not (and if we are, we have bigger issue).
            .expect("failed to serialize a parcel");

        let mut proto = rrg_proto::rrg::Parcel::new();
        proto.set_sink(parcel.sink.into());
        proto.set_payload(payload_any);

        proto
    }
}
