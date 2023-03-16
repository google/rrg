// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use crate::RequestId;

/// An action reply message.
///
/// This is a message wrapper around the [`Item`] type but associates it with a
/// particular request.
///
/// [`Item`]: crate::action::Item
pub struct Reply<I: crate::action::Item> {
    /// A unique request identifier for which this item was yielded.
    request_id: RequestId,
    /// A unique response identifier of this item.
    response_id: ResponseId,
    /// An actual item that the action yielded.
    item: I,
}

impl<I: crate::action::Item> Reply<I> {

    /// Sends the reply message through Fleetspeak to the GRR server.
    ///
    /// This function consumes the item to ensure that it is not sent twice.
    ///
    /// Note that this function will not do any network traffic accounting and
    /// should not be used in general. One should almost always prefer to use
    /// [`Session::reply`] instead.
    ///
    /// [`Session::reply`]: crate::session::Session::reply
    pub fn send_unaccounted(self) -> Result<(), fleetspeak::WriteError> {
        use protobuf::Message as _;

        let data = rrg_proto::v2::rrg::Response::from(self).write_to_bytes()
            // This should only fail in case we are out of memory, which we are
            // almost certainly not (and if we are, we have bigger issue).
            .expect("failed to serialize a result response");

        fleetspeak::send(fleetspeak::Message {
            service: String::from("GRR"),
            kind: Some(String::from("rrg-response")),
            data,
        })
    }
}

// TODO(@panhania): Consider defining an `crate::action::Error` type and make
// the `Status` type non-generic.
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
    /// [`Session::send`]: crate::session::Session::send
    pub fn send_unaccounted(self) -> Result<(), fleetspeak::WriteError> {
        use protobuf::Message as _;

        let data = rrg_proto::v2::rrg::Response::from(self).write_to_bytes()
            // This should only fail in case we are out of memory, which we are
            // almost certainly not (and if we are, we have bigger issue).
            .expect("failed to serialize a status response");

        fleetspeak::send(fleetspeak::Message {
            service: String::from("GRR"),
            kind: Some(String::from("rrg-response")),
            data,
        })
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
        I: crate::action::Item,
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

/// A wrapper around [`Item`] objects addressed to a particular sink.
///
/// Sometimes the agent should send data to the server that is not associated
/// with a particular flow request. An example can be the agent startup data
/// sent to the server regardless of whether there was a request for it or not.
/// Another example can be file contents that are delivered to the server not
/// as part of the flow results but go to a separate store that has logic for
/// deduplicating data that we already collected in the past.
///
/// Since this data is not associated with any flow request it still has to be
/// somehow identified. This is why we send data to a particular [`Sink`] that
/// knows how to deal with items of particular kind (e.g. there is a sink for
/// file contents and a separate sink for startup information).
///
/// [`Item`]: crate::action::Item
/// [`Sink`]: crate::message::Sink
pub struct Parcel<I: crate::action::Item> {
    /// Destination of the parcel.
    sink: crate::message::sink::Sink,
    /// The item contained within this parcel.
    item: I,
}

impl<I: crate::action::Item> Parcel<I> {

    /// Creates a new parcel from the given `item` addressed to `sink`.
    pub fn new(sink: crate::message::sink::Sink, item: I) -> Parcel<I> {
        Parcel {
            sink,
            item,
        }
    }

    /// Sink to which the parcel should be delivered to.
    pub fn sink(&self) -> crate::message::sink::Sink {
        self.sink
    }

    // TODO: Delete or rename this method.
    /// Unpacks the underlying parcel.
    pub fn unpack(self) -> I {
        self.item
    }

    /// Sends the parcel message through Fleetspeak to the GRR server.
    ///
    /// This function consumes the parcel to ensure that it is not sent twice.
    ///
    /// Note that this function should generally not be used if running as part
    /// of some [`Session`], otherwise network usage might not be correctly
    /// accounted for. Prefer to use [`Session::send`] for such cases.
    ///
    /// [`Session`]: crate::session::Session
    /// [`Session::send`]: crate::session::Session::send
    pub fn send(self) {
        super::fleetspeak::send_raw(self.into());
    }
}

impl<I> From<Reply<I>> for rrg_proto::v2::rrg::Response
where
    I: crate::action::Item,
{
    fn from(reply: Reply<I>) -> rrg_proto::v2::rrg::Response {
        let mut proto = rrg_proto::v2::rrg::Response::new();
        proto.set_flow_id(reply.request_id.flow_id);
        proto.set_request_id(reply.request_id.request_id);
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
        proto.set_flow_id(status.request_id.flow_id);
        proto.set_request_id(status.request_id.request_id);
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

impl<I: crate::action::Item> Into<rrg_proto::jobs::GrrMessage> for Parcel<I> {

    fn into(self) -> rrg_proto::jobs::GrrMessage {
        use protobuf::Message as _;

        let mut proto = rrg_proto::jobs::GrrMessage::new();
        proto.set_session_id(String::from(self.sink.id()));
        proto.set_field_type(rrg_proto::jobs::GrrMessage_Type::MESSAGE);

        let serialized_item = self.item
            .into_proto()
            .write_to_bytes()
            // It is not clear what should we do in case of an error. It is very
            // hard to imagine a scenario when serialization fails so for now we
            // just fail hard. If we observe any problems with this assumption,
            // we can always change this behaviour.
            .expect("failed to serialize the item message");

        // Like with response messages, for parcels we also have to store the
        // parcel data in the field named "args". This is something that should
        // be fixed one day.
        proto.set_args_rdf_name(String::from(I::RDF_NAME));
        proto.set_args(serialized_item);

        proto
    }
}
