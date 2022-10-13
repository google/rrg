use crate::message::RequestId;

/// An action item message.
///
/// This is a message wrapper around the [`Item`] type that also contains
/// metadata of the response.
///
/// [`Item`]: crate::action::Item
pub struct Item<I: crate::action::Item> {
    /// A unique request identifier for which this item was yielded.
    request_id: RequestId,
    /// A unique response identifier of this item.
    response_id: ResponseId,
    /// An actual action result.
    item: I,
}

impl<I: crate::action::Item> Item<I> {

    /// Sends the item message through Fleetspeak to the GRR server.
    ///
    /// This function consumes the item to ensure that it is not sent twice.
    pub fn send(self) {
        super::fleetspeak::send_raw(self.into());
    }
}

// TODO(@panhania): Consider defining an `crate::action::Error` type and make
// the `Status` type non-generic.
/// An action execution status message.
///
/// Every action execution should return a status message as the last response
/// to the server. The status should contain information if the action execution
/// succeeded and error details in case it did not.
pub struct Status<E: std::error::Error> {
    /// A unique request identifier for which this status is generated.
    request_id: RequestId,
    /// A unique response identifier of this status.
    response_id: ResponseId,
    /// The action execution status.
    result: Result<(), E>,
}

impl<E: std::error::Error> Status<E> {

    /// Sends the status message through Fleetspeak to the GRR server.
    ///
    /// This function consumes the status to ensure that it is not sent twice.
    pub fn send(self) {
        super::fleetspeak::send_raw(self.into())
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
    pub fn status<E>(self, result: Result<(), E>) -> Status<E>
    where
        E: std::error::Error,
    {
        Status {
            request_id: self.request_id,
            // Because this method consumes the builder, we do not need to
            // increment the response id.
            response_id: self.next_response_id,
            result,
        }
    }

    /// Builds a new item response for the given action item.
    pub fn item<I>(&mut self, item: I) -> Item<I>
    where
        I: crate::action::Item,
    {
        let response_id = self.next_response_id;
        self.next_response_id.0 += 1;

        Item {
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
/// [`Sink`]: crate::message::sink::Sink
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


impl<I> Into<rrg_proto::jobs::GrrMessage> for Item<I>
where
    I: crate::action::Item,
{
    fn into(self) -> rrg_proto::jobs::GrrMessage {
        use protobuf::Message as _;

        let mut proto = rrg_proto::jobs::GrrMessage::new();
        proto.set_session_id(self.request_id.session_id);
        proto.set_request_id(self.request_id.request_id);
        proto.set_response_id(self.response_id.0);
        proto.set_field_type(rrg_proto::jobs::GrrMessage_Type::MESSAGE);

        let serialized_item = self.item
            .into_proto()
            .write_to_bytes()
            // It is not clear what should we do in case of an error. It is very
            // hard to imagine a scenario when serialization fails so for now we
            // just fail hard. If we observe any problems with this assumption,
            // we can always change this behaviour.
            .expect("failed to serialize an action item");

        // The protobuf message uses a field named "args" for storing the action
        // item, so of course we repeat that. One day this should be improved,
        // hopefully.
        proto.set_args_rdf_name(String::from(I::RDF_NAME));
        proto.set_args(serialized_item);

        proto
    }
}

impl<E> Into<rrg_proto::jobs::GrrMessage> for Status<E>
where
    E: std::error::Error,
{
    fn into(self) -> rrg_proto::jobs::GrrMessage {
        use protobuf::Message as _;

        let mut proto_status = rrg_proto::jobs::GrrStatus::new();
        match self.result {
            Ok(()) => {
                proto_status.set_status(rrg_proto::jobs::GrrStatus_ReturnedStatus::OK);
            },
            Err(error) => {
                // TODO(@panhania): Use more specific error types once we have
                // custom error type for actions (see also the comment about the
                // genericity of the `Status` type.
                proto_status.set_status(rrg_proto::jobs::GrrStatus_ReturnedStatus::GENERIC_ERROR);
                proto_status.set_error_message(error.to_string());
            }
        }

        let serialized_status = proto_status
            .write_to_bytes()
            // See a comment in the conversion of the `Item` type for details on
            // why we panic on errors here.
            .expect("failed to serialized action status");

        let mut proto = rrg_proto::jobs::GrrMessage::new();
        proto.set_session_id(self.request_id.session_id);
        proto.set_request_id(self.request_id.request_id);
        proto.set_response_id(self.response_id.0);
        proto.set_field_type(rrg_proto::jobs::GrrMessage_Type::STATUS);

        // Again, for some reason GRR expects the status to be passed as as a
        // serialized proto in a field named "args". This should be definitely
        // fixed when designing the new protocol.
        proto.set_args_rdf_name(String::from("GrrStatus"));
        proto.set_args(serialized_status);

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
