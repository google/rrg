use crate::comms::RequestId;

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

/// A unique identifier of a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResponseId(u64);

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
