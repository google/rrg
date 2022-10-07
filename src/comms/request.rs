/// An action request message.
pub struct Request {
    /// A unique id of the request.
    id: RequestId,
    /// A name of the action to execute.
    action: String,
    /// Serialized Protocol Buffers message with request arguments.
    serialized_args: Option<Vec<u8>>,
}

/// A unique identifier of a request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RequestId {
    /// A server-issued session identifier (usually corresponds to a flow).
    pub(super) session_id: String,
    /// A server-issued request identifier.
    pub(super) request_id: u64,
}

impl Request {

    /// Parses the action arguments stored in this request.
    ///
    /// At the moment the request is received we don't know yet what is the type
    /// of the arguments it contains and so we cannot interpret it. Once the
    /// request is dispatched to an appropriate action handler, we can parse the
    /// arguments to a concrete type.
    pub fn parse_args<A>(&self) -> Result<A, crate::action::ParseArgsError>
    where
        A: crate::action::Args,
    {
        let proto_args = match &self.serialized_args {
            Some(ref bytes) => protobuf::Message::parse_from_bytes(bytes)?,
            None => Default::default(),
        };

        A::from_proto(proto_args)
    }

    /// Awaits for a new request message from Fleetspeak.
    ///
    /// This will suspend execution until the request is actually available.
    /// However, the process will keep heartbeating at the specified rate.
    pub fn receive(heartbeat_rate: std::time::Duration) -> Result<Request, ReceiveRequestError> {
        let proto = crate::message::receive_raw(heartbeat_rate)?;

        use std::convert::TryFrom as _;
        Ok(Request::try_from(proto)?)
    }
}

impl std::convert::TryFrom<rrg_proto::jobs::GrrMessage> for Request {

    type Error = ParseRequestError;

    fn try_from(mut proto: rrg_proto::jobs::GrrMessage) -> Result<Request, ParseRequestError> {
        use ParseRequestErrorKind::*;

        if !proto.has_session_id() {
            return Err(NoSessionId.into());
        }
        if !proto.has_request_id() {
            return Err(NoRequestId.into());
        }
        let request_id = RequestId {
            session_id: proto.take_session_id(),
            request_id: proto.get_request_id(),
        };

        if !proto.has_name() {
            return Err(NoActionName.into());
        }
        let action = proto.take_name();

        let serialized_args = if proto.has_args() {
            Some(proto.take_args())
        } else {
            None
        };

        Ok(Request {
            id: request_id,
            action: action,
            serialized_args,
        })
    }
}

/// The error type for cases when action request parsing fails.
#[derive(Debug)]
pub struct ParseRequestError {
    /// A corresponding [`ParseRequestErrorKind`] of this error.
    kind: ParseRequestErrorKind,
}

/// Kinds of errors that can happen when parsing an action request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParseRequestErrorKind {
    /// No session identifier in the action request protobuf message.
    NoSessionId,
    /// No request identifier in the action request protobuf message.
    NoRequestId,
    /// No action name in the action request protobuf message.
    NoActionName,
}

impl ParseRequestErrorKind {

    fn as_str(&self) -> &'static str {
        use ParseRequestErrorKind::*;

        match *self {
            NoSessionId => "no session id in the action request",
            NoRequestId => "no request id in the action request",
            NoActionName => "no action name in the action request",
        }
    }
}

impl From<ParseRequestErrorKind> for ParseRequestError {

    fn from(kind: ParseRequestErrorKind) -> Self {
        ParseRequestError {
            kind,
        }
    }
}

impl std::fmt::Display for ParseRequestError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}", self.kind.as_str())
    }
}

impl std::error::Error for ParseRequestError {
}

/// The error type for cases when action request cannot be obtained.
#[derive(Debug)]
pub struct ReceiveRequestError {
    /// A corresponding [`ReceiveRequestErrorKind`] of this error.
    kind: ReceiveRequestErrorKind,
    /// A nested error that caused this error.
    error: Box<dyn std::error::Error + Send + Sync>,
}

/// Kinds of errors that can happen when trying to obtain an action request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ReceiveRequestErrorKind {
    /// Fleetspeak connector was unable to receive the message.
    FleetspeakIssue,
    /// The Protocol Buffers message was ill-formed.
    MalformedProtobuf,
}

impl ReceiveRequestErrorKind {

    fn as_str(&self) -> &'static str {
        use ReceiveRequestErrorKind::*;

        match *self {
            FleetspeakIssue => "unable to retrieve a Fleetspeak message",
            MalformedProtobuf => "request protobuf is ill-formed",
        }
    }
}

impl From<ParseRequestError> for ReceiveRequestError {

    fn from(error: ParseRequestError) -> ReceiveRequestError {
        ReceiveRequestError {
            kind: ReceiveRequestErrorKind::MalformedProtobuf,
            error: Box::new(error),
        }
    }
}

impl From<fleetspeak::ReadError> for ReceiveRequestError {

    fn from(error: fleetspeak::ReadError) -> ReceiveRequestError {
        ReceiveRequestError {
            kind: ReceiveRequestErrorKind::FleetspeakIssue,
            error: Box::new(error),
        }
    }
}

impl From<protobuf::ProtobufError> for ReceiveRequestError {

    fn from(error: protobuf::ProtobufError) -> ReceiveRequestError {
        ReceiveRequestError {
            kind: ReceiveRequestErrorKind::MalformedProtobuf,
            error: Box::new(error),
        }
    }
}

impl std::fmt::Display for ReceiveRequestError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}: {}", self.kind.as_str(), self.error)
    }
}

impl std::error::Error for ReceiveRequestError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.error)
    }
}
