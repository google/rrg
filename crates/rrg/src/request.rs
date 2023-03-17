// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use rrg_macro::warn;

/// List of all actions supported by the agent.
///
/// An action is a "unit of execution" and is invoked by flows (created on the
/// GRR server). To start an action execution the flow needs to send a [request]
/// to the agent. Then the agents replies with one or more responses back to the
/// flow.
///
/// [request]: crate::Request
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Get metadata about the operating system and the machine.
    GetSystemMetadata,
}

/// The error type for cases when parsing action fails.
#[derive(Debug)]
pub struct ParseActionError {
    /// A corresponding [`ParseActionErrorKind`] of the error.
    kind: ParseActionErrorKind,
}

impl ParseActionError {
    /// Returns the corresponding [`ParseActionErrorKind`] of the error.
    pub fn kind(&self) -> ParseActionErrorKind {
        self.kind
    }
}

impl std::fmt::Display for ParseActionError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{}", self.kind)
    }
}

impl std::error::Error for ParseActionError {
}

/// List of general categories of action parsing errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParseActionErrorKind {
    /// The action value is not known.
    UnknownAction(i32),
}

impl std::fmt::Display for ParseActionErrorKind {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParseActionErrorKind::UnknownAction(val) => {
                write!(fmt, "unknown action value '{val}'")
            }
        }
    }
}

impl From<ParseActionErrorKind> for ParseActionError {

    fn from(kind: ParseActionErrorKind) -> ParseActionError {
        ParseActionError {
            kind,
        }
    }
}

impl TryFrom<rrg_proto::v2::rrg::Action> for Action {

    type Error = ParseActionError;

    fn try_from(proto: rrg_proto::v2::rrg::Action) -> Result<Action, ParseActionError> {
        use rrg_proto::v2::rrg::Action::*;

        match proto {
            GET_SYSTEM_METADATA => Ok(Action::GetSystemMetadata),
            _ => {
                let val = protobuf::ProtobufEnum::value(&proto);
                Err(ParseActionErrorKind::UnknownAction(val).into())
            },
        }
    }
}

// TODO(@panhania): Hide fields of this struct.
/// A unique identifier of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestId {
    /// An identifier of the flow issuing the request.
    pub flow_id: u64,
    /// A server-issued identifier of the request (unique within the flow).
    pub request_id: u64,
}

/// An action request.
///
/// Requests are issued by flows and delivered to the agent through Fleetspeak.
/// A request contains metadata about the flow issuing the request as well as
/// details of the work to be carried by the agent: the type of the action to
/// execute and its arguments.
pub struct Request {
    /// A unique identifier of the request.
    id: RequestId,
    /// An action to invoke.
    action: Action,
    /// Serialized protobuf message with arguments to invoke the action with.
    serialized_args: Vec<u8>,
}

impl Request {
    /// Gets the unique identifier of the request.
    pub fn id(&self) -> RequestId {
        self.id
    }

    /// Gets the action this request should invoke.
    pub fn action(&self) -> Action {
        self.action
    }

    // TODO(@panhania): Add "Errors" section to this doc comment.
    /// Returns the action arguments stored in this request.
    ///
    /// At the moment the request is received we don't know yet what is the type
    /// of the arguments it contains, so we cannot interpret it. Only once the
    /// request is dispatched to an appropriate action handler, we can parse the
    /// arguments to a concrete type.
    pub fn args<A>(&self) -> Result<A, ParseArgsError>
    where
        A: Args,
    {
        let args_proto = protobuf::Message::parse_from_bytes(&self.serialized_args[..])?;
        A::from_proto(args_proto)
    }

    /// Awaits for a new request message from Fleetspeak.
    ///
    /// This will suspend execution until the request is actually available.
    /// However, the process will keep heartbeating at the specified rate to
    /// ensure that Fleetspeak does not kill the agent for unresponsiveness.
    ///
    /// # Errors
    ///
    /// This function will return an error in case the request was invalid (e.g.
    /// it was missing some necessary fields). However, it will panic in case of
    /// irrecoverable error like Fleetspeak connection issue as it makes little
    /// sense to continue running in such a state.
    pub fn receive(heartbeat_rate: std::time::Duration) -> Result<Request, ParseRequestError> {
        let message = fleetspeak::receive_with_heartbeat(heartbeat_rate)
            // If we fail to receive a message from Fleetspeak, our connection
            // is most likely broken and we should die. In general, this should
            // not happen.
            .expect("failed to receive a message from Fleetspeak");

        if message.service != "GRR" {
            let service = message.service;
            warn!("request send by service '{service}' (instead of 'GRR')");
        }
        if message.kind.as_deref() != Some("rrg-request") {
            match message.kind {
                Some(kind) => warn!("request with unexpected kind '{kind}'"),
                None => warn!("request with unspecified kind"),
            }
        }

        use protobuf::Message as _;
        let proto = rrg_proto::v2::rrg::Request::parse_from_bytes(&message.data[..])
            .map_err(|error| {
                use ParseRequestErrorKind::*;
                ParseRequestError::new(MalformedBytes, error)
            })?;

        Ok(Request::try_from(proto)?)
    }
}

impl TryFrom<rrg_proto::v2::rrg::Request> for Request {

    type Error = ParseRequestError;

    fn try_from(mut proto: rrg_proto::v2::rrg::Request) -> Result<Request, ParseRequestError> {
        Ok(Request {
            id: RequestId {
                flow_id: proto.get_flow_id(),
                request_id: proto.get_request_id(),
            },
            action: proto.get_action().try_into()?,
            serialized_args: proto.take_args().take_value(),
        })
    }
}

/// The error type for cases when parsing a request fails.
#[derive(Debug)]
pub struct ParseRequestError {
    /// A corresponding [`ParseRequestErrorKind`] of the error.
    kind: ParseRequestErrorKind,
    /// A more datailed cause of the error.
    error: Option<Box<dyn std::error::Error>>,
}

impl ParseRequestError {

    /// Creates a new error from a known kind and its cause.
    pub fn new<E>(kind: ParseRequestErrorKind, error: E) -> ParseRequestError
    where
        E: Into<Box<dyn std::error::Error>>
    {
        ParseRequestError {
            kind,
            error: Some(error.into()),
        }
    }
}

impl From<ParseActionError> for ParseRequestError {

    fn from(error: ParseActionError) -> ParseRequestError {
        ParseRequestErrorKind::InvalidAction(error.kind()).into()
    }
}

impl std::fmt::Display for ParseRequestError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{}", self.kind)?;
        if let Some(error) = &self.error {
            write!(fmt, ": {}", error)?;
        }

        Ok(())
    }
}

impl std::error::Error for ParseRequestError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.as_deref()
    }
}

/// List of general categories of action parsing errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParseRequestErrorKind {
    /// The serialized message with request was impossible to deserialize.
    MalformedBytes,
    /// It was not possible to parse the action specified in the request.
    InvalidAction(ParseActionErrorKind),
}

impl std::fmt::Display for ParseRequestErrorKind {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use ParseRequestErrorKind::*;

        match self {
            MalformedBytes => write!(fmt, "malformed protobuf message bytes"),
            InvalidAction(kind) => write!(fmt, "{}", kind),
        }
    }
}

impl From<ParseRequestErrorKind> for ParseRequestError {

    fn from(kind: ParseRequestErrorKind) -> ParseRequestError {
        ParseRequestError {
            kind,
            error: None,
        }
    }
}

/// Arguments to invoke an action with.
///
/// The arguments are specified in the [request] issued by a GRR flow and stored
/// there in a serialized Protocol Buffers message. Once the request is passed
/// to the appropriate action handler this message is parsed to a concrete Rust
/// type.
///
/// [request]: crate::Request
pub trait Args: Sized {
    /// Low-level Protocol Buffers type representing the action arguments.
    type Proto: protobuf::Message + Default;

    /// Converts a low-level type to a structured request arguments.
    fn from_proto(proto: Self::Proto) -> Result<Self, ParseArgsError>;
}

impl Args for () {

    type Proto = protobuf::well_known_types::Empty;

    fn from_proto(_: protobuf::well_known_types::Empty) -> Result<(), ParseArgsError> {
        Ok(())
    }
}

/// The error type for cases when action argument parsing fails.
#[derive(Debug)]
pub struct ParseArgsError {
    /// A corresponding [`ParseArgsErrorKind`] of this error.
    kind: ParseArgsErrorKind,
    /// A detailed payload associated with the error.
    error: Box<dyn std::error::Error + Send + Sync>,
}

impl ParseArgsError {

    /// Creates a new error instance caused by some invalid field error.
    pub fn invalid_field<E>(error: E) -> ParseArgsError
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        ParseArgsError {
            kind: ParseArgsErrorKind::InvalidField,
            error: Box::new(error),
        }
    }

    /// Returns the corresponding [`ParseArgsErrorKind`] of this error.
    pub fn kind(&self) -> ParseArgsErrorKind {
        self.kind
    }
}

/// Kinds of errors that can happen when parsing action arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParseArgsErrorKind {
    // TODO(@panhania): Rename to `MalformedBytes` to be consistent with other
    // error types.
    /// The serialized message with arguments was impossible to deserialize.
    InvalidProto,
    // TODO(panhania@): Augment with field name.
    /// One of the fields of the arguments struct is invalid.
    InvalidField,
}

impl ParseArgsErrorKind {

    fn as_str(&self) -> &'static str {
        use ParseArgsErrorKind::*;

        match *self {
            InvalidProto => "invalid serialized protobuf message",
            InvalidField => "invalid argument field",
        }
    }
}

impl std::fmt::Display for ParseArgsError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}: {}", self.kind.as_str(), self.error)
    }
}

impl std::error::Error for ParseArgsError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

// TODO(@panhania): Verify whether we really need this conversion. Other error
// types seems not to have anything like this.
impl From<protobuf::ProtobufError> for ParseArgsError {

    fn from(error: protobuf::ProtobufError) -> Self {
        ParseArgsError {
            kind: ParseArgsErrorKind::InvalidProto,
            error: Box::new(error),
        }
    }
}
