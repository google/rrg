// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use rrg_macro::warn;

/// List of all actions known by the agent.
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
    /// Get metadata about the specified file.
    GetFileMetadata,
    /// Get contents of the specified file.
    GetFileContents,
    /// Get hash of the specified file.
    GetFileHash,
    /// List contents of a directory.
    ListDirectory,
    /// List processes available on the system.
    ListProcesses,
    /// List connections available on the system.
    ListConnections,
    /// List named pipes available on the system (Windows-only).
    ListNamedPipes,
    /// List users available on the system.
    ListUsers,
    /// Get the snapshot of the entire filesystem.
    GetFilesystemTimeline,
}

impl std::fmt::Display for Action {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Action::GetSystemMetadata => write!(fmt, "get_system_metadata"),
            Action::GetFileMetadata => write!(fmt, "get_file_metadata"),
            Action::GetFileContents => write!(fmt, "get_file_contents"),
            Action::GetFileHash => write!(fmt, "get_file_hash"),
            Action::ListDirectory => write!(fmt, "list_directory"),
            Action::ListProcesses => write!(fmt, "list_processes"),
            Action::ListConnections => write!(fmt, "list_connections"),
            Action::ListNamedPipes => write!(fmt, "list_named_pipes"),
            Action::ListUsers => write!(fmt, "list_users"),
            Action::GetFilesystemTimeline => write!(fmt, "get_filesystem_timeline"),
        }
    }
}

/// An action that is not known to the agent.
///
/// Sometimes we may receive an action that is not known because the server is
/// more up-to-date than the agent (or is just broken). But we should not fail
/// parsing the request as we would like to still communicate failure back to
/// the server. Therefore, we keep this value around and fail at action dispatch
/// delivering a response to the calling flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnknownAction {
    /// A raw value from the Protocol Buffers message.
    value: i32,
}

impl std::fmt::Display for UnknownAction {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "unknown({})", self.value)
    }
}

impl TryFrom<rrg_proto::v2::rrg::Action> for Action {

    type Error = UnknownAction;

    fn try_from(proto: rrg_proto::v2::rrg::Action) -> Result<Action, UnknownAction> {
        use rrg_proto::v2::rrg::Action::*;

        match proto {
            GET_SYSTEM_METADATA => Ok(Action::GetSystemMetadata),
            GET_FILE_METADATA => Ok(Action::GetFileMetadata),
            GET_FILE_CONTENTS => Ok(Action::GetFileContents),
            GET_FILE_HASH => Ok(Action::GetFileHash),
            LIST_DIRECTORY => Ok(Action::ListDirectory),
            LIST_PROCESSES => Ok(Action::ListProcesses),
            LIST_CONNECTIONS => Ok(Action::ListConnections),
            LIST_NAMED_PIPES => Ok(Action::ListNamedPipes),
            LIST_USERS => Ok(Action::ListUsers),
            GET_FILESYSTEM_TIMELINE => Ok(Action::GetFilesystemTimeline),
            _ => {
                let value = protobuf::ProtobufEnum::value(&proto);
                Err(UnknownAction { value })
            },
        }
    }
}

/// A unique identifier of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestId {
    /// An identifier of the flow issuing the request.
    flow_id: u64,
    /// A server-issued identifier of the request (unique within the flow).
    request_id: u64,
}

impl RequestId {
    /// Returns an identifier of the flow issuing the request.
    pub fn flow_id(&self) -> u64 {
        self.flow_id
    }

    /// Returns a server-issued identifier of the request.
    pub fn request_id(&self) -> u64 {
        self.request_id
    }
}

impl std::fmt::Display for RequestId {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{:X}/{}", self.flow_id, self.request_id)
    }
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
    action: Result<Action, UnknownAction>,
    /// Serialized protobuf message with arguments to invoke the action with.
    serialized_args: Vec<u8>,
    /// Maximum number of bytes to send to the server when handling the request.
    network_bytes_limit: Option<u64>,
    /// Maximum CPU time to spend when handling the request.
    cpu_time_limit: Result<Option<std::time::Duration>, rrg_proto::ParseDurationError>,
    /// Maximum real (wall) time to spend when handling the request.
    real_time_limit: Result<Option<std::time::Duration>, rrg_proto::ParseDurationError>,
}

impl Request {
    /// Gets the unique identifier of the request.
    pub fn id(&self) -> RequestId {
        self.id
    }

    /// Gets the action this request should invoke.
    pub fn action(&self) -> Result<Action, UnknownAction> {
        self.action
    }

    /// Returns the action arguments stored in this request.
    ///
    /// At the moment the request is received we don't know yet what is the type
    /// of the arguments it contains, so we cannot interpret it. Only once the
    /// request is dispatched to an appropriate action handler, we can parse the
    /// arguments to a concrete type.
    ///
    /// # Errors
    ///
    /// This function will return an error if it is not possible to interpret
    /// the serialized request arguments as the expected type (e.g. the message
    /// is malformed or some of the required fields are not present).
    pub fn args<A>(&self) -> Result<A, ParseArgsError>
    where
        A: Args,
    {
        let args_proto = protobuf::Message::parse_from_bytes(&self.serialized_args[..])
            .map_err(|error| ParseArgsError {
                kind: ParseArgsErrorKind::MalformedBytes,
                error: Box::new(error),
            })?;

        A::from_proto(args_proto)
    }

    /// Gets the limit on the number of bytes the request handler can send.
    pub fn network_bytes_limit(&self) -> Option<u64> {
        self.network_bytes_limit
    }

    /// Gets the limit on the CPU time the request handler can spend.
    pub fn cpu_time_limit(&self) -> Result<Option<std::time::Duration>, rrg_proto::ParseDurationError> {
        match &self.cpu_time_limit {
            Ok(limit) => Ok(*limit),
            Err(error) => Err(error.clone()),
        }
    }

    /// Gets the limit on the real (wall) time the request handler can spend.
    pub fn real_time_limit(&self) -> Result<Option<std::time::Duration>, rrg_proto::ParseDurationError> {
        match &self.real_time_limit {
            Ok(limit) => Ok(*limit),
            Err(error) => Err(error.clone()),
        }
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
        let message = fleetspeak::receive_with_heartbeat(heartbeat_rate);

        if message.service != "GRR" {
            let service = message.service;
            warn!("request send by service '{service}' (instead of 'GRR')");
        }
        if message.kind.as_deref() != Some("rrg.Request") {
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
        use rrg_proto::try_from_duration;

        let network_bytes_limit = match proto.get_network_bytes_limit() {
            0 => None,
            limit => Some(limit),
        };

        let cpu_time_limit = try_from_duration(proto.take_cpu_time_limit())
            .map(|limit| if limit.is_zero() {
                None
            } else {
                Some(limit)
            });

        let real_time_limit = try_from_duration(proto.take_real_time_limit())
            .map(|limit| if limit.is_zero() {
                None
            } else {
                Some(limit)
            });

        Ok(Request {
            id: RequestId {
                flow_id: proto.get_flow_id(),
                request_id: proto.get_request_id(),
            },
            action: proto.get_action().try_into(),
            serialized_args: proto.take_args().take_value(),
            network_bytes_limit,
            cpu_time_limit,
            real_time_limit,
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
}

impl std::fmt::Display for ParseRequestErrorKind {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use ParseRequestErrorKind::*;

        match self {
            MalformedBytes => write!(fmt, "malformed protobuf message bytes"),
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

    /// Creates a new error instance caused by invalid field error.
    pub fn invalid_field<E>(name: &'static str, error: E) -> ParseArgsError
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        ParseArgsError {
            kind: ParseArgsErrorKind::InvalidField(name),
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
    /// The serialized message with arguments was impossible to deserialize.
    MalformedBytes,
    /// One of the fields of the arguments struct is invalid.
    InvalidField(&'static str),
}

impl std::fmt::Display for ParseArgsErrorKind {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ParseArgsErrorKind::*;

        match *self {
            MalformedBytes => {
                write!(fmt, "malformed protobuf message bytes")
            }
            InvalidField(name) => {
                write!(fmt, "invalid argument field '{name}'")
            }
        }
    }
}

impl std::fmt::Display for ParseArgsError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}: {}", self.kind, self.error)
    }
}

impl std::error::Error for ParseArgsError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn action_try_from_proto_all_known() {
        use protobuf::ProtobufEnum as _;

        for action in rrg_proto::v2::rrg::Action::values() {
            if *action == rrg_proto::v2::rrg::Action::UNKNOWN {
                continue;
            }

            assert!(Action::try_from(*action).is_ok());
        }
    }

    #[test]
    fn action_try_fromt_proto_unknown() {
        assert!(Action::try_from(rrg_proto::v2::rrg::Action::UNKNOWN).is_err());
    }
}
