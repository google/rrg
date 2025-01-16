// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

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
    /// Grep the specified file for a pattern.
    GrepFileContents,
    /// List contents of a directory.
    ListDirectory,
    /// List processes available on the system.
    ListProcesses,
    /// List connections available on the system.
    ListConnections,
    /// List named pipes available on the system (Windows-only).
    ListNamedPipes,
    /// List network interfaces available on the system.
    ListInterfaces,
    /// List filesystem mounts available on the system.
    ListMounts,
    /// List users available on the system.
    ListUsers,
    /// Get the snapshot of the entire filesystem.
    GetFilesystemTimeline,
    /// Connect to a TCP address, write some data and retrieve the response.
    GetTcpResponse,
    // Get a value from the Windows Registry (Windows-only).
    GetWinregValue,
    /// List values of the Windows Registry key (Windows-only).
    ListWinregValues,
    /// List subkeys of the Windows Registry key (Windows-only).
    ListWinregKeys,
    /// Query WMI using WQL (Windows-only).
    QueryWmi,
}

impl std::fmt::Display for Action {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Action::GetSystemMetadata => write!(fmt, "get_system_metadata"),
            Action::GetFileMetadata => write!(fmt, "get_file_metadata"),
            Action::GetFileContents => write!(fmt, "get_file_contents"),
            Action::GetFileHash => write!(fmt, "get_file_hash"),
            Action::GrepFileContents => write!(fmt, "grep_file_contents"),
            Action::ListDirectory => write!(fmt, "list_directory"),
            Action::ListProcesses => write!(fmt, "list_processes"),
            Action::ListConnections => write!(fmt, "list_connections"),
            Action::ListNamedPipes => write!(fmt, "list_named_pipes"),
            Action::ListInterfaces => write!(fmt, "list_interfaces"),
            Action::ListMounts => write!(fmt, "list_mounts"),
            Action::ListUsers => write!(fmt, "list_users"),
            Action::GetFilesystemTimeline => write!(fmt, "get_filesystem_timeline"),
            Action::GetWinregValue => write!(fmt, "get_winreg_value"),
            Action::ListWinregValues => write!(fmt, "list_winreg_values"),
            Action::ListWinregKeys => write!(fmt, "list_winreg_keys"),
            Action::QueryWmi => write!(fmt, "query_wmi"),
            Action::GetTcpResponse => write!(fmt,  "get_tcp_response"),
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

impl TryFrom<rrg_proto::rrg::Action> for Action {

    type Error = UnknownAction;

    fn try_from(proto: rrg_proto::rrg::Action) -> Result<Action, UnknownAction> {
        use rrg_proto::rrg::Action::*;

        match proto {
            GET_SYSTEM_METADATA => Ok(Action::GetSystemMetadata),
            GET_FILE_METADATA => Ok(Action::GetFileMetadata),
            GET_FILE_CONTENTS => Ok(Action::GetFileContents),
            GET_FILE_HASH => Ok(Action::GetFileHash),
            GREP_FILE_CONTENTS => Ok(Action::GrepFileContents),
            LIST_DIRECTORY => Ok(Action::ListDirectory),
            LIST_PROCESSES => Ok(Action::ListProcesses),
            LIST_CONNECTIONS => Ok(Action::ListConnections),
            LIST_NAMED_PIPES => Ok(Action::ListNamedPipes),
            LIST_INTERFACES => Ok(Action::ListInterfaces),
            LIST_MOUNTS => Ok(Action::ListMounts),
            LIST_USERS => Ok(Action::ListUsers),
            GET_FILESYSTEM_TIMELINE => Ok(Action::GetFilesystemTimeline),
            GET_TCP_RESPONSE => Ok(Action::GetTcpResponse),
            GET_WINREG_VALUE => Ok(Action::GetWinregValue),
            LIST_WINREG_VALUES => Ok(Action::ListWinregValues),
            LIST_WINREG_KEYS => Ok(Action::ListWinregKeys),
            QUERY_WMI => Ok(Action::QueryWmi),
            _ => {
                let value = protobuf::Enum::value(&proto);
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
    action: Action,
    /// Serialized protobuf message with arguments to invoke the action with.
    serialized_args: Vec<u8>,
    /// Maximum number of bytes to send to the server when handling the request.
    network_bytes_limit: Option<u64>,
    /// Maximum CPU time to spend when handling the request.
    cpu_time_limit: Option<std::time::Duration>,
    /// Maximum real (wall) time to spend when handling the request.
    real_time_limit: Option<std::time::Duration>,
    /// Minimum level at which logs are going to be sent to the server.
    log_level: log::LevelFilter,
    /// Filters to apply to result messages.
    filters: crate::filter::FilterSet,
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
    pub fn cpu_time_limit(&self) -> Option<std::time::Duration> {
        self.cpu_time_limit
    }

    /// Gets the limit on the real (wall) time the request handler can spend.
    pub fn real_time_limit(&self) -> Option<std::time::Duration> {
        self.real_time_limit
    }

    /// Gets the minimum level at which log messages are sent to the server.
    pub fn log_level(&self) -> log::LevelFilter {
        self.log_level
    }

    /// Takes the filters specified in the request.
    ///
    /// Note that calling this method will permanently clear filters contained
    /// within the request.
    pub fn take_filters(&mut self) -> crate::filter::FilterSet {
        std::mem::replace(&mut self.filters, crate::filter::FilterSet::empty())
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
            log::warn!("request send by service '{service}' (instead of 'GRR')");
        }
        if message.kind.as_deref() != Some("rrg.Request") {
            match message.kind {
                Some(kind) => log::warn!("request with unexpected kind '{kind}'"),
                None => log::warn!("request with unspecified kind"),
            }
        }

        use protobuf::Message as _;
        let proto = rrg_proto::rrg::Request::parse_from_bytes(&message.data[..])
            .map_err(|error| ParseRequestError {
                request_id: None,
                kind: ParseRequestErrorKind::MalformedBytes,
                error: Some(Box::new(error)),
            })?;

        Ok(Request::try_from(proto)?)
    }
}

impl TryFrom<rrg_proto::rrg::Request> for Request {

    type Error = ParseRequestError;

    fn try_from(mut proto: rrg_proto::rrg::Request) -> Result<Request, ParseRequestError> {
        use rrg_proto::try_from_duration;

        let request_id = RequestId {
            flow_id: proto.flow_id(),
            request_id: proto.request_id(),
        };

        let action = match proto.action().try_into() {
            Ok(action) => action,
            Err(action) => return Err(ParseRequestError {
                request_id: Some(request_id),
                kind: ParseRequestErrorKind::UnknownAction(action),
                error: None,
            }),
        };

        let network_bytes_limit = match proto.network_bytes_limit() {
            0 => None,
            limit => Some(limit),
        };

        let proto_cpu_time_limit = proto.take_cpu_time_limit();
        let cpu_time_limit = match try_from_duration(proto_cpu_time_limit) {
            // TODO(@panhania): We should always require time limit to be set.
            Ok(limit) if limit.is_zero() => None,
            Ok(limit) => Some(limit),
            Err(error) => return Err(ParseRequestError {
                request_id: Some(request_id),
                kind: ParseRequestErrorKind::InvalidCpuTimeLimit,
                error: Some(Box::new(error)),
            }),
        };

        let proto_real_time_limit = proto.take_real_time_limit();
        let real_time_limit = match try_from_duration(proto_real_time_limit) {
            // TODO(@panhania): We should always require time limit to be set.
            Ok(limit) if limit.is_zero() => None,
            Ok(limit) => Some(limit),
            Err(error) => return Err(ParseRequestError {
                request_id: Some(request_id),
                kind: ParseRequestErrorKind::InvalidRealTimeLimit,
                error: Some(Box::new(error)),
            }),
        };

        let filters = proto.take_filters().into_iter()
            .map(|proto| crate::filter::Filter::try_from(proto))
            .collect::<Result<_, crate::filter::ParseError>>()
            .map_err(|error| ParseRequestError {
                request_id: Some(request_id),
                kind: ParseRequestErrorKind::InvalidFilter,
                error: Some(Box::new(error)),
            })?;

        Ok(Request {
            id: request_id,
            action,
            serialized_args: proto.take_args().value,
            network_bytes_limit,
            cpu_time_limit,
            real_time_limit,
            log_level: proto.log_level().into(),
            filters,
        })
    }
}

/// The error type for cases when parsing a request fails.
#[derive(Debug)]
pub struct ParseRequestError {
    /// A unique identifier of the request that we failed to parse.
    request_id: Option<RequestId>,
    /// A corresponding [`ParseRequestErrorKind`] of the error.
    kind: ParseRequestErrorKind,
    /// A more detailed cause of the error.
    error: Option<Box<dyn std::error::Error>>,
}

impl ParseRequestError {

    /// Gets the unique identifier of the request that we failed to parse.
    ///
    /// Note that the identifier might not be available. This can happen because
    /// it was missing in the request or because we failed to deserialize the
    /// Protocol Buffers message with the request.
    pub fn request_id(&self) -> Option<RequestId> {
        self.request_id
    }

    /// Returns the corresponding [`ParseRequestErrorKind`] of this error.
    pub fn kind(&self) -> ParseRequestErrorKind {
        self.kind
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
    /// The action in the request is not known.
    UnknownAction(UnknownAction),
    /// The CPU time limit in the request is invalid.
    InvalidCpuTimeLimit,
    /// The real (wall) time limit in the request is invalid.
    InvalidRealTimeLimit,
    /// A filter in the request is invalid.
    InvalidFilter,
}

impl std::fmt::Display for ParseRequestErrorKind {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use ParseRequestErrorKind::*;

        match self {
            MalformedBytes => write!(fmt, "malformed protobuf message bytes"),
            UnknownAction(action) => write!(fmt, "unknown action: {action}"),
            InvalidCpuTimeLimit => write!(fmt, "invalid CPU time limit"),
            InvalidRealTimeLimit => write!(fmt, "invalid real time limit"),
            InvalidFilter => write!(fmt, "invalid filter"),
        }
    }
}

impl From<ParseRequestErrorKind> for rrg_proto::rrg::status::error::Type {

    fn from(kind: ParseRequestErrorKind) -> rrg_proto::rrg::status::error::Type {
        use ParseRequestErrorKind::*;

        match kind {
            // Note that `MalformedBytes` error indicates that we couldn't parse
            // the request and thus we do not have anything to send back to the
            // server. Therefore, there is no corresponding status error type in
            // the Protocol Buffers enum and we just leave it unset.
            MalformedBytes => Self::UNSET,
            UnknownAction(_) => Self::UNKNOWN_ACTION,
            InvalidCpuTimeLimit => Self::INVALID_CPU_TIME_LIMIT,
            InvalidRealTimeLimit => Self::INVALID_REAL_TIME_LIMIT,
            InvalidFilter => Self::INVALID_FILTER,
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

    type Proto = protobuf::well_known_types::empty::Empty;

    fn from_proto(_: protobuf::well_known_types::empty::Empty) -> Result<(), ParseArgsError> {
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
        use protobuf::Enum as _;

        for action in rrg_proto::rrg::Action::VALUES {
            if *action == rrg_proto::rrg::Action::UNKNOWN {
                continue;
            }

            assert!(Action::try_from(*action).is_ok());
        }
    }

    #[test]
    fn action_try_from_proto_unknown() {
        assert!(Action::try_from(rrg_proto::rrg::Action::UNKNOWN).is_err());
    }
}
