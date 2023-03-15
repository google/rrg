// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

// TODO: Hide irrelevant modules.

pub mod action;
pub mod fs;
pub mod io;
pub mod log;
pub mod message;
pub mod args;
pub mod session;

pub mod startup; // TODO(@panhania): Hide this module.

// Consider moving these to a separate submodule.
#[cfg(feature = "action-timeline")]
pub mod chunked;
#[cfg(feature = "action-timeline")]
pub mod gzchunked;

use rrg_macro::warn;

use crate::args::{Args};

/// List of all actions supported by the agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Get metadata about the operating system and the machine.
    GetSystemMetadata,
}

#[derive(Debug)]
pub struct ParseActionError {
    kind: ParseActionErrorKind,
}

impl ParseActionError {

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParseActionErrorKind {
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

pub struct Request {
    // An identifier of the flow issuing the request.
    flow_id: u64,
    // A server-issued identifier of the request (unique within the flow).
    request_id: u64,
    // An action to invoke.
    action: Action,
    // Serialized protobuf message with arguments to invoke the action with.
    serialized_args: Vec<u8>,
}

impl Request {

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
            flow_id: proto.get_flow_id(),
            request_id: proto.get_request_id(),
            action: proto.get_action().try_into()?,
            serialized_args: proto.take_args().take_value(),
        })
    }
}

#[derive(Debug)]
pub struct ParseRequestError {
    kind: ParseRequestErrorKind,
    error: Option<Box<dyn std::error::Error>>,
}

impl ParseRequestError {

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParseRequestErrorKind {
    MalformedBytes,
    // TODO(@panhania): Add support for missing `flow_id`, `request_id` and
    // `action` fields.
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

pub trait Input {
    type Proto: protobuf::Message;

    /// Convert a Protocol Buffers message into an idiomatic Rust type.
    fn from_proto(proto: Self::Proto) -> Self;
}

pub trait Output {
    type Proto: protobuf::Message;

    /// Converts the output into a Protocol Buffers message.
    fn into_proto(self) -> Self::Proto;
}

pub enum Sink {
    Startup,
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

pub struct Parcel<O: Output> {
    /// A sink to deliver the parcel to.
    sink: Sink,
    /// The actual content of the parcel.
    payload: O,
}

impl<O: Output> Parcel<O> {

    pub fn send_unaccounted(self) -> Result<(), fleetspeak::WriteError> {
        use protobuf::Message as _;

        let data = rrg_proto::v2::rrg::Parcel::from(self).write_to_bytes()
            // This should only fail in case we are out of memory, which we are
            // almost certainly not (and if we are, we have bigger issue).
            .unwrap();

        fleetspeak::send(fleetspeak::Message {
            service: String::from("GRR"),
            kind: Some(String::from("rrg-parcel")),
            data,
        })
    }
}

impl<O: Output> From<Parcel<O>> for rrg_proto::v2::rrg::Parcel {

    fn from(parcel: Parcel<O>) -> rrg_proto::v2::rrg::Parcel {
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

/// Initializes the RRG subsystems.
///
/// This function should be called only once (at the very beginning of the
/// process lifetime).
pub fn init(args: &Args) {
    log::init(args)
}

/// Enters the agent's main loop and waits for messages.
///
/// It will poll for messages from the GRR server and should consume very few
/// resources when idling. Once it picks a message, it dispatches it to an
/// appropriate action handler (which should take care of sending heartbeat
/// signals if expected to be long-running) and goes back to idling when action
/// execution is finished.
///
/// This function never terminates and panics only if something went very wrong
/// (e.g. the Fleetspeak connection has been broken). All non-critical errors
/// are going to be handled carefully, notifying the server about the failure if
/// appropriate.
pub fn listen(args: &Args) {
    loop {
        let request = match crate::message::Request::receive(args.heartbeat_rate) {
            Ok(request) => request,
            Err(error) => {
                rrg_macro::error!("failed to obtain a request: {}", error);
                continue
            }
        };

        session::FleetspeakSession::handle(request);
    }
}

/// Sends a system message with startup information to the GRR server.
///
/// This function should be called only once at the beginning of RRG's process
/// lifetime. It communicates to the GRR server that the agent has been started
/// and sends some basic information like agent metadata.
///
/// # Errors
///
/// In case we fail to send startup information, this function will report an
/// error. Note that by "send" we just mean pushing the message to Fleetspeak,
/// whether Fleetspeak manages to reach the GRR server with it is a separate
/// issue. Failure to push the message to Fleetspeak means that the pipe used
/// for communication is most likely broken and we should quit.
pub fn startup() -> Result<(), fleetspeak::WriteError> {
    startup::startup()
}
