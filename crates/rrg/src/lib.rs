// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

// TODO: Hide irrelevant modules.

pub mod action;
pub mod fs;
pub mod io;
pub mod log;
pub mod args;
pub mod session;

mod request;
mod response;

pub mod startup; // TODO(@panhania): Hide this module.

// Consider moving these to a separate submodule.
#[cfg(feature = "action-timeline")]
pub mod chunked;
#[cfg(feature = "action-timeline")]
pub mod gzchunked;

use crate::args::{Args};

pub use request::{Action, Request, RequestId};
pub use response::{Reply, ResponseBuilder, ResponseId};

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
pub struct Parcel<I: crate::action::Item> {
    /// A sink to deliver the parcel to.
    sink: Sink,
    /// The actual content of the parcel.
    payload: I,
}

impl<I: crate::action::Item> Parcel<I> {
    /// Creates a new parcel from the given `item` addressed to `sink`.
    pub fn new(sink: Sink, item: I) -> Parcel<I> {
        Parcel {
            sink,
            payload: item,
        }
    }
}

impl<I: crate::action::Item> Parcel<I> {

    /// Sends the parcel message through Fleetspeak to the GRR server.
    ///
    /// This function consumes the parcel to ensure that it is not sent twice.
    ///
    /// Note that this function should generally not be used if running as part
    /// of some [session], otherwise network usage might not be correctly
    /// accounted for. Prefer to use [`Session::send`] for such cases.
    ///
    /// [session]: crate::session::Session
    /// [`Session::send`]: crate::session::Session::send
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

impl<I: crate::action::Item> From<Parcel<I>> for rrg_proto::v2::rrg::Parcel {

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
        let request = match Request::receive(args.heartbeat_rate) {
            Ok(request) => request,
            Err(error) => {
                rrg_macro::error!("failed to receive a request: {}", error);
                continue
            }
        };

        session::FleetspeakSession::dispatch(request);
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
