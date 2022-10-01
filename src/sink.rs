// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Definitions and utilities for working with sinks.
//!
//! Sinks ("well-known flows" in terms of GRR nomenclature) are ever-existing
//! sessions on the GRR server that listen for various kinds of data. They are
//! a way to break away from the usual request-response workflow.
//!
//! For example, sinks can be used to notify the server about agent startup
//! (which is clearly not a response to a particular request) or to transfer
//! file blobs to a specialized storage.

use crate::action;
use crate::session;

/// Data sent to a server not belonging to a particular action call.
///
/// Sometimes the agent should send data to the server that is not connected
/// with a particular flow request. An example can be the agent startup data
/// sent to the server regardless of whether there was a request for it or not.
/// Another example can be file contents that are delivered to the server not
/// as part of the flow results but go to a separate store that has logic for
/// deduplicating data that we already collected in the past.
pub trait Parcel {
    /// Low-level Protocol Buffers type representing the parcel data.
    type Proto: protobuf::Message;

    /// A name of the corresponding RDF class in GRR.
    const RDF_NAME: &'static str;

    /// Converts the parcel to its low-level representation.
    fn into_proto(self) -> Self::Proto;
}

/// A parcel addressed to a particular server-side sink.
pub struct AddressedParcel<P: Parcel> {
    /// Destination of the parcel.
    dest: Sink,
    /// Actual parcel.
    parcel: P,
}

impl<P: Parcel> std::convert::TryInto<rrg_proto::jobs::GrrMessage> for AddressedParcel<P> {

    type Error = protobuf::ProtobufError;

    fn try_into(self) -> Result<rrg_proto::jobs::GrrMessage, protobuf::ProtobufError> {
        let mut message = rrg_proto::jobs::GrrMessage::new();
        message.set_session_id(String::from(self.dest.id));
        message.set_field_type(rrg_proto::jobs::GrrMessage_Type::MESSAGE);
        message.set_args_rdf_name(String::from(P::RDF_NAME));

        let proto = self.parcel.into_proto();
        message.set_args(protobuf::Message::write_to_bytes(&proto)?);

        Ok(message)
    }
}

/// Handle to a specific sink.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Sink {
    /// An underlying identifier of the sink.
    id: &'static str,
}

impl Sink {

    // TODO: Refactor sinks to use custom `Message` type rather than `Response`
    // and make response always have `request_id` and `response_id` fields.

    /// Adresses a given `parcel` to this sink.
    pub fn address<P: Parcel>(&self, parcel: P) -> AddressedParcel<P> {
        AddressedParcel {
            dest: *self,
            parcel,
        }
    }

    // TODO: Remove the function below once only parcels are used.
    /// Wraps an action response to a sink-specific session response.
    pub fn wrap<R>(&self, response: R) -> session::Response<R>
    where
        R: action::Response,
    {
        session::Response {
            session_id: String::from(self.id),
            request_id: None,
            response_id: None,
            data: response,
        }
    }
}

/// A handle to the sink expecting startup information.
pub const STARTUP: Sink = Sink { id: "/flows/F:Startup" };

/// A handle to the transfer store sink.
pub const TRANSFER_STORE: Sink = Sink { id: "/flows/F:TransferStore" };
