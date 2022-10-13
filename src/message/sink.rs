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
    sink: Sink,
    /// The item contained within this parcel.
    item: I,
}

impl<I: crate::action::Item> Parcel<I> {

    /// Sink to which the parcel should be delivered to.
    pub fn sink(&self) -> Sink {
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

impl<I: crate::action::Item> Into<rrg_proto::jobs::GrrMessage> for Parcel<I> {

    fn into(self) -> rrg_proto::jobs::GrrMessage {
        use protobuf::Message as _;

        let mut message = rrg_proto::jobs::GrrMessage::new();
        message.set_session_id(String::from(self.sink.id));
        message.set_field_type(rrg_proto::jobs::GrrMessage_Type::MESSAGE);

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
        message.set_args_rdf_name(String::from(I::RDF_NAME));
        message.set_args(serialized_item);

        message
    }
}

/// Handle to a specific sink.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Sink {
    /// An underlying identifier of the sink.
    id: &'static str,
}

impl Sink {
    // TODO(panhania@): Consider removing this method.
    /// Adresses the given `item` to this sink.
    pub fn address<I: crate::action::Item>(&self, item: I) -> Parcel<I> {
        Parcel {
            sink: *self,
            item,
        }
    }
}

/// A handle to the sink expecting startup information.
pub const STARTUP: Sink = Sink { id: "/flows/F:Startup" };

/// A handle to the transfer store sink.
pub const TRANSFER_STORE: Sink = Sink { id: "/flows/F:TransferStore" };
