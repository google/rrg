// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Handle to a specific sink.
///
/// Sinks ("well-known flows" in terms of GRR nomenclature) are ever-existing
/// sessions on the GRR server that listen for various kinds of data. They are
/// a way to break away from the usual request-response workflow.
///
/// For example, sinks can be used to notify the server about agent startup
/// (which is clearly not a response to a particular request) or to transfer
/// file blobs to a specialized storage.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Sink {
    /// An underlying identifier of the sink.
    id: &'static str,
}

impl Sink {
    /// A handle to the sink expecting startup information.
    pub const STARTUP: Sink = Sink { id: "/flows/F:Startup" };

    /// A handle to the transfer store sink.
    pub const TRANSFER_STORE: Sink = Sink { id: "/flows/F:TransferStore" };

    /// Gets the sink's unique identifier.
    pub fn id(&self) -> &'static str {
        self.id
    }
}
