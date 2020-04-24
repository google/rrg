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

/// A handle to the sink expecting startup information.
pub const STARTUP: Sink = Sink { id: "/flows/F:Startup" };

/// Handle to a specific sink.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Sink {
    /// An underlying identifier of the sink.
    id: &'static str,
}

impl Sink {

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
