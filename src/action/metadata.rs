// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the metadata action.
//!
//! The metadata action collects basic information about the client (e.g. its
//! version number and its name).

use crate::metadata::{Metadata};
use crate::session::{self, Session};

/// A response type for the metadata action.
pub struct Response {
    /// Metadata about the RRG agent.
    metadata: Metadata,
}

/// Handles requests for the metadata action.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    session.reply(Response {
        metadata: Metadata::from_cargo(),
    })?;

    Ok(())
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("ClientInformation");

    type Proto = rrg_proto::ClientInformation;

    fn into_proto(self) -> rrg_proto::ClientInformation {
        self.metadata.into()
    }
}
