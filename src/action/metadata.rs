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

impl super::Item for Response {

    const RDF_NAME: &'static str = "ClientInformation";

    type Proto = rrg_proto::jobs::ClientInformation;

    fn into_proto(self) -> rrg_proto::jobs::ClientInformation {
        self.metadata.into()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_name() {
        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);

        let metadata = &session.reply::<Response>(0).metadata;
        assert_eq!(metadata.name, "rrg");
    }

    #[test]
    fn test_description() {
        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);

        let metadata = &session.reply::<Response>(0).metadata;
        assert!(!metadata.description.is_empty());
    }

    #[test]
    fn test_version() {
        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);

        let metadata = &session.reply::<Response>(0).metadata;
        assert!(metadata.version.as_numeric() > 0);
    }
}
