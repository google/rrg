// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the startup action.
//!
//! The startup action collects basic information about the system (e.g. its
//! boot time) and metadata about the agent (e.g. it's name and version). It is
//! special in a sense that generally it should be not invoked by flows, but be
//! called explicitly during agent startup.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::error;

use crate::metadata::{Metadata};
use crate::session::{self, Session};

/// A response type for the startup action.
pub struct Response {
    /// Time of last system boot.
    boot_time: SystemTime,
    /// Metadata about the RRG agent.
    metadata: Metadata,
}

/// Handles requests for the startup action.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    session.send(session::Sink::STARTUP, Response {
        boot_time: boot_time(),
        metadata: Metadata::from_cargo(),
    })?;

    Ok(())
}

/// Returns information about the system boot time.
fn boot_time() -> SystemTime {
    use sysinfo::{System, SystemExt};
    let boot_time_secs = System::new().get_boot_time();

    UNIX_EPOCH + Duration::from_secs(boot_time_secs)
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("StartupInfo");

    type Proto = rrg_proto::protobuf::jobs::StartupInfo;

    fn into_proto(self) -> rrg_proto::protobuf::jobs::StartupInfo {

        let mut proto = rrg_proto::protobuf::jobs::StartupInfo::new();
        proto.set_client_info(self.metadata.into());

        match rrg_proto::micros(self.boot_time) {
            Ok(boot_time_micros) => {
                proto.set_boot_time(boot_time_micros);
            }
            Err(error) => {
                error!("failed to convert boot time: {}", error);
            }
        };

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_boot_time() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 0);
        assert_eq!(session.response_count(session::Sink::STARTUP), 1);

        let response = session.response::<Response>(session::Sink::STARTUP, 0);
        assert!(response.boot_time > std::time::UNIX_EPOCH);
        assert!(response.boot_time < std::time::SystemTime::now());
    }

    #[test]
    fn test_metadata() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 0);
        assert_eq!(session.response_count(session::Sink::STARTUP), 1);

        let response = session.response::<Response>(session::Sink::STARTUP, 0);
        assert!(response.metadata.version.as_numeric() > 0);
        assert_eq!(response.metadata.name, "rrg");
    }
}
