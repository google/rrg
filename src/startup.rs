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

use std::time::{SystemTime, UNIX_EPOCH};

use log::error;

use crate::message;
use crate::metadata::{Metadata};
use crate::session;
use crate::sink::Sink;

/// A response type for the startup action.
pub struct Response {
    /// Time of last system boot.
    boot_time: SystemTime,
    /// Metadata about the RRG agent.
    metadata: Metadata,
}

impl Response {

    /// Build a response object with startup information filled-in.
    fn build() -> Response {
        Response {
            boot_time: boot_time(),
            metadata: Metadata::from_cargo(),
        }
    }
}

/// Sends startup information to the server.
pub fn send() -> session::Result<()> {
    use std::convert::TryInto as _;

    let response = Sink::STARTUP.wrap(Response::build());
    message::send(response.try_into()?);

    Ok(())
}

/// Returns information about the system boot time.
fn boot_time() -> SystemTime {
    // TODO: Make `sysinfo` or another crate not an optional dependency.

    #[cfg(feature = "dep:sysinfo")]
    {
        use sysinfo::{System, SystemExt};
        let boot_time_secs = System::new().get_boot_time();

        UNIX_EPOCH + Duration::from_secs(boot_time_secs)
    }

    #[cfg(not(feature = "dep:sysinfo"))]
    {
        UNIX_EPOCH
    }
}

// TODO: Using `action::Response` type feels awkward, try to have more genreic
// type.
impl crate::action::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("StartupInfo");

    type Proto = rrg_proto::jobs::StartupInfo;

    fn into_proto(self) -> rrg_proto::jobs::StartupInfo {

        let mut proto = rrg_proto::jobs::StartupInfo::new();
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

    // TODO: Delete this once `sysinfo` (or a replacement) is made a mandatory
    // dependency.
    #[cfg(feature = "dep:sysinfo")]
    #[test]
    fn test_boot_time() {
        let response = Response::build();
        assert!(response.boot_time > std::time::UNIX_EPOCH);
        assert!(response.boot_time < std::time::SystemTime::now());
    }

    #[test]
    fn test_metadata() {
        let response = Response::build();
        assert!(response.metadata.version.as_numeric() > 0);
        assert_eq!(response.metadata.name, "rrg");
    }
}
