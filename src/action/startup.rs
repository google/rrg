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

use std::fmt::{Display, Formatter};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::error;

use crate::metadata::{Metadata};
use crate::session::{self, Session};

#[derive(Debug)]
struct Error {
    boot_time_error: sys_info::Error,
}

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.boot_time_error)
    }
}

impl Display for Error {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "failed to obtain boot time: {}", self.boot_time_error)
    }
}

impl From<Error> for session::Error {

    fn from(error: Error) -> session::Error {
        session::Error::action(error)
    }
}

/// A response type for the startup action.
pub struct Response {
    /// Time of last system boot.
    boot_time: SystemTime,
    /// Metadata about the RRG agent.
    metadata: Metadata,
}

/// Handles requests for the startup action.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    let boot_time = boot_time()?;

    session.send(session::Sink::STARTUP, Response {
        boot_time: boot_time,
        metadata: Metadata::from_cargo(),
    })?;

    Ok(())
}

/// Returns information about the system boot time.
fn boot_time() -> std::result::Result<SystemTime, Error> {
    // TODO: Consider not failing on failures to obtain the boot time. This is
    // really not that critical and sending the rest of the client metadata is
    // more important.
    let timeval = match sys_info::boottime() {
        Ok(timeval) => timeval,
        Err(error) => return Err(Error { boot_time_error: error }),
    };

    let secs = timeval.tv_sec as u64;
    let micros = timeval.tv_usec as u64;

    Ok(UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_micros(micros))
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("StartupInfo");

    type Proto = rrg_proto::StartupInfo;

    fn into_proto(self) -> rrg_proto::StartupInfo {
        let boot_time_micros = match rrg_proto::micros(self.boot_time) {
            Ok(boot_time_micros) => boot_time_micros,
            Err(error) => {
                error!("failed to convert boot time: {}", error);
                0
            }
        };

        rrg_proto::StartupInfo {
            client_info: Some(self.metadata.into()),
            boot_time: Some(boot_time_micros),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_boot_time() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        let response = session.response::<Response>(session::Sink::STARTUP, 0);
        assert!(response.boot_time > std::time::UNIX_EPOCH);
        assert!(response.boot_time < std::time::SystemTime::now());
    }

    #[test]
    fn test_metadata() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        let response = session.response::<Response>(session::Sink::STARTUP, 0);
        assert!(response.metadata.version.as_numeric() > 0);
        assert_eq!(response.metadata.name, "rrg");
    }
}
