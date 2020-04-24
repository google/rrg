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
    /// Name of the GRR agent.
    name: String,
    /// Description of the GRR agent.
    description: String,
    /// Version of the GRR agent.
    version: Version,
}

/// Handles requests for the startup action.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    let boot_time = boot_time()?;

    session.reply(Response {
        boot_time: boot_time,
        name: String::from(env!("CARGO_PKG_NAME")),
        description: String::from(env!("CARGO_PKG_DESCRIPTION")),
        version: Version::from_crate(),
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

/// A type for representing version metadata.
struct Version {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
    pub revision: u8,
}

impl Version {

    /// Constructs version metadata from Crate information.
    ///
    /// This function assumes that are relevant crate information is correctly
    /// specified in the `Cargo.toml` file.
    fn from_crate() -> Version {
        Version {
            major: env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or(0),
            minor: env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(0),
            patch: env!("CARGO_PKG_VERSION_PATCH").parse().unwrap_or(0),
            revision: env!("CARGO_PKG_VERSION_PRE").parse().unwrap_or(0),
        }
    }

    /// Returns a numeric representation of version metadata.
    ///
    /// This function assumes that all version components are smaller than 10.
    /// In other cases, the output is undefined (but the function call itself
    /// does not panic).
    ///
    /// # Examples
    ///
    /// ```
    /// use rrg::action::startup::Version;
    ///
    /// let version = Version {
    ///     major: 1,
    ///     minor: 2,
    ///     patch: 3,
    ///     revision: 4,
    /// };
    ///
    /// assert_eq!(version.as_numeric(), 1234)
    /// ```
    fn as_numeric(&self) -> u32 {
        let mut result = 0;
        result = 10 * result + self.major as u32;
        result = 10 * result + self.minor as u32;
        result = 10 * result + self.patch as u32;
        result = 10 * result + self.revision as u32;
        result
    }
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
            client_info: Some(rrg_proto::ClientInformation {
                client_name: Some(self.name),
                client_version: Some(self.version.as_numeric()),
                client_description: Some(self.description),
                ..Default::default()
            }),
            boot_time: Some(boot_time_micros),
        }
    }
}
