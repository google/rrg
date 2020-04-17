// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::error;

pub struct Response {
    boot_time: SystemTime,
    name: String,
    description: String,
    version: Version,
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

pub fn handle(_: ()) -> Result<Response, super::Error> {
    Ok(Response {
        boot_time: boot_time()?,
        name: String::from(env!("CARGO_PKG_NAME")),
        description: String::from(env!("CARGO_PKG_DESCRIPTION")),
        version: Version::from_crate(),
    })
}

fn boot_time() -> Result<SystemTime, sys_info::Error> {
    let timeval = sys_info::boottime()?;

    let secs = timeval.tv_sec as u64;
    let micros = timeval.tv_usec as u64;

    Ok(UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_micros(micros))
}

pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
    pub revision: u8,
}

impl Version {

    fn from_crate() -> Version {
        Version {
            major: env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or(0),
            minor: env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(0),
            patch: env!("CARGO_PKG_VERSION_PATCH").parse().unwrap_or(0),
            revision: env!("CARGO_PKG_VERSION_PRE").parse().unwrap_or(0),
        }
    }

    fn as_numeric(&self) -> u32 {
        let mut result = 0;
        result = 10 * result + self.major as u32;
        result = 10 * result + self.minor as u32;
        result = 10 * result + self.patch as u32;
        result = 10 * result + self.revision as u32;
        result
    }
}
