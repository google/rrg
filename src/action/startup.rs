// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::convert::{TryInto};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::error;

pub struct Request {
}

impl super::Request for Request {

    type Proto = ();

    fn from_proto(_: ()) -> Request {
        Request {}
    }
}

pub struct Response {
    boot_time: SystemTime,
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("StartupInfo");

    type Proto = rrg_proto::StartupInfo;

    fn into_proto(self) -> rrg_proto::StartupInfo {
        let boot_time_micros = self.boot_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::new(0, 0))
            .as_micros();

        let boot_time_micros = match boot_time_micros.try_into() {
            Ok(boot_time_micros) => boot_time_micros,
            Err(error) => {
                error!("failed to convert boot time: {}", error);
                0
            }
        };

        rrg_proto::StartupInfo {
            client_info: None,
            boot_time: Some(boot_time_micros),
        }
    }
}

pub fn handle(_: Request) -> Result<Response, super::Error> {
    Ok(Response {
        boot_time: boot_time()?,
    })
}

fn boot_time() -> Result<SystemTime, sys_info::Error> {
    let timeval = sys_info::boottime()?;

    let secs = timeval.tv_sec as u64;
    let micros = timeval.tv_usec as u64;

    Ok(UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_micros(micros))
}
