// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the hostname action.

use crate::session::{self, Session};
#[cfg(target_family = "unix")]
use libc::c_char;
#[cfg(target_family = "unix")]
use std::ffi::CStr;
use std::ffi::OsString;
#[cfg(target_family = "unix")]
use std::io::Error;
#[cfg(target_family = "unix")]
use std::os::unix::prelude::OsStringExt as _;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt as _;
#[cfg(target_os = "windows")]
use windows::{
    core::{Error, PWSTR},
    Win32::System::SystemInformation::{ComputerNamePhysicalDnsHostname, GetComputerNameExW},
};

/// A response type for the hostname action.
struct Response {
    /// The host name reported by the kernel.
    hostname: OsString,
}

impl super::Item for Response {
    const RDF_NAME: &'static str = "DataBlob";

    type Proto = protobuf::well_known_types::StringValue;

    fn into_proto(self) -> Self::Proto {
        let mut proto = protobuf::well_known_types::StringValue::new();
        proto.set_value(self.hostname.to_string_lossy().to_string());

        proto
    }
}

/// Obtains system hostname (Unix version).
///
/// This function returns `std::io::Error` in case of errors.
#[cfg(target_family = "unix")]
fn get_hostname() -> Result<OsString, Error> {
    let hostname_max_size = unsafe { libc::sysconf(libc::_SC_HOST_NAME_MAX) as libc::size_t };

    let mut hostname = vec![0_u8 as c_char; hostname_max_size + 1];

    let result = unsafe { libc::gethostname(hostname.as_mut_ptr(), hostname_max_size) };

    if result != 0 {
        Err(Error::last_os_error())
    } else {
        let hostname =
            unsafe { OsString::from_vec(CStr::from_ptr(hostname.as_ptr()).to_bytes().to_vec()) };

        Ok(hostname)
    }
}

/// Obtains system hostname (Windows version).
///
/// This function returns `windows::core::Error` in case of errors.
#[cfg(target_os = "windows")]
fn get_hostname() -> Result<OsString, Error> {
    let mut computer_name_size = 0;
    unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            PWSTR::null(),
            &mut computer_name_size,
        );
    };

    let mut computer_name = vec![0_u16; computer_name_size as usize];
    unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            PWSTR::from_raw(computer_name.as_mut_ptr()),
            &mut computer_name_size,
        )
    }
    .ok()?;

    unsafe {
        computer_name.set_len(computer_name_size as usize);
    }

    Ok(OsString::from_wide(&computer_name))
}

/// Handles requests for the hostname action.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    session.reply(Response {
        hostname: get_hostname()?,
    })
}

#[cfg(feature = "test-hostname")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, ErrorKind};
    use std::process::{Command, Stdio};

    #[test]
    fn test_hostname() {
        let mut session = session::FakeSession::new();

        if let Err(err) = handle(&mut session, ()) {
            panic!("{:?}", err);
        };

        assert_eq!(session.reply_count(), 1);
        let response: &Response = session.reply(0);
        let hostname = response.hostname.as_ref().unwrap();

        let output = match Command::new("hostname").stdout(Stdio::piped()).spawn() {
            Ok(child) => child.wait_with_output().ok().unwrap(),
            Err(err) if err.kind() == ErrorKind::NotFound => return,
            Err(err) => panic!("{}", err),
        };

        assert!(output.status.success());

        let first_line = output.stdout.lines().next().unwrap();
        let expect = first_line.unwrap();

        assert_eq!(hostname.to_string_lossy().to_string(), expect);
    }
}
