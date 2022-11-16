// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the hostname action.

use crate::session::{self, Session};
use std::ffi::OsString;

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

/// An error type for failures that can occur during the hostname action.
#[derive(Debug)]
enum Error {
    /// Hostname error.
    Hostname(std::io::Error),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            Hostname(ref error) => Some(error),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use Error::*;

        match *self {
            Hostname(ref error) => {
                write!(fmt, "unable to get hostname: {}", error)
            }
        }
    }
}

impl From<Error> for session::Error {
    fn from(error: Error) -> session::Error {
        session::Error::action(error)
    }
}

/// Obtains system hostname (Unix version).
///
/// This function returns `std::io::Error` in case of errors.
#[cfg(target_family = "unix")]
fn get_hostname() -> Result<OsString, std::io::Error> {
    use libc::c_char;
    use std::ffi::CStr;
    use std::io::Error;
    use std::os::unix::prelude::OsStringExt as _;

    let hostname_max_len = unsafe { libc::sysconf(libc::_SC_HOST_NAME_MAX) as libc::size_t };

    let mut hostname_data = vec![0_u8 as c_char; hostname_max_len + 1];
    let hostname_data_ptr = hostname_data.as_mut_ptr();

    let code = unsafe { libc::gethostname(hostname_data_ptr, hostname_max_len) };
    if code != 0 {
        Err(Error::from_raw_os_error(code))
    } else {
        let hostname = unsafe { CStr::from_ptr(hostname_data_ptr).to_bytes().to_vec() };

        Ok(OsString::from_vec(hostname))
    }
}

/// Obtains system hostname (Windows version).
///
/// This function returns `std::io::Error` in case of errors.
#[cfg(target_os = "windows")]
fn get_hostname() -> Result<OsString, std::io::Error> {
    use std::io::Error;
    use std::mem::MaybeUninit;
    use std::os::windows::ffi::OsStringExt as _;
    use std::slice;
    use windows_sys::Win32::System::{
        SystemInformation::{ComputerNamePhysicalDnsHostname, GetComputerNameExW},
        WindowsProgramming::MAX_COMPUTERNAME_LENGTH,
    };

    let mut computer_name_data = MaybeUninit::<[u16; MAX_COMPUTERNAME_LENGTH as usize]>::uninit();
    let mut computer_name_len = MAX_COMPUTERNAME_LENGTH;
    let result = unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            computer_name_data.as_mut_ptr().cast(),
            &mut computer_name_len,
        )
    };
    if result != 1 {
        Err(Error::last_os_error())
    } else {
        let computer_name = unsafe {
            slice::from_raw_parts::<u16>(
                computer_name_data.assume_init().as_ptr(),
                computer_name_len as usize,
            )
        };

        Ok(OsString::from_wide(computer_name))
    }
}

/// Handles requests for the hostname action.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    let hostname = get_hostname().map_err(Error::Hostname)?;

    session.reply(Response { hostname })
}

#[cfg(feature = "test-hostname")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::process::{Command, Stdio};

    #[test]
    fn test_hostname() {
        let mut session = session::FakeSession::new();
        handle(&mut session, ()).unwrap();

        assert_eq!(session.reply_count(), 1);
        let response: &Response = session.reply(0);

        let output = Command::new("hostname")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .ok()
            .unwrap();

        assert!(output.status.success());

        let first_line = output.stdout.lines().next().unwrap();
        let expect = first_line.unwrap();

        assert_eq!(response.hostname.to_string_lossy().to_string(), expect);
    }
}
