// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the hostname action.

#[cfg(target_family = "unix")]
use libc::c_char;
use log::error;
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
    Win32::System::SystemInformation::{
        ComputerNamePhysicalDnsHostname, GetComputerNameExW,
    },
};
use crate::session::{self, Session};

/// A response type for the hostname action.
struct Response {
    /// The host name reported by the kernel, or an error if the attemps to
    /// obtain the host name failed.
    hostname: Result<OsString, Error>,
}

impl super::Item for Response {
    const RDF_NAME: &'static str = "DataBlob";

    type Proto = protobuf::well_known_types::StringValue;

    fn into_proto(self) -> Self::Proto {
        let hostname = match self.hostname {
            Ok(hostname) => hostname,
            Err(err) => {
                error!("{}", err);
                OsString::new()
            },
        };

        let mut proto = protobuf::well_known_types::StringValue::new();
        proto.set_value(hostname.to_string_lossy().to_string());

        proto
    }
}

/// Obtains system hostname (Unix version).
///
/// This function returns `std::io::Error` in case of errors.
#[cfg(target_family = "unix")]
fn get_hostname() -> Result<OsString, Error> {
	let size =
        unsafe { libc::sysconf(libc::_SC_HOST_NAME_MAX) as libc::size_t };

    let mut buf = vec![0_u8 as c_char; size + 1];

    let result = unsafe {
        libc::gethostname(buf.as_mut_ptr(), size)
    };

    if result != 0 {
        Err(Error::last_os_error())
    } else {
        buf.push(0);
        let hostname = unsafe {
            OsString::from_vec(CStr::from_ptr(buf.as_ptr()).to_bytes().to_vec())
        };

        Ok(hostname)
    }
}

/// Obtains system hostname (Windows version).
///
/// This function returns `windows::core::Error` in case of errors.
#[cfg(target_os = "windows")]
fn get_hostname() -> Result<OsString, Error> {
    let mut size = 0;
    unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            PWSTR::null(),
            &mut size,
        );
    };

    let mut buf = vec![0_u16; size as usize];
    let result = unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            PWSTR::from_raw(buf.as_mut_ptr()),
            &mut size,
        )
    };

    match result.ok() {
        Ok(()) => {
            unsafe { buf.set_len(size as usize); }

            Ok(OsString::from_wide(&buf))
        },
        Err(err) => Err(err)
    }
}

/// Handles requests for the hostname action.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    session.reply(Response {hostname: get_hostname()})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, ErrorKind};
    use std::process::{Command, Stdio};

    #[test]
    fn test_hostname() {
        let output = match Command::new("hostname")
            .stdout(Stdio::piped())
            .spawn() {
                Ok(child) => child.wait_with_output().ok().unwrap(),
                Err(err) if err.kind() == ErrorKind::NotFound => return,
                Err(err) => panic!("{}", err),
            };

        assert!(output.status.success());

        let first_line = output.stdout.lines().next().unwrap();
        let expect = first_line.unwrap();

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());
        assert_eq!(session.reply_count(), 1);
        let response: &Response = session.reply(0);
        let hostname = response.hostname.as_ref().unwrap();

        assert_eq!(hostname.to_string_lossy().to_string(), expect);
    }
}
