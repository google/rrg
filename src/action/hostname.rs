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
#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;
#[cfg(target_os = "windows")]
use windows::{
    Win32::System::SystemInformation::{
        ComputerNamePhysicalDnsHostname, GetComputerNameExW,
    },
    core::PWSTR
};
use crate::session::{self, Session};

/// A response type for the hostname action.
struct Response {
    /// The host name reported by the kernel, or `None` if the attemps to
    /// obtain the host name failed.
    hostname: Option<String>,
}

impl super::Item for Response {
    const RDF_NAME: &'static str = "DataBlob";

    type Proto = protobuf::well_known_types::StringValue;

    fn into_proto(self) -> Self::Proto {
        let hostname = match self.hostname {
            Some(hostname) => hostname,
            None => {
                error!("cannot get hostname, all methods failed");
                String::new()
            },
        };

        let mut proto = protobuf::well_known_types::StringValue::new();
        proto.set_value(hostname);

        proto
    }
}

/// Obtains system hostname (Unix version).
///
/// This function returns `None` in case of errors.
#[cfg(target_family = "unix")]
fn get_hostname() -> Option<String> {
	let size =
        unsafe { libc::sysconf(libc::_SC_HOST_NAME_MAX) as libc::size_t };

    let mut buf = vec![0 as c_char; size];

    let p = buf.as_mut_ptr();
    let result = unsafe {
        libc::gethostname(p, size)
    };

    if result != 0 {
        None
    } else {
        let hostname = 
            unsafe { String::from_utf8_lossy(CStr::from_ptr(p).to_bytes()).into() };

        Some(hostname)
    }
}

/// Obtains system hostname (Windows version).
///
/// This function returns `None` in case of errors.
#[cfg(target_os = "windows")]
fn get_hostname() -> Option<String> {
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

    if result.as_bool() {
        unsafe { buf.set_len(size as usize); }

        Some(OsString::from_wide(&buf).to_string_lossy().to_string())
    } else {
        None
    }
}

/// Handles requests for the hostname action.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    session.reply(Response {hostname: get_hostname()})?;
    Ok(())
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
            Err(err) => {
                if let ErrorKind::NotFound = err.kind() {
                    return
                }

                panic!("{}", err);
            }, 
        };

        assert!(output.status.success());

        let first_line = output.stdout.lines().next().unwrap();
        let expect = first_line.unwrap();

        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());
        assert_eq!(session.reply_count(), 1);
        let response: &Response = session.reply(0);
        let hostname = response.hostname.clone().unwrap();

        assert_eq!(hostname, expect);
    }
}
