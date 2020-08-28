// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use sys_info::{linux_os_release, os_type, hostname};
use libc::c_char;
use crate::session::{self, Session};
use std::ffi::CStr;
use std::option::Option;
use std::fmt::{Display, Formatter};

use rrg_proto::Uname;

#[derive(Debug)]
enum Error {
    CannotGetOSType(sys_info::Error),
    CannotGetLinuxRelease(sys_info::Error)
}

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            CannotGetOSType(ref error) => Some(error),
            CannotGetLinuxRelease(ref error) => Some(error)
        }
    }
}

impl Display for Error {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        use Error::*;

        match *self {
            CannotGetOSType(ref error) => {
                write!(fmt, "can't get OS type error: {}", error)
            },
            CannotGetLinuxRelease(ref error) => {
                write!(fmt, "can't get Linux release info error: {}", error)
            }
        }
    }
}

impl From<Error> for session::Error {

    fn from(error: Error) -> session::Error {
        session::Error::action(error)
    }
}

/// A response type for `GetPlatformInfo` action.
/// Gives client platform information.
#[derive(Default)]
pub struct Response {

    system: Option<String>,
    release_name: Option<String>,
    version_id: Option<String>,
    machine: Option<String>,
    kernel_release: Option<String>,
    fqdn: Option<String>,
    architecture: Option<String>,
    node: Option<String>
}

/// Function that converts raw C-strings into `String` type
fn convert_raw_string(c_string: &[c_char]) -> String {
    unsafe { 
        String::from(CStr::from_ptr(c_string.as_ptr()).to_string_lossy().into_owned())
    } 
}

#[cfg(target_os = "linux")]
use libc::{uname, utsname};

/// Function that returns `Response` for Linux operating systems
fn get_linux_response<S: Session>(session: &mut S, os_type: String) -> session::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let linux_release_info = linux_os_release()
                .map_err(Error::CannotGetLinuxRelease)?;

        let mut system_info: utsname;

        unsafe {
            system_info = std::mem::zeroed();
            uname(&mut system_info);
        }

        session.reply(Response {
            system: Some(os_type),
            release_name: linux_release_info.name,
            version_id: linux_release_info.version_id,
            machine: Some(convert_raw_string(&system_info.machine)),
            kernel_release: Some(convert_raw_string(&system_info.release)),
            fqdn: hostname().ok(),
            architecture: Some(convert_raw_string(&system_info.machine)),
            node: Some(convert_raw_string(&system_info.nodename))
        })?;
    }
    Ok(())
}

/// Handles requests for `GetPlatformInfo` action.
pub fn handle<S: Session>(session:&mut S, _: ()) -> session::Result<()> {
    let os_type = os_type().map_err(Error::CannotGetOSType)?;
    if cfg!(target_os = "linux") {
        get_linux_response(session, os_type)?;
    } else {
        session.reply(Response {
                system: Some(os_type),
                fqdn: hostname().ok(),
                ..Default::default() // TODO: Add other systems
            })?;
    }

    Ok(())
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("Uname");

    type Proto = rrg_proto::Uname;

    /// Convert `Response` struct to protobuf message `Uname`.
    fn into_proto(self) -> rrg_proto::Uname {
        let system = self.system.unwrap_or(String::from("None"));
        let release_name = self.release_name.unwrap_or(String::from("None"));
        let architecture = self.architecture.unwrap_or(String::from("None"));
        let pep425tag = Some(
            format!("{}_{}_{}", 
                system, 
                release_name, 
                architecture
        ));
        Uname {
            system: Some(system),
            release: Some(release_name),
            version: self.version_id,
            machine: self.machine,
            kernel: self.kernel_release,
            fqdn: self.fqdn,
            architecture: Some(architecture),
            node: self.node,
            pep425tag: pep425tag,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    // #[test]
    // fn test_system() {
    //     let mut session = session::test::Fake::new();
    //     assert!(handle(&mut session, ()).is_ok());

    //     assert_eq!(session.reply_count(), 1);
    //     let platform_info = &session.reply::<Response>(0);

    //     assert!(platform_info.system.is_some());
    // }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_system_linux() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());
    
        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0);

        assert_eq!(platform_info.system.as_ref().unwrap(), "Linux");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_system_windows() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());
    
        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0);
    
        assert_eq!(platform_info.system.as_ref().unwrap(), "Windows");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_release() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0);
        assert!(platform_info.release_name.is_some());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_version() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0);
        assert!(platform_info.version_id.is_some());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_machine() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0);
        assert!(platform_info.machine.is_some());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_kernel_release() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0);
        assert!(platform_info.kernel_release.is_some());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_architecture() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0);
        assert!(platform_info.architecture.is_some());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_node() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0);
        assert!(platform_info.node.is_some());
    }
}
