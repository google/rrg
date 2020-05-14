// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

extern crate sys_info;

/// Using for `uname` syscall.
extern crate libc;

use sys_info::{linux_os_release, os_type, hostname};
use libc::{uname, utsname, c_char};
use std::ffi::CStr;
use std::option::Option;
use crate::session::{self, Session};

use rrg_proto::Uname;

/// Structure that contains information about client platform.
#[derive(Default)]
pub struct PlatformInfo {
    system: Option<String>,
    release_name: Option<String>,
    version_id: Option<String>,
    machine: Option<String>,
    kernel_release: Option<String>,
    fqdn: Option<String>,
    architecture: Option<String>,
    node: Option<String>
}

/// A Response type for `GetPlatformInfo` action
pub struct Response {
    /// Client platform information
    platform_information: PlatformInfo,
}

/// Funcion that converts raw C-strings into `String` type
#[inline(always)]
fn convert_raw_string(c_string: &[c_char]) -> String {
    unsafe { 
        String::from(CStr::from_ptr(c_string.as_ptr()).to_string_lossy().into_owned())
    } 
}

/// Handles requests for `GetPlatformInfo` action.
/// Currently works fine only for Linux OS.
pub fn handle<S: Session>(session:&mut S, _: ()) -> session::Result<()> {
    let os_type = os_type().expect("Can't get os type");
    match os_type.as_str() {
        "Linux" => {
            let linux_release_info = linux_os_release()
                                        .expect("Can't get info about linux system");
            let mut system_info: utsname;

            unsafe {
                system_info = std::mem::zeroed();
                uname(&mut system_info);
            }

            session.reply(Response {
                platform_information: PlatformInfo {
                    system: Some(os_type.to_string()),
                    release_name: linux_release_info.name,
                    version_id: linux_release_info.version_id,
                    machine: Some(convert_raw_string(&system_info.machine)),
                    kernel_release: Some(convert_raw_string(&system_info.release)),
                    fqdn: hostname().ok(),
                    architecture: Some(convert_raw_string(&system_info.machine)),
                    node: Some(convert_raw_string(&system_info.nodename))
                },
            })?;
        },

        _ => {
            session.reply(Response {
                platform_information: PlatformInfo {
                    system: Some(os_type.to_string()),
                    fqdn: hostname().ok(),
                    ..Default::default() // TODO: Add other systems
                }
            })?;
        }
    }

    Ok(())
}

impl super::Response for Response {
    const RDF_NAME: Option<&'static str> = Some("Uname");

    type Proto = rrg_proto::Uname;

    /// Convert PlatformInformation struct to protobuf message Uname
    fn into_proto(self) -> rrg_proto::Uname {
        Uname {
            system: self.platform_information.system.clone(),
            release: self.platform_information.release_name.clone(),
            version: self.platform_information.version_id,
            machine: self.platform_information.machine,
            kernel: self.platform_information.kernel_release,
            fqdn: self.platform_information.fqdn,
            architecture: self.platform_information.architecture.clone(),
            node: self.platform_information.node,
            pep425tag: Some(
                format!("{}_{}_{}", 
                    self.platform_information.system.unwrap_or(String::from("")), 
                    self.platform_information.release_name.unwrap_or(String::from("")), 
                    self.platform_information.architecture.unwrap_or(String::from(""))
            )),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_system() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0).platform_information;

        assert_eq!(platform_info.system.as_ref().unwrap(), sys_info::os_type().as_ref().unwrap());
    }

    #[test]
    fn test_linux_release() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0).platform_information;

        if sys_info::os_type().unwrap() == "Linux" {
            assert_eq!(platform_info.release_name.as_ref().unwrap(), sys_info::linux_os_release().unwrap().name.as_ref().unwrap());
        }
    }

    #[test]
    fn test_linux_version() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0).platform_information;

        if sys_info::os_type().unwrap() == "Linux" {
            assert_eq!(platform_info.version_id.as_ref().unwrap(), sys_info::linux_os_release().unwrap().version_id.as_ref().unwrap());
        }
    }

    #[test]
    fn test_linux_machine() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0).platform_information;

        if sys_info::os_type().unwrap() == "Linux" {
            let mut system_info: utsname;

            unsafe {
                system_info = std::mem::zeroed();
                uname(&mut system_info);
            }
            assert_eq!(platform_info.machine.as_ref().unwrap(), &convert_raw_string(&system_info.machine));
        }
    }

    #[test]
    fn test_linux_kernel_release() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0).platform_information;

        if sys_info::os_type().unwrap() == "Linux" {
            let mut system_info: utsname;

            unsafe {
                system_info = std::mem::zeroed();
                uname(&mut system_info);
            }
            assert_eq!(platform_info.kernel_release.as_ref().unwrap(), &convert_raw_string(&system_info.release));
        }
    }

    #[test]
    fn test_linux_architecture() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0).platform_information;

        if sys_info::os_type().unwrap() == "Linux" {
            let mut system_info: utsname;

            unsafe {
                system_info = std::mem::zeroed();
                uname(&mut system_info);
            }
            assert_eq!(platform_info.architecture.as_ref().unwrap(), &convert_raw_string(&system_info.machine));
        }
    }

    #[test]
    fn test_linux_node() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);
        let platform_info = &session.reply::<Response>(0).platform_information;

        if sys_info::os_type().unwrap() == "Linux" {
            let mut system_info: utsname;

            unsafe {
                system_info = std::mem::zeroed();
                uname(&mut system_info);
            }
            assert_eq!(platform_info.node.as_ref().unwrap(), &convert_raw_string(&system_info.nodename));
        }
    }
}
