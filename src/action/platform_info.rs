// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

extern crate sys_info;
extern crate libc;
// extern crate sysinfo;

use sys_info::{linux_os_release, os_type, hostname};
use libc::{uname, utsname, c_char};
use std::ffi::CStr;
use std::option::Option;
use crate::session::{self, Session};

use rrg_proto::Uname;

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

pub struct Response {
    platform_information: PlatformInfo,
}

#[inline(always)]
fn convert_raw_string(c_string: &[c_char]) -> String {
    unsafe { 
        String::from(CStr::from_ptr(c_string.as_ptr()).to_string_lossy().into_owned())
    } 
}

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

    type Proto = Uname;

    fn into_proto(self) -> Uname {
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
