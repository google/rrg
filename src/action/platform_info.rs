// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the platform info action.

use crate::action::insttime::get_install_time;
#[cfg(target_os = "windows")]
use crate::fs::windows::dll_module_fileinfo;
use crate::session::{self, Session};
#[cfg(target_os = "macos")]
use cocoa::{
    appkit::*,
    base::nil,
    foundation::{NSInteger, NSProcessInfo},
};
use log::error;
#[cfg(target_os = "macos")]
use objc::{msg_send, sel, sel_impl};
use std::env::consts::ARCH;
#[cfg(target_family = "unix")]
use std::ffi::CStr;
use std::ffi::OsString;
#[cfg(target_family = "unix")]
use std::io::Error;
#[cfg(target_family = "unix")]
use std::mem;
#[cfg(target_family = "unix")]
use std::os::unix::prelude::OsStringExt as _;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt as _;
#[cfg(target_family = "unix")]
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(target_os = "windows")]
use windows::{
    core::{Error, PWSTR},
    w,
    Win32::System::{
        Diagnostics::Debug::{
            PROCESSOR_ARCHITECTURE, PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_ARM,
            PROCESSOR_ARCHITECTURE_IA64, PROCESSOR_ARCHITECTURE_INTEL,
        },
        SystemInformation::{
            ComputerNamePhysicalDnsFullyQualified, ComputerNamePhysicalDnsHostname,
            GetComputerNameExW, GetNativeSystemInfo, SYSTEM_INFO,
        },
    },
};

#[cfg(target_os = "linux")]
#[link(name = "libc_version")]
extern "C" {
    fn libc_version() -> *const libc::c_char;
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
#[repr(C)]
struct NSOperatingSystemVersion {
    major_version: NSInteger,
    minor_version: NSInteger,
    patch_version: NSInteger,
}

/// A response type for the platform information action.
struct Response {
    /// The platform information.
    platform_info: PlatformInfo,
}

/// The platform information.
#[derive(Clone, Debug)]
struct PlatformInfo {
    /// The system platform (Windows|Darwin|Linux).
    system: String,
    /// The hostname of this system.
    node: OsString,
    /// The OS release identifier e.g. 7, OSX, debian.
    release: String,
    /// The OS version ID e.g. 6.1.7601SP1, 10.9.2, 14.04.
    version: Option<String>,
    /// The system architecture e.g. AMD64, x86_64.
    machine: Option<String>,
    // The kernel version string e.g. 6.1.7601, 13.1.0, 3.15-rc2.
    kernel: String,
    /// The system's fully qualified domain name.
    fqdn: OsString,
    /// When system was installed.
    install_date: Option<SystemTime>,
    /// The C library version.
    libc_ver: Option<String>,
    /// The architecture of this binary. (Note this can be different from
    /// the machine architecture in the case of a 32 bit binary running
    /// on a 64 bit system)
    architecture: String,
}

impl Into<rrg_proto::jobs::Uname> for PlatformInfo {
    fn into(self) -> rrg_proto::jobs::Uname {
        let mut proto = rrg_proto::jobs::Uname::new();
        proto.set_system(self.system);
        proto.set_node(self.node.to_string_lossy().into_owned());
        proto.set_release(self.release);
        proto.set_kernel(self.kernel);
        proto.set_fqdn(self.fqdn.to_string_lossy().into_owned());
        proto.set_architecture(self.architecture);

        if let Some(machine) = self.machine {
            proto.set_machine(machine);
        }
        if let Some(version) = self.version {
            proto.set_version(version);
        }
        if let Some(install_date) = self.install_date {
            match install_date.duration_since(UNIX_EPOCH) {
                Ok(duration) => {
                    proto.set_install_date(duration.as_secs());
                }
                Err(err) => {
                    error!(
                        "install date is {} seconds earlier than Unix epoch",
                        err.duration().as_secs()
                    );
                }
            };
        }
        if let Some(libc_ver) = self.libc_ver {
            proto.set_libc_ver(libc_ver);
        }

        proto
    }
}

impl super::Item for Response {
    const RDF_NAME: &'static str = "Uname";

    type Proto = rrg_proto::jobs::Uname;

    fn into_proto(self) -> Self::Proto {
        self.platform_info.into()
    }
}

/// Gets the platform information (Unix version).
#[cfg(target_family = "unix")]
fn get_platform_info() -> Result<PlatformInfo, Error> {
    let mut utsname = mem::MaybeUninit::<libc::utsname>::zeroed();

    let result = unsafe { libc::uname(utsname.as_mut_ptr()) };

    if result != 0 {
        return Err(Error::last_os_error());
    };

    let utsname = unsafe { utsname.assume_init() };

    let sysname = unsafe {
        String::from_utf8_lossy(CStr::from_ptr(utsname.sysname.as_ptr()).to_bytes()).into_owned()
    };
    let hostname = unsafe {
        OsString::from_vec(
            CStr::from_ptr(utsname.nodename.as_ptr())
                .to_bytes()
                .to_vec(),
        )
    };
    let kernel_release = unsafe {
        String::from_utf8_lossy(CStr::from_ptr(utsname.release.as_ptr()).to_bytes()).into_owned()
    };

    #[cfg(target_os = "macos")]
    let os_version = {
        let appkit_version = unsafe { NSAppKitVersionNumber };

        if appkit_version >= NSAppKitVersionNumber10_10 {
            let NSOperatingSystemVersion {
                major_version,
                minor_version,
                patch_version,
            } = unsafe {
                let proc_info = NSProcessInfo::processInfo(nil);
                msg_send![proc_info, operatingSystemVersion]
            };

            Some(format!(
                "{}.{}.{}",
                major_version, minor_version, patch_version
            ))
        } else {
            None
        }
    };

    #[cfg(not(target_os = "macos"))]
    let kernel_version = unsafe {
        String::from_utf8_lossy(CStr::from_ptr(utsname.version.as_ptr()).to_bytes()).into_owned()
    };

    let machine = unsafe {
        String::from_utf8_lossy(CStr::from_ptr(utsname.machine.as_ptr()).to_bytes()).into_owned()
    };

    #[cfg(target_os = "linux")]
    let libc_version = {
        unsafe {
            let libc_version = libc_version();

            if libc_version.is_null() {
                None
            } else {
                Some(String::from_utf8_lossy(CStr::from_ptr(libc_version).to_bytes()).into_owned())
            }
        }
    };

    #[cfg(not(target_os = "linux"))]
    let libc_version = None;

    let hints = mem::MaybeUninit::<libc::addrinfo>::zeroed();
    let mut addrinfo = ptr::null_mut();

    let result = unsafe {
        let mut hints = hints.assume_init();
        hints.ai_flags = libc::AI_CANONNAME;
        hints.ai_socktype = libc::SOCK_DGRAM;

        libc::getaddrinfo(
            utsname.nodename.as_ptr(),
            ptr::null(),
            &hints,
            &mut addrinfo,
        )
    };

    if result != 0 {
        Err(Error::last_os_error())
    } else {
        let fqdn = {
            let addrinfo: libc::addrinfo = unsafe { ptr::read(addrinfo) };
            if addrinfo.ai_canonname.is_null() {
                hostname.clone()
            } else {
                unsafe {
                    OsString::from_vec(CStr::from_ptr(addrinfo.ai_canonname).to_bytes().to_vec())
                }
            }
        };

        unsafe {
            libc::freeaddrinfo(addrinfo);
        }

        Ok(PlatformInfo {
            system: sysname,
            node: hostname,
            #[cfg(target_os = "linux")]
            release: kernel_release.clone(),
            #[cfg(target_os = "macos")]
            release: "OSX".to_string(),
            #[cfg(target_os = "linux")]
            version: Some(kernel_version),
            #[cfg(target_os = "macos")]
            version: os_version,
            machine: Some(machine),
            kernel: kernel_release,
            fqdn,
            install_date: get_install_time(),
            libc_ver: libc_version,
            architecture: ARCH.to_string(),
        })
    }
}

/// Gets the platform information (Windows version).
#[cfg(target_os = "windows")]
fn get_platform_info() -> Result<PlatformInfo, Error> {
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
    let hostname = OsString::from_wide(&computer_name);

    let mut computer_name_size = 0;
    unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsFullyQualified,
            PWSTR::null(),
            &mut computer_name_size,
        );
    };

    let mut computer_name = vec![0_u16; computer_name_size as usize];
    unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsFullyQualified,
            PWSTR::from_raw(computer_name.as_mut_ptr()),
            &mut computer_name_size,
        )
    }
    .ok()?;

    unsafe {
        computer_name.set_len(computer_name_size as usize);
    }
    let fqdn = OsString::from_wide(&computer_name);

    let mut system_info = SYSTEM_INFO::default();
    unsafe {
        GetNativeSystemInfo(&mut system_info);
    };

    let kernel_fileinfo = dll_module_fileinfo(w!("kernel32.dll"))?;

    let (major_version, minor_version, build_version) = (
        (kernel_fileinfo.dwProductVersionMS >> 16) & 0xffff, // HIWORD
        kernel_fileinfo.dwProductVersionMS & 0xffff,         // LOWORD
        (kernel_fileinfo.dwProductVersionLS >> 16) & 0xffff, // HIWORD
    );

    let processor_architecture = unsafe { system_info.Anonymous.Anonymous.wProcessorArchitecture };

    Ok(PlatformInfo {
        system: "Windows".to_string(),
        node: hostname,
        release: major_version.to_string(),
        version: Some(format!(
            "{}.{} ({})",
            major_version, minor_version, build_version,
        )),
        machine: match processor_architecture {
            PROCESSOR_ARCHITECTURE_INTEL => Some("x86".to_string()),
            PROCESSOR_ARCHITECTURE_ARM => Some("ARM".to_string()),
            PROCESSOR_ARCHITECTURE_IA64 => Some("Intel Itanium-based".to_string()),
            PROCESSOR_ARCHITECTURE_AMD64 => Some("x86_64".to_string()),
            PROCESSOR_ARCHITECTURE(12_u16) => Some("ARM64".to_string()),
            _ => None,
        },
        kernel: format!(
            "{}.{}.{} Build {}",
            major_version, minor_version, build_version, build_version
        ),
        fqdn,
        install_date: get_install_time(),
        libc_ver: None,
        architecture: ARCH.to_string(),
    })
}

/// Handles requests for the platform information action.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    session.reply(Response {
        platform_info: get_platform_info()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_info() {
        let mut session = session::FakeSession::new();

        if let Err(err) = handle(&mut session, ()) {
            panic!("{:?}", err);
        };

        assert_eq!(session.reply_count(), 1);
        let response: &Response = session.reply(0);

        println!("{:?}", response.platform_info);
    }
}
