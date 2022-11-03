// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Networking primitives not covered by the standard library.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

// TODO(panhania@): Add support for Windows.

/// A MAC address.
///
/// MAC addresses are defined as 48-bit numbers in a IEEE 802 standard [1].
///
/// [1]: https://standards.ieee.org/wp-content/uploads/import/documents/tutorials/macgrp.pdf
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr {
    /// Octets forming up the 48-bit MAC address number.
    octets: [u8; 6],
}

impl MacAddr {

    /// Return the six 8-bit integers that make up this address.
    pub fn octets(&self) -> [u8; 6] {
        self.octets
    }
}

impl From<[u8; 6]> for MacAddr {

    fn from(octets: [u8; 6]) -> MacAddr {
        MacAddr { octets }
    }
}

/// A network interface information.
pub struct Interface {
    /// A name of this interface as reported by the system.
    name: std::ffi::OsString,
    /// IP addresses associated with this interface.
    ip_addrs: Vec<std::net::IpAddr>,
    /// The MAC address associated with this interface.
    mac_addr: Option<MacAddr>,
}

impl Interface {

    /// Returns the name of this interface as reported by the system.
    pub fn name(&self) -> &std::ffi::OsStr {
        self.name.as_os_str()
    }

    /// Returns the IP addresses associated with this interface.
    pub fn ip_addrs(&self) -> &[std::net::IpAddr] {
        self.ip_addrs.as_slice()
    }

    /// Returns the MAC address associated with this interface (if any).
    pub fn mac_addr(&self) -> Option<&MacAddr> {
        self.mac_addr.as_ref()
    }
}
