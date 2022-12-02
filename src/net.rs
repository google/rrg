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
#[derive(Clone, Debug)]
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

/// Collects information about available network interfaces.
///
/// The information collected by this mathod can be more or less complete,
/// depending on the operating system.
///
/// # Errors
///
/// This function will fail if there was some kind of issue (e.g. insufficient
/// permissions to make certain system calls) during information collection.
///
/// # Examples
///
/// ```
/// let ifaces = rrg::net::interfaces().unwrap();
/// for iface in ifaces {
///     let name = iface.name().to_string_lossy();
///     println!("{} ({} IP addresses)", name, iface.ip_addrs().len());
/// }
/// ```
pub fn interfaces() -> std::io::Result<impl Iterator<Item = Interface>> {
    #[cfg(target_os = "linux")]
    use self::linux::interfaces;

    #[cfg(target_os = "macos")]
    use self::macos::interfaces;

    #[cfg(target_os = "windows")]
    use self::windows::interfaces;

    interfaces()
}

/// A list of possible states of the TCP connection.
///
/// [1]: https://www.ietf.org/rfc/rfc793.txt
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TcpState {
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

/// Information about a TCP connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TcpConnection {
    /// A local address of the connection.
    local_addr: std::net::SocketAddr,
    /// A remote address of the connection.
    remote_addr: std::net::SocketAddr,
    /// A state of the connection.
    state: TcpState,
}

/// Information about a UDP connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UdpConnection {
    /// A local address of the connection.
    local_addr: std::net::SocketAddr,
}

/// Information about an Internet connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Connection {
    /// A TCP connection.
    Tcp(TcpConnection),
    /// A UDP connection.
    Udp(UdpConnection),
}
