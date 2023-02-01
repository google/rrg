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

mod sys {
    #[cfg(target_os = "linux")]
    pub use crate::net::linux::*;

    #[cfg(target_os = "macos")]
    pub use crate::net::macos::*;

    #[cfg(target_os = "windows")]
    pub use crate::net::windows::*;
}

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
    self::sys::interfaces()
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

/// Internal generic type for information about a TCP connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct TcpConnectionInner<A> {
    /// A local address of the connection.
    local_addr: A,
    /// A remote address of the connection.
    remote_addr: A,
    /// A state of the connection.
    state: TcpState,
    /// An identifier of the process that owns the connection.
    pid: u32,
}

/// Information about a TCP IPv4 connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TcpConnectionV4 {
    inner: TcpConnectionInner<std::net::SocketAddrV4>,
}

impl TcpConnectionV4 {

    /// Promotes an inner instance into `TcpConnectionV4` type.
    fn from_inner(conn: TcpConnectionInner<std::net::SocketAddrV4>) -> TcpConnectionV4 {
        TcpConnectionV4 {
            inner: conn,
        }
    }

    /// Returns the local address of the connection metadata.
    pub fn local_addr(&self) -> std::net::SocketAddrV4 {
        self.inner.local_addr
    }

    /// Returns the remote address of the connection metadata.
    pub fn remote_addr(&self) -> std::net::SocketAddrV4 {
        self.inner.remote_addr
    }

    /// Returns the state of the connection metadata.
    pub fn state(&self) -> TcpState {
        self.inner.state
    }

    /// Returns the identifier of the process that owns the connection metadata.
    pub fn pid(&self) -> u32 {
        self.inner.pid
    }

    /// Changes the process identifier associated with this connection metadata.
    pub fn set_pid(&mut self, pid: u32) {
        self.inner.pid = pid;
    }
}

/// Information about a TCP IPv6 connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TcpConnectionV6 {
    inner: TcpConnectionInner<std::net::SocketAddrV6>,
}

impl TcpConnectionV6 {

    /// Promotes an inner instance into `TcpConnectionV4` type.
    fn from_inner(conn: TcpConnectionInner<std::net::SocketAddrV6>) -> TcpConnectionV6 {
        TcpConnectionV6 {
            inner: conn,
        }
    }

    /// Returns the local address of the connection metadata.
    pub fn local_addr(&self) -> std::net::SocketAddrV6 {
        self.inner.local_addr
    }

    /// Returns the remote address of the connection metadata.
    pub fn remote_addr(&self) -> std::net::SocketAddrV6 {
        self.inner.remote_addr
    }

    /// Returns the state of the connection metadata.
    pub fn state(&self) -> TcpState {
        self.inner.state
    }

    /// Returns the identifier of the process that owns the connection metadata.
    pub fn pid(&self) -> u32 {
        self.inner.pid
    }

    /// Changes the process identifier associated with this connection metadata.
    pub fn set_pid(&mut self, pid: u32) {
        self.inner.pid = pid;
    }
}

/// Information about a TCP connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TcpConnection {
    /// An IPv4 TCP connection information.
    V4(TcpConnectionV4),
    /// An IPv6 TCP connection information.
    V6(TcpConnectionV6),
}

impl TcpConnection {

    /// Returns the local address of the connection metadata.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        use TcpConnection::*;
        match self {
            V4(conn) => std::net::SocketAddr::V4(conn.local_addr()),
            V6(conn) => std::net::SocketAddr::V6(conn.local_addr()),
        }
    }

    /// Returns the remote address of the connection metadata.
    pub fn remote_addr(&self) -> std::net::SocketAddr {
        use TcpConnection::*;
        match self {
            V4(conn) => std::net::SocketAddr::V4(conn.remote_addr()),
            V6(conn) => std::net::SocketAddr::V6(conn.remote_addr()),
        }
    }

    /// Returns the state of the connection metadata.
    pub fn state(&self) -> TcpState {
        match self {
            TcpConnection::V4(conn) => conn.state(),
            TcpConnection::V6(conn) => conn.state(),
        }
    }

    /// Returns the identifier of the process that owns the connection metadata.
    pub fn pid(&self) -> u32 {
        match self {
            TcpConnection::V4(conn) => conn.pid(),
            TcpConnection::V6(conn) => conn.pid(),
        }
    }

    /// Changes the process identifier associated with this connection metadata.
    fn set_pid(&mut self, pid: u32) {
        match self {
            TcpConnection::V4(ref mut conn) => conn.set_pid(pid),
            TcpConnection::V6(ref mut conn) => conn.set_pid(pid),
        }
    }
}

impl From<TcpConnectionV4> for TcpConnection {

    fn from(conn: TcpConnectionV4) -> TcpConnection {
        TcpConnection::V4(conn)
    }
}

impl From<TcpConnectionV6> for TcpConnection {

    fn from(conn: TcpConnectionV6) -> TcpConnection {
        TcpConnection::V6(conn)
    }
}

/// Information about a UDP connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UdpConnection {
    /// A local address of the connection.
    local_addr: std::net::SocketAddr,
    /// An identifier of the process that owns the connection.
    pid: u32,
}

/// Information about an Internet connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Connection {
    /// A TCP connection.
    Tcp(TcpConnection),
    /// A UDP connection.
    Udp(UdpConnection),
}

/// Returns an iterator over IPv4 TCP connections for the specified process.
///
/// # Errors
///
/// This function will fail if there was some kind of issue (e.g. insufficient
/// permissions to make certain system calls) during information collection.
pub fn tcp_v4_connections(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnection>>> {
    self::sys::tcp_v4_connections(pid)
}

/// Returns an iterator over IPv6 TCP connections for the specified process.
///
/// # Errors
///
/// This function will fail if there was some kind of issue (e.g. insufficient
/// permissions to make certain system calls) during information collection.
pub fn tcp_v6_connections(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnection>>> {
    self::sys::tcp_v6_connections(pid)
}

/// Returns an iterator over IPv4 UDP connections for the specified process.
///
/// # Errors
///
/// This function will fail if there was some kind of issue (e.g. insufficient
/// permissions to make certain system calls) during information collection.
pub fn udp_v4_connections(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnection>>> {
    self::sys::udp_v4_connections(pid)
}

/// Returns an iterator over IPv6 UDP connections for the specified process.
///
/// # Errors
///
/// This function will fail if there was some kind of issue (e.g. insufficient
/// permissions to make certain system calls) during information collection.
pub fn udp_v6_connections(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnection>>> {
    self::sys::udp_v6_connections(pid)
}

#[cfg(test)]
mod tests {

    use super::*;

    // TODO(@panhania): Enable on macOS once the function is supported there.
    #[cfg_attr(target_os = "macos", ignore)]
    #[test]
    fn tcp_v4_connections_local_connection() {
        use std::net::Ipv4Addr;

        let server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap();
        let server_addr = server.local_addr()
            .unwrap();

        let mut conns = tcp_v4_connections(std::process::id())
            .unwrap()
            .filter_map(Result::ok);

        let server_conn = conns.find(|conn| conn.local_addr() == server_addr)
            .unwrap();

        assert_eq!(server_conn.state(), TcpState::Listen);
        assert_eq!(server_conn.pid(), std::process::id());
    }

    // TODO(@panhania): Enable on macOS once the function is supported there.
    #[cfg_attr(target_os = "macos", ignore)]
    #[test]
    fn tcp_v6_connections_local_connection() {
        use std::net::Ipv6Addr;

        let server = std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
            .unwrap();
        let server_addr = server.local_addr()
            .unwrap();

        let mut conns = tcp_v6_connections(std::process::id())
            .unwrap()
            .filter_map(Result::ok);

        let server_conn = conns.find(|conn| conn.local_addr() == server_addr)
            .unwrap();

        assert_eq!(server_conn.state(), TcpState::Listen);
        assert_eq!(server_conn.pid(), std::process::id());
    }

    // TODO(@panhania): Enable on macOS once the function is supported there.
    #[cfg_attr(target_os = "macos", ignore)]
    #[test]
    fn udp_v4_connections_local_connection() {
        use std::net::Ipv4Addr;

        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap();
        let socket_addr = socket.local_addr()
            .unwrap();

        let mut conns = udp_v4_connections(std::process::id())
            .unwrap()
            .filter_map(Result::ok);

        let server_conn = conns.find(|conn| conn.local_addr == socket_addr)
            .unwrap();

        assert_eq!(server_conn.pid, std::process::id());
    }

    // TODO(@panhania): Enable on macOS once the function is supported there.
    #[cfg_attr(target_os = "macos", ignore)]
    #[test]
    fn udp_v6_connections_local_connection() {
        use std::net::Ipv6Addr;

        let socket = std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))
            .unwrap();
        let socket_addr = socket.local_addr()
            .unwrap();

        let mut conns = udp_v6_connections(std::process::id())
            .unwrap()
            .filter_map(Result::ok);

        let server_conn = conns.find(|conn| conn.local_addr == socket_addr)
            .unwrap();

        assert_eq!(server_conn.pid, std::process::id());
    }
}
