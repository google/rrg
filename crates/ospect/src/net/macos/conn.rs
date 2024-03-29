// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use crate::net::*;

/// Returns an iterator over IPv4 TCP connections for the specified process.
pub fn tcp_v4(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnectionV4>>> {
    let conns = Connections::new(pid, ProtocolFilter::Tcp)?;
    Ok(conns.filter_map(|conn| match conn {
        Ok(Connection::Tcp(TcpConnection::V4(conn))) => Some(Ok(conn)),
        Ok(_) => None,
        Err(error) => Some(Err(error)),
    }))
}

/// Returns an iterator over IPv6 TCP connections for the specified process.
pub fn tcp_v6(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnectionV6>>> {
    let conns = Connections::new(pid, ProtocolFilter::Tcp)?;
    Ok(conns.filter_map(|conn| match conn {
        Ok(Connection::Tcp(TcpConnection::V6(conn))) => Some(Ok(conn)),
        Ok(_) => None,
        Err(error) => Some(Err(error)),
    }))
}

/// Returns an iterator over IPv4 UDP connections for the specified process.
pub fn udp_v4(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnectionV4>>> {
    let conns = Connections::new(pid, ProtocolFilter::Udp)?;
    Ok(conns.filter_map(|conn| match conn {
        Ok(Connection::Udp(UdpConnection::V4(conn))) => Some(Ok(conn)),
        Ok(_) => None,
        Err(error) => Some(Err(error)),
    }))
}

/// Returns an iterator over IPv6 UDP connections for the specified process.
pub fn udp_v6(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnectionV6>>> {
    let conns = Connections::new(pid, ProtocolFilter::Udp)?;
    Ok(conns.filter_map(|conn| match conn {
        Ok(Connection::Udp(UdpConnection::V6(conn))) => Some(Ok(conn)),
        Ok(_) => None,
        Err(error) => Some(Err(error)),
    }))
}

/// An iterator over all connections for the specified process.
struct Connections {
    /// An identifier of the process for which this iterator yields items.
    pid: u32,
    /// A filter of protocol type to apply to the yielded connections.
    protocol: ProtocolFilter,
    /// An iterator over low-level macOS file descriptor metadata.
    iter: std::vec::IntoIter<crate::libc::proc_fdinfo>,
}

impl Connections {

    /// Creates a new iterator over connections for the specified process.
    ///
    /// The iterator will yield only connections that match the given `protocol`
    /// filter.
    ///
    /// # Errors
    ///
    /// This function will yield an error if metadata cannot be obtained for the
    /// specified process.
    pub fn new(
        pid: u32,
        protocol: ProtocolFilter,
    ) -> std::io::Result<Connections> {
        const PROC_FDINFO_SIZE: i32 = {
            std::mem::size_of::<crate::libc::proc_fdinfo>() as i32
        };

        let pid_i32 = i32::try_from(pid)
            .map_err(|_| std::io::ErrorKind::InvalidInput)?;

        // SAFETY: We call the function with null buffer. This should return the
        // size for the buffer that we need or 0 in case of an error.
        let buf_size = unsafe {
            libc::proc_pidinfo(
                pid_i32,
                crate::libc::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        if buf_size == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut buf_len = buf_size / PROC_FDINFO_SIZE;
        if buf_size % PROC_FDINFO_SIZE != 0 {
            buf_len += 1;
        }

        let mut buf = {
            Vec::<crate::libc::proc_fdinfo>::with_capacity(buf_len as usize)
        };

        // SAFETY: We call the function as above but with allocated buffer. The
        // function will return 0 in case of an error which we verify later on.
        let buf_size = unsafe {
            libc::proc_pidinfo(
                pid_i32,
                crate::libc::PROC_PIDLISTFDS,
                0,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf_size,
            )
        };
        if buf_size == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if buf_size % PROC_FDINFO_SIZE != 0 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }

        let buf_len = buf_size / PROC_FDINFO_SIZE;

        // SAFETY: We verified that the call to `proc_pidinfo` succeeded. The
        // call returns the number of bytes filled in the buffer, so we can set
        // the length to the number of bytes divided by the length of individual
        // entry.
        unsafe {
            buf.set_len(buf_len as usize);
        }

        Ok(Connections {
            pid,
            protocol,
            iter: buf.into_iter(),
        })
    }

    /// Parses a macOS TCP socket metadata into platform-agnostic type.
    fn parse_tcp_sockinfo(
        &self,
        info: &crate::libc::socket_fdinfo,
    ) -> Result<TcpConnection, ParseConnectionError> {
        use ParseConnectionError::*;

        if info.psi.soi_protocol != libc::IPPROTO_TCP {
            return Err(InvalidProtocol(info.psi.soi_protocol));
        }

        // This should be ensured by the caller.
        assert_eq!(info.psi.soi_kind, crate::libc::SOCKINFO_TCP);

        // SAFETY: We verified that we have a TCP socket, so we can
        // safely access the `pri_tcp` field.
        let tcp_info = unsafe { info.psi.soi_proto.pri_tcp };

        match info.psi.soi_family {
            libc::AF_INET => self.parse_tcp_v4_sockinfo(tcp_info)
                .map(|conn| conn.into()),
            libc::AF_INET6 => self.parse_tcp_v6_sockinfo(tcp_info)
                .map(|conn| conn.into()),
            _ => Err(InvalidAddressFamily(info.psi.soi_family)),
        }
    }

    /// Parses a macOS UDP socket metadata into platform-agnostic type.
    fn parse_udp_sockinfo(
        &self,
        info: &crate::libc::socket_fdinfo,
    ) -> Result<UdpConnection, ParseConnectionError> {
        use ParseConnectionError::*;

        if info.psi.soi_protocol != libc::IPPROTO_UDP {
            return Err(InvalidProtocol(info.psi.soi_protocol));
        }

        // This should be ensured by the caller.
        assert_eq!(info.psi.soi_kind, crate::libc::SOCKINFO_IN);

        // SAFETY: We verified that we have a generic socket, so we can
        // safely access the `pri_in` field.
        let udp_info = unsafe { info.psi.soi_proto.pri_in };

        match info.psi.soi_family {
            libc::AF_INET => self.parse_udp_v4_sockinfo(udp_info)
                .map(|conn| conn.into()),
            libc::AF_INET6 => self.parse_udp_v6_sockinfo(udp_info)
                .map(|conn| conn.into()),
            _ => Err(InvalidAddressFamily(info.psi.soi_family)),
        }
    }

    /// Parses a macOS TCP IPv4 socket metadata into platform-agnostic type.
    fn parse_tcp_v4_sockinfo(
        &self,
        info: crate::libc::tcp_sockinfo,
    ) -> Result<TcpConnectionV4, ParseConnectionError> {
        use ParseConnectionError::*;

        if info.tcpsi_ini.insi_vflag != crate::libc::INI_IPV4 as u8 {
            return Err(InvalidProtocolFlag(info.tcpsi_ini.insi_vflag));
        }

        // SAFETY: We verified that we are dealing with a TCP IPv4 socket above,
        // so we are allowed to access the IPv4 address.
        let remote_addr = parse_ipv4_addr(unsafe {
            info.tcpsi_ini.insi_faddr.ina_46
        });
        let remote_port = parse_port(info.tcpsi_ini.insi_fport)
            .map_err(InvalidRemotePort)?;

        // SAFETY: Same as with `remote_addr`.
        let local_addr = parse_ipv4_addr(unsafe {
            info.tcpsi_ini.insi_laddr.ina_46
        });
        let local_port = parse_port(info.tcpsi_ini.insi_lport)
            .map_err(InvalidLocalPort)?;

        Ok(TcpConnectionV4::from_inner(TcpConnectionInner {
            local_addr: std::net::SocketAddrV4::new(local_addr, local_port),
            remote_addr: std::net::SocketAddrV4::new(remote_addr, remote_port),
            state: parse_tcp_state(info.tcpsi_state)?,
            pid: self.pid,
        }))
    }

    /// Parses a macOS TCP IPv6 socket metadata into platform-agnostic type.
    fn parse_tcp_v6_sockinfo(
        &self,
        info: crate::libc::tcp_sockinfo,
    ) -> Result<TcpConnectionV6, ParseConnectionError> {
        use std::net::SocketAddrV6;
        use ParseConnectionError::*;

        if info.tcpsi_ini.insi_vflag != crate::libc::INI_IPV6 as u8 {
            return Err(InvalidProtocolFlag(info.tcpsi_ini.insi_vflag));
        }

        // SAFETY: We verified that we are dealing with a TCP IPv6 socket above,
        // so we are allowed to access the IPv6 address.
        let remote_addr = parse_ipv6_addr(unsafe {
            info.tcpsi_ini.insi_faddr.ina_6
        });
        let remote_port = parse_port(info.tcpsi_ini.insi_fport)
            .map_err(InvalidRemotePort)?;

        // SAFETY: Same as with `local_addr`.
        let local_addr = parse_ipv6_addr(unsafe {
            info.tcpsi_ini.insi_laddr.ina_6
        });
        let local_port = parse_port(info.tcpsi_ini.insi_lport)
            .map_err(InvalidLocalPort)?;

        Ok(TcpConnectionV6::from_inner(TcpConnectionInner {
            local_addr: SocketAddrV6::new(local_addr, local_port, 0, 0),
            remote_addr: SocketAddrV6::new(remote_addr, remote_port, 0, 0),
            state: parse_tcp_state(info.tcpsi_state)?,
            pid: self.pid,
        }))
    }

    /// Parses a macOS UDP IPv4 socket metadata into platform-agnostic type.
    fn parse_udp_v4_sockinfo(
        &self,
        info: crate::libc::in_sockinfo,
    ) -> Result<UdpConnectionV4, ParseConnectionError> {
        use ParseConnectionError::*;

        if info.insi_vflag != crate::libc::INI_IPV4 as u8 {
            return Err(InvalidProtocolFlag(info.insi_vflag));
        }

        // SAFETY: We verified that we are dealing with a UDP IPv4 socket above,
        // so we are allowed to access the IPv4 address.
        let local_addr = parse_ipv4_addr(unsafe {
            info.insi_laddr.ina_46
        });
        let local_port = parse_port(info.insi_lport)
            .map_err(InvalidLocalPort)?;

        Ok(UdpConnectionV4::from_inner(UdpConnectionInner {
            local_addr: std::net::SocketAddrV4::new(local_addr, local_port),
            pid: self.pid,
        }))
    }

    /// Parses a macOS UDP IPv6 socket metadata into platform-agnostic type.
    fn parse_udp_v6_sockinfo(
        &self,
        info: crate::libc::in_sockinfo,
    ) -> Result<UdpConnectionV6, ParseConnectionError> {
        use std::net::SocketAddrV6;
        use ParseConnectionError::*;

        if info.insi_vflag != crate::libc::INI_IPV6 as u8 {
            return Err(InvalidProtocolFlag(info.insi_vflag));
        }

        // SAFETY: We verified that we are dealing with a UDP IPv6 socket above,
        // so we are allowed to access the IPv6 address.
        let local_addr = parse_ipv6_addr(unsafe {
            info.insi_laddr.ina_6
        });
        let local_port = parse_port(info.insi_lport)
            .map_err(ParseConnectionError::InvalidLocalPort)?;

        Ok(UdpConnectionV6::from_inner(UdpConnectionInner {
            local_addr: SocketAddrV6::new(local_addr, local_port, 0, 0),
            pid: self.pid,
        }))
    }
}

impl Iterator for Connections {

    type Item = std::io::Result<Connection>;

    fn next(&mut self) -> Option<std::io::Result<Connection>> {
        const SOCKET_FDINFO_SIZE: i32 = {
            std::mem::size_of::<crate::libc::socket_fdinfo>() as i32
        };

        // We verified that `self.pid` fits in `i32` in the constructor, so this
        // should not panic.
        let pid_i32 = self.pid as i32;

        for fdinfo in &mut self.iter {
            if fdinfo.proc_fdtype != crate::libc::PROX_FDTYPE_SOCKET as u32 {
                continue;
            }

            let mut info = {
                std::mem::MaybeUninit::<crate::libc::socket_fdinfo>::uninit()
            };

            // SAFETY: We verifed that the file descriptor corresponds to a
            // socket above. Then we just pass a pointer to the uninitialized
            // struct along with with its size. In case something goes wrong,
            // the function should report an error (which we verify below).
            let size = unsafe {
                libc::proc_pidfdinfo(
                    pid_i32 as i32,
                    fdinfo.proc_fd,
                    crate::libc::PROC_PIDFDSOCKETINFO,
                    info.as_mut_ptr().cast::<libc::c_void>(),
                    SOCKET_FDINFO_SIZE,
                )
            };
            if size == 0 || size < SOCKET_FDINFO_SIZE {
                return Some(Err(std::io::Error::last_os_error()));
            }

            // SAFETY: We verified that the call to `proc_pidfdinfo` succeeded,
            // so the struct should be filled with valid data now.
            let info = unsafe { info.assume_init() };

            match info.psi.soi_kind {
                crate::libc::SOCKINFO_TCP if self.protocol.is_tcp() => {
                    match self.parse_tcp_sockinfo(&info) {
                        Ok(conn) => return Some(Ok(conn.into())),
                        Err(error) => return Some(Err(error.into())),
                    }
                }
                crate::libc::SOCKINFO_IN if self.protocol.is_udp() => {
                    match self.parse_udp_sockinfo(&info) {
                        Ok(conn) => return Some(Ok(conn.into())),
                        Err(error) => return Some(Err(error.into())),
                    }
                }
                _ => continue,
            }
        }

        None
    }
}

/// An enum with possible values for filtering connections by the protocol type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ProtocolFilter {
    /// Allow only TCP connections.
    Tcp,
    /// Allow only UDP connections.
    Udp,
}

impl ProtocolFilter {

    /// Returns `true` if the filter allows TCP.
    fn is_tcp(&self) -> bool {
        use ProtocolFilter::*;

        matches!(self, Tcp)
    }

    /// Returns `true` if the filter allows UDP.
    fn is_udp(&self) -> bool {
        use ProtocolFilter::*;

        matches!(self, Udp)
    }
}

/// Parses a macOS IPv4 socket information into the standard type.
fn parse_ipv4_addr(addr: crate::libc::in4in6_addr) -> std::net::Ipv4Addr {
    // Unlike on Linux, Apple documentation does not say anything whatsoever
    // about the endianness of the address value [1, 2]. We give them the
    // benefit of a doubt and assume that they do a sane thing and follow the
    // Linux convention here.
    //
    // Hence, we have to convert from network endian (big endian) order to what
    // the Rust IPv4 type constructor expects (host endian).
    //
    // [1]: https://developer.apple.com/documentation/kernel/in_addr_t
    // [2]: https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/sys/_types/_in_addr_t.h#L31
    let local_addr_u32 = u32::from_be(addr.i46a_addr4.s_addr);
    std::net::Ipv4Addr::from(local_addr_u32)
}

/// Parses a macOS IPv6 socket information into the standard type.
fn parse_ipv6_addr(addr: libc::in6_addr) -> std::net::Ipv6Addr {
    std::net::Ipv6Addr::from(addr.s6_addr)
}

/// Parses a macOS value representing a port into a standard type.
///
/// # Errors
///
/// If the value cannot be parsed an error is reported. The error contains the
/// original value.
fn parse_port(port: libc::c_int) -> Result<u16, libc::c_int> {
    let port = u16::try_from(port)
        .map_err(|_| port)?;

    // No documention mentions it (well, it would have to exist in the first
    // place), but from manual experimentation it is clear that port is also
    // stored using network-endian byte order and so we have to convert it to
    // something that Rust expects.
    Ok(u16::from_be(port))
}

/// An error that might be returned when interpreting macOS TCP socket metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ParseConnectionError {
    /// The socket address family is invalid.
    InvalidAddressFamily(libc::c_int),
    /// The protocol type was not correct for the connection type.
    InvalidProtocol(libc::c_int),
    /// The protocol type flag was not correct for the connection type.
    InvalidProtocolFlag(u8),
    /// It was not possible to parse the local address port.
    InvalidLocalPort(libc::c_int),
    /// It was not possible to parse the remote address port.
    InvalidRemotePort(libc::c_int),
    /// It was not possible to interpret the connection state.
    InvalidState(ParseTcpStateError),
}

impl std::fmt::Display for ParseConnectionError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ParseConnectionError::*;
        match *self {
            InvalidAddressFamily(family) => {
                write!(fmt, "invalid address family: {}", family)
            }
            InvalidProtocol(proto) => {
                write!(fmt, "invalid protocol type: {}", proto)
            }
            InvalidProtocolFlag(flag) => {
                write!(fmt, "invalid protocol type flag: {}", flag)
            }
            InvalidLocalPort(port) => {
                write!(fmt, "invalid local port: {}", port)
            }
            InvalidRemotePort(port) => {
                write!(fmt, "invalid remote port: {}", port)
            }
            InvalidState(error) => {
                write!(fmt, "invalid state: {}", error)
            }
        }
    }
}

impl std::error::Error for ParseConnectionError {
    // We could implement `source` for this error type but since it is not
    // exposed, there is no need to do so.
}

impl From<ParseConnectionError> for std::io::Error {

    fn from(error: ParseConnectionError) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, error)
    }
}

/// Parses a TCP connection state value returned by the system.
fn parse_tcp_state(val: libc::c_int) -> Result<TcpState, ParseTcpStateError> {
    let state = match val {
        crate::libc::TSI_S_CLOSED => TcpState::Closed,
        crate::libc::TSI_S_LISTEN => TcpState::Listen,
        crate::libc::TSI_S_SYN_SENT => TcpState::SynSent,
        crate::libc::TSI_S_SYN_RECEIVED => TcpState::SynReceived,
        crate::libc::TSI_S_ESTABLISHED => TcpState::Established,
        crate::libc::TSI_S__CLOSE_WAIT => TcpState::CloseWait,
        crate::libc::TSI_S_FIN_WAIT_1 => TcpState::FinWait1,
        crate::libc::TSI_S_CLOSING => TcpState::Closing,
        crate::libc::TSI_S_LAST_ACK => TcpState::LastAck,
        crate::libc::TSI_S_FIN_WAIT_2 => TcpState::FinWait2,
        crate::libc::TSI_S_TIME_WAIT => TcpState::TimeWait,
        _ => return Err(ParseTcpStateError::UnknownState(val)),
    };

    Ok(state)
}

/// An error that might be returned when interpreting macOS TCP state value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ParseTcpStateError {
    /// The state value is not a known.
    UnknownState(libc::c_int),
}

impl std::fmt::Display for ParseTcpStateError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ParseTcpStateError::*;
        match *self {
            UnknownState(val) => {
                write!(fmt, "unknown TPC state value: {}", val)
            },
        }
    }
}

impl std::error::Error for ParseTcpStateError {
}

impl From<ParseTcpStateError> for ParseConnectionError {

    fn from(error: ParseTcpStateError) -> ParseConnectionError {
        ParseConnectionError::InvalidState(error)
    }
}
