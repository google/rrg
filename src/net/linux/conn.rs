// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use crate::net::*;

/// Returns an iterator over IPv4 TCP connections for the specified process.
pub fn tcp_v4(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnectionV4>>> {
    let path = format!("/proc/{pid}/net/tcp");
    Ok(TcpConnections {
        pid,
        iter: Connections::new(path, parse_tcp_v4_connection)?,
    }.map(|conn| Ok(TcpConnectionV4::from_inner(conn?))))
}

/// Returns an iterator over IPv6 TCP connections for the specified process.
pub fn tcp_v6(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnectionV6>>> {
    let path = format!("/proc/{pid}/net/tcp6");
    Ok(TcpConnections {
        pid,
        iter: Connections::new(path, parse_tcp_v6_connection)?,
    }.map(|conn| Ok(TcpConnectionV6::from_inner(conn?))))
}

/// Returns an iterator over IPv4 UDP connections for the specified process.
pub fn udp_v4(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnection>>> {
    let path = format!("/proc/{pid}/net/udp");
    Ok(UdpConnections {
        pid,
        iter: Connections::new(path, parse_udp_v4_connection)?,
    })
}

/// Returns an iterator over IPv6 UDP connections for the specified process.
pub fn udp_v6(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnection>>> {
    let path = format!("/proc/{pid}/net/udp6");
    Ok(UdpConnections {
        pid,
        iter: Connections::new(path, parse_udp_v6_connection)?,
    })
}

// TODO(rust-lang/rust#63063): Simplify as an alias to `impl`.
/// Iterator over UDP connections of a particular process.
///
/// Instances of this iterator can be created using the [`udp_v4_connections`]
/// and [`udp_v6_connections`] functions.
///
/// # Errors
///
/// Each item yield by the iterator can be [`ParseConnectionError`] if the
/// connection information returned by the system was malformed.
pub struct UdpConnections {
    /// Identifier of the process that owns the yielded connections.
    pid: u32,
    /// Underlying iterator over UDP connections.
    iter: Connections<UdpConnection>,
}

// TODO(rust-lang/rust#63063): Simplify as an alias to `impl`.
/// Iterator over TCP connections of a particular process.
///
/// Instances of this iterator can be created using the [`tcp_v4_connections`]
/// and [`tcp_v6_connections`] functions.
///
/// # Errors
///
/// Each item yield by the iterator can be [`ParseConnectionError`] if the
/// connection information returned by the system was malformed.
struct TcpConnections<A> {
    /// Identifier of the process that owns the yielded connections.
    pid: u32,
    /// Underlying iterator over TCP connections.
    iter: Connections<TcpConnectionInner<A>>,
}

impl<A> Iterator for TcpConnections<A> {
    type Item = std::io::Result<TcpConnectionInner<A>>;

    fn next(&mut self) -> Option<std::io::Result<TcpConnectionInner<A>>> {
        let mut conn = self.iter.next()?;
        if let Ok(conn) =  conn.as_mut() {
            conn.pid = self.pid;
        }

        Some(conn)
    }
}

impl Iterator for UdpConnections {
    type Item = std::io::Result<UdpConnection>;

    fn next(&mut self) -> Option<std::io::Result<UdpConnection>> {
        let mut conn = self.iter.next()?;
        if let Ok(conn) =  conn.as_mut() {
            conn.pid = self.pid;
        }

        Some(conn)
    }
}

/// Abstract iterator over connections of a particular process.
///
/// # Errors
///
/// Each item yield by the iterator can be [`ParseConnectionError`] if the
/// connection information returned by the system was malformed.
struct Connections<C> {
    /// Iterator over lines of procfs connections file.
    lines: std::io::Lines<std::io::BufReader<std::fs::File>>,
    /// Function to use for parsing connection information.
    parse_connection: fn(&str) -> Result<C, ParseConnectionError>,
}

impl<C> Connections<C> {

    /// Creates a new instance of the iterator.
    ///
    /// `path` should point to a procfs file [1] with connection information and
    /// `parse_connection` should be a function that can parse the lines of that
    /// file.
    ///
    /// [1]: https://docs.kernel.org/filesystems/proc.html#networking-info-in-proc-net
    fn new<P>(
        path: P,
        parse_connection: fn(&str) -> Result<C, ParseConnectionError>,
    ) -> std::io::Result<Connections<C>>
    where
        P: AsRef<std::path::Path>,
    {
        use std::io::BufRead as _;

        let file = std::fs::File::open(path)?;
        let mut lines = std::io::BufReader::new(file).lines();
        if lines.next().is_none() {
            // TODO(@panhania): Raise more specific error about missing header.
            return Err(std::io::ErrorKind::InvalidData.into());
        }

        Ok(Connections {
            lines,
            parse_connection,
        })
    }
}

impl<C> Iterator for Connections<C> {
    type Item = std::io::Result<C>;

    fn next(&mut self) -> Option<std::io::Result<C>> {
        let line = match self.lines.next() {
            None => return None,
            Some(Ok(line)) => line,
            Some(Err(error)) => return Some(Err(error)),
        };

        match (self.parse_connection)(&line) {
            Ok(conn) => Some(Ok(conn)),
            Err(error) => Some(Err({
                std::io::Error::new(std::io::ErrorKind::InvalidData, error)
            })),
        }
    }
}

/// Parses a TCP IPv4 connection information in the procfs format.
fn parse_tcp_v4_connection(string: &str) -> Result<TcpConnectionInner<std::net::SocketAddrV4>, ParseConnectionError> {
    parse_tcp_connection(string, parse_socket_addr_v4)
}

/// Parses a TCP IPv6 connection information in the procfs format.
fn parse_tcp_v6_connection(string: &str) -> Result<TcpConnectionInner<std::net::SocketAddrV6>, ParseConnectionError> {
    parse_tcp_connection(string, parse_socket_addr_v6)
}

/// Parses a UDP IPv4 connection information in the procfs format.
fn parse_udp_v4_connection(string: &str) -> Result<UdpConnection, ParseConnectionError> {
    parse_udp_connection(string, parse_socket_addr_v4)
}

/// Parses a UDP IPv6 connection information in the procfs format.
fn parse_udp_v6_connection(string: &str) -> Result<UdpConnection, ParseConnectionError> {
    parse_udp_connection(string, parse_socket_addr_v6)
}

/// Parses a TCP connection information in the procfs format.
fn parse_tcp_connection<A>(
    string: &str,
    parse_socket_addr: fn(&str) -> Result<A, ParseSocketAddrError>,
) -> Result<TcpConnectionInner<A>, ParseConnectionError> {
    // There can be some leading whitespace at the beginning of the line, so
    // in order not to get empty parts, we also trim it.
    let mut parts = string.trim_start().split(char::is_whitespace);

    // `sl` column (whathever that means but it is just a line number), we don't
    // care about it but expect it to be there.
    if parts.next().is_none() {
        return Err(ParseConnectionError::InvalidFormat);
    }

    let local_addr_str = parts.next()
        .ok_or(ParseConnectionError::InvalidFormat)?;
    let local_addr = parse_socket_addr(local_addr_str)
        .map_err(ParseConnectionError::InvalidLocalAddr)?;

    let remote_addr_str = parts.next()
        .ok_or(ParseConnectionError::InvalidFormat)?;
    let remote_addr = parse_socket_addr(remote_addr_str)
        .map_err(ParseConnectionError::InvalidRemoteAddr)?;

    let state_str = parts.next()
        .ok_or(ParseConnectionError::InvalidFormat)?;
    let state = parse_tcp_state(state_str)
        .map_err(ParseConnectionError::InvalidState)?;

    // The line afterwards may contain some ill-formed data and we could raise
    // an error if we detect it. However, we choose to be generous and not to do
    // that to keep things simple. It also makes the code slightly more resilent
    // to potential format changes.

    Ok(TcpConnectionInner {
        local_addr: local_addr,
        remote_addr: remote_addr,
        state,
        pid: 0, // Set at the iterator level where PID is available.
    })
}

/// Parses a UDP connection information in the procfs format.
fn parse_udp_connection<A>(
    string: &str,
    parse_socket_addr: fn(&str) -> Result<A, ParseSocketAddrError>,
) -> Result<UdpConnection, ParseConnectionError>
where
    A: Into<std::net::SocketAddr>,
{
    // We take advantage of the fact that TCP and UDP use the same format (but
    // with remote address and state columns having dummy values).
    let conn = parse_tcp_connection(string, parse_socket_addr)?;

    let remote_addr: std::net::SocketAddr = conn.remote_addr.into();
    if !(remote_addr.ip().is_unspecified() && remote_addr.port() == 0) {
        return Err(ParseConnectionError::InvalidFormat);
    }
    if conn.state != TcpState::Closed {
        return Err(ParseConnectionError::InvalidFormat);
    }

    Ok(UdpConnection {
        local_addr: conn.local_addr.into(),
        pid: 0, // Set at the iterator level where PID is available.
    })
}

/// Parses an IPv4 socket address in the procfs format.
fn parse_socket_addr_v4(string: &str) -> Result<std::net::SocketAddrV4, ParseSocketAddrError> {
    let mut parts = string.split(':');

    let ip_addr_str = parts.next()
        .ok_or(ParseSocketAddrError::InvalidFormat)?;
    let port_str = parts.next()
        .ok_or(ParseSocketAddrError::InvalidFormat)?;

    // There should be only one colon, so the iterator should yield two items.
    if parts.next().is_some() {
        return Err(ParseSocketAddrError::InvalidFormat.into());
    }

    let ip_addr_octets = u32::from_str_radix(ip_addr_str, 16)
        .map_err(|_| ParseSocketAddrError::InvalidIp)?;
    let ip_addr = std::net::Ipv4Addr::from(u32::from_be(ip_addr_octets));

    let port = u16::from_str_radix(port_str, 16)
        .map_err(|_| ParseSocketAddrError::InvalidPort)?;

    Ok(std::net::SocketAddrV4::new(ip_addr, port))
}

/// Parses an IPv6 socket address in the procfs format.
fn parse_socket_addr_v6(string: &str) -> Result<std::net::SocketAddrV6, ParseSocketAddrError> {
    let mut parts = string.split(':');

    let ip_addr_str = parts.next()
        .ok_or(ParseSocketAddrError::InvalidFormat)?;
    let port_str = parts.next()
        .ok_or(ParseSocketAddrError::InvalidFormat)?;

    // There should be only one colon, so the iterator should yield two items.
    if parts.next().is_some() {
        return Err(ParseSocketAddrError::InvalidFormat.into());
    }

    // procfs uses pretty awkward representation of IPv6 address [1, 2]. It is
    // grouped to 4 32-bit integers. Within each integer, each byte is displayed
    // as a 2-digit hexadecimal number. Invidual bytes of the integer (so, two
    // hex digit substrings) are in the host-endian order whereas the integers
    // itself are ordered from the most significant to the least significant.
    //
    // Consider the address: `d3d2:d1d0:c3c2:c1c0:b3b2:b1b0:a3a2:a1a0`. Because
    // of the reasons stated above, the procfs representation of this address
    // changes depending on the endianness of the system:
    //
    //   * little-endian: `D0D1D2D3C0C1C2C3B0B1B2B3A0A1A2A3`
    //   * big-endian: `D3D2D1D0C3C2C1C0B3B2B1B0A3A2A1A0`
    //
    // [1]: https://unix.stackexchange.com/questions/719440/binary-format-of-ipv6-loopback-address
    // [2]: https://github.com/torvalds/linux/blob/bce9332220bd677d83b19d21502776ad555a0e73/net/ipv6/tcp_ipv6.c#L2041-L2066

    fn parse_octets(string: &str) -> Result<[u8; 4], ParseSocketAddrError> {
        assert_eq!(string.len(), 8);

        let octets = u32::from_str_radix(string, 16)
            .map_err(|_| ParseSocketAddrError::InvalidIp)?;

        Ok(u32::from_be(octets).to_be_bytes())
    }

    if ip_addr_str.len() != 32 {
        return Err(ParseSocketAddrError::InvalidIp.into());
    }

    let octets_a = parse_octets(&ip_addr_str[00..08])?;
    let octets_b = parse_octets(&ip_addr_str[08..16])?;
    let octets_c = parse_octets(&ip_addr_str[16..24])?;
    let octets_d = parse_octets(&ip_addr_str[24..32])?;

    let ip_addr = std::net::Ipv6Addr::from([
        octets_a[0], octets_a[1], octets_a[2], octets_a[3],
        octets_b[0], octets_b[1], octets_b[2], octets_b[3],
        octets_c[0], octets_c[1], octets_c[2], octets_c[3],
        octets_d[0], octets_d[1], octets_d[2], octets_d[3],
    ]);

    let port = u16::from_str_radix(port_str, 16)
        .map_err(|_| ParseSocketAddrError::InvalidPort)?;

    // Socket data provided by procfs does not include flow and scope info. We
    // don't really care about them either, so constructing them filled with
    // zeros is fine.
    Ok(std::net::SocketAddrV6::new(ip_addr, port, 0, 0))
}

/// Parses a TCP connection state in the procfs format.
fn parse_tcp_state(string: &str) -> Result<TcpState, ParseTcpStateError> {
    let value = u8::from_str_radix(string, 16)
        .map_err(|_| ParseTcpStateError::UnexpectedInput)?;

    // https://github.com/torvalds/linux/blob/ca57f02295f188d6c65ec02202402979880fa6d8/include/net/tcp_states.h#L12-L27
    let state = match value {
        0x01 => TcpState::Established,
        0x02 => TcpState::SynSent,
        0x03 => TcpState::SynReceived,
        0x04 => TcpState::FinWait1,
        0x05 => TcpState::FinWait2,
        0x06 => TcpState::TimeWait,
        0x07 => TcpState::Closed,
        0x08 => TcpState::CloseWait,
        0x09 => TcpState::LastAck,
        0x0A => TcpState::Listen,
        0x0B => TcpState::Closing,
        0x0C => TcpState::SynReceived,
        _ => return Err(ParseTcpStateError::UnknownState.into()),
    };

    Ok(state)
}

/// An error that might be returned when parsing procfs connection line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ParseConnectionError {
    /// The format of the string is not as it should be.
    InvalidFormat,
    /// It was not possible to parse the local address part.
    InvalidLocalAddr(ParseSocketAddrError),
    /// It was not possible to parse the remote address part.
    InvalidRemoteAddr(ParseSocketAddrError),
    /// It was not possible to parse the connection state part.
    InvalidState(ParseTcpStateError),
}

impl std::fmt::Display for ParseConnectionError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ParseConnectionError::*;
        match *self {
            InvalidFormat => {
                write!(fmt, "invalid connection description format")
            }
            InvalidLocalAddr(error) => {
                write!(fmt, "invalid local address: {}", error)
            }
            InvalidRemoteAddr(error) => {
                write!(fmt, "invalid remote address: {}", error)
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

/// An error that might be returned when parsing procfs socket addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParseSocketAddrError {
    /// The format of the string is not as it should be.
    InvalidFormat,
    /// The IP address is malformed.
    InvalidIp,
    /// The port number is malformed.
    InvalidPort,
}

impl ParseSocketAddrError {

    /// Returns a human-friendly string representation of the error.
    fn as_str(&self) -> &'static str {
        use ParseSocketAddrError::*;
        match *self {
            InvalidFormat => "invalid socket address format",
            InvalidIp => "invalid IP address",
            InvalidPort => "invalid port number",
        }
    }
}

impl std::fmt::Display for ParseSocketAddrError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}", self.as_str())
    }
}

impl std::error::Error for ParseSocketAddrError {
}

/// An error that might be returned when parsing procfs TCP connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ParseTcpStateError {
    /// The input string contained unexpected data.
    UnexpectedInput,
    /// The parsed state identifier is not a known TCP state.
    UnknownState,
}

impl ParseTcpStateError {

    /// Returns a human-friendly string representation of the error.
    fn as_str(&self) -> &'static str {
        use ParseTcpStateError::*;
        match *self {
            UnexpectedInput => "unexpected input",
            UnknownState => "unknown TCP state",
        }
    }
}

impl std::fmt::Display for ParseTcpStateError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}", self.as_str())
    }
}

impl std::error::Error for ParseTcpStateError {
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parse_tcp_v4_connection_ok() {
        let conn = parse_tcp_v4_connection(
            "0: 0400007F:1A29 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 666333 1 0000000000000000 100 0 0 10 0"
        ).unwrap();

        let local_addr = conn.local_addr;
        assert_eq!(local_addr.ip(), &std::net::Ipv4Addr::from([127, 0, 0, 4]));
        assert_eq!(local_addr.port(), 6697);

        let remote_addr = conn.remote_addr;
        assert_eq!(remote_addr.ip(), &std::net::Ipv4Addr::from([0, 0, 0, 0]));
        assert_eq!(remote_addr.port(), 0);

        assert_eq!(conn.state, TcpState::Listen);
    }

    #[test]
    fn parse_tcp_v6_connection_ok() {
        use std::net::Ipv6Addr;

        let conn = parse_tcp_v6_connection(
            "0: 00000000000000000000000000000000:2555 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 666333 1 0000000000000000 100 0 0 10 0"
        ).unwrap();

        let local_addr = conn.local_addr;
        assert_eq!(local_addr.ip(), &"::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(local_addr.port(), 0x2555);

        let remote_addr = conn.remote_addr;
        assert_eq!(remote_addr.ip(), &"::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(remote_addr.port(), 0);

        assert_eq!(conn.state, TcpState::Listen);
    }

    #[test]
    fn parse_udp_v4_connection_ok() {
        let conn = parse_udp_v4_connection(
            "2645: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 6663330 2 0000000000000000 0"
        ).unwrap();

        let local_addr = conn.local_addr;
        assert_eq!(local_addr.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
        assert_eq!(local_addr.port(), 0x0035);
    }

    #[test]
    fn parse_udp_v6_connection_ok() {
        use std::net::IpAddr;

        let conn = parse_udp_v6_connection(
            "7945: 00000000000000000000000000000000:14E9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 111 0 66333 2 0000000000000000 0"
        ).unwrap();

        let local_addr = conn.local_addr;
        assert_eq!(local_addr.ip(), "::".parse::<IpAddr>().unwrap());
        assert_eq!(local_addr.port(), 0x14E9);
    }

    #[test]
    fn parse_tcp_v4_connection_empty() {
        let error = parse_tcp_v4_connection("")
            .unwrap_err();

        assert_eq!(error, ParseConnectionError::InvalidFormat);
    }

    #[test]
    fn parse_tcp_v4_connection_missing_local_addr() {
        let error = parse_tcp_v4_connection("0:")
            .unwrap_err();

        assert_eq!(error, ParseConnectionError::InvalidFormat);
    }

    #[test]
    fn parse_tcp_v4_connection_missing_remote_addr() {
        let error = parse_tcp_v4_connection("0: 00000000:0000")
            .unwrap_err();

        assert_eq!(error, ParseConnectionError::InvalidFormat);
    }

    #[test]
    fn parse_tcp_v4_connection_missing_state() {
        let error = parse_tcp_v4_connection("0: 00000000:0000 00000000:0000")
            .unwrap_err();

        assert_eq!(error, ParseConnectionError::InvalidFormat);
    }

    #[test]
    fn parse_tcp_v4_connection_invalid_local_addr() {
        let error = parse_tcp_v4_connection(
            "0: foobar 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 666333 1 0000000000000000 100 0 0 10 0"
        ).unwrap_err();

        assert!(matches!(error, ParseConnectionError::InvalidLocalAddr(_)));
    }

    #[test]
    fn parse_tcp_v4_connection_invalid_remote_addr() {
        let error = parse_tcp_v4_connection(
            "0: 00000000:0000 foobar 0A 00000000:00000000 00:00000000 00000000 0 0 666333 1 0000000000000000 100 0 0 10 0"
        ).unwrap_err();

        assert!(matches!(error, ParseConnectionError::InvalidRemoteAddr(_)));
    }

    #[test]
    fn parse_tcp_v4_connection_invalid_state() {
        let error = parse_tcp_v4_connection(
            "0: 00000000:0000 00000000:0000 XY 00000000:00000000 00:00000000 00000000 0 0 666333 1 0000000000000000 100 0 0 10 0"
        ).unwrap_err();

        assert!(matches!(error, ParseConnectionError::InvalidState(_)));
    }

    #[test]
    fn parse_udp_v4_connection_unexpected_remote_addr() {
        let error = parse_udp_v4_connection(
            "2645: 0100007F:0035 0100007F:0000 07 00000000:00000000 00:00000000 00000000 0 0 6663330 2 0000000000000000 0"
        ).unwrap_err();

        assert_eq!(error, ParseConnectionError::InvalidFormat);
    }

    #[test]
    fn parse_udp_v4_connection_unexpected_state() {
        let error = parse_udp_v4_connection(
            "2645: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 6663330 2 0000000000000000 0"
        ).unwrap_err();

        assert_eq!(error, ParseConnectionError::InvalidFormat);
    }

    #[test]
    fn parse_socket_addr_v4_zeros() {
        let addr = parse_socket_addr_v4("00000000:0000")
            .unwrap();

        assert_eq!(addr.ip(), &std::net::Ipv4Addr::from([0, 0, 0, 0]));
        assert_eq!(addr.port(), 0);
    }

    #[test]
    fn parse_socket_addr_v4_octets() {
        let addr = parse_socket_addr_v4("0100007F:098C")
            .unwrap();

        assert_eq!(addr.ip(), &std::net::Ipv4Addr::from([127, 0, 0, 1]));
        assert_eq!(addr.port(), 2444);
    }

    #[test]
    fn parse_socket_addr_v6_zeros() {
        let addr = parse_socket_addr_v6("00000000000000000000000000000000:0000")
            .unwrap();

        assert_eq!(addr.ip(), &"::".parse::<std::net::Ipv6Addr>().unwrap());
        assert_eq!(addr.port(), 0);
    }

    #[test]
    fn parse_socket_addr_v6_localhost() {
        #[cfg(target_endian = "little")]
        const PROCFS_ADDR_STR: &str = "00000000000000000000000001000000";

        #[cfg(target_endian = "big")]
        const PROCFS_ADDR_STR: &str = "00000000000000000000000000000001";

        let addr = parse_socket_addr_v6(&format!("{PROCFS_ADDR_STR}:BBF6"))
            .unwrap();

        assert_eq!(addr.ip(), &"::1".parse::<std::net::Ipv6Addr>().unwrap());
        assert_eq!(addr.port(), 48118);
    }

    #[test]
    fn parse_socket_addr_v6_octets() {
        #[cfg(target_endian = "little")]
        const PROCFS_ADDR_STR: &str = "D0D1D2D3C0C1C2C3B0B1B2B3A0A1A2A3";

        #[cfg(target_endian = "big")]
        const PROCFS_ADDR_STR: &str = "D3D2D1D0C3C2C1C0B3B2B1B0A3A2A1A0";

        let addr = parse_socket_addr_v6(&format!("{PROCFS_ADDR_STR}:0000"))
            .unwrap();

        assert_eq!(addr.ip(), &std::net::Ipv6Addr::from([
            0xD3, 0xD2, 0xD1, 0xD0,
            0xC3, 0xC2, 0xC1, 0xC0,
            0xB3, 0xB2, 0xB1, 0xB0,
            0xA3, 0xA2, 0xA1, 0xA0,
        ]));
    }

    #[test]
    fn parse_socket_addr_v4_invalid_ip() {
        let error = parse_socket_addr_v4("foobar:0000")
            .unwrap_err();

        assert_eq!(error, ParseSocketAddrError::InvalidIp);
    }

    #[test]
    fn parse_socket_addr_v6_invalid_ip() {
        let error = parse_socket_addr_v6("foobar:0000")
            .unwrap_err();

        assert_eq!(error, ParseSocketAddrError::InvalidIp);
    }

    #[test]
    fn parse_socket_addr_v4_invalid_port() {
        let error = parse_socket_addr_v4("00000000:foobar")
            .unwrap_err();

        assert_eq!(error, ParseSocketAddrError::InvalidPort);
    }

    #[test]
    fn parse_socket_addr_v6_invalid_port() {
        let error = parse_socket_addr_v6("00000000000000000000000000000000:xyz")
            .unwrap_err();

        assert_eq!(error, ParseSocketAddrError::InvalidPort);
    }

    #[test]
    fn parse_socket_addr_v4_empty() {
        let error = parse_socket_addr_v4("")
            .unwrap_err();

        assert_eq!(error, ParseSocketAddrError::InvalidFormat);
    }

    #[test]
    fn parse_socket_addr_v4_missing_port() {
        let error = parse_socket_addr_v4("00000000")
            .unwrap_err();

        assert_eq!(error, ParseSocketAddrError::InvalidFormat);
    }

    #[test]
    fn parse_socket_addr_v4_extra_col() {
        let error = parse_socket_addr_v4("00000000:0000:0000")
            .unwrap_err();

        assert_eq!(error, ParseSocketAddrError::InvalidFormat);
    }

    #[test]
    fn parse_socket_addr_v6_empty() {
        let error = parse_socket_addr_v6("")
            .unwrap_err();

        assert_eq!(error, ParseSocketAddrError::InvalidFormat);
    }

    #[test]
    fn parse_socket_addr_v6_missing_port() {
        let error = parse_socket_addr_v6("00000000000000000000000000000000")
            .unwrap_err();

        assert_eq!(error, ParseSocketAddrError::InvalidFormat);
    }

    #[test]
    fn parse_socket_addr_v6_extra_col() {
        let error = parse_socket_addr_v6("00000000000000000000000000000000:0000:0000")
            .unwrap_err();

        assert_eq!(error, ParseSocketAddrError::InvalidFormat);
    }

    #[test]
    fn parse_tcp_state_ok() {
        let state = parse_tcp_state("0A")
            .unwrap();

        assert_eq!(state, TcpState::Listen);
    }

    #[test]
    fn parse_tcp_state_unexpected_input() {
        let error = parse_tcp_state("foobar")
            .unwrap_err();

        assert_eq!(error, ParseTcpStateError::UnexpectedInput);
    }

    #[test]
    fn parse_tcp_state_unknown_state() {
        let error = parse_tcp_state("42")
            .unwrap_err();

        assert_eq!(error, ParseTcpStateError::UnknownState);
    }
}
