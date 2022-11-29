// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use super::*;

/// Collects information about available network interfaces.
///
/// A system agnostic [`interfaces`] function is available in the parent module
/// and should be the preferred choice in general.
///
/// This function is a wrapper around [`getifaddrs`][1] Linux call.
///
/// [1]: https://man7.org/linux/man-pages/man3/getifaddrs.3.html
///
/// [`interfaces`]: super::interfaces
pub fn interfaces() -> std::io::Result<impl Iterator<Item = Interface>> {
    let mut addrs = std::mem::MaybeUninit::uninit();

    // SAFETY: `getifaddrs` [1] returns a pointer (through an output parameter)
    // so there is no potential of unsafety here and the function is marked as
    // such because it operates on raw pointers.
    //
    // [1]: https://man7.org/linux/man-pages/man3/getifaddrs.3.html
    let code = unsafe {
        libc::getifaddrs(addrs.as_mut_ptr())
    };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code));
    }

    // SAFETY: We check return code above. If there was no error, `getifaddrs`
    // should initialized the `addrs` variable to a correct value.
    let addrs = unsafe {
        addrs.assume_init()
    };

    let mut ifaces = std::collections::HashMap::new();

    let mut addr_iter = addrs;
    // SAFETY: We iterate over the linked list of addresses until we hit the
    // last entry. The validity of the `addr_iter` pointer is ensured by:
    //
    //   * Starting at the value reported by the `getifaddrs` call.
    //   * Always moving to the entry pointed by the `ifa_next` field (at the
    //     end of the loop).
    while let Some(addr) = unsafe { addr_iter.as_ref() } {
        use std::os::unix::ffi::OsStrExt as _;

        // We advance the iterator immediately to avoid getting stuck because of
        // the `continue` statements in the code below.
        addr_iter = addr.ifa_next;

        // SAFETY: `ifa_ddr` is not guaranteed to be not null, so we have to
        // verify it. But if it is not null, it is guaranteed to point to valid
        // address instance.
        let family = match unsafe { addr.ifa_addr.as_ref() } {
            Some(addr) => addr.sa_family,
            None => continue,
        };

        // SAFETY: `ifa_name` is guaranteed to point to a null-terminated string
        // with interface name.
        let name = std::ffi::OsStr::from_bytes(unsafe {
            std::ffi::CStr::from_ptr(addr.ifa_name)
        }.to_bytes());

        let entry = ifaces.entry(name).or_insert(Interface {
            name: name.to_os_string(),
            ip_addrs: Vec::new(),
            mac_addr: None,
        });

        match i32::from(family) {
            libc::AF_INET => {
                // SAFETY: For `AF_INET` family, it is guaranteed that the
                // `ifa_addr` field contains a pointer to a valid IPv4 socket
                // address struct [1].
                //
                // [1]: https://man7.org/linux/man-pages/man7/ip.7.html
                let ipv4_addr_u32 = unsafe {
                    *(addr.ifa_addr as *const libc::sockaddr_in)
                }.sin_addr.s_addr;

                // `s_addr` value is in the network endian (big endian) order
                // but the IPv4 constructor expects a host endian order value.
                // Thus, we have to convert from one to another.
                let ipv4_addr_u32 = u32::from_be(ipv4_addr_u32);

                let ipv4_addr = std::net::Ipv4Addr::from(ipv4_addr_u32);
                entry.ip_addrs.push(ipv4_addr.into());
            }
            libc::AF_INET6 => {
                // SAFETY: For `AF_INET6` family, it is guaranteed that the
                // `ifa_addr` field contains a pointer to a valid IPv6 socket
                // address struct [1].
                //
                // [1]: https://man7.org/linux/man-pages/man7/ipv6.7.html
                let ipv6_addr_octets = unsafe {
                    *(addr.ifa_addr as *const libc::sockaddr_in6)
                }.sin6_addr.s6_addr;

                let ipv6_addr = std::net::Ipv6Addr::from(ipv6_addr_octets);

                entry.ip_addrs.push(ipv6_addr.into());
            },
            libc::AF_PACKET => {
                // SAFETY: For `AF_PACKET family, it is guaranteed that the
                // `ifa_add` field contains a pointer to a valid physical-layer
                // address struct [1].
                //
                //
                // [1]: https://man7.org/linux/man-pages/man7/packet.7.html
                let sockaddr = unsafe {
                    *(addr.ifa_addr as *const libc::sockaddr_ll)
                };

                // MAC addresses should always have 6 8-bit octets. It is not
                // clear whether `sll_halen` value can ever be different but we
                // check just to be sure and skip if the assumption does not
                // hold.
                if sockaddr.sll_halen != 6 {
                    // TODO: Consider logging an error.
                    continue;
                }

                let mac_addr = MacAddr::from([
                    sockaddr.sll_addr[0],
                    sockaddr.sll_addr[1],
                    sockaddr.sll_addr[2],
                    sockaddr.sll_addr[3],
                    sockaddr.sll_addr[4],
                    sockaddr.sll_addr[5],
                ]);

                // TODO: There should only be one MAC address associated with
                // a given interface. Consider logging a warning in case this
                // assumption does not hold.
                entry.mac_addr.replace(mac_addr);
            },
            _ => continue,
        }
    }

    // We need to collect the interfaces to free the addresses below. Otherwise,
    // the keys of the hash map will point to dangling references (since the map
    // keys are owned by the address list).
    let ifaces = ifaces.into_values().collect::<Vec<_>>();

    // SAFETY: The `getifaddrs` call at the beginning of this function creates
    // a linked list that we are responsible for freeing using the `freeifaddrs`
    // function [1]. This is safe as we never release the allocated memory.
    //
    // [1]: https://linux.die.net/man/3/freeifaddrs
    unsafe {
        libc::freeifaddrs(addrs);
    }

    Ok(ifaces.into_iter())
}

/// Parses an IPv4 socket address in the procfs format.
fn parse_socket_addr_v4(string: &str) -> Result<std::net::SocketAddrV4, ParseSocketAddrError> {
    let mut parts = string.split(':');

    let ip_addr_str = parts.next()
        .ok_or(ParseSocketAddrErrorKind::InvalidFormat)?;
    let port_str = parts.next()
        .ok_or(ParseSocketAddrErrorKind::InvalidFormat)?;

    // There should be only one colon, so the iterator should yield two items.
    if parts.next().is_some() {
        return Err(ParseSocketAddrErrorKind::InvalidFormat.into());
    }

    let ip_addr_octets = u32::from_str_radix(ip_addr_str, 16)
        .map_err(|_| ParseSocketAddrErrorKind::InvalidIp)?;
    let ip_addr = std::net::Ipv4Addr::from(u32::from_be(ip_addr_octets));

    let port = u16::from_str_radix(port_str, 16)
        .map_err(|_| ParseSocketAddrErrorKind::InvalidPort)?;

    Ok(std::net::SocketAddrV4::new(ip_addr, port))
}

/// Parses an IPv6 socket address in the procfs format.
fn parse_socket_addr_v6(string: &str) -> Result<std::net::SocketAddrV6, ParseSocketAddrError> {
    let mut parts = string.split(':');

    let ip_addr_str = parts.next()
        .ok_or(ParseSocketAddrErrorKind::InvalidFormat)?;
    let port_str = parts.next()
        .ok_or(ParseSocketAddrErrorKind::InvalidFormat)?;

    // There should be only one colon, so the iterator should yield two items.
    if parts.next().is_some() {
        return Err(ParseSocketAddrErrorKind::InvalidFormat.into());
    }

    let ip_addr_octets = u128::from_str_radix(ip_addr_str, 16)
        .map_err(|_| ParseSocketAddrErrorKind::InvalidIp)?;
    let ip_addr = std::net::Ipv6Addr::from(u128::from_be(ip_addr_octets));

    let port = u16::from_str_radix(port_str, 16)
        .map_err(|_| ParseSocketAddrErrorKind::InvalidPort)?;

    // Socket data provided by procfs does not include flow and scope info. We
    // don't really care about them either, so constructing them filled with
    // zeros is fine.
    Ok(std::net::SocketAddrV6::new(ip_addr, port, 0, 0))
}

/// An error that might be returned when parsing procfs socket addresses.
#[derive(Clone, Debug)]
pub struct ParseSocketAddrError(ParseSocketAddrErrorKind);

/// A list of cases that can happen when parsing of procfs socket addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParseSocketAddrErrorKind {
    /// The format of the string is not as it should be.
    InvalidFormat,
    /// The IP address is malformed.
    InvalidIp,
    /// The port number is malformed.
    InvalidPort,
}

impl ParseSocketAddrError {

    /// Returns the details of what caused the error to be raised.
    pub fn kind(&self) -> ParseSocketAddrErrorKind {
        self.0
    }
}

impl ParseSocketAddrErrorKind {

    /// Returns a human-friendly string representation of the error kind.
    fn as_str(&self) -> &'static str {
        use ParseSocketAddrErrorKind::*;
        match *self {
            InvalidFormat => "invalid socket address format",
            InvalidIp => "invalid IP address",
            InvalidPort => "invalid port number",
        }
    }
}

impl std::fmt::Display for ParseSocketAddrErrorKind {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}", self.as_str())
    }
}

impl From<ParseSocketAddrErrorKind> for ParseSocketAddrError {

    fn from(kind: ParseSocketAddrErrorKind) -> ParseSocketAddrError {
        ParseSocketAddrError(kind)
    }
}

impl std::fmt::Display for ParseSocketAddrError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}", self.0)
    }
}

impl std::error::Error for ParseSocketAddrError {
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn loopback_exists() {
        let loopback = interfaces().unwrap()
            .find(|iface| iface.name() == "lo")
            .unwrap();

        assert! {
            loopback.ip_addrs().iter().all(|ip_addr| ip_addr.is_loopback())
        };
        assert_eq! {
            loopback.mac_addr(), Some(&MacAddr::from([0, 0, 0, 0, 0, 0]))
        };
    }

    #[test]
    fn parse_socket_addr_v4_zeros() {
        let addr = parse_socket_addr_v4("00000000:0000")
            .unwrap();

        assert_eq!(addr.ip(), &std::net::Ipv4Addr::from([0, 0, 0, 0]));
        assert_eq!(addr.port(), 0);
    }

    #[test]
    fn parse_socket_addr_v4_ok() {
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
    fn parse_socket_addr_v6_ok() {
        let addr = parse_socket_addr_v6("00000000000000000000000001000000:BBF6")
            .unwrap();

        assert_eq!(addr.ip(), &"0:1::".parse::<std::net::Ipv6Addr>().unwrap());
        assert_eq!(addr.port(), 48118);
    }


    #[test]
    fn parse_socket_addr_v4_invalid_ip() {
        let error = parse_socket_addr_v4("foobar:0000")
            .unwrap_err();

        assert_eq!(error.kind(), ParseSocketAddrErrorKind::InvalidIp);
    }

    #[test]
    fn parse_socket_addr_v6_invalid_ip() {
        let error = parse_socket_addr_v6("foobar:0000")
            .unwrap_err();

        assert_eq!(error.kind(), ParseSocketAddrErrorKind::InvalidIp);
    }

    #[test]
    fn parse_socket_addr_v4_invalid_port() {
        let error = parse_socket_addr_v4("00000000:foobar")
            .unwrap_err();

        assert_eq!(error.kind(), ParseSocketAddrErrorKind::InvalidPort);
    }

    #[test]
    fn parse_socket_addr_v6_invalid_port() {
        let error = parse_socket_addr_v6("00000000000000000000000000000000:xyz")
            .unwrap_err();

        assert_eq!(error.kind(), ParseSocketAddrErrorKind::InvalidPort);
    }

    #[test]
    fn parse_socket_addr_v4_empty() {
        let error = parse_socket_addr_v4("")
            .unwrap_err();

        assert_eq!(error.kind(), ParseSocketAddrErrorKind::InvalidFormat);
    }

    #[test]
    fn parse_socket_addr_v4_missing_port() {
        let error = parse_socket_addr_v4("00000000")
            .unwrap_err();

        assert_eq!(error.kind(), ParseSocketAddrErrorKind::InvalidFormat);
    }

    #[test]
    fn parse_socket_addr_v4_extra_col() {
        let error = parse_socket_addr_v4("00000000:0000:0000")
            .unwrap_err();

        assert_eq!(error.kind(), ParseSocketAddrErrorKind::InvalidFormat);
    }

    #[test]
    fn parse_socket_addr_v6_empty() {
        let error = parse_socket_addr_v6("")
            .unwrap_err();

        assert_eq!(error.kind(), ParseSocketAddrErrorKind::InvalidFormat);
    }

    #[test]
    fn parse_socket_addr_v6_missing_port() {
        let error = parse_socket_addr_v6("00000000000000000000000000000000")
            .unwrap_err();

        assert_eq!(error.kind(), ParseSocketAddrErrorKind::InvalidFormat);
    }

    #[test]
    fn parse_socket_addr_v6_extra_col() {
        let error = parse_socket_addr_v6("00000000000000000000000000000000:0000:0000")
            .unwrap_err();

        assert_eq!(error.kind(), ParseSocketAddrErrorKind::InvalidFormat);
    }
}
