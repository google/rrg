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
/// This function is a wrapper around [`getifaddrs`][1] macOS call.
///
/// [1]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getifaddrs.3.html
///
/// [`interfaces`]: super::interfaces
pub fn interfaces() -> std::io::Result<impl Iterator<Item = Interface>> {
    // Note that the this function is implemented nearly identically to the
    // Linux one. However, despite identical structure names (except for the
    // MAC address structure), their memory layout is completely different and
    // the code cannot (or rather: it should not) be shared.
    let mut addrs = std::mem::MaybeUninit::uninit();

    // SAFETY: `getifaddrs` [1] returns a pointer (through an output parameter)
    // so there is no potential of unsafety here and the function is marked as
    // such because it operates on raw pointers.
    //
    // [1]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getifaddrs.3.html
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

        // SAFETY: `ifa_name` is a string with interface name. While Apple docs
        // do not mention whether it is null-terminated, it is a safe bet to
        // assume so given the similarity to the Linux version of `getifaddrs`.
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
                // SAFETY: For `AF_INET` family the `ifa_addr` field is instance
                // of the IPv4 address [1, 2]. Again, the documentation on this
                // is quite bad.
                //
                // [1]: https://developer.apple.com/documentation/kernel/sockaddr_in
                // [2]: https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/netinet/in.h#L394-L403
                let ipv4_addr_u32 = unsafe {
                    *(addr.ifa_addr as *const libc::sockaddr_in)
                }.sin_addr.s_addr;

                // Unlike on Linux, Apple documentation does not say anything
                // whatsoever about the endianness of the address value [1, 2].
                // We give them the benefit of a doubt and assume that they do
                // a sane thing and follow the Linux convention here.
                //
                // Hence, we have to convert from network endian (big endian)
                // order to what the Rust IPv4 type constructor expects (host
                // endian).
                //
                // [1]: https://developer.apple.com/documentation/kernel/in_addr_t
                // [2]: https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/sys/_types/_in_addr_t.h#L31
                let ipv4_addr_u32 = u32::from_be(ipv4_addr_u32);

                let ipv4_addr = std::net::Ipv4Addr::from(ipv4_addr_u32);
                entry.ip_addrs.push(ipv4_addr.into());
            }
            libc::AF_INET6 => {
                // SAFETY: For `AF_INET6` family the `ifa_addr` field is an
                // instance of the IPv6 address [1, 2]. The comment on the
                // `sin6_family` field confirms it (unlike for `AF_INET`). Thus,
                // the case is safe.
                //
                // [1]: https://developer.apple.com/documentation/kernel/sockaddr_in6
                // [2]: https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/netinet6/in6.h#L181-L188
                let ipv6_addr_octets = unsafe {
                    *(addr.ifa_addr as *const libc::sockaddr_in6)
                }.sin6_addr.s6_addr;

                let ipv6_addr = std::net::Ipv6Addr::from(ipv6_addr_octets);
                entry.ip_addrs.push(ipv6_addr.into());
            }
            libc::AF_LINK => {
                // SAFETY: For `AF_LINK` family the `ifa_addr` field is an
                // instance of a link-level address [1, 2] (whatever that means
                // exactly). Again, the comment on the `sdl_family` field seems
                // to confirm this and the cast is safe.
                //
                // [1]: https://developer.apple.com/documentation/kernel/sockaddr_dl
                // [2]: https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/net/if_dl.h#L95-L110
                let sockaddr = unsafe {
                    *(addr.ifa_addr as *const libc::sockaddr_dl)
                };

                // Unfortunatelly, it is not uncommon to have some other non-MAC
                // addresses with the `AF_LINK` family. We simply ignore such.
                if sockaddr.sdl_alen != 6 {
                    continue;
                }

                // SAFETY: The original `sdl_data` is typed as `i8` (because it
                // contains the name) but the actual address bytes should be in-
                // terpreted as normal bytes (verified empirically). Validity of
                // indexing is ensured by the `sdl_alen` check above.
                let mac_addr = unsafe {
                    let data = sockaddr.sdl_data.as_ptr()
                        .offset(isize::from(sockaddr.sdl_nlen))
                        .cast::<u8>();

                    MacAddr::from([
                        *data.offset(0),
                        *data.offset(1),
                        *data.offset(2),
                        *data.offset(3),
                        *data.offset(4),
                        *data.offset(5),
                    ])
                };

                // TODO: There should only be one MAC address associated with
                // a given interface. Consider logging a warning in case this
                // assumption does not hold.
                entry.mac_addr.replace(mac_addr);
            }
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
    // [1]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/freeifaddrs.3.html
    unsafe {
        libc::freeifaddrs(addrs);
    }

    Ok(ifaces.into_iter())
}

/// Returns an iterator over IPv4 TCP connections for the specified process.
pub fn tcp_v4_connections(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnection>>> {
    use std::convert::TryFrom as _;

    let pid_i32 = i32::try_from(pid)
        .map_err(|_| std::io::ErrorKind::InvalidInput)?;

    // SAFETY: We call the function with null buffer. This should return the
    // size for the buffer that we need or 0 in case of an error.
    let buf_size = unsafe {
        libc::proc_pidinfo(pid_i32, crate::libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
    };
    if buf_size == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let buf_layout = std::alloc::Layout::from_size_align(
        buf_size as usize,
        std::mem::align_of::<crate::libc::proc_fdinfo>(),
    ).expect("invalid layout for `proc_fdinfo` struct");

    let buf = crate::alloc::Allocation::new(buf_layout)
        .ok_or_else(|| std::io::ErrorKind::OutOfMemory)?;

    let buf_ptr = buf.as_ptr().cast::<libc::c_void>().as_ptr();

    // SAFETY: We call the function as above but with allocated buffer. Both the
    // buffer and the passed size are correct with respect to each other. Again,
    // the fucntion will return 0 in case of an error.
    let buf_size = unsafe {
        libc::proc_pidinfo(pid_i32, crate::libc::PROC_PIDLISTFDS, 0, buf_ptr, buf_size)
    };
    if buf_size == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Note that we calculate the number of records after the second call since
    // the number of records estimated by the first call may no longer be valid
    // at the time we do the second call.
    let fdinfos_len = buf_size as usize / std::mem::size_of::<crate::libc::proc_fdinfo>();

    // SAFETY: The call to `proc_pidinfo` succeeded, so the buffer should be
    // filled with the amount of records as calculated above.
    let fdinfos = unsafe {
        std::slice::from_raw_parts(buf_ptr.cast::<crate::libc::proc_fdinfo>(), fdinfos_len)
    };

    let mut conns = Vec::new();

    for fdinfo in fdinfos {
        if fdinfo.proc_fdtype != crate::libc::PROX_FDTYPE_SOCKET as u32 {
            continue;
        }

        let mut sock_fdinfo = std::mem::MaybeUninit::<crate::libc::socket_fdinfo>::uninit();

        // SAFETY: We verify that the file descriptor corresponds to a socket
        // above and then we just pass a pointer to `sock_fdinfo` along with its
        // size. In case something goes wrong, the function should report an
        // error (which we verify below) but the call itself should be safe.
        let size = unsafe {
            libc::proc_pidfdinfo(
                pid_i32,
                fdinfo.proc_fd,
                crate::libc::PROC_PIDFDSOCKETINFO,
                sock_fdinfo.as_mut_ptr().cast::<libc::c_void>(),
                std::mem::size_of::<crate::libc::socket_fdinfo>() as i32,
            )
        };

        if size == 0 || size < std::mem::size_of::<crate::libc::socket_fdinfo>() as i32 {
            return Err(std::io::Error::last_os_error());
        }

        // SAFETY: We verified that the call prod `proc_pidfdinfo` succeeded,
        // so `sock_fdinfo` should be filled with valid data now.
        let sock_fdinfo = unsafe {
            sock_fdinfo.assume_init()
        };

        match sock_fdinfo.psi.soi_family {
            libc::AF_INET => {
                // SAFETY: We verified that we have a TCP IPv4 socket, so we can
                // safely access the `pri_tcp` field.
                let conn = unsafe {
                    parse_tcp_v4_sockinfo(pid, sock_fdinfo.psi.soi_proto.pri_tcp)
                }.map_err(|error| error.into());
                conns.push(conn);
            }
            _ => continue,
        }
    }

    Ok(conns.into_iter())
}

/// Returns an iterator over IPv6 TCP connections for the specified process.
pub fn tcp_v6_connections(_pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnection>>> {
    // TODO: Implement this function.
    Err::<std::iter::Empty<_>, _>(std::io::ErrorKind::Unsupported.into())
}

/// Returns an iterator over IPv4 UDP connections for the specified process.
pub fn udp_v4_connections(_pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnection>>> {
    // TODO: Implement this function.
    Err::<std::iter::Empty<_>, _>(std::io::ErrorKind::Unsupported.into())
}

/// Returns an iterator over IPv6 UDP connections for the specified process.
pub fn udp_v6_connections(_pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnection>>> {
    // TODO: Implement this function.
    Err::<std::iter::Empty<_>, _>(std::io::ErrorKind::Unsupported.into())
}

/// Parses a macOS TCP IPv4 socket metadata into platform-agnostic type.
///
/// # Safety
///
/// The caller must ensure that `info` was constructed by an appropriate call
/// to `proc_pidfdinfo`.
unsafe fn parse_tcp_v4_sockinfo(
    pid: u32,
    info: crate::libc::tcp_sockinfo,
) -> Result<TcpConnection, ParseConnectionError> {
    use std::convert::TryFrom as _;
    use ParseConnectionError::*;

    if info.tcpsi_ini.insi_vflag != crate::libc::INI_IPV4 as u8 {
        return Err(InvalidProtocolFlag(info.tcpsi_ini.insi_vflag));
    }

    // SAFETY: We verified that we are dealing with a TCP IPv4 socket above, so
    // we are allowed to access the IPv4 address. Note that the function is
    // nevertheless marked "unsafe" in case somebody passes ill-formed metadata.
    let remote_addr_u32 = unsafe {
        info.tcpsi_ini.insi_faddr.ina_46.i46a_addr4
    }.s_addr;

    // Unlike on Linux, Apple documentation does not say anything
    // whatsoever about the endianness of the address value [1, 2].
    // We give them the benefit of a doubt and assume that they do
    // a sane thing and follow the Linux convention here.
    //
    // Hence, we have to convert from network endian (big endian)
    // order to what the Rust IPv4 type constructor expects (host
    // endian).
    //
    // [1]: https://developer.apple.com/documentation/kernel/in_addr_t
    // [2]: https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/sys/_types/_in_addr_t.h#L31
    let remote_addr_u32 = u32::from_be(remote_addr_u32);
    let remote_addr = std::net::Ipv4Addr::from(remote_addr_u32);

    let remote_port = u16::try_from(info.tcpsi_ini.insi_fport)
        .map_err(|_| InvalidRemotePort(info.tcpsi_ini.insi_fport))?;

    // SAFETY: Same as with `remote_addr`.
    // TODO(@panhania): Verify whether we need to change endianness
    // like it is done in Linux case.
    let local_addr_u32 = unsafe {
        info.tcpsi_ini.insi_laddr.ina_46.i46a_addr4
    }.s_addr;

    // See the comment above about we have to perform the endianness
    // correction.
    let local_addr_u32 = u32::from_be(local_addr_u32);
    let local_addr = std::net::Ipv4Addr::from(local_addr_u32);

    let local_port = u16::try_from(info.tcpsi_ini.insi_lport)
        .map_err(|_| InvalidLocalPort(info.tcpsi_ini.insi_lport))?;

    Ok(TcpConnection {
        local_addr: (local_addr, local_port).into(),
        remote_addr: (remote_addr, remote_port).into(),
        state: parse_tcp_state(info.tcpsi_state)?,
        pid,
    })
}

/// Parses a macOS TCP IPv6 socket metadata into platform-agnostic type.
///
/// # Safety
///
/// The caller must ensure that `info` was constructed by an appropriate call
/// to `proc_pidfdinfo`.
unsafe fn parse_tcp_v6_sockinfo(
    pid: u32,
    info: crate::libc::tcp_sockinfo,
) -> Result<TcpConnection, ParseConnectionError> {
    use std::convert::TryFrom as _;
    use ParseConnectionError::*;

    if info.tcpsi_ini.insi_vflag != crate::libc::INI_IPV6 as u8 {
        return Err(InvalidProtocolFlag(info.tcpsi_ini.insi_vflag));
    }

    // SAFETY: We verified that we are dealing with a TCP IPv6 socket above, so
    // we are allowed to access the IPv6 address. Note that the function is
    // nevertheless marked "unsafe" in case somebody passes ill-formed metadata.
    let remote_addr_octets = unsafe {
        info.tcpsi_ini.insi_faddr.ina_6
    }.s6_addr;

    let remote_addr = std::net::Ipv6Addr::from(remote_addr_octets);
    let remote_port = u16::try_from(info.tcpsi_ini.insi_fport)
        .map_err(|_| InvalidRemotePort(info.tcpsi_ini.insi_fport))?;

    // SAFETY: Same as with `local_addr`.
    let local_addr_octets = unsafe {
        info.tcpsi_ini.insi_laddr.ina_6
    }.s6_addr;

    let local_addr = std::net::Ipv6Addr::from(local_addr_octets);
    let local_port = u16::try_from(info.tcpsi_ini.insi_lport)
        .map_err(|_| InvalidLocalPort(info.tcpsi_ini.insi_lport))?;

    Ok(TcpConnection {
        local_addr: (local_addr, local_port).into(),
        remote_addr: (remote_addr, remote_port).into(),
        state: parse_tcp_state(info.tcpsi_state)?,
        pid,
    })
}

/// An error that might be returned when interpreting macOS TCP socket metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ParseConnectionError {
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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn interfaces_loopback_exists() {
        let mut ifaces = interfaces().unwrap();

        // On macOS the loopback interface seems to be always named `lo0` but it
        // does not appear to be documented anywhere, so to be on the safe side
        // we do not make such specific assertions.
        assert! {
            ifaces.any(|iface| {
                iface.ip_addrs().iter().any(|ip_addr| {
                    ip_addr.is_loopback()
                })
            })
        };
    }
}
