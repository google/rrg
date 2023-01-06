// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use super::*;

mod conn;

/// Collects information about available network interfaces.
///
/// A system agnostic [`interfaces`] function is available in the parent module
/// and should be the preferred choice in general.
///
/// This function is a wrapper around [`GetAdaptersAddresses`][1] Windows call.
///
/// [1]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
///
/// [`interfaces`]: super::interfaces
pub fn interfaces() -> std::io::Result<impl Iterator<Item = Interface>> {
    use std::convert::TryFrom as _;

    use windows_sys::Win32::NetworkManagement::IpHelper::*;

    let mut buf_size = u32::try_from(DEFAULT_BUF_SIZE)
        .expect("default buffer size too big");

    let buf_layout = std::alloc::Layout::from_size_align(
        buf_size as usize,
        std::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>(),
    ).expect("invalid layout for adapter addresses table");

    let mut buf = crate::alloc::Allocation::new(buf_layout)
        .ok_or_else(|| std::io::ErrorKind::OutOfMemory)?;

    // SAFETY: We call the function as described in the official docs [1]. In
    // case the allocated buffer is too small, we handle this case below.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses#parameters
    let mut code = unsafe {
        GetAdaptersAddresses(
            // `AF_UNSPEC` will get addresses of both IPv4 and IPv6 adapters.
            windows_sys::Win32::Networking::WinSock::AF_UNSPEC,
            // Probably we don't need any extra information.
            0,
            std::ptr::null_mut(),
            buf.as_ptr().cast().as_ptr(),
            &mut buf_size,
        )
    };

    if code == windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW {
        // Just a sanity check. Since the default buffer was too small, a "good"
        // one should be strictly bigger.
        assert!(DEFAULT_BUF_SIZE < (buf_size as usize));

        buf = buf.resize(buf_size as usize)
            .map_err(|_| std::io::ErrorKind::OutOfMemory)?;

        // SAFETY: We call the function the same as above but with larger result
        // buffer. Note that this can still fail in an unlikely case where a new
        // device was added between the previous call and this one. However, we
        // do not do another attempt and fail if this is the case.
        code = unsafe {
            GetAdaptersAddresses(
                // `AF_UNSPEC` will get addresses of both IPv4 and IPv6 adapters.
                windows_sys::Win32::Networking::WinSock::AF_UNSPEC,
                // Probably we don't need any extra information.
                0,
                std::ptr::null_mut(),
                buf.as_ptr().cast().as_ptr(),
                &mut buf_size,
            )
        };
    }

    if code != windows_sys::Win32::Foundation::NO_ERROR {
        let code = i32::try_from(code)
            .expect("invalid error code");

        return Err(std::io::Error::from_raw_os_error(code));
    }

    let mut ifaces = std::collections::HashMap::new();

    let mut addr_iter = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>().as_ptr();
    // SAFETY: We validate that the `GetAdaptersAddresses` call above did not
    // fail. Thus, the buffer was filled with valid data and now we can iterate
    // over the list using the `Next` pointers [1, 2].
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
    // [2]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses#examples
    while let Some(addr) = unsafe { addr_iter.as_ref() } {
        use std::os::windows::ffi::OsStringExt as _;

        // SAFETY: While the documentation does not say explicitly that `Name`
        // is null-terminated this is clear from Microsoft examples (the value
        // is used for `%s` formatting directive value which expects a null-ter-
        // minated string).
        let name = unsafe {
            std::ffi::CStr::from_ptr(addr.AdapterName.cast())
        };

        let name_wide = name.to_bytes().iter()
            .map(|byte| u16::from(*byte))
            .collect::<Vec<_>>();

        let name = std::ffi::OsString::from_wide(name_wide.as_slice());

        let mac_addr = if addr.PhysicalAddressLength != 6 {
            // MAC addresses should have 6 bytes, otherwise this is something
            // unexpected.
            // TODO: Consider logging an error.
            None
        } else {
            Some(MacAddr::from([
                addr.PhysicalAddress[0],
                addr.PhysicalAddress[1],
                addr.PhysicalAddress[2],
                addr.PhysicalAddress[3],
                addr.PhysicalAddress[4],
                addr.PhysicalAddress[5],
            ]))
        };

        // It's not the best that we have to clone `name` here to avoid borrow-
        // checker yelling at us, but considering all the cycles wasted above
        // on re-typing the string, it is a small price to pay anyway.
        let entry = ifaces.entry(name.clone()).or_insert(Interface {
            name: name,
            ip_addrs: Vec::new(),
            mac_addr: mac_addr,
        });

        let mut sock_addr_iter = addr.FirstAnycastAddress;
        // SAFETY: We simply iterate on a linked list built by the system [1].
        // The list is terminated with a null node for which we check below to
        // end the iteration.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
        while let Some(sock_addr) = unsafe { sock_addr_iter.as_ref() } {
            // SAFETY: The structure is built by the operating system and so the
            // pointer (as long as it is not null, which we verify above) should
            // point to a valid address, making the dereference safe.
            let family = unsafe {
                *sock_addr.Address.lpSockaddr
            }.sa_family;

            match u32::from(family) {
                windows_sys::Win32::Networking::WinSock::AF_INET => {
                    use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN;

                    // SAFETY: For `AF_INET` family, the address is guaranteed
                    // to be a valid instance of the `SOCKADDR_IN` struct [1].
                    //
                    // [1]: https://learn.microsoft.com/en-us/windows/win32/winsock/sockaddr-2
                    let sock_addr = unsafe {
                        *(sock_addr.Address.lpSockaddr as *const SOCKADDR_IN)
                    };

                    // SAFETY: Accessing this union is safe because these are
                    // just alternative ways to "view" the data [1]. We use the
                    // "octets" view rather than the "single-integer" view not
                    // to deal with endianess shenanigans.
                    //
                    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-in_addr
                    let ipv4_addr_octets = unsafe {
                        sock_addr.sin_addr.S_un.S_un_b
                    };

                    let ipv4_addr = std::net::Ipv4Addr::from([
                        ipv4_addr_octets.s_b1,
                        ipv4_addr_octets.s_b2,
                        ipv4_addr_octets.s_b3,
                        ipv4_addr_octets.s_b4,
                    ]);

                    entry.ip_addrs.push(ipv4_addr.into());
                },
                windows_sys::Win32::Networking::WinSock::AF_INET6 => {
                    use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6;

                    // SAFETY: For `AF_INET6` family, the address is guaranteed
                    // to be a valid instance of the `SOCKADDR_IN6` struct [1].
                    //
                    // [1]: https://learn.microsoft.com/en-us/windows/win32/winsock/sockaddr-2
                    let sock_addr = unsafe {
                        *(sock_addr.Address.lpSockaddr as *const SOCKADDR_IN6)
                    };

                    // SAFETY: Accessing this union is safe because these are
                    // just alternative ways to "view" the data [1]. We use the
                    // "octets" view rather than the "wide" view because this is
                    // what the `Ipv6Addr` type constructor expects.
                    //
                    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/in6addr/ns-in6addr-in6_addr
                    let ipv6_addr_octets = unsafe {
                        sock_addr.sin6_addr.u.Byte
                    };

                    let ipv6_addr = std::net::Ipv6Addr::from(ipv6_addr_octets);

                    entry.ip_addrs.push(ipv6_addr.into());
                },
                _ => {
                    // TODO: Consider logging a warning.
                    continue
                },
            }

            sock_addr_iter = sock_addr.Next;
        }

        addr_iter = addr.Next;
    }

    Ok(ifaces.into_values())
}

/// Returns an iterator over IPv4 TCP connections for the specified process.
pub fn tcp_v4_connections(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnection>>> {
    let iter = all_tcp_v4_connections()?
        // TODO: Consider logging a warning before discarding the record.
        .filter_map(|conn| conn.ok())
        .filter(move |conn| conn.pid == pid)
        .map(Ok);

    Ok(iter)
}

/// Returns an iterator over IPv6 TCP connections for the specified process.
pub fn tcp_v6_connections(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnection>>> {
    let iter = all_tcp_v6_connections()?
        // TODO: Consider logging a warning before discarding the record.
        .filter_map(|conn| conn.ok())
        .filter(move |conn| conn.pid == pid)
        .map(Ok);

    Ok(iter)
}

/// Returns an iterator over IPv4 UDP connections for the specified process.
pub fn udp_v4_connections(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnection>>> {
    let iter = all_udp_v4_connections()?
        // TODO: Consider logging a warning before discarding the record.
        .filter_map(|conn| conn.ok())
        .filter(move |conn| conn.pid == pid)
        .map(Ok);

    Ok(iter)
}

/// Returns an iterator over IPv6 UDP connections for the specified process.
pub fn udp_v6_connections(pid: u32) -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnection>>> {
    let iter = all_udp_v6_connections()?
        // TODO: Consider logging a warning before discarding the record.
        .filter_map(|conn| conn.ok())
        .filter(move |conn| conn.pid == pid)
        .map(Ok);

    Ok(iter)
}

/// Returns an iterator over IPv4 TCP connections of all processes.
pub fn all_tcp_v4_connections() -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnection>>> {
    self::conn::all_tcp_v4()
}

/// Returns an iterator over IPv6 TCP connections of all processes.
pub fn all_tcp_v6_connections() -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnection>>> {
    self::conn::all_tcp_v6()
}

/// Returns an iterator over IPv4 UDP connections of all processes.
pub fn all_udp_v4_connections() -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnection>>> {
    self::conn::all_udp_v4()
}

/// Returns an iterator over IPv6 UDP connections of all processes.
pub fn all_udp_v6_connections() -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnection>>> {
    self::conn::all_udp_v6()
}

// The official Microsoft documentation recommends "15KB" [1] as the default
// buffer size but does not specify whether we talk about kibi- or kilo-bytes.
// The example [2] uses literal "15000" value so we use the same thing.
//
// [1]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses#remarks
// [2]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses#examples
const DEFAULT_BUF_SIZE: usize = 15_000;

#[cfg(test)]
mod tests {

    // TODO: Create more meaningful tests.
    #[test]
    fn interfaces_something_exists() {
        let mut ifaces = super::interfaces().unwrap();

        assert!(ifaces.next().is_some());
    }
}
