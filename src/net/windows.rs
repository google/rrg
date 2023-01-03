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

/// Iterator over TCP connections.
pub struct TcpConnections {
    iter: std::vec::IntoIter<TcpConnection>,
}

impl Iterator for TcpConnections {
    type Item = std::io::Result<TcpConnection>;

    fn next(&mut self) -> Option<std::io::Result<TcpConnection>> {
        self.iter.next().map(Result::Ok)
    }
}

/// Iterator over UDP connections.
pub struct UdpConnections {
    iter: std::vec::IntoIter<UdpConnection>,
}

impl Iterator for UdpConnections {
    type Item = std::io::Result<UdpConnection>;

    fn next(&mut self) -> Option<std::io::Result<UdpConnection>> {
        self.iter.next().map(Result::Ok)
    }
}

/// Returns an iterator over IPv4 TCP connections of all processes.
pub fn all_tcp_v4_connections() -> std::io::Result<TcpConnections> {
    use std::convert::TryFrom as _;

    use windows_sys::Win32::NetworkManagement::IpHelper::*;

    let mut buf_size = u32::try_from(DEFAULT_BUF_SIZE)
        .expect("default buffer size too big");

    let buf_layout = std::alloc::Layout::from_size_align(
        buf_size as usize,
        std::mem::align_of::<MIB_TCPTABLE_OWNER_PID>(),
    ).expect("invalid layout for adapter addresses table");

    let mut buf = crate::alloc::Allocation::new(buf_layout)
        .ok_or_else(|| std::io::ErrorKind::OutOfMemory)?;

    // SAFETY: We call the function as described in the official docs [1]. In
    // case the allocated buffer is too small, we handle this case below.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable#parameters
    let mut code = unsafe {
        GetExtendedTcpTable(
            buf.as_ptr().cast().as_ptr(),
            &mut buf_size,
            false.into(),
            windows_sys::Win32::Networking::WinSock::AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
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
            GetExtendedTcpTable(
                buf.as_ptr().cast().as_ptr(),
                &mut buf_size,
                false.into(),
                windows_sys::Win32::Networking::WinSock::AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
    }

    if code != windows_sys::Win32::Foundation::NO_ERROR {
        let code = i32::try_from(code)
            .expect("invalid error code");

        return Err(std::io::Error::from_raw_os_error(code));
    }

    // SAFETY: The buffer was allocated with layout specific to the table type
    // and the allocation is guaranteed to be correct.
    let table = unsafe {
        buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>().as_ref()
    };

    // SAFETY: The `table` field is guaranteed to contain as many elements as
    // given in the `dwNumEntries` table [1]. We simply cast a single-element
    // array to a one with runtime-known size.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcptable_owner_pid#members
    let rows = unsafe {
        std::slice::from_raw_parts(
            table.table.as_ref().as_ptr(),
            table.dwNumEntries as usize,
        )
    };

    let conns = rows
        .into_iter()
        .map(|row| parse_tcp_v4_row(*row))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error)
        })?;

    Ok(TcpConnections {
        iter: conns.into_iter(),
    })
}

/// Returns an iterator over IPv6 TCP connections of all processes.
pub fn all_tcp_v6_connections() -> std::io::Result<TcpConnections> {
    use std::convert::TryFrom as _;

    use windows_sys::Win32::NetworkManagement::IpHelper::*;

    let mut buf_size = u32::try_from(DEFAULT_BUF_SIZE)
        .expect("default buffer size too big");

    let buf_layout = std::alloc::Layout::from_size_align(
        buf_size as usize,
        std::mem::align_of::<MIB_TCP6TABLE_OWNER_PID>(),
    ).expect("invalid layout for adapter addresses table");

    let mut buf = crate::alloc::Allocation::new(buf_layout)
        .ok_or_else(|| std::io::ErrorKind::OutOfMemory)?;

    // SAFETY: We call the function as described in the official docs [1]. In
    // case the allocated buffer is too small, we handle this case below.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable#parameters
    let mut code = unsafe {
        GetExtendedTcpTable(
            buf.as_ptr().cast().as_ptr(),
            &mut buf_size,
            false.into(),
            windows_sys::Win32::Networking::WinSock::AF_INET6,
            TCP_TABLE_OWNER_PID_ALL,
            0,
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
            GetExtendedTcpTable(
                buf.as_ptr().cast().as_ptr(),
                &mut buf_size,
                false.into(),
                windows_sys::Win32::Networking::WinSock::AF_INET6,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
    }

    if code != windows_sys::Win32::Foundation::NO_ERROR {
        let code = i32::try_from(code)
            .expect("invalid error code");

        return Err(std::io::Error::from_raw_os_error(code));
    }

    // SAFETY: The buffer was allocated with layout specific to the table type
    // and the allocation is guaranteed to be correct.
    let table = unsafe {
        buf.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>().as_ref()
    };

    // SAFETY: The `table` field is guaranteed to contain as many elements as
    // given in the `dwNumEntries` table [1]. We simply cast a single-element
    // array to a one with runtime-known size.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcp6table_owner_pid#members
    let rows = unsafe {
        std::slice::from_raw_parts(
            table.table.as_ref().as_ptr(),
            table.dwNumEntries as usize,
        )
    };

    let conns = rows
        .into_iter()
        .map(|row| parse_tcp_v6_row(*row))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error)
        })?;

    Ok(TcpConnections {
        iter: conns.into_iter(),
    })
}

/// Returns an iterator over IPv4 UDP connections of all processes.
pub fn all_udp_v4_connections() -> std::io::Result<UdpConnections> {
    use std::convert::TryFrom as _;

    use windows_sys::Win32::NetworkManagement::IpHelper::*;

    let mut buf_size = u32::try_from(DEFAULT_BUF_SIZE)
        .expect("default buffer size too big");

    let buf_layout = std::alloc::Layout::from_size_align(
        buf_size as usize,
        std::mem::align_of::<MIB_UDPTABLE_OWNER_PID>(),
    ).expect("invalid layout for adapter addresses table");

    let mut buf = crate::alloc::Allocation::new(buf_layout)
        .ok_or_else(|| std::io::ErrorKind::OutOfMemory)?;

    // SAFETY: We call the function as described in the official docs [1]. In
    // case the allocated buffer is too small, we handle this case below.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable
    let mut code = unsafe {
        GetExtendedUdpTable(
            buf.as_ptr().cast().as_ptr(),
            &mut buf_size,
            false.into(),
            windows_sys::Win32::Networking::WinSock::AF_INET,
            UDP_TABLE_OWNER_PID,
            0,
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
            GetExtendedUdpTable(
                buf.as_ptr().cast().as_ptr(),
                &mut buf_size,
                false.into(),
                windows_sys::Win32::Networking::WinSock::AF_INET,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
    }

    if code != windows_sys::Win32::Foundation::NO_ERROR {
        let code = i32::try_from(code)
            .expect("invalid error code");

        return Err(std::io::Error::from_raw_os_error(code));
    }

    // SAFETY: The buffer was allocated with layout specific to the table type
    // and the allocation is guaranteed to be correct.
    let table = unsafe {
        buf.as_ptr().cast::<MIB_UDPTABLE_OWNER_PID>().as_ref()
    };

    // SAFETY: The `table` field is guaranteed to contain as many elements as
    // given in the `dwNumEntries` table [1]. We simply cast a single-element
    // array to a one with runtime-known size.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udptable#members
    let rows = unsafe {
        std::slice::from_raw_parts(
            table.table.as_ref().as_ptr(),
            table.dwNumEntries as usize,
        )
    };

    let conns = rows
        .into_iter()
        .map(|row| parse_udp_v4_row(*row))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error)
        })?;

    Ok(UdpConnections {
        iter: conns.into_iter(),
    })
}

/// Returns an iterator over IPv6 UDP connections of all processes.
pub fn all_udp_v6_connections() -> std::io::Result<UdpConnections> {
    use std::convert::TryFrom as _;

    use windows_sys::Win32::NetworkManagement::IpHelper::*;

    let mut buf_size = u32::try_from(DEFAULT_BUF_SIZE)
        .expect("default buffer size too big");

    let buf_layout = std::alloc::Layout::from_size_align(
        buf_size as usize,
        std::mem::align_of::<MIB_UDP6TABLE_OWNER_PID>(),
    ).expect("invalid layout for adapter addresses table");

    let mut buf = crate::alloc::Allocation::new(buf_layout)
        .ok_or_else(|| std::io::ErrorKind::OutOfMemory)?;

    // SAFETY: We call the function as described in the official docs [1]. In
    // case the allocated buffer is too small, we handle this case below.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable
    let mut code = unsafe {
        GetExtendedUdpTable(
            buf.as_ptr().cast().as_ptr(),
            &mut buf_size,
            false.into(),
            windows_sys::Win32::Networking::WinSock::AF_INET6,
            UDP_TABLE_OWNER_PID,
            0,
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
            GetExtendedUdpTable(
                buf.as_ptr().cast().as_ptr(),
                &mut buf_size,
                false.into(),
                windows_sys::Win32::Networking::WinSock::AF_INET6,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
    }

    if code != windows_sys::Win32::Foundation::NO_ERROR {
        let code = i32::try_from(code)
            .expect("invalid error code");

        return Err(std::io::Error::from_raw_os_error(code));
    }

    // SAFETY: The buffer was allocated with layout specific to the table type
    // and the allocation is guaranteed to be correct.
    let table = unsafe {
        buf.as_ptr().cast::<MIB_UDP6TABLE_OWNER_PID>().as_ref()
    };

    // SAFETY: The `table` field is guaranteed to contain as many elements as
    // given in the `dwNumEntries` table [1]. We simply cast a single-element
    // array to a one with runtime-known size.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udp6table_owner_pid#members
    let rows = unsafe {
        std::slice::from_raw_parts(
            table.table.as_ref().as_ptr(),
            table.dwNumEntries as usize,
        )
    };

    let conns = rows
        .into_iter()
        .map(|row| parse_udp_v6_row(*row))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error)
        })?;

    Ok(UdpConnections {
        iter: conns.into_iter(),
    })
}

mod connection {

    use windows_sys::Win32::NetworkManagement::IpHelper::*;

    use super::*;

    /// Returns an iterator over all system TCP IPv4 connections.
    pub fn all_tcp_v4() -> std::io::Result<impl Iterator<Item = TcpConnection>> {
        all::<MIB_TCPTABLE_OWNER_PID>()
    }

    /// Returns an iterator over all system TCP IPv6 connections.
    pub fn all_tcp_v6() -> std::io::Result<impl Iterator<Item = TcpConnection>> {
        all::<MIB_TCP6TABLE_OWNER_PID>()
    }

    /// Returns an iterator over all system UDP IPv4 connections.
    pub fn all_udp_v4() -> std::io::Result<impl Iterator<Item = UdpConnection>> {
        all::<MIB_UDPTABLE_OWNER_PID>()
    }

    /// Returns an iterator over all system UDP IPv6 connections.
    pub fn all_udp_v6() -> std::io::Result<impl Iterator<Item = UdpConnection>> {
        all::<MIB_UDP6TABLE_OWNER_PID>()
    }

    /// An abstraction over Windows TCP and UDP connection tables.
    ///
    /// This trait makes it possible to work with TCP and UDP tables returned
    /// by the Windows API in a generic way. It should be only implemented for
    /// the following four types:
    ///
    ///   * [`MIB_TCPTABLE_OWNER_PID`]
    ///   * [`MIB_TCP6TABLE_OWNER_PID`]
    ///   * [`MIB_UDPTABLE_OWNER_PID`]
    ///   * [`MIB_UDP6TABLE_OWNER_PID`]
    ///
    /// It is not intended to ever be exposed and should be used only to avoid
    /// code duplication in concrete implementations that care about specific
    /// portocol and version combinations.
    trait Table {
        /// The Windows type of the table rows.
        type Row;

        /// An idiomatic Rust type that the table contains information for.
        type Connection;

        /// Calls the native `GetExtended*Table` system function.
        ///
        /// Implementers should fill `buf` using the `GetExtended*Table` with
        /// table information.
        ///
        /// `buf_size` should be set to the number of bytes written in case of
        /// success and to the number of bytes needed to fill the buffer in case
        /// of an error due to insufficiently large buffer.
        ///
        /// The function should return the error code as returned by the system
        /// function.
        ///
        /// See documentation for the system functions for more details:
        ///
        ///   * [`GetExtendedTcpTable`]
        ///   * [`GetExtendedUdpTable`]
        ///
        /// [`GetExtendedTcpTable`]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
        /// [`GetExtendedUdpTable`]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable
        ///
        /// # Safety
        ///
        /// Implementers can assume that `buf` has length of at least `buf_size`
        /// bytes but should not assume anything about memory being initialized.
        unsafe fn get(buf: *mut std::ffi::c_void, buf_size: &mut u32) -> u32;

        /// Returns array of rows contained in the table.
        ///
        /// # Safety
        ///
        /// Implementers can assume that the table has been already correctly
        /// initialized through an appropriate call to the `GetExteded*Table`
        /// function (and thus `table` and `dwNumEntries` fields uphold to the
        /// invariants specified in the Windows documentation).
        unsafe fn rows(&self) -> &[Self::Row];

        /// Transforms a low-level row structore to an idiomatic Rust type.
        fn parse_row(
            row: &Self::Row,
        ) -> Result<Self::Connection, ParseConnectionError>;
    }

    impl Table for MIB_TCPTABLE_OWNER_PID {

        type Row = MIB_TCPROW_OWNER_PID;

        type Connection = TcpConnection;

        // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable#parameters
        unsafe fn get(buf: *mut std::ffi::c_void, buf_size: &mut u32) -> u32 {
            GetExtendedTcpTable(
                buf,
                buf_size,
                false.into(),
                windows_sys::Win32::Networking::WinSock::AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcptable_owner_pid#members
        unsafe fn rows(&self) -> &[MIB_TCPROW_OWNER_PID] {
            std::slice::from_raw_parts(
                self.table.as_ref().as_ptr(),
                self.dwNumEntries as usize,
            )
        }

        fn parse_row(
            row: &MIB_TCPROW_OWNER_PID,
        ) -> Result<TcpConnection, ParseConnectionError> {
            // TODO(@panhania): Pass by reference.
            super::parse_tcp_v4_row(*row)
        }
    }

    impl Table for MIB_TCP6TABLE_OWNER_PID {

        type Row = MIB_TCP6ROW_OWNER_PID;

        type Connection = TcpConnection;

        // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable#parameters
        unsafe fn get(buf: *mut std::ffi::c_void, buf_size: &mut u32) -> u32 {
            GetExtendedTcpTable(
                buf,
                buf_size,
                false.into(),
                windows_sys::Win32::Networking::WinSock::AF_INET6,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcp6table_owner_pid#members
        unsafe fn rows(&self) -> &[MIB_TCP6ROW_OWNER_PID] {
            std::slice::from_raw_parts(
                self.table.as_ref().as_ptr(),
                self.dwNumEntries as usize,
            )
        }

        fn parse_row(
            row: &MIB_TCP6ROW_OWNER_PID,
        ) -> Result<TcpConnection, ParseConnectionError> {
            // TODO(@panhania): Pass by reference.
            super::parse_tcp_v6_row(*row)
        }
    }

    impl Table for MIB_UDPTABLE_OWNER_PID {

        type Row = MIB_UDPROW_OWNER_PID;

        type Connection = UdpConnection;

        // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable
        unsafe fn get(buf: *mut std::ffi::c_void, buf_size: &mut u32) -> u32 {
            GetExtendedUdpTable(
                buf,
                buf_size,
                false.into(),
                windows_sys::Win32::Networking::WinSock::AF_INET,
                UDP_TABLE_OWNER_PID,
                0,
            )
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udptable#members
        unsafe fn rows(&self) -> &[MIB_UDPROW_OWNER_PID] {
            std::slice::from_raw_parts(
                self.table.as_ref().as_ptr(),
                self.dwNumEntries as usize,
            )
        }

        fn parse_row(
            row: &MIB_UDPROW_OWNER_PID,
        ) -> Result<UdpConnection, ParseConnectionError> {
            // TODO(@panhania): Pass by reference.
            super::parse_udp_v4_row(*row)
        }
    }

    impl Table for MIB_UDP6TABLE_OWNER_PID {

        type Row = MIB_UDP6ROW_OWNER_PID;

        type Connection = UdpConnection;

        // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable
        unsafe fn get(buf: *mut std::ffi::c_void, buf_size: &mut u32) -> u32 {
            GetExtendedUdpTable(
                buf,
                buf_size,
                false.into(),
                windows_sys::Win32::Networking::WinSock::AF_INET6,
                UDP_TABLE_OWNER_PID,
                0,
            )
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udp6table_owner_pid#members
        unsafe fn rows(&self) -> &[MIB_UDP6ROW_OWNER_PID] {
            std::slice::from_raw_parts(
                self.table.as_ref().as_ptr(),
                self.dwNumEntries as usize,
            )
        }

        fn parse_row(
            row: &MIB_UDP6ROW_OWNER_PID,
        ) -> Result<UdpConnection, ParseConnectionError> {
            // TODO(@panhania): Pass by reference.
            super::parse_udp_v6_row(*row)
        }
    }

    /// Returns an iterator over all system connections of a specific type.
    fn all<T>() -> std::io::Result<impl Iterator<Item = T::Connection>>
    where
        T: Table,
    {
        use std::convert::TryFrom as _;

        let mut buf_size = u32::try_from(DEFAULT_BUF_SIZE)
            .expect("default buffer size too big");

        let buf_layout = std::alloc::Layout::from_size_align(
            buf_size as usize,
            std::mem::align_of::<T>(),
        ).expect("invalid layout for adapter addresses table");

        let mut buf = crate::alloc::Allocation::new(buf_layout)
            .ok_or_else(|| std::io::ErrorKind::OutOfMemory)?;

        // SAFETY: As required, we allocated a buffer and pass its size with it.
        // In case the allocated buffer is too small, we handle this case below.
        let mut code = unsafe {
            T::get(buf.as_ptr().cast().as_ptr(), &mut buf_size)
        };

        if code == windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW {
            // Just a sanity check. Since the default buffer was too small, a
            // "good" one should be strictly bigger.
            assert!(DEFAULT_BUF_SIZE < (buf_size as usize));

            buf = buf.resize(buf_size as usize)
                .map_err(|_| std::io::ErrorKind::OutOfMemory)?;

            // SAFETY: We call the function the same as above but with larger
            // buffer. Note that this can still fail in an unlikely case where a
            // new device was added between the previous call and this one. We
            // do not do another attempt and fail if this is the case.
            code = unsafe {
                T::get(buf.as_ptr().cast().as_ptr(), &mut buf_size)
            };
        }

        if code != windows_sys::Win32::Foundation::NO_ERROR {
            let code = i32::try_from(code)
                .expect("invalid error code");

            return Err(std::io::Error::from_raw_os_error(code));
        }

        // SAFETY: The buffer was allocated with layout specific to the table
        // type and the allocation is guaranteed to be correct. The buffer was
        // filled successfully, so it is safe to assume the memory is correctly
        // initialized now.
        let table = unsafe {
            buf.as_ptr().cast::<T>().as_ref()
        };

        // SAFETY: The `table` is guaranteed to be initialized now and so all
        // invariants assumed by the `rows` method should uphold.
        let rows = unsafe {
            table.rows()
        };

        let conns = rows
            .iter()
            .map(T::parse_row)
            // TODO(@panhania): Eliminate vector collection.
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error)
            })?;

        Ok(conns.into_iter())
    }
}

/// Parses a connection row of a TCP IPv4 table.
fn parse_tcp_v4_row(
    row: windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCPROW_OWNER_PID,
) -> Result<TcpConnection, ParseConnectionError>
{
    use std::convert::TryFrom as _;

    let local_addr = std::net::Ipv4Addr::from(row.dwLocalAddr);
    let local_port = u16::try_from(row.dwLocalPort)
        .map_err(|_| ParseConnectionError::InvalidLocalPort)?;

    let remote_addr = std::net::Ipv4Addr::from(row.dwRemoteAddr);
    let remote_port = u16::try_from(row.dwRemotePort)
        .map_err(|_| ParseConnectionError::InvalidRemotePort)?;

    let state = parse_tcp_state(row.dwState)
        .map_err(ParseConnectionError::InvalidState)?;

    // TODO(@panhania): Extend with PID information.

    Ok(TcpConnection {
        local_addr: (local_addr, local_port).into(),
        remote_addr: (remote_addr, remote_port).into(),
        state,
    })
}

/// Parses a connection row of a TCP IPv6 table.
fn parse_tcp_v6_row(
    row: windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCP6ROW_OWNER_PID,
) -> Result<TcpConnection, ParseConnectionError>
{
    use std::convert::TryFrom as _;

    let local_addr = std::net::Ipv6Addr::from(row.ucLocalAddr);
    let local_port = u16::try_from(row.dwLocalPort)
        .map_err(|_| ParseConnectionError::InvalidLocalPort)?;

    let remote_addr = std::net::Ipv6Addr::from(row.ucRemoteAddr);
    let remote_port = u16::try_from(row.dwRemotePort)
        .map_err(|_| ParseConnectionError::InvalidRemotePort)?;

    let state = parse_tcp_state(row.dwState)
        .map_err(ParseConnectionError::InvalidState)?;

    // TODO(@panhania): Extend with PID information.

    Ok(TcpConnection {
        local_addr: (local_addr, local_port).into(),
        remote_addr: (remote_addr, remote_port).into(),
        state,
    })
}

/// Parses a connection row of a UDP IPv4 table.
fn parse_udp_v4_row(
    row: windows_sys::Win32::NetworkManagement::IpHelper::MIB_UDPROW_OWNER_PID,
) -> Result<UdpConnection, ParseConnectionError>
{
    use std::convert::TryFrom as _;

    let local_addr = std::net::Ipv4Addr::from(row.dwLocalAddr);
    let local_port = u16::try_from(row.dwLocalPort)
        .map_err(|_| ParseConnectionError::InvalidLocalPort)?;

    // TODO(@panhania): Extend with PID information.

    Ok(UdpConnection {
        local_addr: (local_addr, local_port).into(),
    })
}

/// Parses a connection row of a UDP IPv6 table.
fn parse_udp_v6_row(
    row: windows_sys::Win32::NetworkManagement::IpHelper::MIB_UDP6ROW_OWNER_PID,
) -> Result<UdpConnection, ParseConnectionError>
{
    use std::convert::TryFrom as _;

    let local_addr = std::net::Ipv6Addr::from(row.ucLocalAddr);
    let local_port = u16::try_from(row.dwLocalPort)
        .map_err(|_| ParseConnectionError::InvalidLocalPort)?;

    // TODO(@panhania): Extend with PID information.

    Ok(UdpConnection {
        local_addr: (local_addr, local_port).into(),
    })
}

/// An error that might be returned when parsing Windows connection table row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ParseConnectionError {
    /// It was not possible to parse the local address port.
    InvalidLocalPort,
    /// It was not possible to parse the remote address port.
    InvalidRemotePort,
    /// It was not possible to interpret the connection state.
    InvalidState(ParseTcpStateError),
}

impl std::fmt::Display for ParseConnectionError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ParseConnectionError::*;
        match *self {
            InvalidLocalPort => {
                write!(fmt, "invalid local port")
            }
            InvalidRemotePort => {
                write!(fmt, "invalid remote port")
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

/// Parses a TCP connection state value returned by the system.
fn parse_tcp_state(val: u32) -> Result<TcpState, ParseTcpStateError> {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;

    let state = match val as i32 {
        MIB_TCP_STATE_CLOSED => TcpState::Closed,
        MIB_TCP_STATE_LISTEN => TcpState::Listen,
        MIB_TCP_STATE_SYN_SENT => TcpState::SynSent,
        MIB_TCP_STATE_SYN_RCVD => TcpState::SynReceived,
        MIB_TCP_STATE_ESTAB => TcpState::Established,
        MIB_TCP_STATE_FIN_WAIT1 => TcpState::FinWait1,
        MIB_TCP_STATE_FIN_WAIT2 => TcpState::FinWait2,
        MIB_TCP_STATE_CLOSE_WAIT => TcpState::CloseWait,
        MIB_TCP_STATE_CLOSING => TcpState::Closing,
        MIB_TCP_STATE_LAST_ACK => TcpState::LastAck,
        MIB_TCP_STATE_TIME_WAIT => TcpState::TimeWait,
        // TCB deletion is not a real state as defined in the TCP specification
        // but a transition to the "closed" state [1].
        //
        // [1]: https://www.ietf.org/rfc/rfc793.txt
        MIB_TCP_STATE_DELETE_TCB => TcpState::Closed,
        _ => return Err(ParseTcpStateError::UnknownState(val)),
    };

    Ok(state)
}

/// An error that might be returned when interpreting Windows TCP state value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ParseTcpStateError {
    /// The state value is not a known.
    UnknownState(u32),
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

// The official Microsoft documentation recommends "15KB" [1] as the default
// buffer size but does not specify whether we talk about kibi- or kilo-bytes.
// The example [2] uses literal "15000" value so we use the same thing.
//
// [1]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses#remarks
// [2]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses#examples
const DEFAULT_BUF_SIZE: usize = 15_000;

#[cfg(test)]
mod tests {

    use super::*;

    // TODO: Create more meaningful tests.
    #[test]
    fn something_exists() {
        let mut ifaces = super::interfaces().unwrap();

        assert!(ifaces.next().is_some());
    }
}
