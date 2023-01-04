// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use windows_sys::Win32::NetworkManagement::IpHelper::*;

use super::*;

/// Returns an iterator over all system TCP IPv4 connections.
pub fn all_tcp_v4() -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnection>>> {
    all::<MIB_TCPTABLE_OWNER_PID>()
}

/// Returns an iterator over all system TCP IPv6 connections.
pub fn all_tcp_v6() -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnection>>> {
    all::<MIB_TCP6TABLE_OWNER_PID>()
}

/// Returns an iterator over all system UDP IPv4 connections.
pub fn all_udp_v4() -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnection>>> {
    all::<MIB_UDPTABLE_OWNER_PID>()
}

/// Returns an iterator over all system UDP IPv6 connections.
pub fn all_udp_v6() -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnection>>> {
    all::<MIB_UDP6TABLE_OWNER_PID>()
}

/// An abstraction over Windows TCP and UDP connection table row.
///
/// This trait makes it possible to work with TCP and UDP tables returned by the
/// Windows API in a generic way. It should be only implemented for the listed
/// four types:
///
///   * [`MIB_TCPTABLE_OWNER_PID`]
///   * [`MIB_TCP6TABLE_OWNER_PID`]
///   * [`MIB_UDPTABLE_OWNER_PID`]
///   * [`MIB_UDP6TABLE_OWNER_PID`]
///
/// It is not intended to ever be exposed and should be used only to avoid code
/// duplication in concrete implementations that care about specific protocol
/// and version combinations.
trait Row {
    /// An idiomatic Rust type that the row type corresponds to.
    type Connection;

    /// Transforms a low-level row structore to an idiomatic Rust type.
    ///
    /// # Errors
    ///
    /// The function returns an error if the row table contains malformed or
    /// uninterpretable data.
    fn parse(&self) -> Result<Self::Connection, ParseConnectionError>;
}

impl Row for MIB_TCPROW_OWNER_PID {

    type Connection = TcpConnection;

    // https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid
    fn parse(&self) -> Result<TcpConnection, ParseConnectionError> {
        use std::convert::TryFrom as _;

        let local_addr = std::net::Ipv4Addr::from(self.dwLocalAddr);
        let local_port = u16::try_from(self.dwLocalPort)
            .map_err(|_| ParseConnectionError::InvalidLocalPort)?;

        let remote_addr = std::net::Ipv4Addr::from(self.dwRemoteAddr);
        let remote_port = u16::try_from(self.dwRemotePort)
            .map_err(|_| ParseConnectionError::InvalidRemotePort)?;

        let state = parse_tcp_state(self.dwState)
            .map_err(ParseConnectionError::InvalidState)?;

        // TODO(@panhania): Extend with PID information.

        Ok(TcpConnection {
            local_addr: (local_addr, local_port).into(),
            remote_addr: (remote_addr, remote_port).into(),
            state,
        })
    }
}

impl Row for MIB_TCP6ROW_OWNER_PID {

    type Connection = TcpConnection;

    // https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcp6row_owner_pid
    fn parse(&self) -> Result<TcpConnection, ParseConnectionError> {
        use std::convert::TryFrom as _;

        let local_addr = std::net::Ipv6Addr::from(self.ucLocalAddr);
        let local_port = u16::try_from(self.dwLocalPort)
            .map_err(|_| ParseConnectionError::InvalidLocalPort)?;

        let remote_addr = std::net::Ipv6Addr::from(self.ucRemoteAddr);
        let remote_port = u16::try_from(self.dwRemotePort)
            .map_err(|_| ParseConnectionError::InvalidRemotePort)?;

        let state = parse_tcp_state(self.dwState)
            .map_err(ParseConnectionError::InvalidState)?;

        // TODO(@panhania): Extend with PID information.

        Ok(TcpConnection {
            local_addr: (local_addr, local_port).into(),
            remote_addr: (remote_addr, remote_port).into(),
            state,
        })
    }
}

impl Row for MIB_UDPROW_OWNER_PID {

    type Connection = UdpConnection;

    // https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udprow_owner_pid
    fn parse(&self) -> Result<UdpConnection, ParseConnectionError> {
        use std::convert::TryFrom as _;

        let local_addr = std::net::Ipv4Addr::from(self.dwLocalAddr);
        let local_port = u16::try_from(self.dwLocalPort)
            .map_err(|_| ParseConnectionError::InvalidLocalPort)?;

        // TODO(@panhania): Extend with PID information.

        Ok(UdpConnection {
            local_addr: (local_addr, local_port).into(),
        })
    }
}

impl Row for MIB_UDP6ROW_OWNER_PID {

    type Connection = UdpConnection;

    // https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udp6row_owner_pid
    fn parse(&self) -> Result<UdpConnection, ParseConnectionError> {
        use std::convert::TryFrom as _;

        let local_addr = std::net::Ipv6Addr::from(self.ucLocalAddr);
        let local_port = u16::try_from(self.dwLocalPort)
            .map_err(|_| ParseConnectionError::InvalidLocalPort)?;

        // TODO(@panhania): Extend with PID information.

        Ok(UdpConnection {
            local_addr: (local_addr, local_port).into(),
        })
    }
}

/// An abstraction over Windows TCP and UDP connection tables.
///
/// This trait makes it possible to work with TCP and UDP tables returned by the
/// Windows API in a generic way. It should be only implemented for the listed
/// four types:
///
///   * [`MIB_TCPTABLE_OWNER_PID`]
///   * [`MIB_TCP6TABLE_OWNER_PID`]
///   * [`MIB_UDPTABLE_OWNER_PID`]
///   * [`MIB_UDP6TABLE_OWNER_PID`]
///
/// It is not intended to ever be exposed and should be used only to avoid code
/// duplication in concrete implementations that care about specific protocol
/// and version combinations.
trait Table {
    /// The Windows type of the table rows.
    type Row: Row;

    /// Calls the native `GetExtended*Table` system function.
    ///
    /// Implementers should fill `buf` using the `GetExtended*Table` with table
    /// information.
    ///
    /// `buf_size` should be set to the number of bytes written in case of a
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
    /// Implementers can assume that the table has been correctly initialized
    /// through an appropriate call to the `GetExteded*Table` function (and thus
    /// `table` and `dwNumEntries` fields uphold to the invariants specified in
    /// the Windows documentation).
    unsafe fn rows(&self) -> &[Self::Row];
}

impl Table for MIB_TCPTABLE_OWNER_PID {

    type Row = MIB_TCPROW_OWNER_PID;

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
}

impl Table for MIB_TCP6TABLE_OWNER_PID {

    type Row = MIB_TCP6ROW_OWNER_PID;

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
}

impl Table for MIB_UDPTABLE_OWNER_PID {

    type Row = MIB_UDPROW_OWNER_PID;

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
}

impl Table for MIB_UDP6TABLE_OWNER_PID {

    type Row = MIB_UDP6ROW_OWNER_PID;

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
}

/// Returns an iterator over all system connections of a specific type.
fn all<T>() -> std::io::Result<impl Iterator<Item = std::io::Result<<<T as Table>::Row as Row>::Connection>>>
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

    // SAFETY: As required, we allocated a buffer and pass its size with it. In
    // case the allocated buffer is too small, we handle this case below.
    let mut code = unsafe {
        T::get(buf.as_ptr().cast().as_ptr(), &mut buf_size)
    };

    if code == windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW {
        // Just a sanity check. Since the default buffer was too small, a "good"
        // one should be strictly bigger.
        assert!(DEFAULT_BUF_SIZE < (buf_size as usize));

        buf = buf.resize(buf_size as usize)
            .map_err(|_| std::io::ErrorKind::OutOfMemory)?;

        // SAFETY: We call the function the same way as above but with larger
        // buffer. Note that this can still fail in an unlikely case where a new
        // device was added between the previous call and this one. We do not do
        // another attempt and fail if this is the case.
        code = unsafe {
            T::get(buf.as_ptr().cast().as_ptr(), &mut buf_size)
        };
    }

    if code != windows_sys::Win32::Foundation::NO_ERROR {
        let code = i32::try_from(code)
            .expect("invalid error code");

        return Err(std::io::Error::from_raw_os_error(code));
    }

    // SAFETY: The buffer was allocated with layout specific to the table type
    // and the allocation is guaranteed to be correct. The buffer was filled
    // successfully, so it is safe to assume the memory is correctly initialized
    // now.
    let table = unsafe {
        buf.as_ptr().cast::<T>().as_ref()
    };

    // SAFETY: The `table` is guaranteed to be initialized now and so all of the
    // invariants assumed by the `rows` method should uphold.
    let rows = unsafe {
        table.rows()
    };

    let conns = rows
        .iter()
        // TODO(@panhania): Simplify the following lines.
        .map(|row| row.parse().map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error)
        }))
        .collect::<Vec<_>>();

    Ok(conns.into_iter())
}
