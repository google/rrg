// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use windows_sys::Win32::NetworkManagement::IpHelper::*;

use crate::net::*;

/// Returns an iterator over all system TCP IPv4 connections.
pub fn all_tcp_v4() -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnectionV4>>> {
    all::<MIB_TCPTABLE_OWNER_PID>()
}

/// Returns an iterator over all system TCP IPv6 connections.
pub fn all_tcp_v6() -> std::io::Result<impl Iterator<Item = std::io::Result<TcpConnectionV6>>> {
    all::<MIB_TCP6TABLE_OWNER_PID>()
}

/// Returns an iterator over all system UDP IPv4 connections.
pub fn all_udp_v4() -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnectionV4>>> {
    all::<MIB_UDPTABLE_OWNER_PID>()
}

/// Returns an iterator over all system UDP IPv6 connections.
pub fn all_udp_v6() -> std::io::Result<impl Iterator<Item = std::io::Result<UdpConnectionV6>>> {
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

    type Connection = TcpConnectionV4;

    // https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid
    fn parse(&self) -> Result<TcpConnectionV4, ParseConnectionError> {
        let local_addr = parse_ipv4_addr(self.dwLocalAddr);
        let local_port = parse_port(self.dwLocalPort)
            .ok_or(ParseConnectionError::InvalidLocalPort)?;

        let remote_addr = parse_ipv4_addr(self.dwRemoteAddr);
        let remote_port = parse_port(self.dwRemotePort)
            .ok_or(ParseConnectionError::InvalidRemotePort)?;

        Ok(TcpConnectionV4::from_inner(TcpConnectionInner {
            local_addr: std::net::SocketAddrV4::new(local_addr, local_port),
            remote_addr: std::net::SocketAddrV4::new(remote_addr, remote_port),
            state: parse_tcp_state(self.dwState)?,
            pid: self.dwOwningPid,
        }).into())
    }
}

impl Row for MIB_TCP6ROW_OWNER_PID {

    type Connection = TcpConnectionV6;

    // https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcp6row_owner_pid
    fn parse(&self) -> Result<TcpConnectionV6, ParseConnectionError> {
        let local_addr = std::net::Ipv6Addr::from(self.ucLocalAddr);
        let local_port = parse_port(self.dwLocalPort)
            .ok_or(ParseConnectionError::InvalidLocalPort)?;

        let remote_addr = std::net::Ipv6Addr::from(self.ucRemoteAddr);
        let remote_port = parse_port(self.dwRemotePort)
            .ok_or(ParseConnectionError::InvalidRemotePort)?;

        Ok(TcpConnectionV6::from_inner(TcpConnectionInner {
            local_addr: std::net::SocketAddrV6::new(local_addr, local_port, 0, 0),
            remote_addr: std::net::SocketAddrV6::new(remote_addr, remote_port, 0, 0),
            state: parse_tcp_state(self.dwState)?,
            pid: self.dwOwningPid,
        }).into())
    }
}

impl Row for MIB_UDPROW_OWNER_PID {

    type Connection = UdpConnectionV4;

    // https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udprow_owner_pid
    fn parse(&self) -> Result<UdpConnectionV4, ParseConnectionError> {
        let local_addr = parse_ipv4_addr(self.dwLocalAddr);
        let local_port = parse_port(self.dwLocalPort)
            .ok_or(ParseConnectionError::InvalidLocalPort)?;

        Ok(UdpConnectionV4::from_inner(UdpConnectionInner {
            local_addr: std::net::SocketAddrV4::new(local_addr, local_port),
            pid: self.dwOwningPid,
        }))
    }
}

impl Row for MIB_UDP6ROW_OWNER_PID {

    type Connection = UdpConnectionV6;

    // https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udp6row_owner_pid
    fn parse(&self) -> Result<UdpConnectionV6, ParseConnectionError> {
        let local_addr = std::net::Ipv6Addr::from(self.ucLocalAddr);
        let local_port = parse_port(self.dwLocalPort)
            .ok_or(ParseConnectionError::InvalidLocalPort)?;

        Ok(UdpConnectionV6::from_inner(UdpConnectionInner {
            local_addr: std::net::SocketAddrV6::new(local_addr, local_port, 0, 0),
            pid: self.dwOwningPid,
        }))
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
    /// In case `buf` is a null pointer, the function should return an overflow
    /// error (while still preserving the correct `buf_size` behaviour).
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
    unsafe fn get(buf: *mut std::ffi::c_void, buf_size: *mut u32) -> u32;

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
    unsafe fn get(buf: *mut std::ffi::c_void, buf_size: *mut u32) -> u32 {
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
    unsafe fn get(buf: *mut std::ffi::c_void, buf_size: *mut u32) -> u32 {
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
    unsafe fn get(buf: *mut std::ffi::c_void, buf_size: *mut u32) -> u32 {
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
    unsafe fn get(buf: *mut std::ffi::c_void, buf_size: *mut u32) -> u32 {
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

    // The documentation does not mention it explicitly, but if we pass a not
    // initialized `buf_size`, even with null buffer, for TCPv6 the call will
    // crash with an access violation.
    let mut buf_size = 0;

    // SAFETY: We pass a null pointer as the buffer and expect the size to be
    // set accordingly. We handle errors below.
    let code = unsafe {
        T::get(std::ptr::null_mut(), &mut buf_size)
    };

    // We passed a null pointer, so everything that is *not* a buffer overflow
    // error is unexpected.
    if code != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER {
        let code = i32::try_from(code)
            .expect("invalid error code");

        return Err(std::io::Error::from_raw_os_error(code));
    }

    // SAFETY: The call "succeeded" (returned the expected error, it means that
    // the buffer size variable has been set to the required size value).

    // TODO(@panhania): Migrate the code away from using the `std::alloc` module
    // to plain `Vec` (the approach taken e.g. on macOS). This way we don't have
    // to collect at the end of the function but have a consuming iterator that
    // yields new items on demand, avoiding one big unnecessary allocation.

    let buf_layout = std::alloc::Layout::from_size_align(
        buf_size as usize,
        std::mem::align_of::<T>(),
    ).expect("invalid layout for adapter addresses table");

    let buf = crate::alloc::Allocation::new(buf_layout)
        .ok_or_else(|| std::io::ErrorKind::OutOfMemory)?;

    // SAFETY: We allocated a buffer of the requested size and pass it along
    // with the unchanged size. Note that this can still fail in an unlikely
    // case where a new device was added between the previous call and this one.
    // We do not retry if that is the case.
    let code = unsafe {
        T::get(buf.as_ptr().cast().as_ptr(), &mut buf_size)
    };

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
        .map(|row| row.parse().map_err(|error| error.into()))
        .collect::<Vec<_>>();

    Ok(conns.into_iter())
}

/// Parses a connection port value returned by the system.
///
/// This will convert a value as returned by the system (a `u32` value) to a one
/// the fits the model used by Rust.
fn parse_port(val: u32) -> Option<u16> {
    use std::convert::TryFrom as _;

    // Note that the documentation says: "This member is stored in network byte
    // order.". However, this is not entirely true: we have to interpret this as
    // a 16-bit long value and only then convert it from the network byte order
    // (as opposed to converting all 32-bit value).
    Some(u16::from_be(u16::try_from(val).ok()?))
}

/// Parses a connection IPv4 value returned by the system.
///
/// This will convert a value as returned by the system (a `u32` value) to a one
/// the fits the model used by Rust.
fn parse_ipv4_addr(val: u32) -> std::net::Ipv4Addr {
    // The documentation mentions that the value is in the same format as one
    // in the `in_addr` [1] structure. While it is not stated explictly, it
    // means that the value is stored in big-endian order and `Ipv4` constructor
    // expectsa native-endian order.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-in_addr
    std::net::Ipv4Addr::from(u32::from_be(val))
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

impl From<ParseConnectionError> for std::io::Error {

    fn from(error: ParseConnectionError) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, error)
    }
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

impl From<ParseTcpStateError> for ParseConnectionError {

    fn from(error: ParseTcpStateError) -> ParseConnectionError {
        ParseConnectionError::InvalidState(error)
    }
}
