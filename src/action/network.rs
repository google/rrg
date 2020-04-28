// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the network connection action.
//!
//! The network connection action lists all the opened connections on the
//! client and the information about them (e.g. type of the connection, source
//! and target IP addresses, the process that owns the connection).

use std::fmt::{Display, Formatter};
use std::net::IpAddr;

use log::error;
use sysinfo::{System, SystemExt, Process, ProcessExt};
use netstat2::{
    self,
    ProtocolSocketInfo::{self, Tcp, Udp},
    TcpState
};
use rrg_proto::{
    ListNetworkConnectionsArgs,
    NetworkConnection,
    NetworkEndpoint,
    network_connection::{Family, Type, State}
};

use crate::session::{self, Session};

#[derive(Debug)]
struct Error {
    connection_info_error: netstat2::error::Error,
}

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.connection_info_error)
    }
}

impl Display for Error {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(
            fmt,
            "failed to list network connections: {}",
            self.connection_info_error
        )
    }
}

impl From<netstat2::error::Error> for Error {

    fn from(error: netstat2::error::Error) -> Error {
        Error { connection_info_error: error }
    }
}

/// A request type for the network connections action.
pub struct Request {
    listening_only: bool
}

/// A type that holds brief information about the process.
struct ProcessInfo {
    /// Process ID.
    pid: u32,
    /// Process name.
    name: Option<String>
}

/// A response type for the network connections action.
pub struct Response<'a> {
    /// Information about the socket which is used by connection.
    socket_info: &'a ProtocolSocketInfo,
    /// Information about the process that owns the connection.
    process_info: Option<ProcessInfo>
}

/// Gets the IP address type from a given address.
fn make_family(addr: &IpAddr) -> Family {
    match addr {
        IpAddr::V4(_) => Family::Inet,
        IpAddr::V6(_) => Family::Inet6
    }
}

/// Contructs `NetworkEndpoint` from the specified address and port.
fn make_network_endpoint(addr: &IpAddr, port: u16) -> NetworkEndpoint {
    NetworkEndpoint {
        ip: Some(addr.to_string()),
        port: Some(port as i32)
    }
}

/// Converts [netstat2::TcpState][tcp_state] to `State`
/// enum used in the protobuf
///
/// [tcp_state]: ../../../netstat2/enum.TcpState.html
fn make_state(state: &TcpState) -> State {
    match state {
        TcpState::Unknown => State::Unknown,
        TcpState::Closed => State::Closed,
        TcpState::Listen => State::Listen,
        TcpState::SynSent => State::SynSent,
        TcpState::SynReceived => State::SynRecv,
        TcpState::Established => State::Established,
        TcpState::FinWait1 => State::FinWait1,
        TcpState::FinWait2 => State::FinWait2,
        TcpState::CloseWait => State::CloseWait,
        TcpState::Closing => State::Closing,
        TcpState::LastAck => State::LastAck,
        TcpState::TimeWait => State::TimeWait,
        TcpState::DeleteTcb => State::DeleteTcb
    }
}

/// Creates `NetworkConnection` protobuf message from
/// [netstat2::ProtocolSocketInfo][protocol_socket_info]. The fields that are
/// impossible to fill using the socket information are set to `None`.
///
/// [protocol_socket_info]: ../../../netstat2/enum.ProtocolSocketInfo.html
fn make_connection_from_socket_info<'a>(
    socket_info: &'a ProtocolSocketInfo
) -> NetworkConnection {
    match socket_info {
        Tcp(tcp_info) => NetworkConnection {
            family: Some(make_family(&tcp_info.local_addr) as i32),
            r#type: Some(Type::SockStream as i32),
            local_address: Some(make_network_endpoint(
                &tcp_info.local_addr,
                tcp_info.local_port
            )),
            remote_address: Some(make_network_endpoint(
                &tcp_info.remote_addr,
                tcp_info.remote_port
            )),
            state: Some(make_state(&tcp_info.state) as i32),
            ..Default::default()
        },
        Udp(udp_info) => NetworkConnection {
            family: Some(make_family(&udp_info.local_addr) as i32),
            r#type: Some(Type::SockDgram as i32),
            local_address: Some(make_network_endpoint(
                &udp_info.local_addr,
                udp_info.local_port
            )),
            remote_address: None,
            state: None,
            ..Default::default()
        }
    }
}

impl super::Request for Request {

    type Proto = ListNetworkConnectionsArgs;

    fn from_proto(proto: ListNetworkConnectionsArgs) -> Request {
        Request {
            listening_only: proto.listening_only.unwrap_or(false)
        }
    }
}

impl<'a> super::Response for Response<'a> {

    const RDF_NAME: Option<&'static str> = Some("NetworkConnection");

    type Proto = NetworkConnection;

    fn into_proto(self) -> Self::Proto {
        let mut result: NetworkConnection;
        result = make_connection_from_socket_info(self.socket_info);
        if let Some(process_info) = self.process_info {
            result.pid = Some(process_info.pid);
            result.process_name = process_info.name;
        }
        result
    }
}

impl From<&Process> for ProcessInfo {

    fn from(process: &Process) -> ProcessInfo {
        ProcessInfo {
            pid: process.pid() as u32,
            name: Some(process.name().to_string())
        }
    }
}

impl ProcessInfo {

    /// Constucts a ProcessInfo system from a given process ID. The process
    /// name will not be set.
    fn from_pid(pid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: None
        }
    }

    /// Constucts a ProcessInfo system from a given process ID. The process
    /// name will be retrieved from the system using `system` parameter.
    fn from_system<S: SystemExt>(system: &S, pid: u32) -> ProcessInfo {
        match system.get_process(pid as i32) {
            Some(process) => ProcessInfo::from(process),
            None => ProcessInfo::from_pid(pid)
        }
    }
}

/// Handles requests for the network connection action.
pub fn handle<S>(session: &mut S, request: Request) -> session::Result<()>
where
    S: Session
{
    let mut system = System::new();
    system.refresh_processes();

    let addr_family_flags = netstat2::AddressFamilyFlags::all();
    // Optimization: when we are asked only for listening connections,
    // we need only TCP protocol.
    let protocol_flags = if request.listening_only {
        netstat2::ProtocolFlags::TCP
    } else {
        netstat2::ProtocolFlags::all()
    };

    let connection_iter = netstat2::iterate_sockets_info(
        addr_family_flags,
        protocol_flags
    );
    let connection_iter = match connection_iter {
        Ok(val) => val,
        Err(err) => return Err(session::Error::action(Error::from(err)))
    };

    for connection in connection_iter {
        let connection = match connection {
            Ok(val) => val,
            Err(err) => {
                error!("unable to get socket information: {}", err);
                continue;
            }
        };
        let socket_info = connection.protocol_socket_info;

        if request.listening_only {
            let tcp_info = match &socket_info {
                Tcp(tcp_info) => tcp_info,
                Udp(_) => {
                    // We are interested only in TCP connections.
                    continue;
                }
            };
            if tcp_info.state != TcpState::Listen {
                // We are interested only in listening connections.
                continue;
            }
        }

        let pids = &connection.associated_pids;

        if pids.is_empty() {
            // If the process ID is not associated, we send a response
            // without it. The behavior is different from Python implementation,
            // because the latter lists only the connections associated with a
            // process.
            session.reply(Response {
                socket_info: &socket_info,
                process_info: None
            })?;
            continue;
        }

        // Otherwise, we have one or more processes associated with the
        // connection. Since the protocol allows to specify only one process
        // for connection, we report this connection multiple times, as if the
        // associated processes had different connections. This behavior is
        // also compatible with the Python implementation, which iterates over
        // all the processes and then iterates over the connections for each
        // of them.
        for pid in pids {
            session.reply(Response {
                socket_info: &socket_info,
                process_info: Some(ProcessInfo::from_system(&system, *pid))
            })?;
        }
    }

    Ok(())
}
