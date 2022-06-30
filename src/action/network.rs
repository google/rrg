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
use netstat2::{self, ProtocolSocketInfo, TcpState};

use crate::session::{self, Session};

/// An error type for situations when the network connection action fails.
#[derive(Debug)]
struct Error(netstat2::error::Error);

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl Display for Error {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "failed to list network connections: {}", self.0)
    }
}

impl From<netstat2::error::Error> for Error {

    fn from(error: netstat2::error::Error) -> Error {
        Error(error)
    }
}

impl Into<session::Error> for Error {

    fn into(self) -> session::Error {
        session::Error::action(self)
    }
}

/// A request type for the network connections action.
#[derive(Debug)]
pub struct Request {
    listening_only: bool,
}

/// A type that holds brief information about the process.
#[derive(Debug)]
struct ProcessInfo {
    /// Process ID.
    pid: u32,
    /// Process name.
    name: Option<String>,
}

/// A response type for the network connections action.
#[derive(Debug)]
pub struct Response {
    /// Information about the socket which is used by connection.
    socket_info: ProtocolSocketInfo,
    /// Information about the process that owns the connection.
    process_info: Option<ProcessInfo>,
}

/// Gets the IP address type from a given address.
fn make_family(addr: &IpAddr) -> rrg_proto::protobuf::sysinfo::NetworkConnection_Family {
    use rrg_proto::protobuf::sysinfo::NetworkConnection_Family::*;
    match addr {
        IpAddr::V4(_) => INET,
        IpAddr::V6(_) => INET6,
    }
}

/// Contructs `NetworkEndpoint` from the specified address and port.
fn make_network_endpoint(addr: &IpAddr, port: u16) -> rrg_proto::protobuf::sysinfo::NetworkEndpoint {
    let mut proto = rrg_proto::protobuf::sysinfo::NetworkEndpoint::new();
    proto.set_ip(addr.to_string());
    proto.set_port(port as i32);

    proto
}

/// Converts [netstat2::TcpState][tcp_state] to `State`
/// enum used in the protobuf
///
/// [tcp_state]: ../../../netstat2/enum.TcpState.html
fn make_state(state: &TcpState) -> rrg_proto::protobuf::sysinfo::NetworkConnection_State {
    use rrg_proto::protobuf::sysinfo::NetworkConnection_State::*;
    match state {
        TcpState::Unknown => UNKNOWN,
        TcpState::Closed => CLOSED,
        TcpState::Listen => LISTEN,
        TcpState::SynSent => SYN_SENT,
        TcpState::SynReceived => SYN_RECV,
        TcpState::Established => ESTABLISHED,
        TcpState::FinWait1 => FIN_WAIT1,
        TcpState::FinWait2 => FIN_WAIT2,
        TcpState::CloseWait => CLOSE_WAIT,
        TcpState::Closing => CLOSING,
        TcpState::LastAck => LAST_ACK,
        TcpState::TimeWait => TIME_WAIT,
        TcpState::DeleteTcb => DELETE_TCB,
    }
}

/// Creates `NetworkConnection` protobuf message from
/// [netstat2::ProtocolSocketInfo][protocol_socket_info]. The fields that are
/// impossible to fill using the socket information are set to `None`.
///
/// [protocol_socket_info]: ../../../netstat2/enum.ProtocolSocketInfo.html
fn make_connection_from_socket_info(
    socket_info: &ProtocolSocketInfo
) -> rrg_proto::protobuf::sysinfo::NetworkConnection {
    use ProtocolSocketInfo::{Tcp, Udp};

    let mut proto = rrg_proto::protobuf::sysinfo::NetworkConnection::new();

    match socket_info {
        Tcp(tcp_info) => {
            proto.set_family(make_family(&tcp_info.local_addr));
            proto.set_field_type(rrg_proto::protobuf::sysinfo::NetworkConnection_Type::SOCK_STREAM);
            proto.set_local_address(make_network_endpoint(
                &tcp_info.local_addr,
                tcp_info.local_port
            ));
            proto.set_remote_address(make_network_endpoint(
                &tcp_info.remote_addr,
                tcp_info.remote_port
            ));
            proto.set_state(make_state(&tcp_info.state));
        },
        Udp(udp_info) => {
            proto.set_family(make_family(&udp_info.local_addr));
            proto.set_field_type(rrg_proto::protobuf::sysinfo::NetworkConnection_Type::SOCK_DGRAM);
            proto.set_local_address(make_network_endpoint(
                &udp_info.local_addr,
                udp_info.local_port
            ));
        },
    }

    proto
}

impl super::Request for Request {

    type Proto = rrg_proto::protobuf::flows::ListNetworkConnectionsArgs;

    fn from_proto(proto: Self::Proto) -> Result<Request, session::ParseError> {
        Ok(Request {
            listening_only: proto.get_listening_only(),
        })
    }
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("NetworkConnection");

    type Proto = rrg_proto::protobuf::sysinfo::NetworkConnection;

    fn into_proto(self) -> Self::Proto {
        let mut result = make_connection_from_socket_info(&self.socket_info);
        if let Some(process_info) = self.process_info {
            result.set_pid(process_info.pid);
            if let Some(name) = process_info.name {
                result.set_process_name(name);
            }
        }
        result
    }
}

impl From<&Process> for ProcessInfo {

    fn from(process: &Process) -> ProcessInfo {
        ProcessInfo {
            pid: process.pid() as u32,
            name: Some(process.name().to_string()),
        }
    }
}

impl ProcessInfo {

    /// Constructs a `ProcessInfo` from the given process ID.
    ///
    /// The process name will not be set.
    fn from_pid(pid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: None,
        }
    }

    /// Constructs a `ProcessInfo` from the given process ID.
    ///
    /// The process name will be retrieved from the system using the `system`
    /// parameter.
    fn from_system<S: SystemExt>(system: &S, pid: u32) -> ProcessInfo {
        match system.get_process(pid as sysinfo::Pid) {
            Some(process) => ProcessInfo::from(process),
            None => ProcessInfo::from_pid(pid),
        }
    }
}

/// Handles requests for the network connection action.
pub fn handle<S>(session: &mut S, request: Request) -> session::Result<()>
where
    S: Session,
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
        Err(err) => return Err(Error::from(err).into()),
    };

    for connection in connection_iter {
        let connection = match connection {
            Ok(val) => val,
            Err(err) => {
                error!("unable to get socket information: {}", err);
                continue;
            },
        };
        let socket_info = connection.protocol_socket_info;

        if request.listening_only {
            use ProtocolSocketInfo::{Tcp, Udp};

            let tcp_info = match &socket_info {
                Tcp(tcp_info) => tcp_info,
                Udp(_) => {
                    // We are interested only in TCP connections.
                    continue;
                },
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
                socket_info: socket_info,
                process_info: None,
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
                socket_info: socket_info.clone(),
                process_info: Some(ProcessInfo::from_system(&system, *pid)),
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use netstat2::TcpSocketInfo;
    use std::net::{TcpStream, TcpListener, UdpSocket};

    /// Gets `TcpSocketInfo` from `response`.
    ///
    /// This function panics if `response` doesn't represent a TCP connection.
    fn extract_tcp_info(response: &Response) -> &TcpSocketInfo {
        match &response.socket_info {
            ProtocolSocketInfo::Tcp(tcp) => tcp,
            ProtocolSocketInfo::Udp(_) => {
                panic!("expected TCP connection");
            },
        }
    }

    /// Checks if `response` represents a UDP connection.
    fn is_udp(response: &Response) -> bool {
        match &response.socket_info {
            ProtocolSocketInfo::Udp(_) => true,
            _ => false,
        }
    }

    // TODO: Make this test work on macOS.
    //
    // For some reason, on macOS, the agent reports only one response. It should
    // be investigated and fixed as it might indicate problems with incorrect
    // assumptions on other platforms as well.
    #[cfg_attr(target_os = "macos", ignore)]
    #[test]
    fn test_tcp() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = TcpStream::connect(server_addr).unwrap();
        let client_addr = client.local_addr().unwrap();

        let mut session = session::test::Fake::new();
        let request = Request { listening_only: false };
        assert!(handle(&mut session, request).is_ok());

        let our_pid = std::process::id();

        let listen_resp = session.replies::<Response>().find(|reply| {
            if socket_info_addr(&reply.socket_info) != server_addr {
                return false;
            }

            let info = match &reply.socket_info {
                ProtocolSocketInfo::Tcp(info) => info,
                ProtocolSocketInfo::Udp(_) => return false,
            };

            info.state == TcpState::Listen
        }).expect("no reply with listening server-side TCP connection");

        let connection_resp = session.replies::<Response>().find(|reply| {
            if socket_info_addr(&reply.socket_info) != server_addr {
                return false;
            }

            let info = match &reply.socket_info {
                ProtocolSocketInfo::Tcp(info) => info,
                ProtocolSocketInfo::Udp(_) => return false,
            };

            info.state == TcpState::Established
        }).expect("no reply with established server-side TCP connection");

        // We don't check PID for `connection_resp`, because it is unset at
        // least on Linux and it's unclear whether PID is set on other systems.
        assert_eq!(listen_resp.process_info.as_ref().unwrap().pid, our_pid);

        let connection_socket = extract_tcp_info(&connection_resp);
        // Local addresses are tested already, because they are used to find
        // the connections.
        assert_eq!(connection_socket.remote_addr, client_addr.ip());
        assert_eq!(connection_socket.remote_port, client_addr.port());

        let client_resp = session.replies::<Response>().find(|reply| {
            socket_info_addr(&reply.socket_info) == client_addr
        }).expect("no reply with established client-side TCP connection");

        assert_eq!(client_resp.process_info.as_ref().unwrap().pid, our_pid);

        let client_socket = extract_tcp_info(&client_resp);
        // Again, we don't need to check the client address, because it is used
        // to find the connection.
        assert_eq!(client_socket.remote_addr, server_addr.ip());
        assert_eq!(client_socket.remote_port, server_addr.port());
        assert_eq!(client_socket.state, TcpState::Established);
    }

    #[test]
    fn test_udp() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client.local_addr().unwrap();
        client.connect(server_addr).unwrap();

        let mut session = session::test::Fake::new();
        let request = Request { listening_only: false };
        assert!(handle(&mut session, request).is_ok());

        let our_pid = std::process::id();

        let server_resp = session.replies::<Response>().find(|reply| {
            socket_info_addr(&reply.socket_info) == server_addr
        }).expect("no reply with a server-side connection");
        assert_eq!(server_resp.process_info.as_ref().unwrap().pid, our_pid);
        assert!(is_udp(&server_resp));

        let client_resp = session.replies::<Response>().find(|reply| {
            socket_info_addr(&reply.socket_info) == client_addr
        }).expect("no reply with a client-side connection");
        assert_eq!(client_resp.process_info.as_ref().unwrap().pid, our_pid);
        assert!(is_udp(&client_resp));
    }

    #[test]
    fn test_tcp_listen_only() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = TcpStream::connect(server_addr).unwrap();
        let client_addr = client.local_addr().unwrap();

        let mut session = session::test::Fake::new();
        let request = Request { listening_only: true };
        assert!(handle(&mut session, request).is_ok());

        let server_resp = session.replies::<Response>().find(|reply| {
            if socket_info_addr(&reply.socket_info) != server_addr {
                return false;
            }

            let info = match &reply.socket_info {
                ProtocolSocketInfo::Tcp(info) => info,
                ProtocolSocketInfo::Udp(_) => return false,
            };

            info.state == TcpState::Listen
        });
        assert!(server_resp.is_some());

        let client_resp = session.replies::<Response>().find(|reply| {
            socket_info_addr(&reply.socket_info) == client_addr
        });
        assert!(client_resp.is_none());
    }

    #[test]
    fn test_udp_listen_only() {
        let connection = UdpSocket::bind("127.0.0.1:0").unwrap();
        let connection_addr = connection.local_addr().unwrap();

        let mut session = session::test::Fake::new();
        let request = Request { listening_only: true };
        assert!(handle(&mut session, request).is_ok());

        let connection_resp = session.replies::<Response>().find(|reply| {
            socket_info_addr(&reply.socket_info) == connection_addr
        });
        assert!(connection_resp.is_none());
    }

    // TODO: Consider moving the following 3 helper methods to the `netstat2`
    // crate.

    /// Retrieves a local IP address of the given socket info object.
    fn socket_info_local_ip(info: &ProtocolSocketInfo) -> std::net::IpAddr {
        match info {
            ProtocolSocketInfo::Tcp(info) => info.local_addr,
            ProtocolSocketInfo::Udp(info) => info.local_addr,
        }
    }

    /// Retrieves a local port of the given socket info object.
    fn socket_info_local_port(info: &ProtocolSocketInfo) -> u16 {
        match info {
            ProtocolSocketInfo::Tcp(info) => info.local_port,
            ProtocolSocketInfo::Udp(info) => info.local_port,
        }
    }

    /// Retrieves a local socket address of the given socket info object.
    fn socket_info_addr(info: &ProtocolSocketInfo) -> std::net::SocketAddr {
        let local_addr = socket_info_local_ip(&info);
        let local_port = socket_info_local_port(&info);
        std::net::SocketAddr::new(local_addr, local_port)
    }
}
