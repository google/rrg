// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::fmt::{Display, Formatter};
use std::net::IpAddr;

use log::error;
use netstat2::{self, ProtocolSocketInfo, TcpSocketInfo, TcpState};
use rrg_proto::network_connection;
use sysinfo::{System, SystemExt, Process, ProcessExt};

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
        write!(fmt, "failed to list network connections: {}",
               self.connection_info_error)
    }
}

impl From<netstat2::error::Error> for Error {
    fn from(error: netstat2::error::Error) -> Error {
        Error { connection_info_error: error }
    }
}

pub struct Request {
    listening_only: bool
}

struct ProcessInfo {
    pid: u32,
    name: Option<String>
}

pub struct Response<'a> {
    socket_info: &'a ProtocolSocketInfo,
    process_info: Option<ProcessInfo>
}

struct SocketInfoWrapper<'a>(&'a ProtocolSocketInfo);

fn make_family(addr: &IpAddr) -> network_connection::Family {
    match addr {
        IpAddr::V4(_) => network_connection::Family::Inet,
        IpAddr::V6(_) => network_connection::Family::Inet6
    }
}

fn make_network_endpoint(addr: &IpAddr, port: u16) -> rrg_proto::NetworkEndpoint {
    rrg_proto::NetworkEndpoint {
        ip: Some(addr.to_string()),
        port: Some(port as i32)
    }
}

fn make_state(state: &TcpState) -> network_connection::State {
    match state {
        TcpState::Unknown     => network_connection::State::Unknown,
        TcpState::Closed      => network_connection::State::Closed,
        TcpState::Listen      => network_connection::State::Listen,
        TcpState::SynSent     => network_connection::State::SynSent,
        TcpState::SynReceived => network_connection::State::SynRecv,
        TcpState::Established => network_connection::State::Established,
        TcpState::FinWait1    => network_connection::State::FinWait1,
        TcpState::FinWait2    => network_connection::State::FinWait2,
        TcpState::CloseWait   => network_connection::State::CloseWait,
        TcpState::Closing     => network_connection::State::Closing,
        TcpState::LastAck     => network_connection::State::LastAck,
        TcpState::TimeWait    => network_connection::State::TimeWait,
        TcpState::DeleteTcb   => network_connection::State::DeleteTcb
    }
}

impl super::Request for Request {
    type Proto = rrg_proto::ListNetworkConnectionsArgs;

    fn from_proto(proto: Self::Proto) -> Request {
        Request {
            listening_only: proto.listening_only.unwrap_or(false)
        }
    }
}

impl<'a> super::Response for Response<'a> {
    
    const RDF_NAME: Option<&'static str> = Some("NetworkConnection");

    type Proto = rrg_proto::NetworkConnection;

    fn into_proto(self) -> Self::Proto {
        let mut result: rrg_proto::NetworkConnection;
        result = SocketInfoWrapper(self.socket_info).into();
        if let Some(process_info) = self.process_info {
            result.pid = Some(process_info.pid);
            result.process_name = process_info.name;
        }
        result
    }
}

impl<'a> Into<rrg_proto::NetworkConnection> for SocketInfoWrapper<'a> {

    fn into(self) -> rrg_proto::NetworkConnection {
        match self.0 {
            ProtocolSocketInfo::Tcp(tcp_info) => {
                rrg_proto::NetworkConnection {
                    family: Some(make_family(&tcp_info.local_addr) as i32),
                    r#type: Some(network_connection::Type::SockStream as i32),
                    local_address:
                        Some(make_network_endpoint(&tcp_info.local_addr,
                                                   tcp_info.local_port)),
                    remote_address:
                        Some(make_network_endpoint(&tcp_info.remote_addr,
                                                   tcp_info.remote_port)),
                    state: Some(make_state(&tcp_info.state) as i32),
                    ..Default::default()
                }
            },
            ProtocolSocketInfo::Udp(udp_info) => {
                rrg_proto::NetworkConnection {
                    family: Some(make_family(&udp_info.local_addr) as i32),
                    r#type: Some(network_connection::Type::SockDgram as i32),
                    local_address:
                        Some(make_network_endpoint(&udp_info.local_addr,
                                                   udp_info.local_port)),
                    remote_address: None,
                    state: None,
                    ..Default::default()
                }
            }
        }
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
    fn from_pid(pid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: None
        }
    }
    
    fn from_system<S: SystemExt>(system: &S, pid: u32) -> ProcessInfo {
        match system.get_process(pid as i32) {
            Some(process) => ProcessInfo::from(process),
            None => ProcessInfo::from_pid(pid)
        }
    }
}

pub fn handle<S: Session>(session: &mut S,
                          request: Request) -> session::Result<()> {
    let mut system = System::new();
    system.refresh_processes();
    
    let connection_iter = netstat2::iterate_sockets_info(
        netstat2::AddressFamilyFlags::all(), netstat2::ProtocolFlags::all());
    let connection_iter = match connection_iter {
        Ok(val) => val,
        Err(err) => return Err(session::Error::action(Error::from(err)))
    };
    
    for connection in connection_iter {
        let connection = match connection {
            Ok(val) => val,
            Err(err) => {
                error!("Unable to get socket information: {}", err);
                continue;
            }
        };
        let socket_info = connection.protocol_socket_info;
        if request.listening_only {
            // TODO: line is toooo long, deal with it somehow
            if let ProtocolSocketInfo::Tcp(TcpSocketInfo { state: TcpState::Listen, .. }) = socket_info {
                // we have a listening connection, do nothing
            } else {
                continue;
            }
        }
        let pids = &connection.associated_pids;
        if pids.is_empty() {
            session.reply(Response {
                socket_info: &socket_info,
                process_info: None
            })?;
            continue;
        }
        for pid in pids {
            session.reply(Response {
                socket_info: &socket_info,
                process_info: Some(ProcessInfo::from_system(&system, *pid))
            })?;
        }
    }

    Ok(())
}
