// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

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

fn make_family(addr: &IpAddr) -> Family {
    match addr {
        IpAddr::V4(_) => Family::Inet,
        IpAddr::V6(_) => Family::Inet6
    }
}

fn make_network_endpoint(addr: &IpAddr, port: u16) -> NetworkEndpoint {
    NetworkEndpoint {
        ip: Some(addr.to_string()),
        port: Some(port as i32)
    }
}

fn make_state(state: &TcpState) -> State {
    match state {
        TcpState::Unknown     => State::Unknown,
        TcpState::Closed      => State::Closed,
        TcpState::Listen      => State::Listen,
        TcpState::SynSent     => State::SynSent,
        TcpState::SynReceived => State::SynRecv,
        TcpState::Established => State::Established,
        TcpState::FinWait1    => State::FinWait1,
        TcpState::FinWait2    => State::FinWait2,
        TcpState::CloseWait   => State::CloseWait,
        TcpState::Closing     => State::Closing,
        TcpState::LastAck     => State::LastAck,
        TcpState::TimeWait    => State::TimeWait,
        TcpState::DeleteTcb   => State::DeleteTcb
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
        result = SocketInfoWrapper(self.socket_info).into();
        if let Some(process_info) = self.process_info {
            result.pid = Some(process_info.pid);
            result.process_name = process_info.name;
        }
        result
    }
}

impl<'a> Into<NetworkConnection> for SocketInfoWrapper<'a> {

    fn into(self) -> NetworkConnection {
        match self.0 {
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

pub fn handle<S: Session>(
    session: &mut S,
    request: Request
) -> session::Result<()> {
    let mut system = System::new();
    system.refresh_processes();

    let connection_iter = netstat2::iterate_sockets_info(
        netstat2::AddressFamilyFlags::all(), netstat2::ProtocolFlags::all()
    );
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
            let tcp_info = match &socket_info {
                Tcp(tcp_info) => tcp_info,
                Udp(_) => {
                    // we are interested only in TCP connections
                    continue;
                }
            };
            if tcp_info.state != TcpState::Listen {
                // we are interested only in listening connections
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
