// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the network connection action.
//!
//! The network connection action lists all the opened connections on the
//! client and the information about them (e.g. type of the connection, source
//! and target IP addresses, the process that owns the connection).

use crate::session::{self, Session};

/// Arguments for the network connections action.
#[derive(Debug)]
pub struct Args {
    /// Whether to return only connections in the listening state.
    listening_only: bool,
}

/// Result yielded by the network connections action.
#[derive(Debug)]
pub struct Item {
    /// Metadata about the network connection.
    conn: ospect::net::Connection,
}

/// An error type for situations when the network connection action fails.
#[derive(Debug)]
struct Error(std::io::Error);

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl std::fmt::Display for Error {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "failed to list network connections: {}", self.0)
    }
}

impl From<Error> for session::Error {

    fn from(error: Error) -> session::Error {
        session::Error::action(error)
    }
}

/// Handles execution of the network connections action.
pub fn handle<S>(session: &mut S, args: Args) -> session::Result<()>
where
    S: Session,
{
    use rrg_macro::warn;

    let pids = ospect::proc::ids()
        .map_err(Error)?;

    for pid in pids {
        let pid = match pid {
            Ok(pid) => pid,
            Err(error) => {
                warn!("failed to get process identifier: {}", error);
                continue;
            }
        };

        let conns = match ospect::net::connections(pid) {
            Ok(conns) => conns,
            Err(error) => {
                warn! {
                    "failed to list network connections for process {}: {}",
                    pid, error,
                };
                continue;
            }
        };

        for conn in conns {
            let conn = match conn {
                Ok(conn) => conn,
                Err(error) => {
                    warn! {
                        "failed to get connection metadata for process {}: {}",
                        pid, error,
                    };
                    continue;
                }
            };

            if args.listening_only {
                match conn {
                    ospect::net::Connection::Tcp(conn) if conn.state() == ospect::net::TcpState::Listen => (),
                    _ => continue,
                }
            }

            session.reply(Item { conn })?;
        }
    }

    Ok(())
}

impl crate::Args for Args {

    type Proto = rrg_proto::flows::ListNetworkConnectionsArgs;

    fn from_proto(proto: Self::Proto) -> Result<Args, crate::ParseArgsError> {
        Ok(Args {
            listening_only: proto.get_listening_only(),
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::sysinfo::NetworkConnection;

    fn into_proto(self) -> Self::Proto {
        let mut result = rrg_proto::sysinfo::NetworkConnection::default();
        result.set_pid(self.conn.pid());

        match self.conn {
            ospect::net::Connection::Tcp(conn) => {
                result.set_field_type(rrg_proto::sysinfo::NetworkConnection_Type::SOCK_STREAM);
                result.set_local_address(addr_to_proto(conn.local_addr()));
                result.set_remote_address(addr_to_proto(conn.remote_addr()));
                result.set_state(state_to_proto(conn.state()));
            }
            ospect::net::Connection::Udp(conn) => {
                result.set_field_type(rrg_proto::sysinfo::NetworkConnection_Type::SOCK_DGRAM);
                result.set_local_address(addr_to_proto(conn.local_addr()));
            }
        }

        result
    }
}

// TOOD(@panhania): Migrate to `std::convert` implementation.
fn addr_to_proto(addr: std::net::SocketAddr) -> rrg_proto::sysinfo::NetworkEndpoint {
    let mut result = rrg_proto::sysinfo::NetworkEndpoint::default();
    result.set_ip(addr.ip().to_string());
    result.set_port(addr.port().into());
    result
}

// TOOD(@panhania): Migrate to `std::convert` implementation.
fn state_to_proto(state: ospect::net::TcpState) -> rrg_proto::sysinfo::NetworkConnection_State {
    use ospect::net::TcpState::*;
    use rrg_proto::sysinfo::NetworkConnection_State::*;

    match state {
        Listen => LISTEN,
        SynSent => SYN_SENT,
        SynReceived => SYN_RECV,
        Established => ESTABLISHED,
        FinWait1 => FIN_WAIT1,
        FinWait2 => FIN_WAIT2,
        CloseWait => CLOSE_WAIT,
        Closing => CLOSING,
        LastAck => LAST_ACK,
        TimeWait => TIME_WAIT,
        Closed => CLOSED,
    }
}
