// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use log::warn;

/// A result of the `list_connections` action.
struct Item {
    // Information about the individual connection.
    conn: ospect::net::Connection,
}

// Handles invocations of the `list_connections` action.
pub fn handle<S>(session: &mut S, _: ()) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let conns = ospect::net::all_connections()
        .map_err(crate::session::Error::action)?;

    for conn in conns {
        let conn = match conn {
            Ok(conn) => conn,
            Err(error) => {
                warn!("failed to obtain connection information: {}", error);
                continue;
            }
        };

        session.reply(Item {
            conn,
        })?;
    }

    Ok(())
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::v2::list_connections::Result;

    fn into_proto(self) -> rrg_proto::v2::list_connections::Result {
        let mut proto = rrg_proto::v2::list_connections::Result::new();
        proto.set_connection(self.conn.into());

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn handle_local_tcp_connection() {
        use std::net::Ipv4Addr;

        let server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap();
        let server_addr = server.local_addr()
            .unwrap();

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());

        let item = session.replies::<Item>().find(|item| {
            item.conn.local_addr() == server_addr
        }).unwrap();

        if let ospect::net::Connection::Tcp(conn) = item.conn {
            assert_eq!(conn.state(), ospect::net::TcpState::Listen);
        } else {
            panic!();
        }
    }

    #[test]
    fn handle_local_udp_connection() {
        use std::net::Ipv4Addr;

        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap();
        let socket_addr = socket.local_addr()
            .unwrap();

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());

        let item = session.replies::<Item>().find(|item| {
            item.conn.local_addr() == socket_addr
        }).unwrap();

        assert!(matches!(item.conn, ospect::net::Connection::Udp(_)));
    }
}
