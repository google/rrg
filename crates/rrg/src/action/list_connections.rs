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
