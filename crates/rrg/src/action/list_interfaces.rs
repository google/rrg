// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// A result of the `list_interfaces` action.
struct Item {
    // Information about the individual network interface.
    iface: ospect::net::Interface,
}

// Handles invocations of the `list_interfaces` action.
pub fn handle<S>(session: &mut S, _: ()) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let ifaces = ospect::net::interfaces()
        .map_err(crate::session::Error::action)?;

    for iface in ifaces {
        session.reply(Item {
            iface,
        })?;
    }

    Ok(())
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::v2::list_interfaces::Result;

    fn into_proto(self) -> rrg_proto::v2::list_interfaces::Result {
        let mut proto = rrg_proto::v2::list_interfaces::Result::default();
        proto.set_interface(self.iface.into());

        proto
    }
}
