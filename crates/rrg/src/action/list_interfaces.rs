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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn loopback_exists() {
        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());

        // A single network interface can be associated with many IP addresses,
        // some of which might not be traditional loopback addresses. Therefore,
        // we use `any` instead of `all`.
        fn is_loopback(iface: &ospect::net::Interface) -> bool {
            iface.ip_addrs().any(std::net::IpAddr::is_loopback)
        }

        assert! {
            session.replies().any(|item: &Item| is_loopback(&item.iface))
        }
    }
}
