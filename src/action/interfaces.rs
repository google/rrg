// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the interfaces action.
//!
//! The interfaces action lists all network interfaces available on the client,
//! collecting their names, MAC and IP addresses.

use rrg_macro::warn;

use crate::session::{self, Session};

/// A response type for the interfaces action.
#[derive(Debug)]
pub struct Response {
    /// Information about an interface.
    interface: crate::net::Interface,
}

/// Handles requests for the interfaces action.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    // TODO(panhania@): Fix error handling.
    for interface in crate::net::interfaces().unwrap() {
        session.reply(Response {
            interface: interface,
        })?;
    }

    Ok(())
}

impl super::Item for Response {

    const RDF_NAME: &'static str = "Interface";

    type Proto = rrg_proto::jobs::Interface;

    fn into_proto(self) -> rrg_proto::jobs::Interface {
        let mut proto = rrg_proto::jobs::Interface::new();

        let name = self.interface.name().to_string_lossy();
        if let std::borrow::Cow::Owned(_) = &name {
            warn!("network interface name with invalid bytes: {:?}", name);
        }
        proto.set_ifname(name.to_string());

        if let Some(mac_addr) = self.interface.mac_addr() {
            proto.set_mac_address(mac_addr.octets().into());
        } else {
            warn!("network interface '{}' without MAC address", name);
        }

        for ip_addr in self.interface.ip_addrs() {
            use rrg_proto::jobs::NetworkAddress_Family::{INET, INET6};

            let mut ip_addr_proto = rrg_proto::jobs::NetworkAddress::new();
            match ip_addr {
                std::net::IpAddr::V4(ip_addr) => {
                    ip_addr_proto.set_address_type(INET);
                    ip_addr_proto.set_packed_bytes(ip_addr.octets().into());
                },
                std::net::IpAddr::V6(ip_addr) => {
                    ip_addr_proto.set_address_type(INET6);
                    ip_addr_proto.set_packed_bytes(ip_addr.octets().into());
                },
            };
            proto.mut_addresses().push(ip_addr_proto);
        }

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_loopback_presence() {
        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());

        let mut is_loopback_present = false;
        for i in 0..session.reply_count() {
            let interface = &session.reply::<Response>(i).interface;
            for ip_addr in interface.ip_addrs() {
                is_loopback_present |= ip_addr.is_loopback();
            }
        }
        assert!(is_loopback_present);
    }
}
