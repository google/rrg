// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the interfaces action.
//!
//! The interfaces action lists all network interfaces available on the client,
//! collecting their names, MAC and IP addresses.

use log::error;

use pnet::{
    datalink::{self, NetworkInterface},
    ipnetwork::IpNetwork,
    util::MacAddr,
};

use crate::session::{self, Session};

/// A response type for the interfaces action.
#[derive(Debug)]
pub struct Response {
    /// Information about an interface.
    interface: NetworkInterface,
}

/// Handles requests for the interfaces action.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    for interface in datalink::interfaces() {
        session.reply(Response {
            interface: interface,
        })?;
    }

    Ok(())
}

/// Converts a [`MacAddr`][mac_addr] to a vector of bytes,
/// which is what protobuf expects as a MAC.
///
/// [mac_addr]: ../../../pnet/util/struct.MacAddr.html
fn mac_to_vec(mac: MacAddr) -> Vec<u8> {
    vec![mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]
}

/// Converts a single [`IpNetwork`][ip_network] to a protobuf struct
/// corresponding to an IP address.
///
/// [ip_network]: ../../../ipnetwork/enum.IpNetwork.html
fn ip_to_proto(ip_network: IpNetwork) -> rrg_proto::jobs::NetworkAddress {
    use std::net::IpAddr::{V4, V6};
    use rrg_proto::jobs::NetworkAddress_Family::*;

    let mut proto = rrg_proto::jobs::NetworkAddress::new();
    match ip_network.ip() {
        V4(ipv4) => {
            proto.set_address_type(INET);
            proto.set_packed_bytes(ipv4.octets().to_vec());
        },
        V6(ipv6) => {
            proto.set_address_type(INET6);
            proto.set_packed_bytes(ipv6.octets().to_vec());
        },
    }

    proto
}

/// Maps a vector of [`IpNetwork`][ip_network]s to a vector
/// of protobuf structs corresponding to an IP address.
///
/// [ip_network]: ../../../ipnetwork/enum.IpNetwork.html
fn ips_to_protos(ips: Vec<IpNetwork>) -> Vec<rrg_proto::jobs::NetworkAddress> {
    ips.into_iter().map(ip_to_proto).collect()
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("Interface");

    type Proto = rrg_proto::jobs::Interface;

    fn into_proto(self) -> rrg_proto::jobs::Interface {
        let mut proto = rrg_proto::jobs::Interface::new();

        match self.interface.mac {
            Some(mac) => {
                proto.set_mac_address(mac_to_vec(mac));
            }
            None => {
                error!(
                    "unable to get MAC address for {} interface",
                    self.interface.name,
                );
            },
        };

        proto.set_ifname(self.interface.name);

        for address in ips_to_protos(self.interface.ips) {
            proto.mut_addresses().push(address);
        }

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_loopback_presence() {
        let mut session = session::test::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());

        let mut is_loopback_present = false;
        for i in 0..session.reply_count() {
            let interface = &session.reply::<Response>(i).interface;
            is_loopback_present |= interface.is_loopback();
        }
        assert!(is_loopback_present);
    }
}
