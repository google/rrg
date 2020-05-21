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
use rrg_proto::{Interface, NetworkAddress};

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
fn ip_to_proto(ip_network: IpNetwork) -> NetworkAddress {
    use rrg_proto::network_address::Family;
    use std::net::IpAddr::{V4, V6};

    match ip_network.ip() {
        V4(ipv4) => NetworkAddress {
            address_type: Some(Family::Inet.into()),
            packed_bytes: Some(ipv4.octets().to_vec()),
            ..Default::default()
        },
        V6(ipv6) => NetworkAddress {
            address_type: Some(Family::Inet6.into()),
            packed_bytes: Some(ipv6.octets().to_vec()),
            ..Default::default()
        },
    }
}

/// Maps a vector of [`IpNetwork`][ip_network]s to a vector
/// of protobuf structs corresponding to an IP address.
///
/// [ip_network]: ../../../ipnetwork/enum.IpNetwork.html
fn ips_to_protos(ips: Vec<IpNetwork>) -> Vec<NetworkAddress> {
    ips.into_iter().map(ip_to_proto).collect()
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("Interface");

    type Proto = Interface;

    fn into_proto(self) -> Interface {
        let mac = match self.interface.mac {
            Some(mac) => Some(mac_to_vec(mac)),
            None => {
                error!(
                    "unable to get MAC address for {} interface",
                    self.interface.name,
                );
                None
            },
        };

        Interface {
            mac_address: mac,
            ifname: Some(self.interface.name),
            addresses: ips_to_protos(self.interface.ips),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_loopback_presence() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());

        let mut is_loopback_present = false;
        for i in 0..session.reply_count() {
            let interface = &session.reply::<Response>(i).interface;
            is_loopback_present |= interface.is_loopback();
        }
        assert!(is_loopback_present);
    }
}
