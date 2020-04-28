// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::net::IpAddr;

use ipnetwork::IpNetwork;
use pnet::{
    datalink::{self, NetworkInterface},
    util::MacAddr,
};
use rrg_proto::{Interface, NetworkAddress, network_address::Family};

use crate::session::{self, Session};

pub struct Response {
    interface: NetworkInterface,
}

pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    for interface in datalink::interfaces() {
        session.reply(Response {
            interface: interface,
        })?;
    }

    Ok(())
}

fn mac_to_vec(mac: MacAddr) -> Vec<u8> {
    vec![mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]
}

fn ip_to_proto(ip_network: IpNetwork) -> NetworkAddress {
    match ip_network.ip() {
        IpAddr::V4(ipv4) => NetworkAddress {
            address_type: Some(Family::Inet as i32),
            packed_bytes: Some(ipv4.octets().to_vec()),
            ..Default::default()
        },
        IpAddr::V6(ipv6) => NetworkAddress {
            address_type: Some(Family::Inet6 as i32),
            packed_bytes: Some(ipv6.octets().to_vec()),
            ..Default::default()
        },
    }
}

fn ips_to_protos(ips: Vec<IpNetwork>) -> Vec<NetworkAddress> {
    ips.into_iter().map(ip_to_proto).collect()
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("Interface");

    type Proto = Interface;

    fn into_proto(self) -> Interface {
        Interface {
            mac_address: Some(mac_to_vec(self.interface.mac_address())),
            ifname: Some(self.interface.name),
            addresses: ips_to_protos(self.interface.ips),
            ..Default::default()
        }
    }
}
