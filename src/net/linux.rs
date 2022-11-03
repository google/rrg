// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use super::*;

/// Collects information about available network interfaces.
///
/// A system agnostic [`interfaces`] function is available in the parent module
/// and should be the preferred choice in general.
///
/// This function is a wrapper around [`getifaddrs`][1] Linux call.
///
/// [1]: https://man7.org/linux/man-pages/man3/getifaddrs.3.html
///
/// [`interfaces`]: super::interfaces
pub fn interfaces() -> std::io::Result<impl Iterator<Item = Interface>> {
    let mut addrs = std::mem::MaybeUninit::uninit();

    // SAFETY: `getifaddrs` [1] returns a pointer (through an output parameter)
    // so there is no potential of unsafety here and the function is marked as
    // such because it operates on raw pointers.
    //
    // [1]: https://man7.org/linux/man-pages/man3/getifaddrs.3.html
    let code = unsafe {
        libc::getifaddrs(addrs.as_mut_ptr())
    };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code));
    }

    // SAFETY: We check return code above. If there was no error, `getifaddrs`
    // should initialized the `addrs` variable to a correct value.
    let addrs = unsafe {
        addrs.assume_init()
    };

    let mut ifaces = std::collections::HashMap::new();

    let mut addr_iter = addrs;
    // SAFETY: We iterate over the linked list of addresses until we hit the
    // last entry. The validity of the `addr_iter` pointer is ensured by:
    //
    //   * Starting at the value reported by the `getifaddrs` call.
    //   * Always moving to the entry pointed by the `ifa_next` field (at the
    //     end of the loop).
    while let Some(addr) = unsafe { addr_iter.as_ref() } {
        use std::os::unix::ffi::OsStrExt as _;

        // SAFETY: `ifa_ddr` is not guaranteed to be not null, so we have to
        // verify it. But if it is not null, it is guaranteed to point to valid
        // address instance.
        let family = match unsafe { addr.ifa_addr.as_ref() } {
            Some(addr) => addr.sa_family,
            None => continue,
        };

        // SAFETY: `ifa_name` is guaranteed to point to a null-terminated string
        // with interface name.
        let name = std::ffi::OsStr::from_bytes(unsafe {
            std::ffi::CStr::from_ptr(addr.ifa_name)
        }.to_bytes());

        let entry = ifaces.entry(name).or_insert(Interface {
            name: name.to_os_string(),
            ip_addrs: Vec::new(),
            mac_addr: None,
        });

        match i32::from(family) {
            libc::AF_INET => {
                // SAFETY: For `AF_INET` family, it is guaranteed that the
                // `ifa_addr` field contains a pointer to a valid IPv4 socket
                // address struct [1].
                //
                // [1]: https://man7.org/linux/man-pages/man7/ip.7.html
                let ipv4_addr_u32 = unsafe {
                    *(addr.ifa_addr as *const libc::sockaddr_in)
                }.sin_addr.s_addr;

                // `s_addr` value is in the network endian (big endian) order
                // but the IPv4 constructor expects a host endian order value.
                // Thus, we have to convert from one to another.
                let ipv4_addr_u32 = u32::from_be(ipv4_addr_u32);

                let ipv4_addr = std::net::Ipv4Addr::from(ipv4_addr_u32);
                entry.ip_addrs.push(ipv4_addr.into());
            }
            libc::AF_INET6 => {
                // SAFETY: For `AF_INET6` family, it is guaranteed that the
                // `ifa_addr` field contains a pointer to a valid IPv6 socket
                // address struct [1].
                //
                // [1]: https://man7.org/linux/man-pages/man7/ipv6.7.html
                let ipv6_addr_octets = unsafe {
                    *(addr.ifa_addr as *const libc::sockaddr_in6)
                }.sin6_addr.s6_addr;

                let ipv6_addr = std::net::Ipv6Addr::from(ipv6_addr_octets);

                entry.ip_addrs.push(ipv6_addr.into());
            },
            libc::AF_PACKET => {
                // SAFETY: For `AF_PACKET family, it is guaranteed that the
                // `ifa_add` field contains a pointer to a valid physical-layer
                // address struct [1].
                //
                //
                // [1]: https://man7.org/linux/man-pages/man7/packet.7.html
                let sockaddr = unsafe {
                    *(addr.ifa_addr as *const libc::sockaddr_ll)
                };

                // MAC addresses should always have 6 8-bit octets. It is not
                // clear whether `sll_halen` value can ever be different but we
                // check just to be sure and skip if the assumption does not
                // hold.
                if sockaddr.sll_halen != 6 {
                    // TODO: Consider logging an error.
                    continue;
                }

                let mac_addr = MacAddr::from([
                    sockaddr.sll_addr[0],
                    sockaddr.sll_addr[1],
                    sockaddr.sll_addr[2],
                    sockaddr.sll_addr[3],
                    sockaddr.sll_addr[4],
                    sockaddr.sll_addr[5],
                ]);

                // TODO: There should only be one MAC address associated with
                // a given interface. Consider logging a warning in case this
                // assumption does not hold.
                entry.mac_addr.replace(mac_addr);
            },
            _ => continue,
        }

        addr_iter = addr.ifa_next;
    }

    // We need to collect the interfaces to free the addresses below. Otherwise,
    // the keys of the hash map will point to dangling references (since the map
    // keys are owned by the address list).
    let ifaces = ifaces.into_values().collect::<Vec<_>>();

    // SAFETY: The `getifaddrs` call at the beginning of this function creates
    // a linked list that we are responsible for freeing using the `freeifaddrs`
    // function [1]. This is safe as we never release the allocated memory.
    //
    // [1]: https://linux.die.net/man/3/freeifaddrs
    unsafe {
        libc::freeifaddrs(addrs);
    }

    Ok(ifaces.into_iter())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn loopback_exists() {
        let loopback = super::interfaces().unwrap()
            .find(|iface| iface.name() == "lo")
            .unwrap();

        assert! {
            loopback.ip_addrs().iter().all(|ip_addr| ip_addr.is_loopback())
        };
        assert_eq! {
            loopback.mac_addr(), Some(&MacAddr::from([0, 0, 0, 0, 0, 0]))
        };
    }
}
