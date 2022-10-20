// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Networking primitives not covered by the standard library.

/// A MAC address.
///
/// MAC addresses are defined as 48-bit numbers in a IEEE 802 standard [1].
///
/// [1]: https://standards.ieee.org/wp-content/uploads/import/documents/tutorials/macgrp.pdf
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct MacAddr {
    /// Octets forming up the 48-bit MAC address number.
    octets: [u8; 6],
}

impl MacAddr {

    /// Return the six 8-bit integers that make up this address.
    pub fn octets(&self) -> [u8; 6] {
        self.octets
    }
}

impl From<[u8; 6]> for MacAddr {

    fn from(octets: [u8; 6]) -> MacAddr {
        MacAddr { octets }
    }
}
