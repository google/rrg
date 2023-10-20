// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

// Binary data object.
pub struct Blob {
    // Binary data that the blob represents.
    data: Vec<u8>,
}

impl Blob {

    /// Extracts the slice of blob data bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl From<Vec<u8>> for Blob {

    fn from(data: Vec<u8>) -> Blob {
        Blob {
            data,
        }
    }
}

impl crate::response::Item for Blob {

    type Proto = rrg_proto::blob::Blob;

    fn into_proto(self) -> Self::Proto {
        let mut proto = Self::Proto::default();
        proto.set_data(self.data);

        proto
    }
}
