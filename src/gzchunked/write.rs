// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::io::Write as _;

use byteorder::{BigEndian, WriteBytesExt as _};

/// Size of a gzchunked block.
const BLOCK_SIZE: usize = 10 << 20;

/// A wrapper type for gzip compression level.
pub struct Compression(flate2::Compression);

/// A type for defining gzip compression level for gzchunked.
impl Compression {

    pub fn new(level: u32) -> Compression {
        Compression(flate2::Compression::new(level))
    }
}

impl Default for Compression {

    fn default() -> Compression {
        Compression(flate2::Compression::new(5))
    }
}

/// A gzchunked streaming encoder.
pub struct Encoder {
    encoder: flate2::write::GzEncoder<Vec<u8>>,
    compression: Compression,
}

impl Encoder {

    /// Creates a new encoder with specified gzip compression level.
    pub fn new(compression: Compression) -> Encoder {
        Encoder {
            encoder: flate2::write::GzEncoder::new(Vec::new(), compression.0),
            compression,
        }
    }

    /// Writes next data chunk into the stream.
    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.encoder.write_u64::<BigEndian>(buf.len() as u64)?;
        self.encoder.write_all(buf)?;
        Ok(())
    }

    /// Attempts to retrieve next gzipped block.
    /// Returns `Ok(None)` if there's not enough data for a whole block.
    pub fn try_next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        self.encoder.flush()?;
        if self.encoder.get_ref().len() < BLOCK_SIZE {
            return Ok(None)
        }

        Ok(Some(self.next_chunk()?))
    }

    /// Retrieves next gzipped block without checking its size.
    pub fn next_chunk(&mut self) -> std::io::Result<Vec<u8>> {
        self.encoder.flush()?;
        let new_encoder = flate2::write::GzEncoder::new(Vec::new(), self.compression.0);
        let old_encoder = std::mem::replace(&mut self.encoder, new_encoder);
        let encoded_data = old_encoder.finish()?;

        Ok(encoded_data)
    }
}
