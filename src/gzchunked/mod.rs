// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Utils for forming gzchunked streams.

use std::vec::Vec;
use std::io::Write;
use flate2::write::GzEncoder;

const BLOCK_SIZE: usize = 10 << 20;

pub struct GzChunked {
    encoder: GzEncoder<Vec<u8>>,
}

impl GzChunked {
    pub fn new() -> GzChunked {
        GzChunked {
            encoder: GzEncoder::new(Vec::new(), flate2::Compression::default())
        }
    }
    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.encoder.write_all(&(buf.len() as u64).to_be_bytes())?;
        self.encoder.write_all(buf)?;
        Ok(())
    }
    pub fn try_next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        self.encoder.flush()?;
        if self.encoder.get_ref().len() < BLOCK_SIZE {
            return Ok(None)
        }
        Ok(Some(self.next_chunk()?))
    }
    pub fn next_chunk(&mut self) -> std::io::Result<Vec<u8>> {
        self.encoder.flush()?;
        self.encoder.try_finish()?;
        let ret = Ok(self.encoder.get_ref().clone());
        self.encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        ret
    }
}
