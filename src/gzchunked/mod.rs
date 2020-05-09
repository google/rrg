// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Utils for forming gzchunked streams.

use std::vec::Vec;
use std::collections::VecDeque;
use std::io::Write;
use flate2::{Compression, write::{GzEncoder, GzDecoder}};

/// Size of a gzchunked block.
const BLOCK_SIZE: usize = 10 << 20;

/// A gzchunked streaming encoder.
pub struct GzChunkedEncoder {
    encoder: GzEncoder<Vec<u8>>,
}

/// A gzchunked streaming decoder.
pub struct GzChunkedDecoder {
    queue: VecDeque<Vec<u8>>,
}

impl GzChunkedEncoder {
    /// Creates a new encoder with specified gzip compression level.
    pub fn new(compression: Compression) -> GzChunkedEncoder {
        GzChunkedEncoder {
            encoder: GzEncoder::new(Vec::new(), compression)
        }
    }

    /// Writes next data chunk into the stream.
    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.encoder.write_all(&(buf.len() as u64).to_be_bytes())?;
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
        self.encoder.try_finish()?;

        let ret = Ok(self.encoder.get_ref().clone());
        self.encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        ret
    }
}

impl GzChunkedDecoder {
    /// Creates a new decoder.
    pub fn new() -> GzChunkedDecoder {
        GzChunkedDecoder {
            queue: VecDeque::new()
        }
    }

    /// Decodes next gzchunked block and puts all results into the internal queue.
    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let mut decoder = GzDecoder::new(Vec::new());
        decoder.write(buf)?;
        let chunked_data_vec = decoder.finish()?;
        let mut chunked_data = chunked_data_vec.as_slice();
        while !chunked_data.is_empty() {
            let (length_slice, remainder) = chunked_data.split_at(8);
            let mut length: [u8; 8] = Default::default();
            length.copy_from_slice(length_slice);
            let length = u64::from_be_bytes(length);
            let (data_slice, remainder) = remainder.split_at(length as usize);
            self.queue.push_back(Vec::from(data_slice));
            chunked_data = remainder;
        }
        Ok(())
    }

    /// Attempts to retrieve next data piece from queue.
    /// Returns `None` if the queue is empty.
    pub fn try_next_data(&mut self) -> Option<Vec<u8>> {
        self.queue.pop_front()
    }
}
