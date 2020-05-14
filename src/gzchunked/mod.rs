// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Utils for forming gzchunked streams.

use std::vec::Vec;
use std::mem;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::default::Default;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use flate2::{Compression, write::GzEncoder, read::GzDecoder};

/// Size of a gzchunked block.
const BLOCK_SIZE: usize = 10 << 20;

/// A wrapper type for gzip compression level.
pub struct GzChunkedCompression(Compression);

/// A gzchunked streaming encoder.
pub struct GzChunkedEncoder {
    encoder: GzEncoder<Vec<u8>>,
    compression: GzChunkedCompression,
}

/// A gzchunked streaming decoder.
pub struct GzChunkedDecoder {
    queue: VecDeque<Vec<u8>>,
}

impl GzChunkedCompression {
    pub fn new(level: u32) -> GzChunkedCompression {
        GzChunkedCompression(Compression::new(level))
    }
}

impl Default for GzChunkedCompression {
    fn default() -> GzChunkedCompression {
        GzChunkedCompression(Compression::new(5))
    }
}

impl GzChunkedEncoder {
    /// Creates a new encoder with specified gzip compression level.
    pub fn new(compression: GzChunkedCompression) -> GzChunkedEncoder {
        GzChunkedEncoder {
            encoder: GzEncoder::new(Vec::new(), compression.0),
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
        let new_encoder = GzEncoder::new(Vec::new(), self.compression.0);
        let old_encoder = mem::replace(&mut self.encoder, new_encoder);
        let encoded_data = old_encoder.finish()?;

        Ok(encoded_data)
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
        let mut decoder = GzDecoder::new(buf);
        let mut chunked_data_vec: Vec<u8> = Vec::new();
        decoder.read_to_end(&mut chunked_data_vec)?;
        let mut chunked_data = chunked_data_vec.as_slice();
        while !chunked_data.is_empty() {
            let length = chunked_data.read_u64::<BigEndian>()?;
            let mut data = vec![0; length as usize];
            chunked_data.read_exact(data.as_mut_slice())?;
            self.queue.push_back(data);
        }
        Ok(())
    }

    /// Attempts to retrieve next data piece from queue.
    /// Returns `None` if the queue is empty.
    pub fn try_next_data(&mut self) -> Option<Vec<u8>> {
        self.queue.pop_front()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    #[test]
    fn test_encode_and_decode_empty() {
        let mut encoder = GzChunkedEncoder::new(GzChunkedCompression::default());
        let mut decoder = GzChunkedDecoder::new();

        let encoded_block = encoder.next_chunk().unwrap();
        // should contain gzip header
        assert_ne!(encoded_block.len(), 0);
        decoder.write(encoded_block.as_slice()).unwrap();
        decoder.write(encoded_block.as_slice()).unwrap();

        assert!(decoder.try_next_data().is_none());
    }

    #[test]
    fn test_encode_and_decode_all_in_one_block() {
        let mut encoder = GzChunkedEncoder::new(GzChunkedCompression::default());
        let mut decoder = GzChunkedDecoder::new();
        let blocks = vec![
            vec![1, 2, 3, 4],
            vec![],
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            vec![1],
        ];

        for block in &blocks {
            encoder.write(block.as_slice()).unwrap();
        }

        let encoded_block = encoder.next_chunk().unwrap();
        decoder.write(encoded_block.as_slice()).unwrap();

        for block in blocks {
            assert_eq!(block, decoder.try_next_data().unwrap());
        }
        assert!(decoder.try_next_data().is_none());
    }

    #[test]
    fn test_encode_and_decode_one_per_block() {
        let mut encoder = GzChunkedEncoder::new(GzChunkedCompression::default());
        let mut decoder = GzChunkedDecoder::new();
        let blocks = vec![
            vec![1, 2, 3, 4],
            vec![],
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            vec![1],
        ];

        for block in blocks {
            encoder.write(block.as_slice()).unwrap();
            let encoded_block = encoder.next_chunk().unwrap();

            decoder.write(encoded_block.as_slice()).unwrap();

            assert_eq!(block, decoder.try_next_data().unwrap());
            assert!(decoder.try_next_data().is_none());
        }
    }

    #[test]
    fn test_encode_and_decode_random() {
        let mut rng = StdRng::seed_from_u64(20200509);
        let mut encoder = GzChunkedEncoder::new(GzChunkedCompression::default());
        let mut decoder = GzChunkedDecoder::new();
        let mut expected_data: Vec<Vec<u8>> = Vec::new();
        let mut decoded_data: Vec<Vec<u8>> = Vec::new();
        for _ in 0..256 {
            let size = rng.gen_range(128, 256);
            let data: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
            encoder.write(data.as_slice()).unwrap();
            if let Some(block) = encoder.try_next_chunk().unwrap() {
                decoder.write(block.as_slice()).unwrap();
                while let Some(data) = decoder.try_next_data() {
                    decoded_data.push(data);
                }
            }
            expected_data.push(data);
        }
        let last_block = encoder.next_chunk().unwrap();
        decoder.write(last_block.as_slice()).unwrap();
        while let Some(data) = decoder.try_next_data() {
            decoded_data.push(data);
        }
        assert_eq!(expected_data, decoded_data);
    }
}
