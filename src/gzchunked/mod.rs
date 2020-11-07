// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Utils for forming gzchunked streams.

mod read;
mod write;

pub use write::{Encoder, Compression};
pub use read::{Decoder};

pub struct Encode<I> {
    chunked: crate::chunked::Encode<I>,
}

impl<'a, I> Encode<I>
where
    I: Iterator<Item = &'a [u8]>,
{
    pub fn new(iter: I) -> Encode<I> {
        Encode {
            chunked: crate::chunked::encode(iter),
        }
    }

    fn pull(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        use std::io::{Read as _, Write as _};
        // TODO: Move the magic number to a constant.
        let mut buf = [0; 1024];
        // TODO: Customize compression.
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        loop {
            let size = self.chunked.read(&mut buf[..])?;
            if size == 0 {
                break;
            }

            encoder.write_all(&buf[..size])?;
            // TODO: Move the magic number to a constant.
            if encoder.get_ref().len() > 1024 {
                return Ok(Some(encoder.finish()?));
            }
        }

        let leftover = encoder.finish()?;
        if !leftover.is_empty() {
            Ok(Some(leftover))
        } else {
            Ok(None)
        }
    }
}

impl<'a, I> Iterator for Encode<I>
where
    I: Iterator<Item = &'a [u8]>,
{
    type Item = std::io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<std::io::Result<Vec<u8>>> {
        self.pull().transpose()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_encode_and_decode_empty() {
        let mut encoder = Encoder::new(Compression::default());
        let mut decoder = Decoder::new();

        let encoded_block = encoder.next_chunk().unwrap();
        // This is because the block should at least contain gzip header.
        assert!(!encoded_block.is_empty());
        decoder.write(encoded_block.as_slice()).unwrap();
        decoder.write(encoded_block.as_slice()).unwrap();

        assert_eq!(decoder.try_next_data(), None);
    }

    #[test]
    fn test_encode_and_decode_all_in_one_block() {
        let mut encoder = Encoder::new(Compression::default());
        let mut decoder = Decoder::new();

        encoder.write(&[1, 2, 3, 4]).unwrap();
        encoder.write(&[]).unwrap();
        encoder.write(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        encoder.write(&[1]).unwrap();

        let encoded_block = encoder.next_chunk().unwrap();
        decoder.write(encoded_block.as_slice()).unwrap();

        assert_eq!(decoder.try_next_data(), Some(vec![1, 2, 3, 4]));
        assert_eq!(decoder.try_next_data(), Some(Vec::new()));
        assert_eq!(decoder.try_next_data(), Some(vec![1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(decoder.try_next_data(), Some(vec![1]));
        assert_eq!(decoder.try_next_data(), None);
    }

    #[test]
    fn test_encode_and_decode_one_per_block() {
        let mut encoder = Encoder::new(Compression::default());
        let mut decoder = Decoder::new();

        encoder.write(&[1, 2, 3, 4]).unwrap();
        let encoded_block = encoder.next_chunk().unwrap();
        decoder.write(encoded_block.as_slice()).unwrap();
        assert_eq!(decoder.try_next_data(), Some(vec![1, 2, 3, 4]));
        assert_eq!(decoder.try_next_data(), None);

        encoder.write(&[]).unwrap();
        let encoded_block = encoder.next_chunk().unwrap();
        decoder.write(encoded_block.as_slice()).unwrap();
        assert_eq!(decoder.try_next_data(), Some(Vec::new()));
        assert_eq!(decoder.try_next_data(), None);

        encoder.write(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let encoded_block = encoder.next_chunk().unwrap();
        decoder.write(encoded_block.as_slice()).unwrap();
        assert_eq!(decoder.try_next_data(), Some(vec![1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(decoder.try_next_data(), None);

        encoder.write(&[1]).unwrap();
        let encoded_block = encoder.next_chunk().unwrap();
        decoder.write(encoded_block.as_slice()).unwrap();
        assert_eq!(decoder.try_next_data(), Some(vec![1]));
        assert_eq!(decoder.try_next_data(), None);
    }

    #[test]
    fn test_encode_and_decode_random() {
        use rand::{Rng as _, SeedableRng as _};
        let mut rng = rand::rngs::StdRng::seed_from_u64(20200509);

        let mut encoder = Encoder::new(Compression::default());
        let mut decoder = Decoder::new();
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
        assert_eq!(decoded_data, expected_data);
    }

    #[test]
    fn test_encode_and_decode_max_compression() {
        let mut encoder = Encoder::new(Compression::new(9));
        let mut decoder = Decoder::new();

        encoder.write(&[1, 2, 3, 4]).unwrap();
        let encoded_block = encoder.next_chunk().unwrap();
        decoder.write(encoded_block.as_slice()).unwrap();
        assert_eq!(decoder.try_next_data(), Some(vec![1, 2, 3, 4]));
        assert_eq!(decoder.try_next_data(), None);
    }

    #[test]
    fn test_encode_and_decode_min_compression() {
        let mut encoder = Encoder::new(Compression::new(0));
        let mut decoder = Decoder::new();

        encoder.write(&[1, 2, 3, 4]).unwrap();
        let encoded_block = encoder.next_chunk().unwrap();
        decoder.write(encoded_block.as_slice()).unwrap();
        assert_eq!(decoder.try_next_data(), Some(vec![1, 2, 3, 4]));
        assert_eq!(decoder.try_next_data(), None);
    }

    // Should panic because the underlying gzip only supports levels from 0 to 9.
    #[test]
    #[should_panic]
    fn test_huge_compression() {
        Encoder::new(Compression::new(100500));
    }
}
