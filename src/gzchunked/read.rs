// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::collections::VecDeque;
use std::io::Read;

use byteorder::{BigEndian, ReadBytesExt as _};

/// A gzchunked streaming decoder.
pub struct Decoder {
    queue: VecDeque<Vec<u8>>,
}

impl Decoder {

    /// Creates a new decoder.
    pub fn new() -> Decoder {
        Decoder {
            queue: VecDeque::new()
        }
    }

    /// Decodes next gzchunked block and puts all results into the internal queue.
    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let mut decoder = flate2::read::GzDecoder::new(buf);
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

/// Decodes an iterator over gzchunked file parts into a stream of messages.
///
/// This is a streaming decoder that performs the decoding in a lazy way and can
/// be used to effectively process megabytes of data.
///
/// # Examples
///
/// ```no_run
/// use std::fs::File;
///
/// let paths = ["foo.gzc.1", "foo.gzc.2", "foo.gzc.3"];
/// let files = paths.iter().map(|path| File::open(path).unwrap());
///
/// for (idx, msg) in rrg::gzchunked::decode(files).enumerate() {
///     let msg: String = msg.unwrap();
///     println!("item #{}: {:?}", idx, msg);
/// }
/// ```
pub fn decode<I, R, M>(iter: I) -> impl Iterator<Item=std::io::Result<M>>
where
    I: Iterator<Item=R>,
    R: std::io::Read,
    M: prost::Message + Default,
{
    let parts = iter.map(flate2::read::GzDecoder::new);
    crate::chunked::decode(crate::io::IterReader::new(parts))
}
