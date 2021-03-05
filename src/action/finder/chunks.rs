/// Implements `Iterator` trait splitting underlying `bytes` into chunks.
#[derive(Debug)]
pub struct Chunks<R> {
    /// Data source for the chunks.
    data: std::io::Bytes<R>,
    /// Chunks reading configuration.
    config: ChunksConfig,
    /// Data from the previous chunk to be used as an overlap in the next chunk.
    overlap_data: Vec<u8>,
}

#[derive(Debug)]
pub struct ChunksConfig {
    /// Desired number of bytes in chunks. Only the last chunk can be smaller
    /// than the `bytes_per_chunk`
    pub bytes_per_chunk: u64,
    /// A number of bytes that the next chunk will share with the previous one.
    pub overlap_bytes: u64,
}

impl<R: std::io::Read> std::iter::Iterator for Chunks<R> {
    type Item = std::io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<std::io::Result<Vec<u8>>> {
        let mut ret = std::mem::take(&mut self.overlap_data);
        let mut bytes_read = false;
        for byte in &mut self.data {
            let byte = match byte {
                Ok(byte) => byte,
                Err(err) => return Some(Err(err)),
            };
            bytes_read = true;
            ret.push(byte);

            if ret.len() == self.config.bytes_per_chunk as usize {
                let overlap_start =
                    ret.len() - self.config.overlap_bytes as usize;
                self.overlap_data = Vec::from(&ret[overlap_start..]);
                return Some(Ok(ret));
            }
        }
        if bytes_read {
            return Some(Ok(ret));
        }

        return None;
    }
}

/// Returns an iterator over `reader` returning chunks of bytes.
pub fn chunks<R: std::io::Read>(reader: R, config: ChunksConfig) -> Chunks<R> {
    assert!(config.bytes_per_chunk > 0);
    assert!(config.bytes_per_chunk > config.overlap_bytes);
    Chunks {
        data: reader.bytes(),
        config,
        overlap_data: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_chunks() {
        let data = vec![1, 2, 3, 4, 5];
        let mut chunks = chunks(
            data.as_slice(),
            ChunksConfig {
                bytes_per_chunk: 2,
                overlap_bytes: 0,
            },
        );
        assert_eq!(chunks.next().unwrap().unwrap(), vec![1, 2]);
        assert_eq!(chunks.next().unwrap().unwrap(), vec![3, 4]);
        assert_eq!(chunks.next().unwrap().unwrap(), vec![5]);
        assert!(chunks.next().is_none());
    }

    #[test]
    fn test_overlapping_chunks() {
        let data = vec![1, 2, 3, 4, 5];
        let mut chunks = chunks(
            data.as_slice(),
            ChunksConfig {
                bytes_per_chunk: 3,
                overlap_bytes: 1,
            },
        );
        assert_eq!(chunks.next().unwrap().unwrap(), vec![1, 2, 3]);
        assert_eq!(chunks.next().unwrap().unwrap(), vec![3, 4, 5]);
        assert!(chunks.next().is_none());
    }
}
