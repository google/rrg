use crate::action::finder::chunks::{chunks, Chunks, ChunksConfig};
use log::warn;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Take};
use std::path::Path;

// TODO: test offset
// TODO: maybe pub not needed
pub fn open_file(
    path: &Path,
    offset: u64,
    max_size: u64,
) -> Option<Take<File>> {
    match File::open(path) {
        Ok(mut f) => {
            if let Err(err) = f.seek(SeekFrom::Start(offset)) {
                warn!(
                    "failed to seek in file: {}, error: {}",
                    path.display(),
                    err
                );
                return None;
            }
            Some(f.take(max_size))
        }
        Err(err) => {
            warn!("failed to open file: {}, error: {}", path.display(), err);
            None
        }
    }
}

// TODO: doc
pub struct GetFileChunksConfig {
    pub start_offset: u64,
    pub max_read_bytes: u64,
    pub bytes_per_chunk: u64,
    pub overlap_bytes: u64,
}

pub fn get_file_chunks(
    path: &Path,
    config: &GetFileChunksConfig,
) -> Option<Chunks<BufReader<Take<File>>>> {
    let file = open_file(&path, config.start_offset, config.max_read_bytes)?;

    Some(chunks(
        BufReader::new(file),
        ChunksConfig {
            bytes_per_chunk: config.bytes_per_chunk,
            overlap_bytes: config.overlap_bytes,
        },
    ))
}

// TODO: merge with chunks if "open_file" is not used
