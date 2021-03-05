use crate::action::finder::chunks::{chunks, Chunks, ChunksConfig};
use crate::action::finder::request::{
    DownloadActionOptions, HashActionOptions,
};
use crate::fs::Entry;
use log::warn;
use rrg_proto::file_finder_download_action_options::OversizedFilePolicy as DownloadOversizedFilePolicy;
use rrg_proto::file_finder_hash_action_options::OversizedFilePolicy as HashOversizedFilePolicy;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read, Take};

#[derive(Debug)]
pub enum Response {
    /// Download action is not performed and no further action is required.
    Skip(),
    /// File was not downloaded, but hash action must be executed.
    HashRequest(HashActionOptions),
    /// Chunks of data to be downloaded.
    DownloadData(Chunks<BufReader<Take<File>>>),
}

/// Performs `download` action logic and returns file contents to be uploaded
/// or another action to be executed.
pub fn download(entry: &Entry, config: &DownloadActionOptions) -> Response {
    if entry.metadata.len() > config.max_size {
        match config.oversized_file_policy {
            DownloadOversizedFilePolicy::Skip => {
                return Response::Skip();
            }
            DownloadOversizedFilePolicy::DownloadTruncated => (),
            DownloadOversizedFilePolicy::HashTruncated => {
                let hash_config = HashActionOptions {
                    max_size: config.max_size,
                    oversized_file_policy:
                        HashOversizedFilePolicy::HashTruncated,
                };
                return Response::HashRequest(hash_config);
            }
        };
    }

    let file = match File::open(&entry.path) {
        Ok(f) => f.take(config.max_size),
        Err(err) => {
            warn!(
                "failed to open file: {}, error: {}",
                entry.path.display(),
                err
            );
            return Response::Skip();
        }
    };

    let reader = BufReader::new(file);
    Response::DownloadData(chunks(
        reader,
        ChunksConfig {
            bytes_per_chunk: config.chunk_size,
            overlap_bytes: 0,
        },
    ))
}

/// A type representing unique identifier of a given chunk.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChunkId {
    /// A SHA-256 digest of the referenced chunk data.
    sha256: [u8; 32],
    offset: u64,
    length: u64,
}

impl ChunkId {
    /// Creates a chunk identifier for the given chunk.
    pub fn make(chunk: &Vec<u8>, offset: u64) -> ChunkId {
        ChunkId {
            sha256: Sha256::digest(&chunk).into(),
            length: chunk.len() as u64,
            offset,
        }
    }
}

#[derive(Debug)]
pub struct DownloadEntry {
    pub chunk_ids: Vec<ChunkId>,
    pub chunk_size: u64,
}

impl From<DownloadEntry> for rrg_proto::BlobImageDescriptor {
    fn from(entry: DownloadEntry) -> rrg_proto::BlobImageDescriptor {
        rrg_proto::BlobImageDescriptor {
            chunks: entry
                .chunk_ids
                .into_iter()
                .map(|x| rrg_proto::BlobImageChunkDescriptor {
                    offset: Some(x.offset),
                    length: Some(x.length),
                    digest: Some(x.sha256.to_vec()),
                })
                .collect::<Vec<_>>(),
            chunk_size: Some(entry.chunk_size),
        }
    }
}

/// A type representing a particular chunk of the returned timeline.
pub struct Chunk {
    pub data: Vec<u8>,
}

impl super::super::Response for Chunk {
    const RDF_NAME: Option<&'static str> = Some("DataBlob");

    type Proto = rrg_proto::DataBlob;

    fn into_proto(self) -> rrg_proto::DataBlob {
        self.data.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunked_download() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "some_data").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path,
        };

        let result = download(
            &entry,
            &DownloadActionOptions {
                max_size: 100,
                oversized_file_policy: DownloadOversizedFilePolicy::Skip,
                use_external_stores: false,
                chunk_size: 5,
            },
        );

        let mut chunks = match result {
            Response::DownloadData(chunks) => chunks,
            _ => panic!("Unexpected result type."),
        };

        assert_eq!(
            chunks.next().unwrap().unwrap(),
            "some_".bytes().collect::<Vec<_>>()
        );
        assert_eq!(
            chunks.next().unwrap().unwrap(),
            "data".bytes().collect::<Vec<_>>()
        );
        assert!(chunks.next().is_none());
    }

    #[test]
    fn test_no_empty_chunk_download() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "some_").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path,
        };

        let result = download(
            &entry,
            &DownloadActionOptions {
                max_size: 100,
                oversized_file_policy: DownloadOversizedFilePolicy::Skip,
                use_external_stores: false,
                chunk_size: 5,
            },
        );

        let mut chunks = match result {
            Response::DownloadData(chunks) => chunks,
            _ => panic!("Unexpected result type."),
        };

        assert_eq!(
            chunks.next().unwrap().unwrap(),
            "some_".bytes().collect::<Vec<_>>()
        );
        assert!(chunks.next().is_none());
    }

    #[test]
    fn test_skip_above_max_size() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "some_1").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path,
        };

        let result = download(
            &entry,
            &DownloadActionOptions {
                max_size: 5,
                oversized_file_policy: DownloadOversizedFilePolicy::Skip,
                use_external_stores: false,
                chunk_size: 5,
            },
        );

        assert!(matches!(result, Response::Skip()));
    }

    #[test]
    fn test_hash_above_max_size() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "some_1").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path,
        };

        let result = download(
            &entry,
            &DownloadActionOptions {
                max_size: 5,
                oversized_file_policy:
                    DownloadOversizedFilePolicy::HashTruncated,
                use_external_stores: false,
                chunk_size: 5,
            },
        );

        assert!(matches!(
            result,
            Response::HashRequest(HashActionOptions {
                max_size: 5,
                oversized_file_policy: HashOversizedFilePolicy::HashTruncated,
            })
        ));
    }

    #[test]
    fn test_download_truncated_above_max_size() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "some_1").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path,
        };

        let result = download(
            &entry,
            &DownloadActionOptions {
                max_size: 5,
                oversized_file_policy:
                    DownloadOversizedFilePolicy::DownloadTruncated,
                use_external_stores: false,
                chunk_size: 3,
            },
        );

        let mut chunks = match result {
            Response::DownloadData(chunks) => chunks,
            _ => panic!("Unexpected result type."),
        };

        assert_eq!(
            chunks.next().unwrap().unwrap(),
            "som".bytes().collect::<Vec<_>>()
        );
        assert_eq!(
            chunks.next().unwrap().unwrap(),
            "e_".bytes().collect::<Vec<_>>()
        );
        assert!(chunks.next().is_none());
    }

    #[test]
    fn test_chunk_id() {
        let chunk = ChunkId::make(&"some_test_data".as_bytes().to_vec(), 5);
        assert_eq!(&chunk.length, &14);
        assert_eq!(&chunk.offset, &5);
        assert_eq!(&chunk.sha256, &[
            0xd7, 0x6d, 0x85, 0xad, 0xca, 0x8a, 0xfa, 0xd2, 0x05, 0xed,
            0xeb, 0xc1, 0x1f, 0x9b, 0x50, 0x86, 0xbc, 0xa7, 0x5a, 0xcb,
            0x51, 0x2a, 0x74, 0x8b, 0xc7, 0x96, 0x60, 0xe1, 0x34, 0x6a,
            0xf5, 0x46
        ]);
    }
}
