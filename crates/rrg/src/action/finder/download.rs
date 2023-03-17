use crate::action::finder::chunks::{
    get_file_chunks, Chunks, GetFileChunksConfig,
};
use crate::action::finder::request::{
    DownloadActionOptions, HashActionOptions,
};
use crate::fs::Entry;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Take};

#[derive(Debug)]
pub enum Response {
    /// Download action is not performed and no further action is required.
    Skip(),
    /// File was not downloaded, but hash action must be executed.
    HashRequest(HashActionOptions),
    /// Chunks of data to be uploaded.
    CollectData(Chunks<BufReader<Take<File>>>),
}

/// Performs `download` action logic and returns file contents to be uploaded
/// or another action to be executed.
pub fn download(entry: &Entry, config: &DownloadActionOptions) -> Response {
    if entry.metadata.len() > config.max_size {
        use rrg_proto::flows::FileFinderDownloadActionOptions_OversizedFilePolicy::*;
        match config.oversized_file_policy {
            SKIP => {
                return Response::Skip();
            }
            DOWNLOAD_TRUNCATED => (),
            HASH_TRUNCATED => {
                let hash_config = HashActionOptions {
                    max_size: config.max_size,
                    oversized_file_policy:
                        rrg_proto::flows::FileFinderHashActionOptions_OversizedFilePolicy::HASH_TRUNCATED,
                };
                return Response::HashRequest(hash_config);
            }
        };
    }

    let chunks = get_file_chunks(
        &entry.path,
        &GetFileChunksConfig {
            max_read_bytes: config.max_size,
            bytes_per_chunk: config.chunk_size,
            start_offset: 0,
            overlap_bytes: 0,
        },
    );

    match chunks {
        Some(chunks) => Response::CollectData(chunks),
        None => Response::Skip(),
    }
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
    pub fn make(chunk: &[u8], offset: u64) -> ChunkId {
        ChunkId {
            sha256: Sha256::digest(chunk).into(),
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

impl From<DownloadEntry> for rrg_proto::jobs::BlobImageDescriptor {

    fn from(entry: DownloadEntry) -> rrg_proto::jobs::BlobImageDescriptor {
        let chunks = entry.chunk_ids
            .into_iter()
            .map(|chunk_id| chunk_id.into())
            .collect();

        let mut proto = rrg_proto::jobs::BlobImageDescriptor::new();
        proto.set_chunk_size(entry.chunk_size);
        proto.set_chunks(chunks);

        proto
    }
}

impl From<ChunkId> for rrg_proto::jobs::BlobImageChunkDescriptor {

    fn from(chunk_id: ChunkId) -> rrg_proto::jobs::BlobImageChunkDescriptor {
        let mut proto = rrg_proto::jobs::BlobImageChunkDescriptor::new();
        proto.set_offset(chunk_id.offset);
        proto.set_length(chunk_id.length);
        proto.set_digest(chunk_id.sha256.to_vec());

        proto
    }
}

/// A type representing a particular chunk of the returned timeline.
pub struct Chunk {
    pub data: Vec<u8>,
}

impl crate::response::Item for Chunk {
    type Proto = rrg_proto::jobs::DataBlob;

    fn into_proto(self) -> rrg_proto::jobs::DataBlob {
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
                oversized_file_policy: rrg_proto::flows::FileFinderDownloadActionOptions_OversizedFilePolicy::SKIP,
                use_external_stores: false,
                chunk_size: 5,
            },
        );

        let mut chunks = match result {
            Response::CollectData(chunks) => chunks,
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
                oversized_file_policy: rrg_proto::flows::FileFinderDownloadActionOptions_OversizedFilePolicy::SKIP,
                use_external_stores: false,
                chunk_size: 5,
            },
        );

        let mut chunks = match result {
            Response::CollectData(chunks) => chunks,
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
                oversized_file_policy: rrg_proto::flows::FileFinderDownloadActionOptions_OversizedFilePolicy::SKIP,
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
                oversized_file_policy: rrg_proto::flows::FileFinderDownloadActionOptions_OversizedFilePolicy::HASH_TRUNCATED,
                use_external_stores: false,
                chunk_size: 5,
            },
        );

        assert!(matches!(
            result,
            Response::HashRequest(HashActionOptions {
                max_size: 5,
                oversized_file_policy: rrg_proto::flows::FileFinderHashActionOptions_OversizedFilePolicy::HASH_TRUNCATED,
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
                oversized_file_policy: rrg_proto::flows::FileFinderDownloadActionOptions_OversizedFilePolicy::DOWNLOAD_TRUNCATED,
                use_external_stores: false,
                chunk_size: 3,
            },
        );

        let mut chunks = match result {
            Response::CollectData(chunks) => chunks,
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
        let chunk = ChunkId::make(b"some_test_data", 5);
        assert_eq!(&chunk.length, &14);
        assert_eq!(&chunk.offset, &5);
        assert_eq!(
            &chunk.sha256,
            &[
                0xd7, 0x6d, 0x85, 0xad, 0xca, 0x8a, 0xfa, 0xd2, 0x05, 0xed,
                0xeb, 0xc1, 0x1f, 0x9b, 0x50, 0x86, 0xbc, 0xa7, 0x5a, 0xcb,
                0x51, 0x2a, 0x74, 0x8b, 0xc7, 0x96, 0x60, 0xe1, 0x34, 0x6a,
                0xf5, 0x46
            ]
        );
    }
}
