use crate::action::finder::request::HashActionOptions;
use crate::fs::Entry;
use digest::Digest as _;
use log::warn;
use md5::Md5;
use rrg_macro::ack;
use sha1::Sha1;
use sha2::Sha256;
use std::cmp::min;
use std::fs::File;
use std::io::Read;

/// Hashes data writen to it using SHA-1, SHA-256 and MD5 algorithms.
struct Hasher {
    /// Digest with SHA-1 hash.
    sha1: Sha1,
    /// Digest with SHA-256 hash.
    sha256: Sha256,
    /// Digest with MD5 hash.
    md5: Md5,
    /// Stores total number of bytes inserted into hasher.
    total_byte_count: u64,
}

impl Hasher {
    pub fn new() -> Hasher {
        Hasher {
            sha1: sha1::Sha1::new(),
            sha256: sha2::Sha256::new(),
            md5: md5::Md5::new(),
            total_byte_count: 0,
        }
    }
}

impl std::io::Write for Hasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sha1.update(buf);
        self.sha256.update(buf);
        self.md5.update(buf);
        self.total_byte_count += buf.len() as u64;

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Performs `hash` action on the file in `entry` and returns the result to be reported in case of success.
pub fn hash(entry: &Entry, config: &HashActionOptions) -> Option<FileHash> {
    use rrg_proto::flows::FileFinderHashActionOptions_OversizedFilePolicy::*;
    match config.oversized_file_policy {
        SKIP => {
            if entry.metadata.len() > config.max_size {
                return None;
            }
        }
        HASH_TRUNCATED => {}
    };

    let file = ack! {
        File::open(&entry.path),
        error: "failed to open file: {}", entry.path.display()
    }?;
    let mut file = file.take(config.max_size);

    let mut hasher = Hasher::new();
    let read_bytes = ack! {
        std::io::copy(&mut file, &mut hasher),
        error: "failed to copy data from: {}", entry.path.display()
    }?;

    let expected_bytes = min(entry.metadata.len(), config.max_size);
    if read_bytes != expected_bytes {
        warn!(
            "failed to read all data from: {}, {} bytes were read, but {} were expected",
            entry.path.display(),
            &read_bytes,
            expected_bytes
        );
        return None;
    }

    Some(FileHash {
        sha1: hasher.sha1.finalize().to_vec(),
        sha256: hasher.sha256.finalize().to_vec(),
        md5: hasher.md5.finalize().to_vec(),
        num_bytes: hasher.total_byte_count,
    })
}

#[derive(Debug)]
pub struct FileHash {
    pub sha256: std::vec::Vec<u8>,
    pub sha1: std::vec::Vec<u8>,
    pub md5: std::vec::Vec<u8>,
    pub num_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_values() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "some_test_data").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path: path,
        };

        let result = hash(
            &entry,
            &HashActionOptions {
                max_size: 14,
                oversized_file_policy: rrg_proto::flows::FileFinderHashActionOptions_OversizedFilePolicy::SKIP,
            },
        )
        .unwrap();

        assert_eq!(
            result.sha1,
            vec![
                0xa6, 0x2a, 0x6d, 0x59, 0x91, 0x23, 0x8a, 0xe7, 0x2d, 0x81,
                0xfe, 0x6e, 0x47, 0x69, 0xb3, 0x04, 0x3d, 0x9f, 0xe6, 0x70
            ]
            .to_vec()
        );
        assert_eq!(
            result.sha256,
            vec![
                0xd7, 0x6d, 0x85, 0xad, 0xca, 0x8a, 0xfa, 0xd2, 0x05, 0xed,
                0xeb, 0xc1, 0x1f, 0x9b, 0x50, 0x86, 0xbc, 0xa7, 0x5a, 0xcb,
                0x51, 0x2a, 0x74, 0x8b, 0xc7, 0x96, 0x60, 0xe1, 0x34, 0x6a,
                0xf5, 0x46
            ]
            .to_vec()
        );
        assert_eq!(
            result.md5,
            vec![
                0xe0, 0x91, 0xb6, 0xf1, 0xa2, 0x33, 0x04, 0x9d, 0x22, 0xd2,
                0x80, 0x7f, 0xa8, 0x08, 0x6f, 0x3f
            ]
            .to_vec()
        );
        assert_eq!(result.num_bytes, 14);
    }

    #[test]
    fn test_trim_file_over_max_size() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "some_test_data").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path,
        };

        let result = hash(
            &entry,
            &HashActionOptions {
                max_size: 10,
                oversized_file_policy: rrg_proto::flows::FileFinderHashActionOptions_OversizedFilePolicy::HASH_TRUNCATED,
            },
        )
        .unwrap();

        assert_eq!(result.num_bytes, 10);
    }

    #[test]
    fn test_skip_file_over_max_size() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "some_test_data").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path,
        };

        assert!(hash(
            &entry,
            &HashActionOptions {
                max_size: 10,
                oversized_file_policy: rrg_proto::flows::FileFinderHashActionOptions_OversizedFilePolicy::SKIP,
            },
        )
        .is_none());
    }
}
