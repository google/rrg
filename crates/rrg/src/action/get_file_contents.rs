// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::path::PathBuf;

/// Limit on the size of individual file part blob sent to the blob sink.
const MAX_BLOB_LEN: usize = 1 * 1024 * 1024; // 1 MiB.

/// Mode of the blob transfer to the GRR server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Blobs are sent to the blob sink.
    Sink,
    /// Blobs are sent directly in the reply.
    Inline,
}

/// File part contents reported to the GRR server.
///
/// Different variants are used depending on the chosen [mode][`Mode`].
#[derive(Debug)]
enum Blob {
    /// SHA-256 digest of the file part sent to the blob sink.
    Sha256([u8; 32]),
    /// Actual contents of the file part.
    Contents(Vec<u8>),
}

/// Arguments of the `get_file_contents` action.
pub struct Args {
    /// Paths to the files to get the contents of.
    paths: Vec<PathBuf>,
    /// Offset from which to read the file contents.
    offset: u64,
    /// Number of bytes to read from the file.
    len: usize,
    /// Mode of the blob transfer to use for the files.
    mode: Mode,
}

/// Result of the `get_file_contents` action.
type Item = Result<OkItem, ErrorItem>;

/// Result of the `get_file_contents` action in case of success.
#[derive(Debug)]
struct OkItem {
    /// Path to the file this result corresponds to.
    path: PathBuf,
    /// Byte offset of the file part sent to the blob sink.
    offset: u64,
    /// Number of bytes of the file part sent to the blob sink.
    len: usize,
    /// File part contents reported to the GRR server.
    blob: Blob,
}

/// Result of the `get_file_contents` action in case of an error.
#[derive(Debug)]
struct ErrorItem {
    /// Path to the file that cause the issue.
    path: PathBuf,
    /// Error that occurred when working with the file.
    error: FileError,
}

/// Handle invocations of the `get_file_contents` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use std::io::{Read as _, Seek as _};
    use sha2::Digest as _;

    for path in args.paths {
        let mut file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(error) => {
                session.reply(Err(ErrorItem {
                    path,
                    error: FileError {
                        kind: FileErrorKind::Open,
                        cause: error,
                    },
                }))?;
                continue
            }
        };

        let mut offset = args.offset;
        let mut len_left = args.len;

        match file.seek(std::io::SeekFrom::Start(offset)) {
            Ok(_) => (),
            Err(error) => {
                session.reply(Err(ErrorItem {
                    path,
                    error: FileError {
                        kind: FileErrorKind::Seek,
                        cause: error,
                    },
                }))?;
                continue
            }
        }

        loop {
            let mut buf = vec![0; std::cmp::min(len_left, MAX_BLOB_LEN)];

            let len_read = match file.read(&mut buf[..]) {
                Ok(0) => break,
                Ok(len_read) => len_read,
                Err(error) => {
                    session.reply(Err(ErrorItem {
                        path,
                        error: FileError {
                            kind: FileErrorKind::Read,
                            cause: error,
                        },
                    }))?;
                    break
                }
            };

            buf.truncate(len_read);

            let blob = match args.mode {
                Mode::Sink => {
                    let blob = crate::blob::Blob::from(buf);
                    let blob_sha256 = sha2::Sha256::digest(blob.as_bytes())
                        .into();

                    session.send(crate::Sink::Blob, blob)?;

                    Blob::Sha256(blob_sha256)
                }
                Mode::Inline => Blob::Contents(buf),
            };

            session.reply(Ok(OkItem {
                path: path.clone(),
                offset,
                len: len_read,
                blob,
            }))?;

            offset += len_read as u64;
            len_left -= len_read;
        }
    }

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_file_contents::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let paths = proto.take_paths().into_iter()
            .map(PathBuf::try_from)
            // TODO(@panhania): Improve error handling (it is not obvious which
            // path caused the error right now).
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ParseArgsError::invalid_field("paths", error))?;

        let len = match proto.length() {
            0 => usize::MAX,
            len => len as usize,
        };

        let mode = match proto.mode.enum_value_or_default() {
            rrg_proto::get_file_contents::Mode::SINK => Mode::Sink,
            rrg_proto::get_file_contents::Mode::INLINE => Mode::Inline,
        };

        Ok(Args {
            paths,
            offset: proto.offset(),
            len,
            mode,
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_file_contents::Result;

    fn into_proto(self) -> rrg_proto::get_file_contents::Result {
        let mut proto = rrg_proto::get_file_contents::Result::new();

        match self {
            Ok(item) => {
                proto.set_path(item.path.into());
                proto.set_offset(item.offset);
                proto.set_length(item.len as u64);

                match item.blob {
                    Blob::Sha256(blob_sha256) => {
                        proto.set_blob_sha256(blob_sha256.into());
                    }
                    Blob::Contents(blob_contents) => {
                        proto.set_blob_contents(blob_contents);
                    }
                }
            }
            Err(item) => {
                proto.set_path(item.path.into());
                proto.set_error(item.error.to_string());
            }
        }

        proto
    }
}

/// Error which can occur when processing the file.
#[derive(Debug)]
struct FileError {
    kind: FileErrorKind,
    cause: std::io::Error,
}

impl std::fmt::Display for FileError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}: {}", self.kind, self.cause)
    }
}

/// List of possible types of errors that can occur when processing the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FileErrorKind {
    /// Failed to open the file.
    Open,
    /// Failed to seek the file to the given offset.
    Seek,
    /// Failed to read contents of the file.
    Read,
}

impl std::fmt::Display for FileErrorKind {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileErrorKind::Open => write!(fmt, "open failed"),
            FileErrorKind::Seek => write!(fmt, "seek to offset failed"),
            FileErrorKind::Read => write!(fmt, "read contents failed"),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn handle_non_existing_file() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let args = Args {
            paths: vec![tempdir.path().join("idonotexist")],
            offset: 0,
            len: usize::MAX,
            mode: Mode::Sink,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);
        assert_eq!(session.parcel_count(crate::Sink::Blob), 0);

        let error_item = session.reply::<Item>(0)
            .as_ref().unwrap_err();
        assert_eq!(error_item.path, tempdir.path().join("idonotexist"));
        assert_eq!(error_item.error.kind, FileErrorKind::Open);
    }

    #[test]
    fn handle_empty_file() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        std::fs::write(tempdir.path().join("foo"), b"")
            .unwrap();

        let args = Args {
            paths: vec![tempdir.path().join("foo")],
            offset: 0,
            len: usize::MAX,
            mode: Mode::Sink,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 0);
        assert_eq!(session.parcel_count(crate::Sink::Blob), 0);
    }

    #[test]
    fn handle_small_file_all() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        std::fs::write(tempdir.path().join("foo"), b"0123456789")
            .unwrap();

        let args = Args {
            paths: vec![tempdir.path().join("foo")],
            offset: 0,
            len: usize::MAX,
            mode: Mode::Sink,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0)
            .as_ref().unwrap();
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, 10);

        assert_eq!(session.parcel_count(crate::Sink::Blob), 1);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 0);
        assert_eq!(blob.as_bytes(), b"0123456789");
    }

    #[test]
    fn handle_small_file_from_offset() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        std::fs::write(tempdir.path().join("foo"), b"0123456789")
            .unwrap();

        let args = Args {
            paths: vec![tempdir.path().join("foo")],
            offset: 5,
            len: usize::MAX,
            mode: Mode::Sink,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0)
            .as_ref().unwrap();
        assert_eq!(item.offset, 5);
        assert_eq!(item.len, 5);

        assert_eq!(session.parcel_count(crate::Sink::Blob), 1);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 0);
        assert_eq!(blob.as_bytes(), b"56789");
    }

    #[test]
    fn handle_small_file_to_len() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        std::fs::write(tempdir.path().join("foo"), b"0123456789")
            .unwrap();

        let args = Args {
            paths: vec![tempdir.path().join("foo")],
            offset: 0,
            len: 5,
            mode: Mode::Sink,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0)
            .as_ref().unwrap();
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, 5);

        assert_eq!(session.parcel_count(crate::Sink::Blob), 1);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 0);
        assert_eq!(blob.as_bytes(), b"01234");
    }

    #[test]
    // `/dev/zero` is not available on Windows (nor there is an equivalent).
    #[cfg_attr(target_family = "windows", ignore)]
    fn handle_big_file_to_len() {
        let args = Args {
            paths: vec![PathBuf::from("/dev/zero")],
            offset: 0,
            len: MAX_BLOB_LEN * 2 + 1337,
            mode: Mode::Sink,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 3);

        let item = session.reply::<Item>(0)
            .as_ref().unwrap();
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, MAX_BLOB_LEN);

        let item = session.reply::<Item>(1)
            .as_ref().unwrap();
        assert_eq!(item.offset, MAX_BLOB_LEN as u64);
        assert_eq!(item.len, MAX_BLOB_LEN);

        let item = session.reply::<Item>(2)
            .as_ref().unwrap();
        assert_eq!(item.offset, MAX_BLOB_LEN as u64 * 2);
        assert_eq!(item.len, 1337);

        assert_eq!(session.parcel_count(crate::Sink::Blob), 3);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 0);
        assert_eq!(blob.as_bytes().len(), MAX_BLOB_LEN);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 1);
        assert_eq!(blob.as_bytes().len(), MAX_BLOB_LEN);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 2);
        assert_eq!(blob.as_bytes().len(), 1337);
    }

    #[test]
    // `/dev/zero` is not available on Windows (nor there is an equivalent).
    #[cfg_attr(target_family = "windows", ignore)]
    fn handle_big_file_from_offset_to_len() {
        let args = Args {
            paths: vec![PathBuf::from("/dev/zero")],
            offset: 0xb33f,
            len: MAX_BLOB_LEN + 1337,
            mode: Mode::Sink,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 2);

        let item = session.reply::<Item>(0)
            .as_ref().unwrap();
        assert_eq!(item.offset, 0xb33f);
        assert_eq!(item.len, MAX_BLOB_LEN);

        let item = session.reply::<Item>(1)
            .as_ref().unwrap();
        assert_eq!(item.offset, 0xb33f + MAX_BLOB_LEN as u64);
        assert_eq!(item.len, 1337);
    }

    #[test]
    fn handle_many_files() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::write(tempdir.join("foo"), b"012")
            .unwrap();
        std::fs::write(tempdir.join("bar"), b"345")
            .unwrap();
        std::fs::write(tempdir.join("baz"), b"678")
            .unwrap();

        let args = Args {
            paths: vec![
                tempdir.join("foo"),
                tempdir.join("bar"),
                tempdir.join("baz"),
            ],
            offset: 0,
            len: usize::MAX,
            mode: Mode::Sink,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 3);

        let items_by_path = session
            .replies::<Item>()
            .map(|item| item.as_ref().unwrap())
            .map(|item| (item.path.clone(), item))
            .collect::<std::collections::HashMap::<_, _>>();

        assert_eq!(session.parcel_count(crate::Sink::Blob), 3);

        let blobs_by_sha256 = session
            .parcels::<crate::blob::Blob>(crate::Sink::Blob)
            .map(|blob| {
                use sha2::Digest as _;
                (sha2::Sha256::digest(blob.as_bytes()).into(), blob)
            })
            .collect::<std::collections::HashMap::<[u8; 32], _>>();

        let item_foo = items_by_path[&tempdir.join("foo")];
        assert_eq!(item_foo.offset, 0);
        assert_eq!(item_foo.len, 3);
        assert_eq!(blobs_by_sha256[&item_blob_sha256(&item_foo)].as_bytes(), b"012");

        let item_bar = items_by_path[&tempdir.join("bar")];
        assert_eq!(item_bar.offset, 0);
        assert_eq!(item_bar.len, 3);
        assert_eq!(blobs_by_sha256[&item_blob_sha256(&item_bar)].as_bytes(), b"345");

        let item_baz = items_by_path[&tempdir.join("baz")];
        assert_eq!(item_baz.offset, 0);
        assert_eq!(item_baz.len, 3);
        assert_eq!(blobs_by_sha256[&item_blob_sha256(&item_baz)].as_bytes(), b"678");
    }

    #[test]
    fn handle_many_files_with_non_existing() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::write(tempdir.join("foo"), b"012")
            .unwrap();
        std::fs::write(tempdir.join("bar"), b"345")
            .unwrap();

        let args = Args {
            paths: vec![
                tempdir.join("foo"),
                tempdir.join("idonotexist"),
                tempdir.join("bar"),
            ],
            offset: 0,
            len: usize::MAX,
            mode: Mode::Sink,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 3);

        let items_by_path = session
            .replies::<Item>()
            .map(|item| {
                let path = match item {
                    Ok(item) => &item.path,
                    Err(item) => &item.path,
                };

                (path.clone(), item)
            })
            .collect::<std::collections::HashMap::<_, _>>();

        assert_eq!(session.parcel_count(crate::Sink::Blob), 2);

        let blobs_by_sha256 = session
            .parcels::<crate::blob::Blob>(crate::Sink::Blob)
            .map(|blob| {
                use sha2::Digest as _;
                (sha2::Sha256::digest(blob.as_bytes()).into(), blob)
            })
            .collect::<std::collections::HashMap::<[u8; 32], _>>();


        let item_foo = items_by_path[&tempdir.join("foo")]
            .as_ref().unwrap();
        assert_eq!(item_foo.offset, 0);
        assert_eq!(item_foo.len, 3);
        assert_eq!(blobs_by_sha256[&item_blob_sha256(&item_foo)].as_bytes(), b"012");

        let item_bar = items_by_path[&tempdir.join("bar")]
            .as_ref().unwrap();
        assert_eq!(item_bar.offset, 0);
        assert_eq!(item_bar.len, 3);
        assert_eq!(blobs_by_sha256[&item_blob_sha256(&item_bar)].as_bytes(), b"345");

        let item_error = items_by_path[&tempdir.join("idonotexist")]
            .as_ref().unwrap_err();
        assert_eq!(item_error.error.kind, FileErrorKind::Open);
    }

    #[test]
    fn handle_mode_inline() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        std::fs::write(tempdir.path().join("foo"), b"0123456789")
            .unwrap();

        let args = Args {
            paths: vec![tempdir.path().join("foo")],
            offset: 0,
            len: usize::MAX,
            mode: Mode::Inline,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.parcel_count(crate::Sink::Blob), 0);
        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0)
            .as_ref().unwrap();
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, 10);
        assert_eq!(item_blob_contents(item), b"0123456789");
    }

    fn item_blob_sha256(item: &OkItem) -> [u8; 32] {
        match item.blob {
            Blob::Sha256(blob_sha256) => blob_sha256,
            Blob::Contents(_) => panic!("non-contents blob: {:?}", item.blob),
        }
    }

    fn item_blob_contents(item: &OkItem) -> &[u8] {
        match &item.blob {
             Blob::Sha256(_) => panic!("non-SHA-256 blob: {:?}", item.blob),
             Blob::Contents(blob_contents) => &blob_contents,
        }
    }
}
