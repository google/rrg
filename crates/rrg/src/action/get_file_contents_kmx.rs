// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Limit on the size of individual file part blob sent to the blob sink.
const MAX_BLOB_LEN: usize = 1 * 1024 * 1024; // 1 MiB.

enum VolumePath {
    // Absolute path to the raw volume file (e.g. `\\?\Volume{...}`.
    Direct(std::path::PathBuf),
    // Absolute path to the mount point of a raw volume file (e.g. `C:\`).
    Mount(std::path::PathBuf),
}

/// Arguments of the `get_file_contents_kmx` action.
pub struct Args {
    /// Path to the volume with NTFS filesystem to use for parsing.
    volume_path: VolumePath,
    /// Paths to the files to get the contents of.
    paths: Vec<keramics_formats::ntfs::NtfsPath>,
    /// Offsets from which to read the file contents.
    offsets: Vec<u64>,
    /// Number of bytes to read from the file.
    len: usize,
}

/// Result of the `get_file_contents` action.
type Item = Result<OkItem, ErrorItem>;

/// Result of the `get_file_contents` action in case of success.
#[derive(Debug)]
pub struct OkItem {
    /// Path to the file this result corresponds to.
    path: keramics_formats::ntfs::NtfsPath,
    /// Byte offset of the file part sent to the blob sink.
    offset: u64,
    /// Number of bytes of the file part sent to the blob sink.
    len: usize,
    /// SHA-256 digest of the file part sent to the blob sink.
    blob_sha256: [u8; 32],
}

/// Result of the `get_file_contents` action in case of an error.
#[derive(Debug)]
struct ErrorItem {
    /// Path to the file that cause the issue.
    path: keramics_formats::ntfs::NtfsPath,
    /// Error that occurred when working with the file.
    error: FileError,
}

/// Handles invocations of the `get_file_contents_kmx` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let volume_path = match args.volume_path {
        VolumePath::Direct(path) => path,
        #[cfg(target_os = "windows")]
        VolumePath::Mount(path) => {
            log::debug!("inferring direct volume path from mount: {}", path.display());

            ospect::fs::windows::raw_device_path(&path)
                .map_err(crate::session::Error::action)?
        }
        #[cfg(not(target_os = "windows"))]
        VolumePath::Mount(_path) => return Err(crate::session::Error::action(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "volume path inference not on Windows",
        ))),
    };

    log::debug!("opening NTFS volume at '{}'", volume_path.display());

    let volume = std::fs::File::open(&volume_path)
        .map_err(crate::session::Error::action)?;
    let volume_data_stream: keramics_core::DataStreamReference = {
        std::sync::Arc::new(std::sync::RwLock::new(volume))
    };

    log::debug!("parsing NTFS volume at '{}'", volume_path.display());

    let mut ntfs = keramics_formats::ntfs::NtfsFileSystem::new();
    ntfs.read_data_stream(&volume_data_stream)
        .map_err(|error| crate::session::Error::action(error))?;

    for path in args.paths {
        log::debug!("finding entry for '{:?}'", path);

        let file_entry = match ntfs.get_file_entry_by_path(&path) {
            Ok(Some(file_entry)) => Ok(file_entry),
            // TODO(@panhania): Consult with @jbmetz what `None` actually means
            // in this case.
            Ok(None) => Err(FileError {
                kind: FileErrorKind::OpenEntry,
                cause: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no entry",
                ),
            }),
            Err(error) => Err(FileError {
                kind: FileErrorKind::OpenEntry,
                cause: std::io::Error::new(
                    std::io::ErrorKind::Other,
                    error,
                ),
            }),
        };
        let file_entry = match file_entry {
            Ok(file_entry) => file_entry,
            Err(error) => {
                session.reply(Err(ErrorItem {
                    path,
                    error,
                }))?;
                continue
            }
        };

        log::debug!("collecting contents of '{:?}'", path);

        let file_data_stream = match file_entry.get_data_stream() {
            Ok(Some(file_data_stream)) => Ok(file_data_stream),
            // TODO(@panhania): Consult with @jbmetz what `None` actually means
            // in this case.
            Ok(None) => Err(FileError {
                kind: FileErrorKind::OpenDataStream,
                cause: std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "no content",
                ),
            }),
            Err(error) => Err(FileError {
                kind: FileErrorKind::OpenDataStream,
                cause: std::io::Error::new(
                    std::io::ErrorKind::Other,
                    error,
                ),
            }),
        };
        let file_data_stream = match file_data_stream {
            Ok(file_data_stream) => file_data_stream,
            Err(error) => {
                session.reply(Err(ErrorItem {
                    path: path.clone(),
                    error,
                }))?;
                continue
            }
        };

        let mut file_data_stream = match file_data_stream.write() {
            Ok(file_data_stream) => file_data_stream,
            // In case of the lock poison we fail the whole action because this
            // should not really happen and something must have gone really bad.
            Err(_) => {
                let error = std::io::Error::from(std::io::ErrorKind::Other);
                return Err(crate::session::Error::action(error))
            }
        };

        for mut offset in args.offsets.iter().cloned() {
            let mut len_left = args.len;

            match file_data_stream.seek(std::io::SeekFrom::Start(offset)) {
                Ok(_) => (),
                Err(error) => {
                    session.reply(Err(ErrorItem {
                        path: path.clone(),
                        error: FileError {
                            kind: FileErrorKind::Seek,
                            cause: std::io::Error::new(
                                std::io::ErrorKind::Other,
                                error,
                            ),
                        },
                    }))?;
                    continue
                }
            }

            loop {
                use sha2::Digest as _;

                let mut buf = vec![0; std::cmp::min(len_left, MAX_BLOB_LEN)];

                let len_read = match file_data_stream.read(&mut buf[..]) {
                    Ok(0) => break,
                    Ok(len_read) => len_read,
                    Err(error) => {
                        session.reply(Err(ErrorItem {
                            path: path.clone(),
                            error: FileError {
                                kind: FileErrorKind::Read,
                                cause: std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    error,
                                ),
                            },
                        }))?;
                        break
                    }
                };
                buf.truncate(len_read);

                let blob = crate::blob::Blob::from(buf);
                let blob_sha256 = sha2::Sha256::digest(blob.as_bytes()).into();

                session.send(crate::Sink::Blob, blob)?;
                session.reply(Ok(OkItem {
                    path: path.clone(),
                    offset,
                    len: len_read,
                    blob_sha256,
                }))?;

                offset += len_read as u64;
                len_left -= len_read;
            }
        }
    }

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_file_contents_kmx::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let volume_path = if !proto.volume_mount_path().raw_bytes().is_empty() {
            let volume_mount_path = proto.take_volume_mount_path()
                .try_into()
                .map_err(|error| ParseArgsError::invalid_field("volume mount path", error))?;

            VolumePath::Mount(volume_mount_path)
        } else {
            let volume_path = proto.take_volume_path()
                .try_into()
                .map_err(|error| ParseArgsError::invalid_field("volume path", error))?;

            VolumePath::Direct(volume_path)
        };

        let paths = proto.take_paths().into_iter().map(|path| {
            // TODO: Do not go through UTF-8 conversion.
            let path = str::from_utf8(path.raw_bytes())
                .map_err(|error| ParseArgsError::invalid_field("paths", error))?;

            Ok(keramics_formats::ntfs::NtfsPath::from(path))
        }).collect::<Result<Vec<_>, _>>()?;

        let mut offsets = proto.take_offsets();
        if offsets.is_empty() {
            offsets.push(0);
        }

        let len = match proto.length() {
            0 => usize::MAX,
            len => len as usize,
        };

        Ok(Args {
            volume_path,
            paths,
            offsets,
            len,
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_file_contents_kmx::Result;

    fn into_proto(self) -> rrg_proto::get_file_contents_kmx::Result {
        let mut proto = rrg_proto::get_file_contents_kmx::Result::new();

        match self {
            Ok(item) => {
                // TODO: Use lossless conversion (preferably in Keramics directly).
                let path = std::path::PathBuf::from_iter(
                    item.path.components.iter()
                        .map(|comp| String::from_utf16_lossy(&comp.elements))
                );

                proto.set_path(path.into());
                proto.set_offset(item.offset);
                proto.set_length(item.len as u64);
                proto.set_blob_sha256(item.blob_sha256.into());
            }
            Err(item) => {
                // TODO: Use lossless conversion (preferably in Keramics directly).
                let path = std::path::PathBuf::from_iter(
                    item.path.components.iter()
                        .map(|comp| String::from_utf16_lossy(&comp.elements))
                );

                proto.set_path(path.into());
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
    /// Failed to open the file entry.
    OpenEntry,
    /// Failed to open the file data stream.
    OpenDataStream,
    /// Failed to seek the file to the given offset.
    Seek,
    /// Failed to read contents of the file.
    Read,
}

impl std::fmt::Display for FileErrorKind {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileErrorKind::OpenEntry => write!(fmt, "open entry failed"),
            FileErrorKind::OpenDataStream => write!(fmt, "open data stream failed"),
            FileErrorKind::Seek => write!(fmt, "seek to offset failed"),
            FileErrorKind::Read => write!(fmt, "read contents failed"),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_non_existing_file() {
        let ntfs_file = tempntfs::create(|_| Ok(()))
            .unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            paths: vec![keramics_formats::ntfs::NtfsPath::from("\\idonotexist")],
            offsets: vec![0],
            len: usize::MAX,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);
        assert_eq!(session.parcel_count(crate::Sink::Blob), 0);

        let error_item = session.reply::<Item>(0)
            .as_ref().unwrap_err();
        assert_eq!(error_item.path, "\\idonotexist".into());
        assert_eq!(error_item.error.kind, FileErrorKind::OpenEntry);
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_non_regular_file() {
        let ntfs_file = tempntfs::create(|path| {
            std::fs::create_dir(path.join("dir"))?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            paths: vec![keramics_formats::ntfs::NtfsPath::from("\\dir")],
            offsets: vec![0],
            len: usize::MAX,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);
        assert_eq!(session.parcel_count(crate::Sink::Blob), 0);

        let error_item = session.reply::<Item>(0)
            .as_ref().unwrap_err();
        assert_eq!(error_item.path, "\\dir".into());
        assert_eq!(error_item.error.kind, FileErrorKind::OpenDataStream);
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_empty_file() {
        let ntfs_file = tempntfs::create(|path| {
            std::fs::File::create_new(path.join("empty"))?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            paths: vec![keramics_formats::ntfs::NtfsPath::from("\\empty")],
            offsets: vec![0],
            len: usize::MAX,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 0);
        assert_eq!(session.parcel_count(crate::Sink::Blob), 0);
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_small_file_all() {
        let ntfs_file = tempntfs::create(|path| {
            use std::io::Write as _;

            let mut file = std::fs::File::create_new(path.join("file"))?;
            file.write_all(b"0123456789")?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            paths: vec![keramics_formats::ntfs::NtfsPath::from("\\file")],
            offsets: vec![0],
            len: usize::MAX,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0)
            .as_ref().unwrap();
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, b"0123456789".len());

        assert_eq!(session.parcel_count(crate::Sink::Blob), 1);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 0);
        assert_eq!(blob.as_bytes(), b"0123456789");
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_small_file_from_offset() {
        let ntfs_file = tempntfs::create(|path| {
            use std::io::Write as _;

            let mut file = std::fs::File::create_new(path.join("file"))?;
            file.write_all(b"0123456789")?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            paths: vec![keramics_formats::ntfs::NtfsPath::from("\\file")],
            offsets: vec![5],
            len: usize::MAX,
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

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_small_file_to_len() {
        let ntfs_file = tempntfs::create(|path| {
            use std::io::Write as _;

            let mut file = std::fs::File::create_new(path.join("file"))?;
            file.write_all(b"0123456789")?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            paths: vec![keramics_formats::ntfs::NtfsPath::from("\\file")],
            offsets: vec![0],
            len: 5,
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

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_big_file_from_offset_to_len() {
        let ntfs_file = tempntfs::create_with_size(20 * 1024 * 1024, |path| {
            use std::io::{Read as _};

            let mut file = std::fs::File::create_new(path.join("file"))?;
            std::io::copy(&mut std::io::repeat(0xf0).take(13371337), &mut file)?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            paths: vec![keramics_formats::ntfs::NtfsPath::from("\\file")],
            offsets: vec![0xb33f],
            len: MAX_BLOB_LEN + 1337,
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

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_many_files() {
        let ntfs_file = tempntfs::create(|path| {
            std::fs::write(path.join("foo"), b"012")?;
            std::fs::write(path.join("bar"), b"345")?;
            std::fs::write(path.join("baz"), b"678")?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            paths: vec![
                keramics_formats::ntfs::NtfsPath::from("\\foo"),
                keramics_formats::ntfs::NtfsPath::from("\\bar"),
                keramics_formats::ntfs::NtfsPath::from("\\baz"),
            ],
            offsets: vec![0],
            len: usize::MAX,
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

        let item_foo = items_by_path[&"\\foo".into()];
        assert_eq!(item_foo.offset, 0);
        assert_eq!(item_foo.len, 3);
        assert_eq!(blobs_by_sha256[&item_foo.blob_sha256].as_bytes(), b"012");

        let item_bar = items_by_path[&"\\bar".into()];
        assert_eq!(item_bar.offset, 0);
        assert_eq!(item_bar.len, 3);
        assert_eq!(blobs_by_sha256[&item_bar.blob_sha256].as_bytes(), b"345");

        let item_baz = items_by_path[&"\\baz".into()];
        assert_eq!(item_baz.offset, 0);
        assert_eq!(item_baz.len, 3);
        assert_eq!(blobs_by_sha256[&item_baz.blob_sha256].as_bytes(), b"678");
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_many_files_with_non_existing() {
        let ntfs_file = tempntfs::create(|path| {
            std::fs::write(path.join("foo"), b"012")?;
            std::fs::write(path.join("bar"), b"345")?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            paths: vec![
                keramics_formats::ntfs::NtfsPath::from("\\foo"),
                keramics_formats::ntfs::NtfsPath::from("\\idonotexist"),
                keramics_formats::ntfs::NtfsPath::from("\\bar"),
            ],
            offsets: vec![0],
            len: usize::MAX,
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

        let item_foo = items_by_path[&"\\foo".into()]
            .as_ref().unwrap();
        assert_eq!(item_foo.offset, 0);
        assert_eq!(item_foo.len, 3);
        assert_eq!(blobs_by_sha256[&item_foo.blob_sha256].as_bytes(), b"012");

        let item_bar = items_by_path[&"\\bar".into()]
            .as_ref().unwrap();
        assert_eq!(item_bar.offset, 0);
        assert_eq!(item_bar.len, 3);
        assert_eq!(blobs_by_sha256[&item_bar.blob_sha256].as_bytes(), b"345");

        let item_error = items_by_path[&"\\idonotexist".into()]
            .as_ref().unwrap_err();
        assert_eq!(item_error.error.kind, FileErrorKind::OpenEntry);
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_many_offsets() {
        let ntfs_file = tempntfs::create(|path| {
            std::fs::write(path.join("foo"), b"0123456789")?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            paths: vec![
                keramics_formats::ntfs::NtfsPath::from("\\foo"),
            ],
            offsets: vec![3, 7, 9],
            len: 2,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 3);

        let item_34 = session.reply::<Item>(0)
            .as_ref().unwrap();
        assert_eq!(item_34.path, "\\foo".into());
        assert_eq!(item_34.offset, 3);
        assert_eq!(item_34.len, 2);

        let item_78 = session.reply::<Item>(1)
            .as_ref().unwrap();
        assert_eq!(item_78.path, "\\foo".into());
        assert_eq!(item_78.offset, 7);
        assert_eq!(item_78.len, 2);

        let item_9 = session.reply::<Item>(2)
            .as_ref().unwrap();
        assert_eq!(item_9.path, "\\foo".into());
        assert_eq!(item_9.offset, 9);
        assert_eq!(item_9.len, 1);

        assert_eq!(session.parcel_count(crate::Sink::Blob), 3);

        let blobs_by_sha256 = session
            .parcels::<crate::blob::Blob>(crate::Sink::Blob)
            .map(|blob| {
                use sha2::Digest as _;
                (sha2::Sha256::digest(blob.as_bytes()).into(), blob)
            })
            .collect::<std::collections::HashMap::<[u8; 32], _>>();

        let blob_34 = blobs_by_sha256[&item_34.blob_sha256];
        assert_eq!(blob_34.as_bytes(), b"34");

        let blob_78 = blobs_by_sha256[&item_78.blob_sha256];
        assert_eq!(blob_78.as_bytes(), b"78");

        let blob_9 = blobs_by_sha256[&item_9.blob_sha256];
        assert_eq!(blob_9.as_bytes(), b"9");
    }
}
