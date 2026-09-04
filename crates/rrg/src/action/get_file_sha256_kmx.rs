// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::path::PathBuf;

enum VolumePath {
    // Absolute path to the raw volume file (e.g. `\\?\Volume{...}`.
    Direct(PathBuf),
    // Absolute path to the mount point of a raw volume file (e.g. `C:\`).
    Mount(PathBuf),
}

/// Arguments of the `get_file_sha256_kmx` action.
pub struct Args {
    /// Path to the volume with NTFS filesystem to use for parsing.
    volume_path: VolumePath,
    /// Path to the file to get the SHA-256 hash of.
    path: keramics_formats::ntfs::NtfsPath,
    /// Byte offsets from which the content should be hashed.
    offsets: Vec<u64>,
    /// Number of bytes to hash (from the start offset).
    len: Option<std::num::NonZero<u64>>,
}

/// Result of the `get_file_sha256_kmx` action.
struct Item {
    /// Path of the file this result corresponds to.
    path: keramics_formats::ntfs::NtfsPath,
    /// Byte offset from which the file content was hashed.
    offset: u64,
    /// Number of bytes of the file used to produce the hash.
    len: u64,
    /// SHA-256 hash digest of the file content.
    sha256: [u8; 32],
}

/// Handle invocations of the `get_file_sha256_kmx` action.
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

    log::debug!("finding entry for '{:?}'", args.path);

    let file_entry = ntfs.get_file_entry_by_path(&args.path)
        .map_err(FileError::OpenEntry)?
        .ok_or(FileError::NoEntry)?;

    log::debug!("opening data stream of '{:?}'", args.path);

    let file_data_stream = file_entry.get_data_stream()
        .map_err(FileError::OpenDataStream)?
        .ok_or(FileError::NoDataStream)?;
    let mut file_data_stream = file_data_stream.write()
        .map_err(|_| FileError::LockDataStream)?;

    let mut buf = [0u8; 8 * 1024];

    for offset in args.offsets {
        log::debug!("seeking data stream of '{:?}' to {:?}", args.path, offset);

        file_data_stream.seek(std::io::SeekFrom::Start(offset))
            .map_err(FileError::SeekDataStream)?;

        let mut len_left = match args.len {
            Some(len) => u64::from(len),
            None => u64::MAX,
        };
        let mut len_read_total = 0u64;

        use sha2::Digest as _;
        let mut sha256 = sha2::Sha256::new();
        loop {
            let buf_len = usize::try_from(len_left)
                .unwrap_or(usize::MAX)
                .min(buf.len());
            let buf = &mut buf[..buf_len];

            let len_read = file_data_stream.read(&mut buf[..])
                .map_err(FileError::ReadDataStream)?;
            if len_read == 0 {
                break
            }
            len_left -= len_read as u64;
            len_read_total += len_read as u64;

            sha256.update(&buf[..len_read]);
        }
        let sha256 = <[u8; 32]>::from(sha256.finalize());

        session.reply(Item {
            path: args.path.clone(),
            offset,
            len: len_read_total,
            sha256,
        })?;
    }

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_file_sha256_kmx::Args;

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

        // TODO(@panhania): Do not go through UTF-8 conversion.
        let path = str::from_utf8(proto.take_path().raw_bytes())
            .map_err(|error| ParseArgsError::invalid_field("path", error))?
            .into();

        let mut offsets = proto.take_offsets();
        if offsets.is_empty() {
            offsets.push(0);
        }

        Ok(Args {
            volume_path,
            path,
            offsets,
            len: std::num::NonZero::new(proto.length()),
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_file_sha256::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = rrg_proto::get_file_sha256::Result::new();

        // TODO: Use lossless conversion (preferably in Keramics directly).
        let path = std::path::PathBuf::from_iter(
            self.path.components.iter()
                .map(|comp| String::from_utf16_lossy(&comp.elements))
        );

        proto.set_path(path.into());
        proto.set_offset(self.offset);
        proto.set_length(self.len);
        proto.set_sha256(self.sha256.to_vec());

        proto
    }
}

/// Error which can occur when processing the file.
#[derive(Debug)]
enum FileError {
    NoEntry,
    OpenEntry(keramics_core::ErrorTrace),
    NoDataStream,
    OpenDataStream(keramics_core::ErrorTrace),
    LockDataStream,
    SeekDataStream(keramics_core::ErrorTrace),
    ReadDataStream(keramics_core::ErrorTrace),
}

impl std::fmt::Display for FileError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileError::NoEntry => {
                write!(fmt, "no file entry")
            }
            FileError::OpenEntry(error) => {
                write!(fmt, "failed to open file entry: {error}")
            }
            FileError::NoDataStream => {
                write!(fmt, "no file data stream")
            }
            FileError::OpenDataStream(error) => {
                write!(fmt, "failed to open file data stream: {error}")
            }
            FileError::LockDataStream => {
                write!(fmt, "poisoned data stream lock")
            }
            FileError::SeekDataStream(error) => {
                write!(fmt, "failed to seek data stream: {error}")
            }
            FileError::ReadDataStream(error) => {
                write!(fmt, "failed to read data stream: {error}")
            }
        }
    }
}

impl std::error::Error for FileError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FileError::NoEntry => None,
            FileError::OpenEntry(error) => Some(error),
            FileError::NoDataStream => None,
            FileError::OpenDataStream(error) => Some(error),
            FileError::LockDataStream => None,
            FileError::SeekDataStream(error) => Some(error),
            FileError::ReadDataStream(error) => Some(error),
        }
    }
}

impl From<FileError> for crate::session::Error {

    fn from(error: FileError) -> crate::session::Error {
        crate::session::Error::action(error)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_default() {
        let ntfs_file = tempntfs::create(|path| {
            use std::io::Write as _;

            let mut file = std::fs::File::create_new(path.join("foo"))?;
            file.write_all(b"hello\n")?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\foo"),
            offsets: vec![0],
            len: None,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, "\\foo".into());
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, u64::try_from(b"hello\n".len()).unwrap());
        assert_eq!(item.sha256, [
            // Pre-computed by the `sha256sum` tool.
            0x58, 0x91, 0xb5, 0xb5, 0x22, 0xd5, 0xdf, 0x08,
            0x6d, 0x0f, 0xf0, 0xb1, 0x10, 0xfb, 0xd9, 0xd2,
            0x1b, 0xb4, 0xfc, 0x71, 0x63, 0xaf, 0x34, 0xd0,
            0x82, 0x86, 0xa2, 0xe8, 0x46, 0xf6, 0xbe, 0x03,
        ]);
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_offset() {
        let ntfs_file = tempntfs::create(|path| {
            use std::io::Write as _;

            let mut file = std::fs::File::create_new(path.join("foo"))?;
            file.write_all(b"<ignore me>hello\n")?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\foo"),
            offsets: vec![u64::try_from("<ignore me>".len()).unwrap()],
            len: None,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, "\\foo".into());
        assert_eq!(item.offset, u64::try_from(b"<ignore me>".len()).unwrap());
        assert_eq!(item.len, u64::try_from(b"hello\n".len()).unwrap());
        assert_eq!(item.sha256, [
            // Pre-computed by the `sha256sum` tool.
            0x58, 0x91, 0xb5, 0xb5, 0x22, 0xd5, 0xdf, 0x08,
            0x6d, 0x0f, 0xf0, 0xb1, 0x10, 0xfb, 0xd9, 0xd2,
            0x1b, 0xb4, 0xfc, 0x71, 0x63, 0xaf, 0x34, 0xd0,
            0x82, 0x86, 0xa2, 0xe8, 0x46, 0xf6, 0xbe, 0x03,
        ]);
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_offset_multiple() {
        let ntfs_file = tempntfs::create(|path| {
            use std::io::Write as _;

            let mut file = std::fs::File::create_new(path.join("foo"))?;
            file.write_all(b"<ignore1>foo<ignore2>bar")?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\foo"),
            offsets: vec![
                u64::try_from(b"<ignore1>".len()).unwrap(),
                u64::try_from(b"<ignore1>foo<ignore2>".len()).unwrap(),
            ],
            len: std::num::NonZeroU64::new(3),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 2);

        let item_foo = session.reply::<Item>(0);
        assert_eq!(item_foo.path, "\\foo".into());
        assert_eq!(item_foo.offset, 9);
        assert_eq!(item_foo.len, 3);
        assert_eq!(item_foo.sha256, [
            // Pre-computed with `echo -n 'foo' | sha256sum`.
            0x2c, 0x26, 0xb4, 0x6b, 0x68, 0xff, 0xc6, 0x8f,
            0xf9, 0x9b, 0x45, 0x3c, 0x1d, 0x30, 0x41, 0x34,
            0x13, 0x42, 0x2d, 0x70, 0x64, 0x83, 0xbf, 0xa0,
            0xf9, 0x8a, 0x5e, 0x88, 0x62, 0x66, 0xe7, 0xae,
        ]);

        let item_bar = session.reply::<Item>(1);
        assert_eq!(item_bar.path, "\\foo".into());
        assert_eq!(item_bar.offset, 21);
        assert_eq!(item_bar.len, 3);
        assert_eq!(item_bar.sha256, [
            // Pre-computed with `echo -n 'bar' | sha256sum`.
            0xfc, 0xde, 0x2b, 0x2e, 0xdb, 0xa5, 0x6b, 0xf4,
            0x08, 0x60, 0x1f, 0xb7, 0x21, 0xfe, 0x9b, 0x5c,
            0x33, 0x8d, 0x10, 0xee, 0x42, 0x9e, 0xa0, 0x4f,
            0xae, 0x55, 0x11, 0xb6, 0x8f, 0xbf, 0x8f, 0xb9,
        ]);
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_len() {
        let ntfs_file = tempntfs::create(|path| {
            use std::io::Write as _;

            let mut file = std::fs::File::create_new(path.join("foo"))?;
            file.write_all(b"hello\n<ignore me>")?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\foo"),
            offsets: vec![0],
            len: std::num::NonZero::new(b"hello\n".len().try_into().unwrap()),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, "\\foo".into());
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, u64::try_from(b"hello\n".len()).unwrap());
        assert_eq!(item.sha256, [
            // Pre-computed by the `sha256sum` tool.
            0x58, 0x91, 0xb5, 0xb5, 0x22, 0xd5, 0xdf, 0x08,
            0x6d, 0x0f, 0xf0, 0xb1, 0x10, 0xfb, 0xd9, 0xd2,
            0x1b, 0xb4, 0xfc, 0x71, 0x63, 0xaf, 0x34, 0xd0,
            0x82, 0x86, 0xa2, 0xe8, 0x46, 0xf6, 0xbe, 0x03,
        ]);
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_large() {
        let ntfs_file = tempntfs::create_with_size(20 * 1024 * 1024, |path| {
            use std::io::{Read as _};

            let mut file = std::fs::File::create_new(path.join("foo"))?;
            std::io::copy(&mut std::io::repeat(0).take(13371337), &mut file)?;

            Ok(())
        }).unwrap();


        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\foo"),
            offsets: vec![0],
            len: None,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, "\\foo".into());
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, 13371337);
        assert_eq!(item.sha256, [
            // Pre-computed by `head --bytes=13371337 < /dev/zero | sha256sum`.
            0xda, 0xa6, 0x04, 0x11, 0x35, 0x03, 0xdb, 0x38,
            0xe3, 0x62, 0xfe, 0xff, 0x8f, 0x73, 0xc1, 0xf9,
            0xb2, 0x6f, 0x02, 0x85, 0x3d, 0x2f, 0x47, 0x8d,
            0x52, 0x16, 0xc5, 0x70, 0x32, 0x54, 0x1c, 0xf8,
        ]);
    }
}
