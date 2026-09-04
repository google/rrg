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
        let ntfs_file = ntfs_temp_file(|path| {
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
        let ntfs_file = ntfs_temp_file(|path| {
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
        let ntfs_file = ntfs_temp_file(|path| {
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
        let ntfs_file = ntfs_temp_file(|path| {
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
        let ntfs_file = ntfs_temp_file_with_size(20 * 1024 * 1024, |path| {
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

    // TODO(@panhania): Keramics defines its own `DataStream` type rather than
    // using standard interfaces. Thus, we wrap `NamedTempFile` to provide our
    // own implementation of it.
    struct NamedTempFileWrapper(tempfile::NamedTempFile);
    impl keramics_core::DataStream for NamedTempFileWrapper {

        fn get_size(&mut self) -> Result<u64, keramics_core::ErrorTrace> {
            self.0.as_file_mut().get_size()
        }

        fn read(&mut self, buf: &mut [u8]) -> Result<usize, keramics_core::ErrorTrace> {
            self.0.as_file_mut().read(buf)
        }

        fn seek(&mut self, pos: std::io::SeekFrom) -> Result<u64, keramics_core::ErrorTrace> {
            self.0.as_file_mut().seek(pos)
        }
    }

    // TODO(@panhania): The utilities below (and their tests) were copied from
    // `get_file_contents_kmx` action. This should be refactored to a separate
    // crate.

    fn ntfs_temp_file(
        init: impl FnOnce(&std::path::Path) -> std::io::Result<()>,
    ) -> std::io::Result<tempfile::NamedTempFile>
    {
        // We use the default of 2 MiB as the minimum size supported by NTFS is
        // 1 MiB, so we double that just to be on the safe side.
        ntfs_temp_file_with_size(2 * 1024 * 1024, init)
    }

    fn ntfs_temp_file_with_size(
        size: usize,
        init: impl FnOnce(&std::path::Path) -> std::io::Result<()>,
    ) -> std::io::Result<tempfile::NamedTempFile>
    {
        use std::io::Write as _;

        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(&vec![0; size])?;
        file.flush()?;

        let output = std::process::Command::new("mkfs.ntfs")
            .arg("--force")
            .arg(file.path())
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, format! {
                "failed to run `mkfs.ntfs` (stdout: {:?}, stderr: {:?})",
                String::from_utf8_lossy(&output.stdout).as_ref(),
                String::from_utf8_lossy(&output.stderr).as_ref(),
            }))
        }

        let mountpoint = tempfile::tempdir()?;

        let mount = GuestMount::new(file.path(), mountpoint.path())?;
        init(mountpoint.path())?;
        mount.unmount()?;

        Ok(file)
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn ntfs_temp_file_empty() {
        let file = ntfs_temp_file(|_| Ok(()))
            .unwrap();

        let data_stream: keramics_core::DataStreamReference = {
            std::sync::Arc::new(std::sync::RwLock::new(NamedTempFileWrapper(file)))
        };

        let mut ntfs = keramics_formats::ntfs::NtfsFileSystem::new();
        ntfs.read_data_stream(&data_stream)
            .unwrap();

        assert!(ntfs.get_root_directory().is_ok());
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn ntfs_temp_file_files() {
        let file = ntfs_temp_file(|path| {
            std::fs::write(path.join("foo"), b"Lorem ipsum.")
                .unwrap();
            std::fs::write(path.join("bar"), b"Dolor sit amet.")
                .unwrap();

            Ok(())
        }).unwrap();

        let data_stream: keramics_core::DataStreamReference = {
            std::sync::Arc::new(std::sync::RwLock::new(NamedTempFileWrapper(file)))
        };

        let mut ntfs = keramics_formats::ntfs::NtfsFileSystem::new();
        ntfs.read_data_stream(&data_stream)
            .unwrap();

        let mut entry_root = ntfs.get_root_directory()
            .unwrap();

        let entry_foo = entry_root.get_sub_file_entry_by_name(&keramics_types::Ucs2String::from("foo"))
            .unwrap().unwrap();
        assert_eq!(entry_foo.get_size(), b"Lorem ipsum.".len() as u64);

        let entry_bar = entry_root.get_sub_file_entry_by_name(&keramics_types::Ucs2String::from("bar"))
            .unwrap().unwrap();
        assert_eq!(entry_bar.get_size(), b"Dolor sit amet.".len() as u64);
    }

    struct GuestMount {
        mountpoint: std::path::PathBuf,
        pid: Option<u32>,
        is_mounted: bool,
    }

    impl GuestMount {

        fn new<PI, PM>(image: PI, mountpoint: PM) -> std::io::Result<GuestMount>
        where
            PI: AsRef<std::path::Path>,
            PM: AsRef<std::path::Path>,
        {
            // `guestmount` spawns a separate process to serve the files. When
            // we call `guestunmount` to unmount, even though the call returns,
            // the background process still flushes the file in the background.
            // To only finish the unmount after everything is properly flushed,
            // we wait until the background process is gone [1].
            //
            // The only way to get the PID for the background process seems to
            // be through a "PID file" which is written by `guestmount`, so we
            // use a temporary file for that.
            //
            // [1]: https://libguestfs.org/guestmount.1.html#race-conditions-possible-when-shutting-down-the-connection
            let pid_file = tempfile::NamedTempFile::new()?;

            let output = std::process::Command::new("guestmount")
                .arg("--add").arg(image.as_ref().as_os_str())
                .arg("--mount").arg("/dev/sda:/::ntfs")
                .arg("--pid-file").arg(pid_file.path().as_os_str())
                .arg(mountpoint.as_ref().as_os_str())
                .output()?;
            if !output.status.success() {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, format! {
                    "failed to run `guestmount` (stdout: {:?}, stderr: {:?})",
                    String::from_utf8_lossy(&output.stdout).as_ref(),
                    String::from_utf8_lossy(&output.stderr).as_ref(),
                }))
            }

            // At this point we successfully created the mount but we have not
            // parsed the PID file yet which we mail fail to do so. But even if
            // we cannot read the PID file, we should still clean the mount when
            // returning an error.
            //
            //
            // Thus we create a `GuestMount` instance here (without PID) an in
            // case of an error, RAII will take care of running `guestunmount`.
            let mut mount = GuestMount {
                mountpoint: mountpoint.as_ref().to_path_buf(),
                pid: None,
                is_mounted: true,
            };

            let pid = || -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
                let pid_string = String::from_utf8(std::fs::read(pid_file.path())?)?;
                Ok(pid_string.trim().parse::<u32>()?)
            }().map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, format! {
                "invalid PID file contents: {error}"
            }))?;
            mount.pid = Some(pid);

            Ok(mount)
        }

        fn unmount(mut self) -> std::io::Result<()> {
            assert!(self.is_mounted);
            // We set this bit even before the file is actually closed (which
            // may fail and not actually close the device!). This is because in
            // case closing fails, we don't want to allow closing again. we need
            // this behaviour especially because of the `drop` method that is
            // bound to run eventually, attempting to close again any unclosed
            // device.
            self.is_mounted = false;

            let output = std::process::Command::new("guestunmount")
                .arg(self.mountpoint.as_os_str())
                .output()?;
            if !output.status.success() {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, format! {
                    "failed to run `guestunmount` (stdout: {:?}, stderr: {:?})",
                    String::from_utf8_lossy(&output.stdout).as_ref(),
                    String::from_utf8_lossy(&output.stderr).as_ref(),
                }))
            }

            // See the constructor and [1] for more information about this PID.
            // Note that might not have the PID available and still want to run
            // the constructor (e.g. in case `guestmount` succeeded but parsing
            // the PID file failed).
            //
            // We use procfs [2] to determine whether the background process is
            // done. We do a bit of busy waiting here but this involves a system
            // call, so we should not waste too much time.
            //
            // [1]: https://libguestfs.org/guestmount.1.html#race-conditions-possible-when-shutting-down-the-connection
            // [2]: https://en.wikipedia.org/wiki/Procfs
            if let Some(pid) = self.pid {
                let pid_path = format!("/proc/{}", pid);
                while std::fs::exists(&pid_path)? {
                    std::thread::yield_now();
                }
            }

            Ok(())
        }
    }

    impl Drop for GuestMount {

        fn drop(&mut self) {
            if self.is_mounted {
                // `unmount` takes an owned value, so we replace `self` with a
                // dummy closed device (it being unmounted is important to avoid
                // infinite recursion) and then call explicit close on obtained
                // owned value.
                let unmounted = GuestMount {
                    mountpoint: std::path::PathBuf::new(),
                    pid: None,
                    is_mounted: false,
                };

                std::mem::replace(self, unmounted).unmount()
                    .expect("failed to unmount");
            }
        }
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn guest_mount_new_and_unmount() {
        use std::io::Write as _;

        let mut image = tempfile::NamedTempFile::new()
            .unwrap();
        // We initialize the file to have 2 MiB. Minimum size of NTFS image is
        // 1 MiB, so we use 2 MiB just to be on the safe side.
        image.write_all(&vec![0; 2 * 1024 * 1024])
            .unwrap();
        image.flush()
            .unwrap();
        std::process::Command::new("mkfs.ntfs")
            .arg("--force")
            .arg(image.path())
            .output()
            .unwrap();

        let mountpoint = tempfile::tempdir()
            .unwrap();

        let mount = GuestMount::new(&image, &mountpoint)
            .unwrap();

        mount.unmount()
            .unwrap();
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn guest_mount_new_and_drop() {
        use std::io::Write as _;

        let mut image = tempfile::NamedTempFile::new()
            .unwrap();
        // We initialize the file to have 2 MiB. Minimum size of NTFS image is
        // 1 MiB, so we use 2 MiB just to be on the safe side.
        image.write_all(&vec![0; 2 * 1024 * 1024])
            .unwrap();
        image.flush()
            .unwrap();
        std::process::Command::new("mkfs.ntfs")
            .arg("--force")
            .arg(image.path())
            .output()
            .unwrap();

        let mountpoint = tempfile::tempdir()
            .unwrap();

        let mount = GuestMount::new(&image, &mountpoint)
            .unwrap();

        drop(mount)
    }
}
