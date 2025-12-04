// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Limit on the size of individual file part blob sent to the blob sink.
const MAX_BLOB_LEN: usize = 1 * 1024 * 1024; // 1 MiB.

/// Arguments of the `get_file_contents_kmx` action.
pub struct Args {
    /// Path to the NTFS filesystem volume to use for parsing.
    volume_path: Option<std::path::PathBuf>,
    /// Path to the file to get the contents of.
    path: keramics_formats::ntfs::NtfsPath,
    /// Offset from which to read the file contents.
    offset: u64,
    /// Number of bytes to read from the file.
    len: usize,
}

/// Result of the `get_file_contents_kmx` action.
pub struct Item {
    /// Path to the file this result corresponds to.
    path: keramics_formats::ntfs::NtfsPath,
    /// Byte offset of the file part sent to the blob sink.
    offset: u64,
    /// Number of bytes of the file part sent to the blob sink.
    len: usize,
    /// SHA-256 digest of the file part sent to the blob sink.
    blob_sha256: [u8; 32],
}

/// Handles invocations of the `get_file_contents_kmx` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    // TODO: Add support for inferring the volume from path.
    let Some(volume_path) = args.volume_path else {
        return Err(crate::session::Error::action(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "volume path must be provided",
        )));
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

    let file_entry = match ntfs.get_file_entry_by_path(&args.path) {
        Ok(Some(file_entry)) => file_entry,
        Ok(None) => {
            // TODO(@panhania): Consult with @jbmetz what `None` actually means
            // in this case.
            let error = std::io::Error::new(std::io::ErrorKind::NotFound, "no entry");
            return Err(crate::session::Error::action(error))
        }
        Err(error) => return Err(crate::session::Error::action(error)),
    };

    log::debug!("collecting contents of '{:?}'", args.path);

    let file_data_stream = match file_entry.get_data_stream() {
        Ok(Some(file_data_stream)) => file_data_stream,
        Ok(None) => {
            // TODO(@panhania): Consult with @jbmetz what `None` actually means
            // in this case.
            let error = std::io::Error::new(std::io::ErrorKind::NotFound, "no content");
            return Err(crate::session::Error::action(error))
        }
        Err(error) => return Err(crate::session::Error::action(error)),
    };

    let mut file_data_stream = match file_data_stream.write() {
        Ok(file_data_stream) => file_data_stream,
        Err(_) => {
            let error = std::io::Error::from(std::io::ErrorKind::Other);
            return Err(crate::session::Error::action(error))
        }
    };

    let mut offset = args.offset;
    let mut len_left = args.len;

    file_data_stream.seek(std::io::SeekFrom::Start(offset))
        .map_err(crate::session::Error::action)?;

    loop {
        use sha2::Digest as _;

        let mut buf = vec![0; std::cmp::min(len_left, MAX_BLOB_LEN)];

        let len_read = match file_data_stream.read(&mut buf[..]) {
            Ok(0) => break,
            Ok(len_read) => len_read,
            Err(error) => return Err(crate::session::Error::action(error)),
        };
        buf.truncate(len_read);

        let blob = crate::blob::Blob::from(buf);
        let blob_sha256 = sha2::Sha256::digest(blob.as_bytes()).into();

        session.send(crate::Sink::Blob, blob)?;
        session.reply(Item {
            path: args.path.clone(),
            offset,
            len: len_read,
            blob_sha256,
        })?;

        offset += len_read as u64;
        len_left -= len_read;
    }

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_file_contents_kmx::Args;

    fn from_proto(proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        // TODO: Do not go through UTF-8 conversion.
        let path = str::from_utf8(proto.path().raw_bytes())
            .map_err(|error| ParseArgsError::invalid_field("path", error))?;
        let path = keramics_formats::ntfs::NtfsPath::from(path);

        let len = match proto.length() {
            0 => usize::MAX,
            len if len > MAX_BLOB_LEN as u64 => {
                return Err(ParseArgsError::invalid_field("length", LenError {
                    len,
                }));
            },
            len => len as usize,
        };

        Ok(Args {
            volume_path: None,
            path,
            offset: proto.offset(),
            len,
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_file_contents_kmx::Result;

    fn into_proto(self) -> rrg_proto::get_file_contents_kmx::Result {
        // TODO: Use lossless conversion (preferably in Keramics directly).
        let path = std::path::PathBuf::from_iter(
            self.path.components.iter()
                .map(|comp| String::from_utf16_lossy(&comp.elements))
        );

        let mut proto = rrg_proto::get_file_contents_kmx::Result::new();
        proto.set_path(path.into());
        proto.set_offset(self.offset);
        proto.set_length(self.len as u64);
        proto.set_blob_sha256(self.blob_sha256.into());

        proto
    }
}

/// An error indicating that the action was invoked with invalid length.
#[derive(Debug)]
struct LenError {
    len: u64,
}

impl std::fmt::Display for LenError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write! {
            fmt,
            "provided length ({}) is bigger than allowed ({})",
            self.len, MAX_BLOB_LEN
        }
    }
}

impl std::error::Error for LenError {
}

#[cfg(test)]
mod tests {

    use super::*;

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_empty_file() {
        let ntfs_file = ntfs_temp_file(|path| {
            std::fs::File::create_new(path.join("empty"))?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: Some(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\empty"),
            offset: 0,
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
        let ntfs_file = ntfs_temp_file(|path| {
            use std::io::Write as _;

            let mut file = std::fs::File::create_new(path.join("file"))?;
            file.write_all(b"0123456789")?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: Some(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\file"),
            offset: 0,
            len: usize::MAX,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, b"0123456789".len());

        assert_eq!(session.parcel_count(crate::Sink::Blob), 1);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 0);
        assert_eq!(blob.as_bytes(), b"0123456789");
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_small_file_from_offset() {
        let ntfs_file = ntfs_temp_file(|path| {
            use std::io::Write as _;

            let mut file = std::fs::File::create_new(path.join("file"))?;
            file.write_all(b"0123456789")?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: Some(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\file"),
            offset: 5,
            len: usize::MAX,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.offset, 5);
        assert_eq!(item.len, 5);

        assert_eq!(session.parcel_count(crate::Sink::Blob), 1);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 0);
        assert_eq!(blob.as_bytes(), b"56789");
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_small_file_to_len() {
        let ntfs_file = ntfs_temp_file(|path| {
            use std::io::Write as _;

            let mut file = std::fs::File::create_new(path.join("file"))?;
            file.write_all(b"0123456789")?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: Some(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\file"),
            offset: 0,
            len: 5,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, 5);

        assert_eq!(session.parcel_count(crate::Sink::Blob), 1);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 0);
        assert_eq!(blob.as_bytes(), b"01234");
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_big_file_from_offset_to_len() {
        let ntfs_file = ntfs_temp_file_with_size(20 * 1024 * 1024, |path| {
            use std::io::{Read as _};

            let mut file = std::fs::File::create_new(path.join("file"))?;
            std::io::copy(&mut std::io::repeat(0xf0).take(13371337), &mut file)?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: Some(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\file"),
            offset: 0xb33f,
            len: MAX_BLOB_LEN + 1337,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 2);

        let item = session.reply::<Item>(0);
        assert_eq!(item.offset, 0xb33f);
        assert_eq!(item.len, MAX_BLOB_LEN);

        let item = session.reply::<Item>(1);
        assert_eq!(item.offset, 0xb33f + MAX_BLOB_LEN as u64);
        assert_eq!(item.len, 1337);
    }

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

    // TODO: Keramics defines its own `DataStream` type rather than using
    // standard interfaces. Thus, we wrap `NamedTempFile` to provide our own
    // implementation of it.
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
            // The only way to get the PID fo the background process seems to be
            // through a "PID file" which is written by `guestmount`, so we use
            // a temporary file for that.
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
