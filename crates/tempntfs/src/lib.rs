// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Library for creating temporary files with NTFS filesystem images.
//!
//! It is intended to be used for testing code dependant on parsing raw NTFS
//! data.
//!
//! The library wraps [`libguestfs`] utilities (and [`mkfs.ntfs`]) and so is
//! usable only on Linux.
//!
//! [`libguestfs`]: https://libguestfs.org/
//! [`mkfs.ntfs`]: https://linux.die.net/man/8/mkfs.ntfs

/// Creates a small temporary file with NTFS filesystem generated with `init`.
///
/// `init` takes a path to the root of the directory holding the filesystem and
/// can create new files e.g. using `std::fs:*` functions.
pub fn create(
    init: impl FnOnce(&std::path::Path) -> std::io::Result<()>,
) -> std::io::Result<tempfile::NamedTempFile>
{
    // We use the default of 2 MiB as the minimum size supported by NTFS is
    // 1 MiB, so we double that just to be on the safe side.
    create_with_size(2 * 1024 * 1024, init)
}

/// Creates a temporary file with NTFS filesystem generated with `init` of the
/// given `size`.
///
/// `init` takes a path to the root of the directory holding the filesystem and
/// can create new files e.g. using `std::fs:*` functions.
pub fn create_with_size(
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

/// RAII wrapper for a guestmounted filesystem.
struct GuestMount {
    /// Path to a directory in which the filesystem is (or was) mounted.
    mountpoint: std::path::PathBuf,
    /// PID of the `guestmount` subprocess for serving the files.
    pid: Option<u32>,
    /// Whether the filesystem is still mounted.
    is_mounted: bool,
}

impl GuestMount {

    fn new<PI, PM>(image: PI, mountpoint: PM) -> std::io::Result<GuestMount>
    where
        PI: AsRef<std::path::Path>,
        PM: AsRef<std::path::Path>,
    {
        // `guestmount` spawns a separate process to serve the files. When we
        // call `guestunmount` to unmount, even though the call returns, the
        // background process still flushes the file in the background. To only
        // finish the unmount after everything is properly flushed, we wait
        // until the background process is gone [1].
        //
        // The only way to get the PID for the background process seems to be
        // through a "PID file" which is written by `guestmount`, so we use a
        // temporary file for that.
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
        // parsed the PID file yet which we mail fail to do so. But even if we
        // cannot read the PID file, we should still clean the mount when
        // returning an error.
        //
        //
        // Thus we create a `GuestMount` instance here (without PID) an in case
        // of an error, RAII will take care of running `guestunmount`.
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
        // We set this bit even before the file is actually closed (which may
        // fail and not actually close the device!). This is because in case
        // closing fails, we don't want to allow closing again. we need this
        // behaviour especially because of the `drop` method that is bound to
        // run eventually, attempting to close again any unclosed device.
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

        // See the constructor and [1] for more information about this PID. Note
        // that might not have the PID available and still want to run the cons-
        // tructor (e.g. in case `guestmount` succeeded but parsing the PID file
        // failed).
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
            // `unmount` takes an owned value, so we replace `self` with a dummy
            // closed device (it being unmounted is important to avoid infinite
            // recursion) and then call explicit close on obtained owned value.
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

#[cfg(test)]
mod tests {

    use super::*;

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

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn create_empty() {
        let file = create(|_| Ok(()))
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
    fn create_files() {
        let file = create(|path| {
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
