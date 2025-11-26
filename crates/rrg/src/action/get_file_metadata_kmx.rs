// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Arguments of the `get_file_metadata_kmx` action.
pub struct Args {
    // TODO.
}

/// Result of the `get_file_metadata_kmx` action.
pub struct Item {
    // TODO.
}

/// Handles invocations of the `get_file_metadata_kmx` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    todo!()
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_file_metadata_kmx::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        todo!()
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_file_metadata_kmx::Result;

    fn into_proto(self) -> Self::Proto {
        todo!()
    }
}

#[cfg(test)]
mod tests {

    struct LoopDevNtfsMount<'dev> {
        loop_dev: &'dev mut LoopDev,
        path: std::path::PathBuf,
        is_unmounted: bool,
    }

    impl<'dev> LoopDevNtfsMount<'dev> {

        fn new(loop_dev: &'dev mut LoopDev) -> std::io::Result<LoopDevNtfsMount<'dev>> {
            use regex::Regex;

            let output = std::process::Command::new("udisksctl")
                .arg("mount")
                .arg("--filesystem-type").arg("ntfs")
                .arg("--block-device").arg(&loop_dev.path)
                .arg("--no-user-interaction")
                .output()?;
            if !output.status.success() {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, format! {
                    "failed to run `udisksctl mount` (stdout: {:?}, stderr: {:?})",
                    String::from_utf8_lossy(&output.stdout).as_ref(),
                    String::from_utf8_lossy(&output.stderr).as_ref(),
                }))
            }
            let output_stdout = String::from_utf8_lossy(&output.stdout);

            match Regex::new("Mounted .* at (?P<mount>.*)")
                .unwrap()
                .captures(&output_stdout)
            {
                Some(captures) => Ok(LoopDevNtfsMount {
                    path: std::path::PathBuf::from(&captures["mount"]),
                    is_unmounted: false,
                    loop_dev,
                }),
                None => return Err(std::io::Error::new(std::io::ErrorKind::Other, format! {
                    "unexpected `udisksctl loop-setup` output: {:?}",
                    output_stdout,
                })),
            }
        }

        fn unmount(mut self) -> std::io::Result<()> {
            assert!(!self.is_unmounted);
            // See similar comment in `LoopDev::close` method on why we set it
            // even before unmounting succeeded.
            self.is_unmounted = true;

            let output = std::process::Command::new("udisksctl")
                .arg("unmount")
                .arg("--block-device").arg(&self.loop_dev.path)
                .arg("--no-user-interaction")
                .output()?;
            if !output.status.success() {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, format! {
                    "failed to run `udisksctl unmount` (stdout: {:?}, stderr: {:?})",
                    String::from_utf8_lossy(&output.stdout).as_ref(),
                    String::from_utf8_lossy(&output.stderr).as_ref(),
                }))
            }

            Ok(())
        }
    }

    #[test]
    fn loop_dev_ntfs_mount_new_and_unmount() {
        use std::io::Write as _;

        let mut file = tempfile::NamedTempFile::new()
            .unwrap();
        // We initialize the file to have 2 MiB. Minimum size of NTFS image is
        // 1 MiB, so we use 2 MiB just to be on the safe side.
        file.write_all(&vec![0; 2 * 1024 * 1024])
            .unwrap();
        file.flush()
            .unwrap();
        std::process::Command::new("mkfs.ntfs")
            .arg("--force")
            .arg(file.path())
            .output()
            .unwrap();

        let mut loop_dev = LoopDev::new(&file)
            .unwrap();

        let loop_dev_ntfs_mount = LoopDevNtfsMount::new(&mut loop_dev)
            .unwrap();

        loop_dev_ntfs_mount.unmount()
            .unwrap();
    }

    #[test]
    fn loop_dev_ntfs_mount_new_and_drop() {
        use std::io::Write as _;

        let mut file = tempfile::NamedTempFile::new()
            .unwrap();
        // We initialize the file to have 2 MiB. Minimum size of NTFS image is
        // 1 MiB, so we use 2 MiB just to be on the safe side.
        file.write_all(&vec![0; 2 * 1024 * 1024])
            .unwrap();
        file.flush()
            .unwrap();
        std::process::Command::new("mkfs.ntfs")
            .arg("--force")
            .arg(file.path())
            .output()
            .unwrap();

        let mut loop_dev = LoopDev::new(&file)
            .unwrap();

        let loop_dev_ntfs_mount = LoopDevNtfsMount::new(&mut loop_dev)
            .unwrap();

        drop(loop_dev_ntfs_mount);
    }

    struct LoopDev {
        path: std::path::PathBuf,
        is_closed: bool,
    }

    impl LoopDev {

        fn new<P>(file_path: P) -> std::io::Result<LoopDev>
        where
            P: AsRef<std::path::Path>,
        {
            use regex::Regex;

            let output = std::process::Command::new("udisksctl")
                .arg("loop-setup")
                .arg("--file").arg(file_path.as_ref())
                .arg("--no-user-interaction")
                .output()?;
            if !output.status.success() {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, format! {
                    "failed to run `udisksctl loop-setup` (stdout: {:?}, stderr: {:?})",
                    String::from_utf8_lossy(&output.stdout).as_ref(),
                    String::from_utf8_lossy(&output.stderr).as_ref(),
                }))
            }
            let output_stdout = String::from_utf8_lossy(&output.stdout);

            match Regex::new("Mapped file .* as (?P<devloop>.*)\\.")
                .unwrap()
                .captures(&output_stdout)
            {
                Some(captures) => Ok(LoopDev {
                    path: std::path::PathBuf::from(&captures["devloop"]),
                    is_closed: false,
                }),
                None => return Err(std::io::Error::new(std::io::ErrorKind::Other, format! {
                    "unexpected `udisksctl loop-setup` output: {:?}",
                    output_stdout,
                })),
            }
        }

        fn close(mut self) -> std::io::Result<()> {
            assert!(!self.is_closed);
            // We set this bit even before the file is actually closed (which
            // may fail and not actually close the device!). This is because in
            // case closing fails, we don't want to allow closing again. we need
            // this behaviour especially because of the `drop` method that is
            // bound to run eventually, attempting to close again any unclosed
            // device.
            self.is_closed = true;

            let output = std::process::Command::new("udisksctl")
                .arg("loop-delete")
                .arg("--block-device").arg(&self.path)
                .arg("--no-user-interaction")
                .output()?;
            if !output.status.success() {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, format! {
                    "failed to run `udisksctl loop-delete` (stdout: {:?}, stderr: {:?})",
                    String::from_utf8_lossy(&output.stdout).as_ref(),
                    String::from_utf8_lossy(&output.stderr).as_ref(),
                }))
            }

            Ok(())
        }
    }

    impl Drop for LoopDev {

        fn drop(&mut self) {
            if !self.is_closed {
                // `close` takes an owned value, so we replace `self` with some
                // dummy closed device (it being closed is important to avoid
                // infinite recursion) and then call explicit close on obtained
                // owned value.
                let closed = LoopDev {
                    path: std::path::PathBuf::new(),
                    is_closed: true,
                };

                std::mem::replace(self, closed).close()
                    .expect("failed to close the loop device");
            }
        }
    }

    #[test]
    fn loop_dev_new_and_close() {
        let file = tempfile::NamedTempFile::new()
            .unwrap();

        let loop_dev = LoopDev::new(&file)
            .unwrap();

        loop_dev.close()
            .unwrap();
    }

    #[test]
    fn loop_dev_new_and_drop() {
        let file = tempfile::NamedTempFile::new()
            .unwrap();

        let loop_dev = LoopDev::new(&file)
            .unwrap();

        drop(loop_dev);
    }
}
