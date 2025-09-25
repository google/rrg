// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the timeline action.

use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

use ospect::fs::Mount;

use crate::session::Error;

/// Arguments of the `get_filesystem_timeline` action.
pub struct Args {
    raw_fs: Option<PathBuf>,
    root: PathBuf,
}

/// Result of the `get_filesystem_timeline` action.
pub struct Item {
    /// SHA-256 digest of the timeline batch sent to the blob sink.
    blob_sha256: [u8; 32],
    // Number of entries in the batch sent to the blob sink.
    entry_count: usize,
}

/// Information about a mounted raw filesystem.
#[derive(Debug, PartialEq, Eq)]
pub struct RawDeviceMount {
    /// Path to the raw filesystem image.
    /// e.g. /dev/sda1, /dev/mapper/root, /dev/loop0.
    pub image_path: std::path::PathBuf,
    /// Path to which the raw filesystem is mounted.
    pub mountpoint: std::path::PathBuf,
}

/// Returns the mount that contains the file at the given path.
pub fn get_mount(mounts: &[Mount], path: &Path) -> std::io::Result<Mount> {
    // Note: std::path::absolute does not follow symlinks like std::fs::canonicalize does.
    // It also returns C:\-style paths on windows rather than \\?\C:\-style paths.
    let path: PathBuf = std::path::absolute(path)?;
    mounts
        .iter()
        .cloned()
        .filter_map(|mut m| {
            std::path::absolute(&m.path).ok().map(move |abs_path| {
                m.path = abs_path;
                m
            })
        })
        .filter(|m| path.starts_with(&m.path))
        // Filter out dummy and remote filesystems whose names may start with /.
        .max_by_key(|m| m.path.as_os_str().len())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Failed to locate mount for {path:?}"),
            )
        })
}

pub fn get_raw_device(mounts: &[Mount], path: &Path) -> std::io::Result<RawDeviceMount> {
    let mount = get_mount(mounts, path)?;
    #[cfg(not(target_os = "windows"))]
    {
        // Comprehensive list of raw filesystem types supported by RRG.
        const SUPPORTED_FS_TYPES: &[&str] = &["ext2", "ext3", "ext4", "vfat", "ntfs", "fuseblk"];
        if !SUPPORTED_FS_TYPES.contains(&mount.fs_type.as_ref()) {
            return Err(std::io::Error::other(format!(
                "Unsupported filesystem type: {}",
                mount.fs_type
            )));
        }
        Ok(RawDeviceMount {
            image_path: mount.name.into(),
            mountpoint: mount.path.to_path_buf(),
        })
    }
    #[cfg(target_os = "windows")]
    {
        Ok(RawDeviceMount {
            // The "name" of the mount is the volume GUID path: \\?\Volume{...}\
            // Opening \\?\Volume{...}\ opens the directory.
            // Opening \\?\Volume{...} opens the raw bytes of the volume.
            image_path: mount.name.trim_end_matches('\\').into(),
            mountpoint: mount.path.to_path_buf(),
        })
    }
}

/// Given an absolute path and the raw device that contains it, computes the path
/// embedded within the raw device to give TSK.
///
/// This path must start with `/`, and this function normalizes all path
/// separators in the embedded path to use `/` for consistency.
fn get_embedded_path(mount: &RawDeviceMount, absolute_path: &Path) -> PathBuf {
    absolute_path
        .strip_prefix(&mount.mountpoint)
        .expect("mountpoint not prefix of root")
        .iter()
        .flat_map(|component| [OsStr::new("/"), component])
        .collect::<OsString>()
        .into()
}

/// Handles requests for the timeline action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let raw_fs: PathBuf;
    let embedded_path;
    if let Some(raw_fs_arg) = args.raw_fs {
        raw_fs = raw_fs_arg;
        embedded_path = args.root;
    } else {
        // Detect raw filesystem
        let mounts = ospect::fs::mounts()
            .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
            .map_err(crate::session::Error::action)?;
        let mount = get_raw_device(&mounts, &args.root).map_err(crate::session::Error::action)?;
        embedded_path = get_embedded_path(&mount, &args.root);
        // The raw fs path may be e.g. /dev/sda1 on Linux or \\?\C: on Windows.
        raw_fs = mount.image_path;
    };

    let (tx, rx) = std::sync::mpsc::sync_channel(0);
    let tsk_thread = std::thread::spawn(move || -> tsk::Result<()> {
        let image = tsk::Image::open(&raw_fs)?;
        let fs = tsk::Filesystem::open(&image)?;
        let dir = fs.open_dir(&embedded_path)?;
        let root_bytes = embedded_path.as_os_str().as_encoded_bytes();
        fs.walk_dir(&dir, |file, path| {
            match tx.send(make_entry(root_bytes, path, file)) {
                Ok(()) => tsk::WalkDirCallbackResult::Continue,
                // rx disconnected, no need to keep searching.
                Err(_) => tsk::WalkDirCallbackResult::Stop,
            }
        })
    });

    // `entry_count` keeps track of the number of entries that are included in
    // each batch. Each time the `entries` iterator (defined below) yields an
    // entry, we increase the count (through `Iterator::inspect`). We read the
    // of `entry_count` when we are about to send a batch and reset the counter
    // so that we start from 0 for the next batch.
    //
    // Note that `entry_count` has to be a cell because it is mutably borrowed
    // by the `entries` iterator but we still want to be able to also modify it
    // when we process batches.
    let entry_count = &std::cell::RefCell::new(0);

    let result_iter = rx.into_iter().inspect(|_| *entry_count.borrow_mut() += 1);

    let encode_and_send_result = (move || -> crate::session::Result<()> {
        use sha2::Digest as _;
        for batch in crate::gzchunked::encode(result_iter) {
            let batch = batch.map_err(crate::session::Error::action)?;

            let blob = crate::blob::Blob::from(batch);
            let blob_sha256 = sha2::Sha256::digest(blob.as_bytes()).into();

            session.send(crate::Sink::Blob, blob)?;
            session.reply(Item {
                blob_sha256,
                entry_count: *entry_count.borrow(),
            })?;

            *entry_count.borrow_mut() = 0;
        }
        Ok(())
    })();

    tsk_thread
        .join()
        .expect("tsk file walker thread panicked")
        .map_err(Error::action)?;
    // Check this after the thread joined.
    encode_and_send_result?;

    Ok(())
}

impl crate::request::Args for Args {
    type Proto = rrg_proto::get_filesystem_timeline_tsk::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let raw_fs = Some(
            PathBuf::try_from(proto.take_raw_fs())
                .map_err(|error| ParseArgsError::invalid_field("raw_fs", error))?,
        )
        .filter(|path| !path.as_os_str().is_empty());

        let root = PathBuf::try_from(proto.take_root())
            .map_err(|error| ParseArgsError::invalid_field("root", error))?;

        Ok(Args { raw_fs, root })
    }
}

impl crate::response::Item for Item {
    type Proto = rrg_proto::get_filesystem_timeline_tsk::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = Self::Proto::default();
        proto.set_blob_sha256(self.blob_sha256.into());
        proto.set_entry_count(self.entry_count as u64);

        proto
    }
}

fn make_entry(
    // Absolute path to the start of the search.
    root: &[u8],
    // Relative path to the parent directory from the root.
    parent_path: &[u8],
    // Handle to the file.
    file: tsk::File,
) -> rrg_proto::get_filesystem_timeline::Entry {
    let mut proto = rrg_proto::get_filesystem_timeline::Entry::default();
    if let Some(name) = file.name() {
        let mut path = Vec::from(root);
        path.push(b'/');
        path.extend_from_slice(parent_path);
        path.append(&mut name.into_bytes());
        proto.set_path(path);
    }

    fn nanos(seconds: i64, nanos: u32) -> i64 {
        seconds * 1_000_000_000 + nanos as i64
    }

    if let Some(meta) = file.meta() {
        if let Ok(size) = meta.size().try_into() {
            proto.set_size(size);
        }
        proto.set_atime_nanos(nanos(meta.atime(), meta.atime_nano()));
        proto.set_mtime_nanos(nanos(meta.mtime(), meta.mtime_nano()));
        proto.set_btime_nanos(nanos(meta.crtime(), meta.crtime_nano()));
        proto.set_ctime_nanos(nanos(meta.ctime(), meta.ctime_nano()));
        proto.set_unix_mode(i64::from(meta.mode()));
        proto.set_unix_ino(meta.addr());
        proto.set_unix_uid(i64::from(meta.uid()));
        proto.set_unix_gid(i64::from(meta.gid()));
    }

    proto
}

#[cfg(test)]
mod tests {

    use std::io::{Read, Write};

    use tempfile::NamedTempFile;

    use super::*;

    const SMOL_NTFS_GZ: &[u8] = include_bytes!("../../../tsk/test_data/smol.ntfs.gz");

    fn load_gzipped_test_data(gzipped_ntfs_bytes: &[u8]) -> NamedTempFile {
        let mut gz = flate2::read::GzDecoder::new(gzipped_ntfs_bytes);
        let mut ntfs_raw = Vec::new();
        gz.read_to_end(&mut ntfs_raw)
            .expect("failed to read test data");
        let mut tempfile = NamedTempFile::new().expect("failed to open tempfile");
        tempfile
            .write_all(&ntfs_raw)
            .expect("failed to write tempfile");
        tempfile
    }

    #[test]
    fn handle_non_existent_path() {
        let tempdir = tempfile::tempdir().unwrap();

        let request = Args {
            raw_fs: Some(tempdir.path().join("ntfs")),
            root: tempdir.path().join("foo"),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, request).is_err());
    }

    #[test]
    fn handle_empty_dir() {
        let tempfile = load_gzipped_test_data(SMOL_NTFS_GZ);

        let request = Args {
            raw_fs: Some(tempfile.path().into()),
            root: "/emptydir".into(),
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, request).unwrap();

        let entries = entries(&session);
        // Includes . and ..
        assert_eq!(entries.len(), 2);
        assert_eq!(str_path(&entries[0]), "/emptydir/.");
        assert_eq!(str_path(&entries[1]), "/emptydir/..");
    }

    #[test]
    fn handle_dir_with_files() {
        let tempfile = load_gzipped_test_data(SMOL_NTFS_GZ);

        let request = Args {
            raw_fs: Some(tempfile.path().into()),
            root: "/dir/subdir".into(),
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, request).unwrap();

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.path().to_owned());

        assert_eq!(entries.len(), 3);
        assert_eq!(str_path(&entries[0]), "/dir/subdir/.");
        assert_eq!(str_path(&entries[1]), "/dir/subdir/..");
        assert_eq!(str_path(&entries[2]), "/dir/subdir/deepfile");
    }

    #[test]
    fn handle_dir_with_nested_dirs() {
        let tempfile = load_gzipped_test_data(SMOL_NTFS_GZ);

        let request = Args {
            raw_fs: Some(tempfile.path().into()),
            root: "/dir".into(),
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, request).unwrap();

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.path().to_owned());

        assert_eq!(entries.len(), 7);
        assert_eq!(str_path(&entries[0]), "/dir/.");
        assert_eq!(str_path(&entries[1]), "/dir/..");
        assert_eq!(str_path(&entries[2]), "/dir/foobar");
        assert_eq!(str_path(&entries[3]), "/dir/subdir");
        assert_eq!(str_path(&entries[4]), "/dir/subdir/.");
        assert_eq!(str_path(&entries[5]), "/dir/subdir/..");
        assert_eq!(str_path(&entries[6]), "/dir/subdir/deepfile");
    }

    #[test]
    fn handle_dir_with_circular_symlinks() {
        let tempfile = load_gzipped_test_data(SMOL_NTFS_GZ);

        let request = Args {
            raw_fs: Some(tempfile.path().into()),
            root: "/circular".into(),
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, request).unwrap();

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.path().to_owned());

        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].path(), b"/circular/.");
        assert_eq!(entries[1].path(), b"/circular/..");
        assert_eq!(entries[2].path(), b"/circular/one");
        assert_eq!(entries[3].path(), b"/circular/two");
    }

    #[test]
    fn handle_ucs2_encoding() {
        let tempfile = load_gzipped_test_data(SMOL_NTFS_GZ);

        let request = Args {
            raw_fs: Some(tempfile.path().into()),
            root: "/encoding".into(),
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, request).unwrap();

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.path().to_owned());

        assert_eq!(entries.len(), 6);
        assert_eq!(str_path(&entries[0]), "/encoding/.");
        assert_eq!(str_path(&entries[1]), "/encoding/..");

        // This filename is invalid UTF-16; it is encoded as (hex)
        // 45 00 56 00 59 00 4C 00 3E D8 20 00 20 00 20 00
        // The 3E D8 is an unmatched UTF-16 high surrogate.
        // TSK translates it into 0x5e, or '^'. ¯\_(ツ)_/¯
        assert_eq!(entries[2].path(), b"/encoding/EVIL^  ");
        assert_eq!(str_path(&entries[2]), "/encoding/EVIL^  ");

        assert_eq!(str_path(&entries[3]), "/encoding/zażółć gęślą jaźń");
        assert_eq!(str_path(&entries[4]), "/encoding/што й па мору");
        assert_eq!(str_path(&entries[5]), "/encoding/☃");
    }

    #[test]
    fn handle_file_metadata() {
        let tempfile = load_gzipped_test_data(SMOL_NTFS_GZ);

        let request = Args {
            raw_fs: Some(tempfile.path().into()),
            root: "/dir/subdir".into(),
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, request).unwrap();

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.path().to_owned());

        assert_eq!(entries.len(), 3);
        assert_eq!(str_path(&entries[0]), "/dir/subdir/.");
        assert_eq!(str_path(&entries[1]), "/dir/subdir/..");
        assert_eq!(str_path(&entries[2]), "/dir/subdir/deepfile");
        assert_eq!(entries[2].size(), 0);
        assert_eq!(entries[2].unix_ino(), 69);
    }

    #[test]
    fn handle_hardlink_metadata() {
        let tempfile = load_gzipped_test_data(SMOL_NTFS_GZ);

        let request = Args {
            raw_fs: Some(tempfile.path().into()),
            root: "/hardlinks".into(),
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, request).unwrap();

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.path().to_owned());

        assert_eq!(entries.len(), 4);
        assert_eq!(str_path(&entries[0]), "/hardlinks/.");
        assert_eq!(str_path(&entries[1]), "/hardlinks/..");
        assert_eq!(str_path(&entries[2]), "/hardlinks/one");
        assert_eq!(entries[2].unix_ino(), 88);
        assert_eq!(str_path(&entries[3]), "/hardlinks/two");
        assert_eq!(entries[3].unix_ino(), 88);
    }

    /// Retrieves timeline entries from the given session object.
    fn entries(
        session: &crate::session::FakeSession,
    ) -> Vec<rrg_proto::get_filesystem_timeline::Entry> {
        let blob_count = session.parcel_count(crate::Sink::Blob);
        let reply_count = session.reply_count();
        assert_eq!(blob_count, reply_count);

        let chunks = session
            .parcels::<crate::blob::Blob>(crate::Sink::Blob)
            .map(|blob| blob.as_bytes().to_vec());

        let entries = crate::gzchunked::decode(chunks)
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        let total_entry_count = session.replies::<Item>().map(|item| item.entry_count).sum::<usize>();

        assert_eq!(entries.len(), total_entry_count);

        entries
    }

    /// Returns the path of the entry as a string. Panics if it is invalid utf8.
    ///
    /// Intended for better test failure output.
    fn str_path(entry: &rrg_proto::get_filesystem_timeline::Entry) -> &str {
        std::str::from_utf8(entry.path()).unwrap()
    }

    #[test]
    fn get_mount_empty() {
        assert_eq!(
            get_mount(&[], "/asdf".as_ref()).err().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn get_mount_linux() {
        use std::os::unix::ffi::OsStrExt;

        let sysfs_mount = Mount {
            name: "sysfs".to_string(),
            path: "/sys".parse().unwrap(),
            fs_type: "sysfs".to_string(),
        };
        let root_mount = Mount {
            name: "/dev/mapper/root".to_string(),
            path: "/".parse().unwrap(),
            fs_type: "ext4".to_string(),
        };
        let home_mount = Mount {
            name: "/etc/auto.home.local".to_string(),
            path: "/home".parse().unwrap(),
            fs_type: "autofs".to_string(),
        };
        let boot_mount = Mount {
            name: "/dev/sda2".to_string(),
            path: "/boot".parse().unwrap(),
            fs_type: "ext2".to_string(),
        };
        let efi_mount = Mount {
            name: "/dev/sda1".to_string(),
            path: "/boot/efi".parse().unwrap(),
            fs_type: "vfat".to_string(),
        };

        let mounts = vec![
            sysfs_mount.clone(),
            home_mount.clone(),
            boot_mount.clone(),
            efi_mount.clone(),
            root_mount.clone(),
        ];
        assert_eq!(&get_mount(&mounts, "/".as_ref()).unwrap(), &root_mount);
        let root_path = "/foo/bar/baz".as_ref();
        assert_eq!(&get_mount(&mounts, root_path).unwrap(), &root_mount);
        let home_path = "/home/foo/bar/baz".as_ref();
        assert_eq!(&get_mount(&mounts, home_path).unwrap(), &home_mount);
        assert_eq!(&get_mount(&mounts, "/boot".as_ref()).unwrap(), &boot_mount);
        let boot_path = std::path::PathBuf::from(OsStr::from_bytes(b"/boot/efi\xff\xff\xff"));
        assert_eq!(&get_mount(&mounts, &boot_path).unwrap(), &boot_mount);
        let efi_path = "/boot/efi/EFI".as_ref();
        assert_eq!(&get_mount(&mounts, efi_path).unwrap(), &efi_mount);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn get_raw_device_linux() {
        use std::os::unix::ffi::OsStrExt;
        let root_mount = Mount {
            name: "/dev/mapper/root".to_string(),
            path: "/".parse().unwrap(),
            fs_type: "ext4".to_string(),
        };
        let boot_mount = Mount {
            name: "/dev/sda2".to_string(),
            path: "/boot".parse().unwrap(),
            fs_type: "ext2".to_string(),
        };
        let efi_mount = Mount {
            name: "/dev/sda1".to_string(),
            path: "/boot/efi".parse().unwrap(),
            fs_type: "vfat".to_string(),
        };
        let home_mount = Mount {
            name: "/etc/auto.home.local".to_string(),
            path: "/home".parse().unwrap(),
            fs_type: "autofs".to_string(),
        };
        let mounts = vec![root_mount, boot_mount, efi_mount, home_mount];
        assert!(
            get_raw_device(&mounts, "/home/foo/bar/baz".as_ref())
                .err()
                .unwrap()
                .kind()
                == std::io::ErrorKind::Other
        );
        let boot_path = std::path::PathBuf::from(OsStr::from_bytes(b"/boot/\xff\xff"));
        assert_eq!(
            get_raw_device(&mounts, &boot_path).unwrap(),
            RawDeviceMount {
                image_path: std::path::PathBuf::from("/dev/sda2"),
                mountpoint: std::path::PathBuf::from("/boot"),
            }
        );
        let root_path = "/".as_ref();
        assert_eq!(
            get_raw_device(&mounts, root_path).unwrap(),
            RawDeviceMount {
                image_path: std::path::PathBuf::from("/dev/mapper/root"),
                mountpoint: std::path::PathBuf::from("/"),
            }
        );
    }
}
