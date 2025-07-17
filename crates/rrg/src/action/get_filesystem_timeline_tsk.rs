// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the timeline action.

use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

use ospect::fs::RawDeviceMount;

use crate::session::Error;

/// Arguments of the `get_filesystem_timeline` action.
pub struct Args {
    raw_fs: PathBuf,
    root: PathBuf,
}

/// Result of the `get_filesystem_timeline` action.
pub struct Item {
    /// SHA-256 digest of the timeline batch sent to the blob sink.
    blob_sha256: [u8; 32],
    // Number of entries in the batch sent to the blob sink.
    entry_count: usize,
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
    use sha2::Digest as _;

    let raw_fs: PathBuf;
    let embedded_path;
    if !args.raw_fs.as_os_str().is_empty() {
        raw_fs = args.raw_fs;
        embedded_path = args.root;
    } else {
        // Detect raw filesystem
        let mounts = ospect::fs::mounts()
            .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
            .map_err(crate::session::Error::action)?;
        let mount = ospect::fs::get_raw_device(&mounts, &args.root)
            .map_err(crate::session::Error::action)?;
        embedded_path = get_embedded_path(&mount, &args.root);
        // The raw fs path may be e.g. /dev/sda1 on Linux or \\?\C: on Windows.
        raw_fs = mount.image_path;
    };

    let (tx, rx) = std::sync::mpsc::sync_channel(0);
    let tsk_thread = std::thread::spawn(move || -> tsk::TskResult<()> {
        let image = tsk::TskImage::open(&raw_fs)?;
        let mut fs = image.open_fs()?;
        let dir = fs.open_dir(&embedded_path)?;
        let root_bytes = embedded_path.as_os_str().as_encoded_bytes();
        fs.walk_dir(dir.addr(), |file, path| {
            match tx.send(serialize_entry(root_bytes, path, file)) {
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
        .expect("TSK file walker thread panicked")
        .map_err(Error::action)?;
    // Check this after the thread joined.
    encode_and_send_result?;

    Ok(())
}

impl crate::request::Args for Args {
    type Proto = rrg_proto::get_filesystem_timeline_tsk::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let raw_fs = PathBuf::try_from(proto.take_raw_fs())
            .map_err(|error| ParseArgsError::invalid_field("raw_fs", error))?;
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

fn serialize_entry(
    // Absolute path to the start of the search.
    root: &[u8],
    // Relative path to the parent directory from the root.
    parent_path: &[u8],
    // Base name of the file.
    file: tsk::TskFsFile,
) -> rrg_proto::get_filesystem_timeline::Entry {
    let mut proto = rrg_proto::get_filesystem_timeline::Entry::default();
    if let Some(name) = file.get_name() {
        let mut path = Vec::from(root);
        path.push(b'/');
        path.extend_from_slice(parent_path);
        path.append(&mut name.into_bytes());
        proto.set_path(path);
    }

    fn nanos(seconds: i64, nanos: u32) -> i64 {
        seconds * 1_000_000_000 + nanos as i64
    }

    if let Some(meta) = file.get_meta() {
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
            .expect("Failed to read test data");
        let mut tempfile = NamedTempFile::new().expect("Failed to open tempfile");
        tempfile
            .write_all(&ntfs_raw)
            .expect("Failed to write tempfile");
        tempfile
    }

    #[test]
    fn handle_non_existent_path() {
        let tempdir = tempfile::tempdir().unwrap();

        let request = Args {
            raw_fs: tempdir.path().join("ntfs"),
            root: tempdir.path().join("foo"),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, request).is_err());
    }

    #[test]
    fn handle_empty_dir() {
        let tempfile = load_gzipped_test_data(SMOL_NTFS_GZ);

        let request = Args {
            raw_fs: tempfile.path().into(),
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
            raw_fs: tempfile.path().into(),
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
            raw_fs: tempfile.path().into(),
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
            raw_fs: tempfile.path().into(),
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
            raw_fs: tempfile.path().into(),
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
            raw_fs: tempfile.path().into(),
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
            raw_fs: tempfile.path().into(),
            root: "/hardlinks".into(),
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, request).unwrap();

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.path().to_owned());

        assert_eq!(entries.len(), 5);
        assert_eq!(str_path(&entries[0]), "/hardlinks/.");
        assert_eq!(str_path(&entries[1]), "/hardlinks/..");
        // Note: /hardlinks/bar is a deleted file.
        assert_eq!(str_path(&entries[2]), "/hardlinks/bar");
        assert_eq!(str_path(&entries[3]), "/hardlinks/one");
        assert_eq!(entries[3].unix_ino(), 88);
        assert_eq!(str_path(&entries[4]), "/hardlinks/two");
        assert_eq!(entries[4].unix_ino(), 88);
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

        let total_entry_count = session.replies::<Item>().map(|item| item.entry_count).sum();

        assert_eq!(entries.len(), total_entry_count);

        entries
    }

    /// Returns the path of the entry as a string. Panics if it is invalid utf8.
    ///
    /// Intended for better test failure output.
    fn str_path(entry: &rrg_proto::get_filesystem_timeline::Entry) -> &str {
        std::str::from_utf8(entry.path()).unwrap()
    }
}
