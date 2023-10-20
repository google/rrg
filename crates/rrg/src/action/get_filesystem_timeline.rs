// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the timeline action.

use std::path::PathBuf;

use rrg_proto::convert::FromLossy;

/// Arguments of the `get_filesystem_timeline` action.
pub struct Args {
    root: PathBuf,
}

/// Result of the `get_filesystem_timeline` action.
pub struct Item {
    /// SHA-256 digest of the timeline batch sent to the blob sink.
    blob_sha256: [u8; 32],
    // Number of entries in the batch sent to the blob sink.
    entry_count: usize,
}

/// Handles requests for the timeline action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use sha2::Digest as _;

    // `entry_count` keeps track of the number of entries that are included in
    // each batch. Each time the `entries` iterator (defined below) yields an
    // entry, we increase the count (through `Iterator::inspect`). We read the
    // of `entry_count` when we are about to send a batch and reset the counter
    // so that we start from 0 for the next batch.
    //
    // Note that `entry_count` has to be a cell because it is mutably borrowed
    // by the `entries` iterator but we still want to be able to also modify it
    // when we process batches.
    let entry_count = std::cell::Cell::new(0);

    let entries = crate::fs::walk_dir(&args.root)
        .map_err(crate::session::Error::action)?
        .filter_map(|entry| match entry {
            Ok(entry) => Some(entry),
            Err(error) => {
                log::warn!("failed to obtain directory entry: {}", error);
                None
            }
        })
        .inspect(|_| {
            entry_count.set(entry_count.get() + 1);
        })
        .map(rrg_proto::get_filesystem_timeline::Entry::from_lossy);

    for batch in crate::gzchunked::encode(entries) {
        let batch = batch
            .map_err(crate::session::Error::action)?;

        let blob = crate::blob::Blob::from(batch);
        let blob_sha256 = sha2::Sha256::digest(blob.as_bytes()).into();

        session.send(crate::Sink::Blob, blob)?;
        session.reply(Item {
            blob_sha256,
            entry_count: entry_count.get(),
        })?;

        entry_count.set(0);
    }

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_filesystem_timeline::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let root = PathBuf::try_from(proto.take_root())
            .map_err(|error| ParseArgsError::invalid_field("root", error))?;

        Ok(Args {
            root: root,
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_filesystem_timeline::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = Self::Proto::default();
        proto.set_blob_sha256(self.blob_sha256.into());
        proto.set_entry_count(self.entry_count as u64);

        proto
    }
}

impl FromLossy<crate::fs::Entry> for rrg_proto::get_filesystem_timeline::Entry {

    fn from_lossy(entry: crate::fs::Entry) -> Self {
        let mut proto = Self::default();
        proto.set_path(rrg_proto::path::into_bytes(entry.path));
        proto.set_size(entry.metadata.len());

        fn nanos(time: std::time::SystemTime) -> Option<i64> {
            i64::try_from(rrg_proto::nanos(time).ok()?).ok()
        }

        let atime_nanos = entry.metadata.accessed().ok().and_then(nanos);
        if let Some(atime_nanos) = atime_nanos {
            proto.set_atime_nanos(atime_nanos);
        }

        let mtime_nanos = entry.metadata.modified().ok().and_then(nanos);
        if let Some(mtime_nanos) = mtime_nanos {
            proto.set_mtime_nanos(mtime_nanos);
        }

        let btime_nanos = entry.metadata.created().ok().and_then(nanos);
        if let Some(btime_nanos) = btime_nanos {
            proto.set_btime_nanos(btime_nanos);
        }

        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::MetadataExt as _;

            proto.set_unix_mode(i64::from(entry.metadata.mode()));
            proto.set_unix_ino(entry.metadata.ino());
            if let Some(dev) = i64::try_from(entry.metadata.dev()).ok() {
                proto.set_unix_dev(dev);
            }
            if let Some(uid) = i64::try_from(entry.metadata.uid()).ok() {
                proto.set_unix_uid(uid);
            }
            if let Some(gid) = i64::try_from(entry.metadata.gid()).ok() {
                proto.set_unix_gid(gid);
            }
            proto.set_ctime_nanos(entry.metadata.ctime_nsec());
        }

        #[cfg(target_family = "windows")]
        {
            use std::os::windows::fs::MetadataExt as _;

            let attributes = entry.metadata.file_attributes();
            proto.set_windows_attributes(u64::from(attributes));
        }

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn handle_non_existent_path() {
        let tempdir = tempfile::tempdir().unwrap();

        let request = Args {
            root: tempdir.path().join("foo")
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, request).is_err());
    }

    #[test]
    fn handle_empty_dir() {
        let tempdir = tempfile::tempdir().unwrap();
        let tempdir_path = tempdir.path().to_path_buf();

        let request = Args {
            root: tempdir_path.clone(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        let entries = entries(&session);
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn handle_dir_with_files() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::File::create(tempdir.path().join("a")).unwrap();
        std::fs::File::create(tempdir.path().join("b")).unwrap();
        std::fs::File::create(tempdir.path().join("c")).unwrap();

        let request = Args {
            root: tempdir.path().to_path_buf(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.get_path().to_owned());

        assert_eq!(entries.len(), 3);
        assert_eq!(path(&entries[0]), Some(tempdir.path().join("a")));
        assert_eq!(path(&entries[1]), Some(tempdir.path().join("b")));
        assert_eq!(path(&entries[2]), Some(tempdir.path().join("c")));
    }

    #[test]
    fn handle_dir_with_nested_dirs() {
        let tempdir = tempfile::tempdir().unwrap();
        let tempdir_path = tempdir.path().to_path_buf();

        std::fs::create_dir_all(tempdir_path.join("a").join("b")).unwrap();

        let request = Args {
            root: tempdir_path.clone(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.get_path().to_owned());

        assert_eq!(entries.len(), 2);
        assert_eq!(path(&entries[0]), Some(tempdir_path.join("a")));
        assert_eq!(path(&entries[1]), Some(tempdir_path.join("a").join("b")));
    }

    // Symlinking is supported only on Unix-like systems.
    #[cfg(target_family = "unix")]
    #[test]
    fn handle_dir_with_circular_symlinks() {
        let tempdir = tempfile::tempdir().unwrap();

        let root_path = tempdir.path().to_path_buf();
        let dir_path = root_path.join("dir");
        let symlink_path = dir_path.join("symlink");

        std::fs::create_dir(&dir_path).unwrap();
        std::os::unix::fs::symlink(&dir_path, &symlink_path).unwrap();

        let request = Args {
            root: root_path.clone(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.get_path().to_owned());

        assert_eq!(entries.len(), 2);
        assert_eq!(path(&entries[0]), Some(dir_path));
        assert_eq!(path(&entries[1]), Some(symlink_path));
    }

    #[test]
    fn handle_dir_with_unicode_files() {
        let tempdir = tempfile::tempdir().unwrap();

        let root_path = tempdir.path().to_path_buf();
        let file_path_1 = root_path.join("zażółć gęślą jaźń");
        let file_path_2 = root_path.join("што й па мору");

        std::fs::File::create(&file_path_1).unwrap();
        std::fs::File::create(&file_path_2).unwrap();

        let request = Args {
            root: root_path.clone(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.get_path().to_owned());

        assert_eq!(entries.len(), 2);

        // macOS mangles Unicode-specific characters in filenames.
        #[cfg(not(target_os = "macos"))]
        {
            assert_eq!(path(&entries[0]), Some(file_path_1));
            assert_eq!(path(&entries[1]), Some(file_path_2));
        }
    }

    #[test]
    fn handle_file_metadata() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::write(tempdir.path().join("foo"), b"123456789").unwrap();

        let request = Args {
            root: tempdir.path().to_path_buf(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.get_path().to_owned());

        assert_eq!(entries.len(), 1);
        assert_eq!(path(&entries[0]), Some(tempdir.path().join("foo")));
        assert_eq!(entries[0].get_size(), 9);

        // Information about the file mode, user and group identifiers is
        // available only on UNIX systems.
        #[cfg(target_family = "unix")]
        {
            let mode = entries[0].get_unix_mode() as libc::mode_t;
            assert_eq!(mode & libc::S_IFMT, libc::S_IFREG);

            let uid = unsafe { libc::getuid() };
            assert_eq!(entries[0].get_unix_uid(), uid.into());

            let gid = unsafe { libc::getgid() };
            assert_eq!(entries[0].get_unix_gid(), gid.into());
        }
    }

    #[test]
    fn handle_hardlink_metadata() {
        let tempdir = tempfile::tempdir().unwrap();

        let root_path = tempdir.path().to_path_buf();
        let file_path = root_path.join("file");
        let hardlink_path = root_path.join("hardlink");

        std::fs::File::create(&file_path).unwrap();
        std::fs::hard_link(&file_path, &hardlink_path).unwrap();

        let request = Args {
            root: root_path.clone(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.get_path().to_owned());

        assert_eq!(entries.len(), 2);
        assert_eq!(path(&entries[0]), Some(file_path));
        assert_eq!(path(&entries[1]), Some(hardlink_path));

        // Information about inode is not available on Windows.
        #[cfg(not(target_os = "windows"))]
        assert_eq!(entries[0].get_unix_ino(), entries[1].get_unix_ino());
    }

    #[test]
    // Attributes are supported only on Windows.
    #[cfg(target_family = "windows")]
    fn handle_file_attributes() {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Win32::Storage::FileSystem::*;

        let temp_dir = tempfile::tempdir().unwrap();

        let temp_path = temp_dir.path().join("foo");
        std::fs::write(&temp_path, b"").unwrap();

        // We want to use Windows API to set file attributes. But for this we
        // first need to convert Rust type to something more digestible by the
        // Windows API.
        let mut temp_path_wstr = temp_path.as_path().as_os_str()
            .encode_wide()
            .collect::<Vec<_>>();
        temp_path_wstr.push(0);

        // SAFETY: We encoded the path with 16-bit encoding and null-terminated
        // it. We verify that the status is non-zero afterwards.
        let status = unsafe {
            SetFileAttributesW(temp_path_wstr.as_ptr(), FILE_ATTRIBUTE_HIDDEN)
        };
        assert!(status > 0);

        let request = Args {
            root: temp_dir.path().to_path_buf(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, request).is_ok());

        let entries = entries(&session);
        assert_eq!(entries.len(), 1);
        assert_eq!(path(&entries[0]), Some(temp_path));

        let attributes = entries[0].get_windows_attributes() as u32;
        assert_eq!(attributes & FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_HIDDEN);
    }

    /// Retrieves timeline entries from the given session object.
    fn entries(
        session: &crate::session::FakeSession,
    ) -> Vec<rrg_proto::get_filesystem_timeline::Entry> {
        let blob_count = session.parcel_count(crate::Sink::Blob);
        let reply_count = session.reply_count();
        assert_eq!(blob_count, reply_count);

        let chunks = session.parcels::<crate::blob::Blob>(crate::Sink::Blob)
            .map(crate::blob::Blob::as_bytes);

        let entries = crate::gzchunked::decode(chunks)
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        let total_entry_count = session.replies::<Item>()
            .map(|item| item.entry_count)
            .sum();

        assert_eq!(entries.len(), total_entry_count);

        entries
    }

    /// Constructs a path for the given timeline entry.
    fn path(
        entry: &rrg_proto::get_filesystem_timeline::Entry,
    ) -> Option<PathBuf> {
        rrg_proto::path::from_bytes(entry.get_path().to_owned()).ok()
    }
}
