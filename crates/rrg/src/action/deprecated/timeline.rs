// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the timeline action.

use std::path::PathBuf;
use std::result::Result;
use std::vec::Vec;

use sha2::{Digest, Sha256};
use rrg_macro::ack;
use rrg_proto::convert::FromLossy;

use crate::session::{self, Session};

/// A request type for the timeline action.
pub struct Request {
    pub root: PathBuf,
}

/// A response type for the timeline action.
pub struct Response {
    pub chunk_ids: Vec<ChunkId>,
}

/// An error type for failures that can occur during the timeline action.
#[derive(Debug)]
enum Error {
    /// A failure occurred during an attempt to start the recursive walk.
    WalkDir(std::io::Error),
    /// A failure occurred during encoding of the timeline entries.
    Encode(std::io::Error),
}

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            WalkDir(ref error) => Some(error),
            Encode(ref error) => Some(error),
        }
    }
}

impl std::fmt::Display for Error {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use Error::*;

        match *self {
            WalkDir(ref error) => {
                write!(fmt, "failed to start the recursive walk: {}", error)
            },
            Encode(ref error) => {
                write!(fmt, "failed to encode timeline entries: {}", error)
            },
        }
    }
}

impl From<Error> for session::Error {

    fn from(error: Error) -> session::Error {
        session::Error::action(error)
    }
}

/// A type representing unique identifier of a given chunk.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChunkId {
    /// A SHA-256 digest of the referenced chunk data.
    pub sha256: [u8; 32],
}

impl ChunkId {

    /// Creates a chunk identifier for the given chunk.
    fn of(chunk: &Chunk) -> ChunkId {
        ChunkId {
            sha256: Sha256::digest(&chunk.data).into(),
        }
    }

    /// Converts the chunk identifier into raw bytes of SHA-256 hash.
    fn to_sha256_bytes(self) -> Vec<u8> {
        self.sha256.to_vec()
    }
}

/// A type representing a particular chunk of the returned timeline.
pub struct Chunk {
    pub data: Vec<u8>,
}

impl Chunk {

    /// Constructs a chunk from the given blob of bytes.
    fn from_bytes(data: Vec<u8>) -> Chunk {
        Chunk {
            data: data,
        }
    }

    /// Returns an identifier of the chunk.
    fn id(&self) -> ChunkId {
        ChunkId::of(&self)
    }
}

impl FromLossy<crate::fs::Entry> for rrg_proto::timeline::TimelineEntry {

    fn from_lossy(entry: crate::fs::Entry) -> rrg_proto::timeline::TimelineEntry {
        let mut proto = rrg_proto::timeline::TimelineEntry::new();
        proto.set_path(rrg_proto::path::into_bytes(entry.path));
        proto.set_size(entry.metadata.len());

        let atime_nanos = entry.metadata.accessed().ok().and_then(|atime| ack! {
            rrg_proto::nanos(atime),
            error: "failed to convert access time to seconds"
        }).and_then(|nanos| i64::try_from(nanos).ok());
        if let Some(atime_nanos) = atime_nanos {
            proto.set_atime_ns(atime_nanos);
        }

        let mtime_nanos = entry.metadata.modified().ok().and_then(|mtime| ack! {
            rrg_proto::nanos(mtime),
            error: "failed to convert modification time to seconds"
        }).and_then(|nanos| i64::try_from(nanos).ok());
        if let Some(mtime_nanos) = mtime_nanos {
            proto.set_mtime_ns(mtime_nanos);
        }

        let btime_nanos = entry.metadata.created().ok().and_then(|btime| ack! {
            rrg_proto::nanos(btime),
            error: "failed to convert creation time to seconds"
        }).and_then(|nanos| i64::try_from(nanos).ok());
        if let Some(btime_nanos) = btime_nanos {
            proto.set_btime_ns(btime_nanos);
        }

        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::MetadataExt as _;

            proto.set_mode(i64::from(entry.metadata.mode()));
            proto.set_ino(entry.metadata.ino());
            if let Some(dev) = i64::try_from(entry.metadata.dev()).ok() {
                proto.set_dev(dev);
            }
            if let Some(uid) = i64::try_from(entry.metadata.uid()).ok() {
                proto.set_uid(uid);
            }
            if let Some(gid) = i64::try_from(entry.metadata.gid()).ok() {
                proto.set_gid(gid);
            }
            proto.set_ctime_ns(entry.metadata.ctime_nsec());
        }

        // TODO: Export file attributes on Windows.
        proto
    }
}

/// Handles requests for the timeline action.
pub fn handle<S>(session: &mut S, request: Request) -> session::Result<()>
where
    S: Session,
{
    let entries = crate::fs::walk_dir(&request.root).map_err(Error::WalkDir)?
        .filter_map(|entry| match entry {
            Ok(entry) => Some(entry),
            Err(error) => {
                log::warn!("failed to obtain directory entry: {}", error);
                None
            }
        })
        .map(rrg_proto::timeline::TimelineEntry::from_lossy);

    let mut response = Response {
        chunk_ids: vec!(),
    };

    for part in crate::gzchunked::encode(entries) {
        let part = part.map_err(Error::Encode)?;

        let chunk = Chunk::from_bytes(part);
        let chunk_id = chunk.id();

        session.send(crate::Sink::Blob, chunk)?;
        response.chunk_ids.push(chunk_id);
    }

    session.reply(response)?;

    Ok(())
}

impl crate::request::Args for Request {

    type Proto = rrg_proto::timeline::TimelineArgs;

    fn from_proto(mut proto: Self::Proto) -> Result<Request, crate::request::ParseArgsError> {
        let root = rrg_proto::path::from_bytes(proto.take_root())
            .map_err(|error| {
                crate::request::ParseArgsError::invalid_field("root", error)
            })?;

        Ok(Request {
            root: root,
        })
    }
}

impl crate::response::Item for Response {

    type Proto = rrg_proto::timeline::TimelineResult;

    fn into_proto(self) -> rrg_proto::timeline::TimelineResult {
        let chunk_ids = self.chunk_ids
            .into_iter()
            .map(ChunkId::to_sha256_bytes)
            .collect();

        let mut proto = rrg_proto::timeline::TimelineResult::new();
        proto.set_entry_batch_blob_ids(chunk_ids);

        proto
    }
}

impl crate::response::Item for Chunk {

    type Proto = rrg_proto::jobs::DataBlob;

    fn into_proto(self) -> rrg_proto::jobs::DataBlob {
        self.data.into()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use session::FakeSession as Session;

    #[test]
    fn test_non_existent_path() {
        let tempdir = tempfile::tempdir().unwrap();

        let request = Request {
            root: tempdir.path().join("foo")
        };

        let mut session = Session::new();
        assert!(handle(&mut session, request).is_err());
    }

    #[test]
    fn test_empty_dir() {
        let tempdir = tempfile::tempdir().unwrap();
        let tempdir_path = tempdir.path().to_path_buf();

        let request = Request {
            root: tempdir_path.clone(),
        };

        let mut session = Session::new();
        assert!(handle(&mut session, request).is_ok());

        let entries = entries(&session);
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_dir_with_files() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::File::create(tempdir.path().join("a")).unwrap();
        std::fs::File::create(tempdir.path().join("b")).unwrap();
        std::fs::File::create(tempdir.path().join("c")).unwrap();

        let request = Request {
            root: tempdir.path().to_path_buf(),
        };

        let mut session = Session::new();
        assert!(handle(&mut session, request).is_ok());

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.get_path().to_owned());

        assert_eq!(entries.len(), 3);
        assert_eq!(path(&entries[0]), Some(tempdir.path().join("a")));
        assert_eq!(path(&entries[1]), Some(tempdir.path().join("b")));
        assert_eq!(path(&entries[2]), Some(tempdir.path().join("c")));
    }

    #[test]
    fn test_dir_with_nested_dirs() {
        let tempdir = tempfile::tempdir().unwrap();
        let tempdir_path = tempdir.path().to_path_buf();

        std::fs::create_dir_all(tempdir_path.join("a").join("b")).unwrap();

        let request = Request {
            root: tempdir_path.clone(),
        };

        let mut session = Session::new();
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
    fn test_dir_with_circular_symlinks() {
        let tempdir = tempfile::tempdir().unwrap();

        let root_path = tempdir.path().to_path_buf();
        let dir_path = root_path.join("dir");
        let symlink_path = dir_path.join("symlink");

        std::fs::create_dir(&dir_path).unwrap();
        std::os::unix::fs::symlink(&dir_path, &symlink_path).unwrap();

        let request = Request {
            root: root_path.clone(),
        };

        let mut session = Session::new();
        assert!(handle(&mut session, request).is_ok());

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.get_path().to_owned());

        assert_eq!(entries.len(), 2);
        assert_eq!(path(&entries[0]), Some(dir_path));
        assert_eq!(path(&entries[1]), Some(symlink_path));
    }

    #[test]
    fn test_dir_with_unicode_files() {
        let tempdir = tempfile::tempdir().unwrap();

        let root_path = tempdir.path().to_path_buf();
        let file_path_1 = root_path.join("zażółć gęślą jaźń");
        let file_path_2 = root_path.join("што й па мору");

        std::fs::File::create(&file_path_1).unwrap();
        std::fs::File::create(&file_path_2).unwrap();

        let request = Request {
            root: root_path.clone(),
        };

        let mut session = Session::new();
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
    fn test_file_metadata() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::write(tempdir.path().join("foo"), b"123456789").unwrap();

        let request = Request {
            root: tempdir.path().to_path_buf(),
        };

        let mut session = Session::new();
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
            let mode = entries[0].get_mode() as libc::mode_t;
            assert_eq!(mode & libc::S_IFMT, libc::S_IFREG);

            let uid = unsafe { libc::getuid() };
            assert_eq!(entries[0].get_uid(), uid.into());

            let gid = unsafe { libc::getgid() };
            assert_eq!(entries[0].get_gid(), gid.into());
        }
    }

    #[test]
    fn test_hardlink_metadata() {
        let tempdir = tempfile::tempdir().unwrap();

        let root_path = tempdir.path().to_path_buf();
        let file_path = root_path.join("file");
        let hardlink_path = root_path.join("hardlink");

        std::fs::File::create(&file_path).unwrap();
        std::fs::hard_link(&file_path, &hardlink_path).unwrap();

        let request = Request {
            root: root_path.clone(),
        };

        let mut session = Session::new();
        assert!(handle(&mut session, request).is_ok());

        let mut entries = entries(&session);
        entries.sort_by_key(|entry| entry.get_path().to_owned());

        assert_eq!(entries.len(), 2);
        assert_eq!(path(&entries[0]), Some(file_path));
        assert_eq!(path(&entries[1]), Some(hardlink_path));

        // Information about inode is not available on Windows.
        #[cfg(not(target_os = "windows"))]
        assert_eq!(entries[0].get_ino(), entries[1].get_ino());
    }

    /// Retrieves timeline entries from the given session object.
    fn entries(session: &Session) -> Vec<rrg_proto::timeline::TimelineEntry> {
        use std::collections::HashMap;

        let chunk_count = session.parcel_count(crate::Sink::Blob);
        assert_eq!(session.reply_count(), 1);
        assert_eq!(session.reply::<Response>(0).chunk_ids.len(), chunk_count);

        let chunks_by_id = session.parcels::<Chunk>(crate::Sink::Blob)
            .map(|chunk| (chunk.id(), chunk))
            .collect::<HashMap<_, _>>();

        let chunks = session.reply::<Response>(0).chunk_ids
            .iter()
            .map(|chunk_id| &chunks_by_id[chunk_id].data[..]);

        crate::gzchunked::decode(chunks)
            .map(Result::unwrap)
            .collect()
    }

    /// Constructs a path for the given timeline entry.
    fn path(entry: &rrg_proto::timeline::TimelineEntry) -> Option<PathBuf> {
        rrg_proto::path::from_bytes(entry.get_path().to_owned()).ok()
    }
}
