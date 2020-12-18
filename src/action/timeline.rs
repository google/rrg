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
    root: PathBuf,
}

/// A response type for the timeline action.
struct Response {
    chunk_ids: Vec<ChunkId>,
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
struct ChunkId {
    /// A SHA-256 digest of the referenced chunk data.
    sha256: [u8; 32],
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
struct Chunk {
    data: Vec<u8>,
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

impl FromLossy<crate::fs::Entry> for rrg_proto::TimelineEntry {

    fn from_lossy(entry: crate::fs::Entry) -> rrg_proto::TimelineEntry {
        use std::convert::TryFrom as _;
        #[cfg(target_family = "unix")]
        use std::os::unix::fs::MetadataExt as _;

        let atime_nanos = entry.metadata.accessed().ok().and_then(|atime| ack! {
            rrg_proto::nanos(atime),
            error: "failed to convert access time to seconds"
        });

        let mtime_nanos = entry.metadata.modified().ok().and_then(|mtime| ack! {
            rrg_proto::nanos(mtime),
            error: "failed to convert modification time to seconds"
        });

        let btime_nanos = entry.metadata.created().ok().and_then(|btime| ack! {
            rrg_proto::nanos(btime),
            error: "failed to convert creation time to seconds"
        });

        rrg_proto::TimelineEntry {
            path: Some(rrg_proto::path::to_bytes(entry.path)),
            #[cfg(target_family = "unix")]
            mode: Some(i64::from(entry.metadata.mode())),
            size: Some(entry.metadata.len()),
            #[cfg(target_family = "unix")]
            dev: i64::try_from(entry.metadata.dev()).ok(),
            #[cfg(target_family = "unix")]
            ino: Some(entry.metadata.ino()),
            #[cfg(target_family = "unix")]
            uid: i64::try_from(entry.metadata.uid()).ok(),
            #[cfg(target_family = "unix")]
            gid: i64::try_from(entry.metadata.gid()).ok(),
            atime_ns: atime_nanos.and_then(|nanos| i64::try_from(nanos).ok()),
            mtime_ns: mtime_nanos.and_then(|nanos| i64::try_from(nanos).ok()),
            #[cfg(target_family = "unix")]
            ctime_ns: Some(entry.metadata.ctime_nsec()),
            btime_ns: btime_nanos.and_then(|nanos| i64::try_from(nanos).ok()),
            // TODO: Export file attributes on Windows.
            ..rrg_proto::TimelineEntry::default()
        }
    }
}

/// Handles requests for the timeline action.
pub fn handle<S>(session: &mut S, request: Request) -> session::Result<()>
where
    S: Session,
{
    let entries = crate::fs::walk_dir(&request.root).map_err(Error::WalkDir)?
        .map(rrg_proto::TimelineEntry::from_lossy);

    let mut response = Response {
        chunk_ids: vec!(),
    };

    for part in crate::gzchunked::encode(entries) {
        let part = part.map_err(Error::Encode)?;

        let chunk = Chunk::from_bytes(part);
        let chunk_id = chunk.id();

        session.send(session::Sink::TRANSFER_STORE, chunk)?;
        response.chunk_ids.push(chunk_id);
    }

    session.reply(response)?;

    Ok(())
}

impl super::Request for Request {

    type Proto = rrg_proto::TimelineArgs;

    fn from_proto(proto: Self::Proto) -> Result<Request, session::ParseError> {
        let root_bytes = proto.root
            .ok_or(session::MissingFieldError::new("root"))?;

        Ok(Request {
            root: rrg_proto::path::from_bytes(root_bytes),
        })
    }
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("TimelineResult");

    type Proto = rrg_proto::TimelineResult;

    fn into_proto(self) -> rrg_proto::TimelineResult {
        let chunk_ids = self.chunk_ids
            .into_iter()
            .map(ChunkId::to_sha256_bytes)
            .collect();

        rrg_proto::TimelineResult {
            entry_batch_blob_ids: chunk_ids,
        }
    }
}

impl super::Response for Chunk {

    const RDF_NAME: Option<&'static str> = Some("DataBlob");

    type Proto = rrg_proto::DataBlob;

    fn into_proto(self) -> rrg_proto::DataBlob {
        self.data.into()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use session::test::Fake as Session;

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
        assert_eq!(entries.len(), 1);
        assert_eq!(path(&entries[0]), Some(tempdir_path.clone()));
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
        entries.sort_by_key(|entry| entry.path.clone());

        assert_eq!(entries.len(), 4);
        assert_eq!(path(&entries[0]), Some(tempdir.path().to_path_buf()));
        assert_eq!(path(&entries[1]), Some(tempdir.path().join("a")));
        assert_eq!(path(&entries[2]), Some(tempdir.path().join("b")));
        assert_eq!(path(&entries[3]), Some(tempdir.path().join("c")));
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
        entries.sort_by_key(|entry| entry.path.clone());

        assert_eq!(entries.len(), 3);
        assert_eq!(path(&entries[0]), Some(tempdir_path.clone()));
        assert_eq!(path(&entries[1]), Some(tempdir_path.join("a")));
        assert_eq!(path(&entries[2]), Some(tempdir_path.join("a").join("b")));
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
        entries.sort_by_key(|entry| entry.path.clone());

        assert_eq!(entries.len(), 3);
        assert_eq!(path(&entries[0]), Some(root_path));
        assert_eq!(path(&entries[1]), Some(dir_path));
        assert_eq!(path(&entries[2]), Some(symlink_path));
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
        entries.sort_by_key(|entry| entry.path.clone());

        assert_eq!(entries.len(), 3);

        // macOS mangles Unicode-specific characters in filenames.
        #[cfg(not(target_os = "macos"))]
        {
            assert_eq!(path(&entries[0]), Some(root_path));
            assert_eq!(path(&entries[1]), Some(file_path_1));
            assert_eq!(path(&entries[2]), Some(file_path_2));
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
        entries.sort_by_key(|entry| entry.path.clone());

        assert_eq!(entries.len(), 2);
        assert_eq!(path(&entries[1]), Some(tempdir.path().join("foo")));
        assert_eq!(entries[1].size, Some(9));

        // Information about the file mode, user and group identifiers is
        // available only on UNIX systems.
        #[cfg(target_family = "unix")]
        {
            let mode = entries[1].mode.unwrap() as libc::mode_t;
            assert_eq!(mode & libc::S_IFMT, libc::S_IFREG);

            assert_eq!(entries[1].uid, Some(users::get_current_uid() as i64));
            assert_eq!(entries[1].gid, Some(users::get_current_gid() as i64));
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
        entries.sort_by_key(|entry| entry.path.clone());

        assert_eq!(entries.len(), 3);
        assert_eq!(path(&entries[1]), Some(file_path));
        assert_eq!(path(&entries[2]), Some(hardlink_path));

        // Information about inode is not available on Windows.
        #[cfg(not(target_os = "windows"))]
        assert_eq!(entries[1].ino, entries[2].ino);
    }

    /// Retrieves timeline entries from the given session object.
    fn entries(session: &Session) -> Vec<rrg_proto::TimelineEntry> {
        use std::collections::HashMap;
        use crate::session::Sink;

        let chunk_count = session.response_count(Sink::TRANSFER_STORE);
        assert_eq!(session.reply_count(), 1);
        assert_eq!(session.reply::<Response>(0).chunk_ids.len(), chunk_count);

        let chunks_by_id = session.responses::<Chunk>(Sink::TRANSFER_STORE)
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
    fn path(entry: &rrg_proto::TimelineEntry) -> Option<PathBuf> {
        entry.path.clone().map(rrg_proto::path::from_bytes)
    }
}
