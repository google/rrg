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
    use std::fs::{hard_link, create_dir, write};
    use tempfile::tempdir;

    use session::test::Fake as Session;

    #[test]
    fn test_nonexistent_path() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path().join("nonexistent_subdir");

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, Request { root: dir_path }).is_err());
    }

    #[test]
    fn test_one_empty_dir() {
        let dir = tempdir().unwrap();

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, Request { root: PathBuf::from(dir.path()) }).is_ok());

        let mut entries = entries(&session);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, Some(rrg_proto::path::to_bytes(dir.path().to_path_buf())));
    }

    #[cfg_attr(target_family = "windows", ignore)]
    #[test]
    fn test_file_hardlink() {
        let dir = tempdir().unwrap();

        let test1_path = dir.path().join("test1.txt");
        write(&test1_path, "foo").unwrap();

        let test2_path = dir.path().join("test2.txt");
        hard_link(&test1_path, &test2_path).unwrap();

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, Request { root: PathBuf::from(dir.path()) }).is_ok());

        let mut entries = entries(&session);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(entries.len(), 3);
        assert_ne!(entries[0].ino, entries[1].ino);
        assert_eq!(entries[1].ino, entries[2].ino);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_file_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();

        let test1_path = dir.path().join("test1.txt");
        write(&test1_path, "foo").unwrap();

        let test2_path = dir.path().join("test2.txt");
        symlink(&test1_path, &test2_path).unwrap();

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, Request { root: PathBuf::from(dir.path()) }).is_ok());

        let mut entries = entries(&session);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(entries.len(), 3);
        assert_ne!(entries[0].ino.unwrap(), entries[1].ino.unwrap());
        assert_ne!(entries[1].ino.unwrap(), entries[2].ino.unwrap());
        assert_eq!(entries[1].size, Some(3));
        // Drop mode bits because symlinks have actual modes on some unix systems.
        assert_eq!(entries[2].mode.unwrap() & 0o120000, 0o120000);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_symlink_loops() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();

        let test1_path = dir.path().join("test1");
        let test2_path = dir.path().join("test2");
        let test3_path = dir.path().join("test3");
        let test4_path = test3_path.join("test4");
        symlink(&test2_path, &test1_path).unwrap();
        symlink(&test1_path, &test2_path).unwrap();
        create_dir(&test3_path).unwrap();
        symlink("../test3", &test4_path).unwrap();

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, Request { root: PathBuf::from(dir.path()) }).is_ok());

        let mut entries = entries(&session);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[1].path, Some(rrg_proto::path::to_bytes(test1_path)));
        assert_eq!(entries[2].path, Some(rrg_proto::path::to_bytes(test2_path)));
        assert_eq!(entries[3].path, Some(rrg_proto::path::to_bytes(test3_path)));
        assert_eq!(entries[4].path, Some(rrg_proto::path::to_bytes(test4_path)));
    }

    #[test]
    fn test_weird_unicode_names() {
        let dir = tempdir().unwrap();

        let path1 = dir.path().join("1with spaces");
        write(&path1, "foo").unwrap();

        let path2 = dir.path().join("2'quotes'");
        write(&path2, "foo").unwrap();

        let path3 = dir.path().join("3кириллица");
        write(&path3, "foo").unwrap();

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, Request { root: PathBuf::from(dir.path()) }).is_ok());

        let mut entries = entries(&session);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[1].path, Some(rrg_proto::path::to_bytes(path1)));
        assert_eq!(entries[2].path, Some(rrg_proto::path::to_bytes(path2)));
        assert_eq!(entries[3].path, Some(rrg_proto::path::to_bytes(path3)));
    }

    // TODO: Debug this test on MacOS.
    #[cfg_attr(target_os = "macos", ignore)]
    #[test]
    fn test_deep_dirs() {
        const MAX_DIR_COUNT: usize = 512;
        let mut dir_count = 0;

        let dir = tempdir().unwrap();

        let mut path = PathBuf::from(dir.path());
        while dir_count < MAX_DIR_COUNT {
            path.push("d");
            if let Err(_) = create_dir(&path) {
                break;
            }
            dir_count += 1;
        }
        // Let's suppose we can create at least this much.
        assert!(dir_count >= 64);

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, Request { root: PathBuf::from(dir.path()) }).is_ok());

        let entries = entries(&session);
        assert_eq!(entries.len(), dir_count + 1);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_mode_and_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::fs::{set_permissions, Permissions};

        let dir = tempdir().unwrap();

        let unavailable_dir_path = dir.path().join("unavailable");
        let unavailable_file_path = unavailable_dir_path.join("file");
        let readonly_path = dir.path().join("readonly.txt");
        let symlink_path = dir.path().join("writeonly.txt");
        create_dir(&unavailable_dir_path).unwrap();
        write(&unavailable_file_path, "foo").unwrap();
        write(&readonly_path, "foo").unwrap();
        symlink(&readonly_path, &symlink_path).unwrap();

        set_permissions(&unavailable_dir_path, Permissions::from_mode(0o000)).unwrap();
        set_permissions(&readonly_path, Permissions::from_mode(0o444)).unwrap();

        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, Request { root: PathBuf::from(dir.path()) }).is_ok());

        let mut entries = entries(&session);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[2].mode, Some(0o040000));
        assert_eq!(entries[1].mode, Some(0o100444));
        // Drop mode bits because symlinks have actual modes on some unix systems.
        assert_eq!(entries[3].mode.unwrap() & 0o120000, 0o120000);
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
}
