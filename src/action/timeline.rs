// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the timeline action.

use std::vec::Vec;
use std::ffi::OsString;
use std::result::Result;
use std::path::PathBuf;
use std::fs::{symlink_metadata, read_dir};
use std::os::unix::{fs::MetadataExt, ffi::OsStringExt};

use sha2::{Digest, Sha256};
use rrg_proto::{TimelineArgs, TimelineEntry, TimelineResult, DataBlob};

use crate::session::{self, Session, Error, ParseError, MissingFieldError};
use crate::gzchunked::{GzChunkedEncoder, GzChunkedCompression};


/// A request type for the timeline action.
pub struct Request {
    root: PathBuf,
}

/// A newtype wrapper for SHA-256 chunk digest.
#[derive(Debug, PartialEq, Clone)]
struct ChunkDigest([u8; 32]);

/// A response type for the timeline action (actual response).
struct Response {
    ids: Vec<ChunkDigest>,
}

/// A response type for the timeline action (transfer store chunks).
struct ChunkResponse {
    data: Vec<u8>,
}

/// An object for recursively traversing filesystem and gathering
/// timeline info.
struct RecurseState {
    device: u64,
    ids: Vec<ChunkDigest>,
    encoder: GzChunkedEncoder,
}

/// Encodes filesystem metadata into timeline entry proto.
fn entry_from_metadata<M>(metadata: &M, path: &PathBuf) -> TimelineEntry 
where
    M: MetadataExt,
{
    TimelineEntry {
        path: Some(path.clone().into_os_string().into_vec()),
        mode: Some(metadata.mode()),
        size: Some(metadata.size()),
        dev: Some(metadata.dev()),
        ino: Some(metadata.ino()),
        uid: Some(metadata.uid() as i64),
        gid: Some(metadata.gid() as i64),
        atime_ns: Some(metadata.atime_nsec() as u64),
        ctime_ns: Some(metadata.ctime_nsec() as u64),
        mtime_ns: Some(metadata.mtime_nsec() as u64),
    }
}

impl RecurseState {
    /// Constructs new state that would only traverse filesystems from `device`.
    fn new(device: u64) -> RecurseState {
        RecurseState {
            device,
            ids: Vec::new(),
            encoder: GzChunkedEncoder::new(GzChunkedCompression::default()),
        }
    }

    /// Sends block to transfer store and saves its digest.
    fn send_block<S>(&mut self, block: Vec<u8>, session: &mut S) -> session::Result<()>
    where
        S: Session,
    {
        let digest = ChunkDigest(Sha256::digest(block.as_slice()).into());
        self.ids.push(digest);
        session.send(session::Sink::TRANSFER_STORE, ChunkResponse { data: block })?;
        session.heartbeat();
        Ok(())
    }

    /// Encodes the entry and sends next block to the session if needed.
    fn process_entry<S>(&mut self, entry: TimelineEntry, session: &mut S) -> session::Result<()>
    where
        S: Session,
    {
        let mut entry_data: Vec<u8> = Vec::new();
        prost::Message::encode(&entry, &mut entry_data)?;
        self.encoder.write(entry_data.as_slice()).map_err(Error::action)?;
        if let Some(data) = self.encoder.try_next_chunk().map_err(Error::action)? {
            self.send_block(data, session)?;
        }
        Ok(())
    }

    /// Recursively traverses path specified as root, sends gzchunked stat data to session in
    /// process.
    fn recurse<S>(&mut self, root: &PathBuf, session: &mut S) -> session::Result<()>
    where
        S: Session,
    {
        let metadata = match symlink_metadata(&root) {
            Ok(metadata) => metadata,
            Err(_) => return Ok(()),
        };
        let entry = entry_from_metadata(&metadata, root);
        self.process_entry(entry, session)?;
        if metadata.is_dir() && metadata.dev() == self.device {
            let entry_iter = match read_dir(root) {
                Ok(iter) => iter,
                Err(_) => return Ok(()),
            };
            for entry in entry_iter {
                self.recurse(&entry.map_err(Error::action)?.path(), session)?;
            }
        }
        Ok(())
    }

    /// Sends final pieces of data to the session.
    fn finish<S: Session>(mut self, session: &mut S) -> session::Result<Vec<ChunkDigest>> {
        let final_block = self.encoder.next_chunk().map_err(Error::action)?;
        self.send_block(final_block, session)?;
        Ok(self.ids)
    }
}

/// Handles requests for the timeline action.
pub fn handle<S: Session>(session: &mut S, request: Request) -> session::Result<()> {
    let target_device = symlink_metadata(&request.root).map_err(Error::action)?.dev();
    let mut state = RecurseState::new(target_device);

    state.recurse(&request.root, session)?;
    let action_response = Response {
        ids: state.finish(session)?,
    };
    session.reply(action_response)?;

    Ok(())
}

impl super::Request for Request {

    type Proto = TimelineArgs;

    fn from_proto(proto: TimelineArgs) -> Result<Request, ParseError> {
        match proto.root {
            Some(root) => Ok(Request {
                root: PathBuf::from(OsString::from_vec(root)),
            }),
            None => Err(ParseError::malformed(MissingFieldError::new("root"))),
        }
    }
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("TimelineResult");

    type Proto = TimelineResult;

    fn into_proto(self) -> TimelineResult {
        TimelineResult {
            entry_batch_blob_ids: self.ids.iter().map(|id| id.0.to_vec()).collect()
        }
    }
}

impl super::Response for ChunkResponse {

    const RDF_NAME: Option<&'static str> = Some("DataBlob");

    type Proto = DataBlob;

    fn into_proto(self) -> DataBlob {
        DataBlob {
            data: Some(self.data),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::fs::{hard_link, create_dir, write};
    use std::path::Path;
    use std::os::unix::{ffi::OsStrExt, fs::symlink};
    use tempfile::tempdir;
    use crate::action::Request;
    use crate::gzchunked::GzChunkedDecoder;

    fn handle_for_path<S>(session: &mut S, path: &Path) -> session::Result<()>
    where
        S: Session,
    {
        let path_bytes = Vec::from(path.as_os_str().as_bytes());
        let args_proto = TimelineArgs { root: Some(path_bytes) };
        let request = Request::from_proto(args_proto).unwrap();
        handle(session, request)
    }

    fn entry_for_path(path: &Path) -> TimelineEntry {
        let metadata = symlink_metadata(path).unwrap();
        entry_from_metadata(&metadata, &PathBuf::from(path))
    }

    fn entries_from_session_response(session: &session::test::Fake) -> Vec<TimelineEntry> {
        assert_eq!(session.reply_count(), 1);
        let block_count = session.response_count(session::Sink::TRANSFER_STORE);

        let mut expected_ids = session.reply::<Response>(0).ids.clone();
        let mut ids = Vec::new();
        assert_eq!(expected_ids.len(), block_count);
        expected_ids.sort_by(|a, b| a.0.cmp(&b.0));

        let mut decoder = GzChunkedDecoder::new();
        for block_number in 0..block_count {
            let block = session.response::<ChunkResponse>(session::Sink::TRANSFER_STORE, block_number);
            let response_digest = ChunkDigest(Sha256::digest(&block.data).into());
            ids.push(response_digest);

            decoder.write(block.data.as_slice()).unwrap();
        }

        expected_ids.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(ids, expected_ids);

        let mut ret = Vec::new();
        while let Some(entry_data) = decoder.try_next_data() {
            let entry: TimelineEntry = prost::Message::decode(entry_data.as_slice()).unwrap();
            ret.push(entry);
        }
        ret.sort_by(|a, b| a.path.cmp(&b.path));
        ret
    }

    #[test]
    fn test_nonexistent_path() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path().join("nonexistent_subdir");

        let mut session = session::test::Fake::new();
        assert!(handle_for_path(&mut session, dir_path.as_path()).is_err());
    }

    #[test]
    fn test_one_empty_dir() {
        let mut expected_entries = Vec::new();

        let dir = tempdir().unwrap();
        expected_entries.push(entry_for_path(dir.path()));

        expected_entries.sort_by(|a, b| a.path.cmp(&b.path));

        let mut session = session::test::Fake::new();
        assert!(handle_for_path(&mut session, dir.path()).is_ok());

        let entries = entries_from_session_response(&session);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries, expected_entries);
    }

    #[test]
    fn test_file_hardlink() {
        let mut expected_entries = Vec::new();

        let dir = tempdir().unwrap();

        let test1_path = dir.path().join("test1.txt");
        write(&test1_path, "foo");

        let test2_path = dir.path().join("test2.txt");
        hard_link(&test1_path, &test2_path).unwrap();

        let test1_entry = entry_for_path(&test1_path);
        let test2_entry = entry_for_path(&test2_path);
        assert_eq!(test1_entry.ino, test2_entry.ino);

        expected_entries.push(entry_for_path(dir.path()));
        expected_entries.push(test1_entry);
        expected_entries.push(test2_entry);

        expected_entries.sort_by(|a, b| a.path.cmp(&b.path));

        let mut session = session::test::Fake::new();
        assert!(handle_for_path(&mut session, dir.path()).is_ok());

        let entries = entries_from_session_response(&session);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries, expected_entries);
    }
}
