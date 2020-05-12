// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the timeline action.

use std::vec::Vec;
use std::ffi::OsString;
use std::result::Result;
use std::path::PathBuf;
use std::fs;
use std::os::unix::{fs::MetadataExt, ffi::OsStringExt};
use sha2::{Digest, Sha256};
use crate::session::{self, Session, Error, ParseError, MissingFieldError};
use crate::gzchunked::GzChunkedEncoder;

/// A request type for the timeline action.
pub struct Request {
    root: PathBuf,
}

/// A newtype wrapper for SHA-256 chunk digest.
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

/// Encodes filesystem metadata into Timeline entry proto.
fn entry_from_metadata<M>(metadata: &M, path: &PathBuf) -> rrg_proto::TimelineEntry 
where
    M: MetadataExt,
{
    rrg_proto::TimelineEntry {
        path: Some(path.clone().into_os_string().into_vec()),
        mode: Some(metadata.mode()),
        size: Some(metadata.size()),
        dev: Some(metadata.dev()),
        ino: Some(metadata.dev()),
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
            encoder: GzChunkedEncoder::new(flate2::Compression::default()),
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
    fn process_entry<S>(&mut self, entry: rrg_proto::TimelineEntry, session: &mut S) -> session::Result<()>
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
        let metadata = match fs::symlink_metadata(&root) {
            Ok(metadata) => metadata,
            Err(_) => return Ok(()),
        };
        let entry = entry_from_metadata(&metadata, root);
        self.process_entry(entry, session)?;
        if metadata.is_dir() && metadata.dev() == self.device {
            let entry_iter = match fs::read_dir(root) {
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
    let target_device = fs::symlink_metadata(&request.root).map_err(Error::action)?.dev();
    let mut state = RecurseState::new(target_device);

    state.recurse(&request.root, session)?;
    let action_response = Response {
        ids: state.finish(session)?,
    };
    session.reply(action_response)?;

    Ok(())
}

impl super::Request for Request {

    type Proto = rrg_proto::TimelineArgs;

    fn from_proto(proto: rrg_proto::TimelineArgs) -> Result<Request, ParseError> {
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

    type Proto = rrg_proto::TimelineResult;

    fn into_proto(self) -> rrg_proto::TimelineResult {
        rrg_proto::TimelineResult {
            entry_batch_blob_ids: self.ids.iter().map(|id| id.0.to_vec()).collect()
        }
    }
}

impl super::Response for ChunkResponse {

    const RDF_NAME: Option<&'static str> = Some("DataBlob");

    type Proto = rrg_proto::DataBlob;

    fn into_proto(self) -> rrg_proto::DataBlob {
        rrg_proto::DataBlob {
            data: Some(self.data),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use tempfile::tempdir;
    use crate::action::Request;
    use std::os::unix::ffi::OsStrExt;
    use crate::gzchunked::GzChunkedDecoder;

    #[test]
    fn test_one_empty_dir() {
        let dir = tempdir().unwrap();
        let dir_metadata = fs::metadata(dir.path()).unwrap();
        let dir_path_bytes = Vec::from(dir.path().as_os_str().as_bytes());

        let expected_entry = entry_from_metadata(&dir_metadata, &PathBuf::from(dir.path()));

        let args_proto = rrg_proto::TimelineArgs { root: Some(dir_path_bytes) };
        let request = Request::from_proto(args_proto).unwrap();
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());

        assert_eq!(session.reply_count(), 1);
        assert_eq!(session.response_count(session::Sink::TRANSFER_STORE), 1);

        let reply = session.reply::<Response>(0);
        assert_eq!(reply.ids.len(), 1);
        let response = session.response::<ChunkResponse>(session::Sink::TRANSFER_STORE, 0);
        let response_digest = ChunkDigest(Sha256::digest(&response.data).into());
        assert_eq!(response_digest.0, reply.ids[0].0);

        let mut decoder = GzChunkedDecoder::new();
        decoder.write(response.data.as_slice()).unwrap();
        let entry_data = decoder.try_next_data().unwrap();
        assert_eq!(decoder.try_next_data(), None);

        let entry: rrg_proto::TimelineEntry = prost::Message::decode(entry_data.as_slice()).unwrap();
        assert_eq!(entry, expected_entry);
    }
}
