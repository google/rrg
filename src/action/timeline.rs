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


fn send_data<S>(session: &mut S, data: Vec<u8>) -> session::Result<ChunkDigest>
where
    S: Session,
{
    let digest = ChunkDigest(Sha256::digest(data.as_slice()).into());
    session.send(session::Sink::TRANSFER_STORE, ChunkResponse { data })?;
    session.heartbeat();
    Ok(digest)
}

impl RecurseState {
    /// Recursively traverses path specified as root, sends gzchunked stat data to session.
    fn recurse<S: Session>(&mut self, root: &PathBuf, session: &mut S) -> session::Result<()> {
        let metadata = match fs::symlink_metadata(&root) {
            Ok(metadata) => metadata,
            Err(_) => return Ok(()),
        };
        let entry_proto = entry_from_metadata(&metadata, root);
        let mut entry_data: Vec<u8> = Vec::new();
        prost::Message::encode(&entry_proto, &mut entry_data)?;
        self.encoder.write(entry_data.as_slice()).map_err(Error::action)?;
        if let Some(data) = self.encoder.try_next_chunk().map_err(Error::action)? {
            self.ids.push(send_data(session, data)?);
        }
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
}

/// Handles requests for the timeline action.
pub fn handle<S: Session>(session: &mut S, request: Request) -> session::Result<()> {

    let mut state = RecurseState {
        device: fs::symlink_metadata(&request.root).map_err(Error::action)?.dev(),
        ids: Vec::new(),
        encoder: GzChunkedEncoder::new(flate2::Compression::default()),
    };
    state.recurse(&request.root, session)?;
    state.ids.push(send_data(session, state.encoder.next_chunk().map_err(Error::action)?)?);
    session.reply(Response {ids: state.ids})?;

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