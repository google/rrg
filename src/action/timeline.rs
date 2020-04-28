// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the timeline action.

use std::vec::Vec;
use std::path::PathBuf;
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use sha2::{Digest, Sha256};
use flate2::{write::GzEncoder, Compression};
use crate::session::{self, Session, Error};

const BLOCK_SIZE: usize = 10 << 20;

/// A request type for the timeline action.
pub struct Request {
    root: PathBuf
}

/// A response type for the timeline action (actual response).
pub struct Response {
    ids: Vec<Vec<u8>>
}

/// A response type for the timeline action (transfer store chunks).
pub struct ChunkResponse {
    data: Vec<u8>
}

struct RecurseState {
    device: u64,
    ids: Vec<Vec<u8>>,
    encoder: GzEncoder<Vec<u8>>
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::action(e)
    }
}

fn entry_from_stat<M: MetadataExt>(md: &M, p: &PathBuf) -> rrg_proto::TimelineEntry {
    rrg_proto::TimelineEntry {
        path: Some(Vec::from(p.to_string_lossy().as_bytes())),
        mode: Some(md.mode()),
        size: Some(md.size()),
        dev: Some(md.dev()),
        ino: Some(md.dev()),
        uid: Some(md.uid() as i64),
        gid: Some(md.gid() as i64),
        atime_ns: Some(md.atime_nsec() as u64),
        ctime_ns: Some(md.ctime_nsec() as u64),
        mtime_ns: Some(md.mtime_nsec() as u64)
    }
}

impl RecurseState {
    /// Recursively traverses path specified as root, sends gzchunked stat data to session.
    fn recurse<S: Session>(&mut self, root: &PathBuf, session: &mut S) -> session::Result<()> {
        let statentry = match fs::symlink_metadata(&root) {
            Ok(v) => v,
            Err(_) => return Ok(())
        };
        let statproto = entry_from_stat(&statentry, root);
        let mut statdata: Vec<u8> = Vec::new();
        prost::Message::encode(&statproto, &mut statdata)?;
        self.encoder.write_all(&(statdata.len() as u64).to_be_bytes())?;
        self.encoder.write_all(statdata.as_slice())?;
        self.encoder.flush()?;
        if self.encoder.get_ref().len() >= BLOCK_SIZE {
            self.flush(session)?;
        }
        if statentry.is_dir() && statentry.dev() == self.device {
            for entry in match fs::read_dir(root) {
                Ok(v) => v,
                Err(_) => return Ok(())
            } {
                self.recurse(&entry?.path(), session)?;
            }
        }
        Ok(())
    }

    /// Sends currently accumulated gzchunked data to transfer store.
    fn flush<S: Session>(&mut self, session: &mut S) -> session::Result<()> {
        self.encoder.try_finish()?;
        let data = self.encoder.get_ref().clone();
        self.ids.push(Vec::from(Sha256::digest(data.as_slice()).as_slice()));
        session.send(session::Sink::TRANSFER_STORE, ChunkResponse{ data })?;
        // TODO(xtsm) add session.progress here
        self.encoder = GzEncoder::new(Vec::new(), Compression::default());
        Ok(())
    }
}

/// Handles requests for the timeline action.
pub fn handle<S: Session>(sess: &mut S, request: Request) -> session::Result<()> {

    let mut rs = RecurseState {
        device: match fs::symlink_metadata(&request.root) {
            Ok(v) => v.dev(),
            Err(_) => {
                sess.reply(Response {ids : Vec::new()})?;
                return Ok(());
            }
        },
        ids: Vec::new(),
        encoder: GzEncoder::new(Vec::new(), flate2::Compression::default()),
    };
    rs.recurse(&request.root, sess)?;
    rs.flush(sess)?;
    sess.reply(Response {ids: rs.ids})?;

    Ok(())
}

impl super::Request for Request {

    type Proto = rrg_proto::TimelineArgs;

    fn from_proto(proto: rrg_proto::TimelineArgs) -> Request {
        // TODO fix unwrap
        Request {
            root: PathBuf::from(String::from_utf8(proto.root.unwrap()).unwrap())
        }
    }
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("TimelineResult");

    type Proto = rrg_proto::TimelineResult;

    fn into_proto(self) -> rrg_proto::TimelineResult {
        rrg_proto::TimelineResult {
            entry_batch_blob_ids: self.ids
        }
    }
}

impl super::Response for ChunkResponse {

    const RDF_NAME: Option<&'static str> = Some("DataBlob");

    type Proto = rrg_proto::DataBlob;

    fn into_proto(self) -> rrg_proto::DataBlob {
        rrg_proto::DataBlob {
            integer: None,
            data: Some(self.data),
            string: None,
            proto_name: None,
            none: None,
            boolean: None,
            list: None,
            dict: None,
            rdf_value: None,
            float: None,
            set: None,
            compression: None
        }
    }
}
