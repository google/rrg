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
    dev: u64,
    ids: Vec<Vec<u8>>,
    enc: GzEncoder<Vec<u8>>
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::action(e)
    }
}

fn entry_from_stat<M: MetadataExt>(md: &M, p: &PathBuf) -> rrg_proto::TimelineEntry {
    rrg_proto::TimelineEntry {
        // TODO path -> bytes = ???, how to non-unicode?
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
    fn recurse<S: Session>(&mut self, root: &PathBuf, sess: &mut S) -> session::Result<()> {
        let statentry = fs::symlink_metadata(&root)?;
        let statproto = entry_from_stat(&statentry, root);
        let mut statdata: Vec<u8> = Vec::new();
        prost::Message::encode(&statproto, &mut statdata)?;
        self.enc.write_all(&(statdata.len() as u64).to_be_bytes())?;
        self.enc.write_all(statdata.as_slice())?;
        self.enc.flush()?;
        if self.enc.get_ref().len() >= BLOCK_SIZE {
            self.flush(sess)?;
        }
        if statentry.is_dir() && statentry.dev() == self.dev {
            for entry in fs::read_dir(root)? {
                self.recurse(&entry?.path(), sess)?;
            }
        }
        Ok(())
    }
    fn flush<S: Session>(&mut self, sess: &mut S) -> session::Result<()> {
        self.enc.try_finish()?;
        let data = self.enc.get_ref().clone();
        self.ids.push(Vec::from(Sha256::digest(data.as_slice()).as_slice()));
        sess.send(session::Sink::TRANSFER_STORE, ChunkResponse{ data })?;
        self.enc = GzEncoder::new(Vec::new(), Compression::default());
        Ok(())
    }
}

/// Handles requests for the timeline action.
pub fn handle<S: Session>(sess: &mut S, request: Request) -> session::Result<()> {

    let mut rs = RecurseState {
        dev: fs::symlink_metadata(&request.root)?.dev(),
        ids: Vec::new(),
        enc: GzEncoder::new(Vec::new(), flate2::Compression::default()),
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
            // but it's gzipped...
            compression: None
        }
    }
}
