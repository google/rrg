// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the timeline action.

use std::ffi::{OsStr, OsString};
use std::fs::{symlink_metadata, read_dir, Metadata};
use std::path::{Path, PathBuf};
use std::result::Result;
use std::vec::Vec;

use cfg_if::cfg_if;
use sha2::{Digest, Sha256};
use rrg_proto::{TimelineArgs, TimelineEntry, TimelineResult, DataBlob};

use crate::gzchunked;
use crate::session::{self, Session, Error, ParseError, MissingFieldError};

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
    encoder: gzchunked::Encoder,
}

/// Retrieves device ID from metadata.
#[allow(unused_variables)]
fn dev_from_metadata(metadata: &Metadata) -> u64 {
    cfg_if! {
        if #[cfg(target_family = "unix")] {
            use std::os::unix::fs::MetadataExt;
            metadata.dev()
        } else if #[cfg(target_family = "windows")] {
            0
        } else {
            compile_error!("unsupported OS family");
        }
    }
}

/// Tries to convert OS-dependent string to raw bytes.
fn bytes_from_os_str(s: &OsStr) -> std::io::Result<Vec<u8>> {
    cfg_if! {
        if #[cfg(target_family = "unix")] {
            use std::os::unix::ffi::OsStrExt;
            Ok(Vec::from(s.as_bytes()))
        } else if #[cfg(target_family = "windows")] {
            // Using UTF16LE because Windows *seems* to be using only little-endian version.
            // If RRG starts supporting Windows for real in future, it would be better to
            // review this piece to ensure that it uses the same path encoding as GRR server.

            use std::os::windows::ffi::OsStrExt;
            use byteorder::{LittleEndian, WriteBytesExt};
            s.encode_wide().try_fold(Vec::new(), |mut stream, ch| {
                stream.write_u16::<LittleEndian>(ch).map(|_| stream)
            })
        } else {
            compile_error!("unsupported OS family");
        }
    }
}

/// Converts raw bytes to OS-dependent string.
fn os_string_from_bytes(bytes: &[u8]) -> OsString {
    cfg_if! {
        if #[cfg(target_family = "unix")] {
            use std::os::unix::ffi::OsStringExt;
            OsString::from_vec(Vec::from(bytes))
        } else if #[cfg(target_family = "windows")] {
            // Using UTF16LE because Windows *seems* to be using only little-endian version.
            // If RRG starts supporting Windows for real in future, it would be better to
            // review this piece to ensure that it uses the same path encoding as GRR server.

            use std::os::windows::ffi::OsStringExt;
            use byteorder::{LittleEndian, ReadBytesExt};
            let mut wchars = Vec::new();
            let mut bytes_slice = bytes;
            while let Ok(wchar) = bytes_slice.read_u16::<LittleEndian>() {
                wchars.push(wchar);
            }
            OsString::from_wide(wchars.as_slice())
        } else {
            compile_error!("unsupported OS family");
        }
    }
}

/// Encodes filesystem metadata into timeline entry proto.
fn entry_from_metadata(metadata: &Metadata, path: &Path) -> std::io::Result<TimelineEntry>
{
    cfg_if! {
        if #[cfg(target_family = "unix")] {
            use std::os::unix::fs::MetadataExt;
            Ok(TimelineEntry {
                path: Some(bytes_from_os_str(path.as_os_str())?),
                mode: Some(i64::from(metadata.mode())),
                size: Some(metadata.size()),
                dev: Some(metadata.dev() as i64),
                ino: Some(metadata.ino()),
                uid: Some(metadata.uid() as i64),
                gid: Some(metadata.gid() as i64),
                atime_ns: Some(metadata.atime_nsec() as i64),
                ctime_ns: Some(metadata.ctime_nsec() as i64),
                mtime_ns: Some(metadata.mtime_nsec() as i64),
                btime_ns: None,
                attributes: None,
            })
        } else if #[cfg(target_family = "windows")] {
            use std::os::windows::fs::MetadataExt;
            Ok(TimelineEntry {
                path: Some(bytes_from_os_str(path.as_os_str())?),
                mode: None,
                size: Some(metadata.len()),
                dev: None,
                ino: None,
                uid: None,
                gid: None,
                atime_ns: Some(metadata.last_access_time() as i64),
                ctime_ns: Some(metadata.creation_time() as i64),
                mtime_ns: Some(metadata.last_write_time() as i64),
                btime_ns: None,
                attributes: None,
            })
        } else {
            compile_error!("unsupported OS family");
        }
    }
}

impl RecurseState {
    /// Constructs new state that would only traverse filesystems from `device`.
    fn new(device: u64) -> RecurseState {
        RecurseState {
            device,
            ids: Vec::new(),
            encoder: gzchunked::Encoder::new(gzchunked::Compression::default()),
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
    fn recurse<S>(&mut self, root: &Path, session: &mut S) -> session::Result<()>
    where
        S: Session,
    {
        let mut path = PathBuf::from(root);
        let mut dir_iter_stack = Vec::new();
        loop {
            let metadata = match symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            let entry = entry_from_metadata(&metadata, &path).map_err(Error::action)?;
            self.process_entry(entry, session)?;
            if metadata.is_dir() && dev_from_metadata(&metadata) == self.device {
                if let Ok(dir_iter) = read_dir(&path) {
                    dir_iter_stack.push(dir_iter);
                }
            }
            let mut new_path = None;
            while let Some(dir_iter) = dir_iter_stack.last_mut() {
                if let Some(dir_entry) = dir_iter.next() {
                    new_path = Some(dir_entry.map_err(Error::action)?.path());
                    break;
                } else {
                    dir_iter_stack.pop();
                }
            }
            if let Some(new_path) = new_path {
                path = new_path;
            } else {
                break;
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
    let root_metadata = symlink_metadata(&request.root).map_err(Error::action)?;
    let target_device = dev_from_metadata(&root_metadata);
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
                root: PathBuf::from(os_string_from_bytes(root.as_slice())),
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
        self.data.into()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::fs::{hard_link, create_dir, write};
    use tempfile::tempdir;

    fn entries_from_session_response(session: &session::test::Fake) -> Vec<TimelineEntry> {
        assert_eq!(session.reply_count(), 1);
        let block_count = session.response_count(session::Sink::TRANSFER_STORE);

        let mut expected_ids = session.reply::<Response>(0).ids.clone();
        let mut ids = Vec::new();
        assert_eq!(block_count, expected_ids.len());
        expected_ids.sort_by(|a, b| a.0.cmp(&b.0));

        let mut decoder = gzchunked::Decoder::new();
        for block_number in 0..block_count {
            let block = session.response::<ChunkResponse>(session::Sink::TRANSFER_STORE, block_number);
            let response_digest = ChunkDigest(Sha256::digest(&block.data).into());
            ids.push(response_digest);

            decoder.write(block.data.as_slice()).unwrap();
        }

        ids.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(ids, expected_ids);

        let mut ret = Vec::new();
        while let Some(entry_data) = decoder.try_next_data() {
            let entry: TimelineEntry = prost::Message::decode(entry_data.as_slice()).unwrap();
            ret.push(entry);
        }
        ret
    }

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

        let mut entries = entries_from_session_response(&session);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, Some(bytes_from_os_str(dir.path().as_os_str()).unwrap()));
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

        let mut entries = entries_from_session_response(&session);
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

        let mut entries = entries_from_session_response(&session);
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

        let mut entries = entries_from_session_response(&session);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[1].path, Some(bytes_from_os_str(test1_path.as_os_str()).unwrap()));
        assert_eq!(entries[2].path, Some(bytes_from_os_str(test2_path.as_os_str()).unwrap()));
        assert_eq!(entries[3].path, Some(bytes_from_os_str(test3_path.as_os_str()).unwrap()));
        assert_eq!(entries[4].path, Some(bytes_from_os_str(test4_path.as_os_str()).unwrap()));
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

        let mut entries = entries_from_session_response(&session);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[1].path, Some(bytes_from_os_str(path1.as_os_str()).unwrap()));
        assert_eq!(entries[2].path, Some(bytes_from_os_str(path2.as_os_str()).unwrap()));
        assert_eq!(entries[3].path, Some(bytes_from_os_str(path3.as_os_str()).unwrap()));
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

        let entries = entries_from_session_response(&session);
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

        let mut entries = entries_from_session_response(&session);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[2].mode, Some(0o040000));
        assert_eq!(entries[1].mode, Some(0o100444));
        // Drop mode bits because symlinks have actual modes on some unix systems.
        assert_eq!(entries[3].mode.unwrap() & 0o120000, 0o120000);
    }
}
