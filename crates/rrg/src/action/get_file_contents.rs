// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::{path::PathBuf};

const MAX_BLOB_LEN: usize = 2 * 1024 * 1024; // 2 MiB.

/// Arguments of the `get_file_contents` action.
pub struct Args {
    /// Path to the file to get the contents of.
    path: PathBuf,
    /// Offset from which to read the file contents.
    offset: u64,
    /// Number of bytes to read from the file.
    len: usize,
}

/// Result of the `get_file_contents` action.
pub struct Item {
    /// Byte offset of the file part sent to the blob sink.
    offset: u64,
    /// Number of bytes of the file part sent to the blob sink.
    len: usize,
    /// SHA-256 digest of the file part sent to the blob sink.
    blob_sha256: [u8; 32],
}

/// Handle invocations of the `get_file_contents` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use std::io::{Read as _, Seek as _};
    use sha2::Digest as _;

    let mut file = std::fs::File::open(args.path)
        .map_err(crate::session::Error::action)?;

    let mut offset = args.offset;
    let mut len_left = args.len;

    file.seek(std::io::SeekFrom::Start(offset))
        .map_err(crate::session::Error::action)?;

    loop {
        let mut buf = vec![0; std::cmp::min(len_left, MAX_BLOB_LEN)];

        let len_read = file.read(&mut buf[..])
            .map_err(crate::session::Error::action)?;

        if len_read == 0 {
            break;
        }

        buf.truncate(len_read);

        let blob = crate::blob::Blob::from(buf);
        let blob_sha256 = sha2::Sha256::digest(blob.as_bytes()).into();

        session.send(crate::Sink::Blob, blob)?;
        session.reply(Item {
            offset,
            len: len_read,
            blob_sha256,
        })?;

        offset += len_read as u64;
        len_left -= len_read;
    }

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::v2::get_file_contents::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let path = PathBuf::try_from(proto.take_path())
            .map_err(|error| ParseArgsError::invalid_field("path", error))?;

        let len = match proto.get_length() {
            0 => usize::MAX,
            len if len > MAX_BLOB_LEN as u64 => {
                return Err(ParseArgsError::invalid_field("length", LenError {
                    len,
                }));
            }
            len => len as usize,
        };

        Ok(Args {
            path,
            offset: proto.get_offset(),
            len,
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::v2::get_file_contents::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = Self::Proto::default();
        proto.set_offset(self.offset);
        proto.set_length(self.len as u64);
        proto.set_blob_sha256(self.blob_sha256.into());

        proto
    }
}

/// An error indicating that the action was invoked with invalid length.
#[derive(Debug)]
struct LenError {
    len: u64,
}

impl std::fmt::Display for LenError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write! {
            fmt,
            "provded length ({}) is bigger than allowed ({})",
            self.len, MAX_BLOB_LEN
        }
    }
}

impl std::error::Error for LenError {
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn handle_empty_file() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        std::fs::write(tempdir.path().join("foo"), b"")
            .unwrap();

        let args = Args {
            path: tempdir.path().join("foo"),
            offset: 0,
            len: usize::MAX,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 0);
        assert_eq!(session.parcel_count(crate::Sink::Blob), 0);
    }

    #[test]
    fn handle_small_file_all() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        std::fs::write(tempdir.path().join("foo"), b"0123456789")
            .unwrap();

        let args = Args {
            path: tempdir.path().join("foo"),
            offset: 0,
            len: usize::MAX,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, 10);

        assert_eq!(session.parcel_count(crate::Sink::Blob), 1);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 0);
        assert_eq!(blob.as_bytes(), b"0123456789");
    }

    #[test]
    fn handle_small_file_from_offset() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        std::fs::write(tempdir.path().join("foo"), b"0123456789")
            .unwrap();

        let args = Args {
            path: tempdir.path().join("foo"),
            offset: 5,
            len: usize::MAX,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.offset, 5);
        assert_eq!(item.len, 5);

        assert_eq!(session.parcel_count(crate::Sink::Blob), 1);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 0);
        assert_eq!(blob.as_bytes(), b"56789");
    }

    #[test]
    fn handle_small_file_to_len() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        std::fs::write(tempdir.path().join("foo"), b"0123456789")
            .unwrap();

        let args = Args {
            path: tempdir.path().join("foo"),
            offset: 0,
            len: 5,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, 5);

        assert_eq!(session.parcel_count(crate::Sink::Blob), 1);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 0);
        assert_eq!(blob.as_bytes(), b"01234");
    }

    #[test]
    // `/dev/zero` is not available on Windows (nor there is an equivalent).
    #[cfg_attr(target_family = "windows", ignore)]
    fn handle_big_file_to_len() {
        let args = Args {
            path: PathBuf::from("/dev/zero"),
            offset: 0,
            len: MAX_BLOB_LEN * 2 + 1337,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 3);

        let item = session.reply::<Item>(0);
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, MAX_BLOB_LEN);

        let item = session.reply::<Item>(1);
        assert_eq!(item.offset, MAX_BLOB_LEN as u64);
        assert_eq!(item.len, MAX_BLOB_LEN);

        let item = session.reply::<Item>(2);
        assert_eq!(item.offset, MAX_BLOB_LEN as u64 * 2);
        assert_eq!(item.len, 1337);

        assert_eq!(session.parcel_count(crate::Sink::Blob), 3);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 0);
        assert_eq!(blob.as_bytes().len(), MAX_BLOB_LEN);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 1);
        assert_eq!(blob.as_bytes().len(), MAX_BLOB_LEN);

        let blob = session.parcel::<crate::blob::Blob>(crate::Sink::Blob, 2);
        assert_eq!(blob.as_bytes().len(), 1337);
    }

    #[test]
    // `/dev/zero` is not available on Windows (nor there is an equivalent).
    #[cfg_attr(target_family = "windows", ignore)]
    fn handle_big_file_from_offset_to_len() {
        let args = Args {
            path: PathBuf::from("/dev/zero"),
            offset: 0xb33f,
            len: MAX_BLOB_LEN + 1337,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 2);

        let item = session.reply::<Item>(0);
        assert_eq!(item.offset, 0xb33f);
        assert_eq!(item.len, MAX_BLOB_LEN);

        let item = session.reply::<Item>(1);
        assert_eq!(item.offset, 0xb33f + MAX_BLOB_LEN as u64);
        assert_eq!(item.len, 1337);
    }
}
