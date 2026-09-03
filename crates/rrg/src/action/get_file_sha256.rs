// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::path::PathBuf;

/// Arguments of the `get_file_sha256` action.
pub struct Args {
    /// Absolute path to the file to get the SHA-256 hash of.
    path: PathBuf,
    /// Byte offsets from which the content should be hashed.
    offsets: Vec<u64>,
    /// Number of bytes to hash (from the start offset).
    len: Option<std::num::NonZero<u64>>,
}

/// Result of the `get_file_sha256` action.
struct Item {
    /// Absolute path of the file this result corresponds to.
    path: PathBuf,
    /// Byte offset from which the file content was hashed.
    offset: u64,
    /// Number of bytes of the file used to produce the hash.
    len: u64,
    /// SHA-256 hash digest of the file content.
    sha256: [u8; 32],
}

/// Handle invocations of the `get_file_sha256` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use std::io::{BufRead as _, Read as _, Seek as _};

    let file = std::fs::File::open(&args.path)
        .map_err(crate::session::Error::action)?;
    let mut file = std::io::BufReader::new(file);

    for offset in args.offsets {
        file.seek(std::io::SeekFrom::Start(offset))
            .map_err(crate::session::Error::action)?;

        let mut file_limited = file.take(match args.len {
            Some(len) => u64::from(len),
            None => u64::MAX,
        });

        use sha2::Digest as _;
        let mut sha256 = sha2::Sha256::new();
        let mut len = 0u64;
        loop {
            let buf = match file_limited.fill_buf() {
                Ok(buf) if buf.is_empty() => break,
                Ok(buf) => buf,
                Err(error) => return Err(crate::session::Error::action(error)),
            };
            sha256.update(&buf[..]);

            let buf_len = buf.len();
            file_limited.consume(buf_len);
            len += buf_len as u64;
        }
        let sha256 = <[u8; 32]>::from(sha256.finalize());

        session.reply(Item {
            path: args.path.clone(),
            offset: offset,
            len,
            sha256,
        })?;

        file = file_limited.into_inner();
    }

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_file_sha256::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let path = PathBuf::try_from(proto.take_path())
            .map_err(|error| ParseArgsError::invalid_field("path", error))?;

        let mut offsets = proto.take_offsets();
        if offsets.is_empty() {
            offsets.push(0);
        }

        Ok(Args {
            path,
            offsets,
            len: std::num::NonZero::new(proto.length()),
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_file_sha256::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = rrg_proto::get_file_sha256::Result::new();
        proto.set_path(self.path.into());
        proto.set_offset(self.offset);
        proto.set_length(self.len);
        proto.set_sha256(self.sha256.to_vec());

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn handle_default() {
        let mut tempfile = tempfile::NamedTempFile::new()
            .unwrap();

        use std::io::Write as _;
        tempfile.as_file_mut().write_all(b"hello\n")
            .unwrap();

        let args = Args {
            path: tempfile.path().to_path_buf(),
            offsets: vec![0],
            len: None,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempfile.path());
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, u64::try_from(b"hello\n".len()).unwrap());
        assert_eq!(item.sha256, [
            // Pre-computed by the `sha256sum` tool.
            0x58, 0x91, 0xb5, 0xb5, 0x22, 0xd5, 0xdf, 0x08,
            0x6d, 0x0f, 0xf0, 0xb1, 0x10, 0xfb, 0xd9, 0xd2,
            0x1b, 0xb4, 0xfc, 0x71, 0x63, 0xaf, 0x34, 0xd0,
            0x82, 0x86, 0xa2, 0xe8, 0x46, 0xf6, 0xbe, 0x03,
        ]);
    }

    #[test]
    fn handle_offset() {
        let mut tempfile = tempfile::NamedTempFile::new()
            .unwrap();

        use std::io::Write as _;
        tempfile.as_file_mut().write_all(b"<ignore me>hello\n")
            .unwrap();

        let args = Args {
            path: tempfile.path().to_path_buf(),
            offsets: vec![u64::try_from("<ignore me>".len()).unwrap()],
            len: None,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempfile.path());
        assert_eq!(item.offset, u64::try_from(b"<ignore me>".len()).unwrap());
        assert_eq!(item.len, u64::try_from(b"hello\n".len()).unwrap());
        assert_eq!(item.sha256, [
            // Pre-computed by the `sha256sum` tool.
            0x58, 0x91, 0xb5, 0xb5, 0x22, 0xd5, 0xdf, 0x08,
            0x6d, 0x0f, 0xf0, 0xb1, 0x10, 0xfb, 0xd9, 0xd2,
            0x1b, 0xb4, 0xfc, 0x71, 0x63, 0xaf, 0x34, 0xd0,
            0x82, 0x86, 0xa2, 0xe8, 0x46, 0xf6, 0xbe, 0x03,
        ]);
    }

    #[test]
    fn handle_offset_multiple() {
        let mut tempfile = tempfile::NamedTempFile::new()
            .unwrap();

        use std::io::Write as _;
        tempfile.as_file_mut().write_all(b"<ignore1>foo<ignore2>bar")
            .unwrap();

        let args = Args {
            path: tempfile.path().to_path_buf(),
            offsets: vec![
                u64::try_from(b"<ignore1>".len()).unwrap(),
                u64::try_from(b"<ignore1>foo<ignore2>".len()).unwrap(),
            ],
            len: std::num::NonZeroU64::new(3),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 2);

        let item_foo = session.reply::<Item>(0);
        assert_eq!(item_foo.path, tempfile.path());
        assert_eq!(item_foo.offset, 9);
        assert_eq!(item_foo.len, 3);
        assert_eq!(item_foo.sha256, [
            // Pre-computed with `echo -n 'foo' | sha256sum`.
            0x2c, 0x26, 0xb4, 0x6b, 0x68, 0xff, 0xc6, 0x8f,
            0xf9, 0x9b, 0x45, 0x3c, 0x1d, 0x30, 0x41, 0x34,
            0x13, 0x42, 0x2d, 0x70, 0x64, 0x83, 0xbf, 0xa0,
            0xf9, 0x8a, 0x5e, 0x88, 0x62, 0x66, 0xe7, 0xae,
        ]);

        let item_bar = session.reply::<Item>(1);
        assert_eq!(item_bar.path, tempfile.path());
        assert_eq!(item_bar.offset, 21);
        assert_eq!(item_bar.len, 3);
        assert_eq!(item_bar.sha256, [
            // Pre-computed with `echo -n 'bar' | sha256sum`.
            0xfc, 0xde, 0x2b, 0x2e, 0xdb, 0xa5, 0x6b, 0xf4,
            0x08, 0x60, 0x1f, 0xb7, 0x21, 0xfe, 0x9b, 0x5c,
            0x33, 0x8d, 0x10, 0xee, 0x42, 0x9e, 0xa0, 0x4f,
            0xae, 0x55, 0x11, 0xb6, 0x8f, 0xbf, 0x8f, 0xb9,
        ]);
    }

    #[test]
    fn handle_len() {
        let mut tempfile = tempfile::NamedTempFile::new()
            .unwrap();

        use std::io::Write as _;
        tempfile.as_file_mut().write_all(b"hello\n<ignore me>")
            .unwrap();

        let args = Args {
            path: tempfile.path().to_path_buf(),
            offsets: vec![0],
            len: std::num::NonZero::new(b"hello\n".len().try_into().unwrap()),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempfile.path());
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, u64::try_from(b"hello\n".len()).unwrap());
        assert_eq!(item.sha256, [
            // Pre-computed by the `sha256sum` tool.
            0x58, 0x91, 0xb5, 0xb5, 0x22, 0xd5, 0xdf, 0x08,
            0x6d, 0x0f, 0xf0, 0xb1, 0x10, 0xfb, 0xd9, 0xd2,
            0x1b, 0xb4, 0xfc, 0x71, 0x63, 0xaf, 0x34, 0xd0,
            0x82, 0x86, 0xa2, 0xe8, 0x46, 0xf6, 0xbe, 0x03,
        ]);
    }

    #[test]
    fn handle_large() {
        let mut tempfile = tempfile::NamedTempFile::new()
            .unwrap();

        use std::io::Read as _;
        std::io::copy(&mut std::io::repeat(0).take(13371337), &mut tempfile)
            .unwrap();

        let args = Args {
            path: tempfile.path().to_path_buf(),
            offsets: vec![0],
            len: None,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempfile.path());
        assert_eq!(item.offset, 0);
        assert_eq!(item.len, 13371337);
        assert_eq!(item.sha256, [
            // Pre-computed by `head --bytes=13371337 < /dev/zero | sha256sum`.
            0xda, 0xa6, 0x04, 0x11, 0x35, 0x03, 0xdb, 0x38,
            0xe3, 0x62, 0xfe, 0xff, 0x8f, 0x73, 0xc1, 0xf9,
            0xb2, 0x6f, 0x02, 0x85, 0x3d, 0x2f, 0x47, 0x8d,
            0x52, 0x16, 0xc5, 0x70, 0x32, 0x54, 0x1c, 0xf8,
        ]);
    }
}
