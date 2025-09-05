// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::path::PathBuf;

pub struct Args {
    path: PathBuf,
    offset: u64,
    len: Option<std::num::NonZero<u64>>,
}

struct Item {
    path: PathBuf,
    offset: u64,
    len: u64,
    sha256: [u8; 32],
}

pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use std::io::{BufRead as _, Read as _, Seek as _};
    use sha2::Digest as _;

    let file = std::fs::File::open(&args.path)
        .map_err(crate::session::Error::action)?;
    let mut file = std::io::BufReader::new(file);

    file.seek(std::io::SeekFrom::Start(args.offset))
        .map_err(crate::session::Error::action)?;

    let mut file = file.take(match args.len {
        Some(len) => u64::from(len),
        None => u64::MAX,
    });

    let mut hasher = sha2::Sha256::new();
    loop {
        let buf = match file.fill_buf() {
            Ok(buf) if buf.is_empty() => break,
            Ok(buf) => buf,
            Err(error) => return Err(crate::session::Error::action(error)),
        };
        hasher.update(&buf[..]);

        let buf_len = buf.len();
        file.consume(buf_len);
    }
    let sha256 = <[u8; 32]>::from(hasher.finalize());

    let len = file.stream_position()
        .map_err(crate::session::Error::action)?;

    session.reply(Item {
        path: args.path,
        offset: args.offset,
        len,
        sha256,
    })?;

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_file_sha256::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let path = PathBuf::try_from(proto.take_path())
            .map_err(|error| ParseArgsError::invalid_field("path", error))?;

        Ok(Args {
            path,
            offset: proto.offset(),
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
            offset: 0,
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
            offset: u64::try_from("<ignore me>".len()).unwrap(),
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
    fn handle_len() {
        let mut tempfile = tempfile::NamedTempFile::new()
            .unwrap();

        use std::io::Write as _;
        tempfile.as_file_mut().write_all(b"hello\n<ignore me>")
            .unwrap();

        let args = Args {
            path: tempfile.path().to_path_buf(),
            offset: 0,
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
            offset: 0,
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
