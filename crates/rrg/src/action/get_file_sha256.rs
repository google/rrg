// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::path::PathBuf;

pub struct Args {
    path: PathBuf,
}

struct Item {
    path: PathBuf,
    sha256: [u8; 32],
}

pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use sha2::Digest as _;

    let mut file = match std::fs::File::open(&args.path) {
        Ok(file) => std::io::BufReader::new(file),
        Err(error) => return Err(crate::session::Error::action(error)),
    };

    let mut hasher = sha2::Sha256::new();
    loop {
        use std::io::BufRead as _;

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

    session.reply(Item {
        path: args.path,
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
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_file_sha256::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = rrg_proto::get_file_sha256::Result::new();
        proto.set_path(self.path.into());
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
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempfile.path());
        assert_eq!(item.sha256, [
            // Pre-computed by the `sha256sum` tool.
            0x58, 0x91, 0xb5, 0xb5, 0x22, 0xd5, 0xdf, 0x08,
            0x6d, 0x0f, 0xf0, 0xb1, 0x10, 0xfb, 0xd9, 0xd2,
            0x1b, 0xb4, 0xfc, 0x71, 0x63, 0xaf, 0x34, 0xd0,
            0x82, 0x86, 0xa2, 0xe8, 0x46, 0xf6, 0xbe, 0x03,
        ]);
    }
}
