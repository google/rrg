// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Arguments of the `store_filestore_part` action.
pub struct Args {
    file_id: String,
    file_sha256: [u8; 32],
    file_len: u64,
    part_offset: u64,
    part_content: Vec<u8>,
}

/// Result of the `store_filestore_part` action.
pub struct Item {
    file_id: String,
    status: crate::filestore::Status,
}

/// Handles invocations of the `store_filestore_part` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let status = session.filestore_store(args.file_sha256, crate::filestore::Part {
        offset: args.part_offset,
        content: args.part_content,
        file_len: args.file_len,
    })?;

    session.reply(Item {
        file_id: args.file_id,
        status,
    })?;

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::store_filestore_part::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        let file_id = proto.take_file_id();
        let file_sha256 = <[u8; 32]>::try_from(&proto.take_file_sha256()[..])
            .map_err(|error| crate::request::ParseArgsError::invalid_field(
                "file_sha256",
                error,
            ))?;
        let file_len = proto.file_size();

        let part_offset = proto.part_offset();
        let part_content = proto.take_part_content();

        Ok(Args {
            file_id,
            file_sha256,
            file_len,
            part_offset,
            part_content,
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::store_filestore_part::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = Self::Proto::new();
        proto.set_file_id(self.file_id);
        proto.set_status(match self.status {
            crate::filestore::Status::Complete => {
                rrg_proto::store_filestore_part::Status::COMPLETE
            }
            crate::filestore::Status::Pending { .. } => {
                rrg_proto::store_filestore_part::Status::PENDING
            }
        });

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn handle_complete() {
        let mut session = crate::session::FakeSession::new()
            .with_filestore();

        let args = Args {
            file_id: String::from("foo"),
            file_sha256: sha256(b"BARBAZ"),
            file_len: b"BARBAZ".len() as u64,
            part_offset: 0,
            part_content: b"BARBAZ".to_vec(),
        };
        assert!(handle(&mut session, args).is_ok());
        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.file_id, "foo");
        assert_eq!(item.status, crate::filestore::Status::Complete);
    }

    #[test]
    fn handle_pending() {
        let mut session = crate::session::FakeSession::new()
            .with_filestore();

        let args = Args {
            file_id: String::from("foo"),
            file_sha256: sha256(b"BARBAZ"),
            file_len: b"BARBAZ".len() as u64,
            part_offset: 0,
            part_content: b"BAR".to_vec(),
        };
        assert!(handle(&mut session, args).is_ok());
        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.file_id, "foo");
        assert_eq!(item.status, crate::filestore::Status::Pending {
            offset: b"BAR".len() as u64,
            len: b"BAZ".len() as u64,
        });
    }

    fn sha256(content: &[u8]) -> [u8; 32] {
        use sha2::Digest as _;

        let mut sha256 = sha2::Sha256::new();
        sha256.update(content);
        sha256.finalize()
            .into()
    }
}
