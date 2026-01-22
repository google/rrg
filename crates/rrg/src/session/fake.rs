use std::any::Any;

use crate::Sink;

/// A session implementation intended to be used in tests.
///
/// Testing actions with normal session objects can be quite hard, since
/// they communicate with the outside world (through Fleetspeak). Since we
/// want to keep the tests minimal and not waste resources on unneeded I/O,
/// using real sessions is not an option.
///
/// Instead, one can use a `Fake` session. It simply accumulates responses
/// that the action sends and lets the creator inspect them later.
pub struct FakeSession {
    args: crate::args::Args,
    filestore: Option<crate::filestore::Filestore>,
    // We need to keep the temporary directory handle around or otherwise it
    // will be deleted and the filestore object won't be valid anymore.
    filestore_tempdir: Option<tempfile::TempDir>,
    replies: Vec<Box<dyn Any>>,
    parcels: std::collections::HashMap<Sink, Vec<Box<dyn Any>>>,
}

impl FakeSession {

    /// Constructs a new fake session with test default agent arguments.
    pub fn new() -> FakeSession {
        FakeSession::with_args(crate::args::Args {
            heartbeat_rate: std::time::Duration::from_secs(0),
            ping_rate: std::time::Duration::from_secs(0),
            command_verification_key: Some(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng).verifying_key()),
            verbosity: log::LevelFilter::Debug,
            log_to_stdout: false,
            log_to_file: None,
            filestore_dir: None,
            filestore_ttl: std::time::Duration::ZERO,
        })
    }

    /// Constructs a new fake session with the given agent arguments.
    pub fn with_args(args: crate::args::Args) -> FakeSession {
        FakeSession {
            args,
            filestore: None,
            filestore_tempdir: None,
            replies: Vec::new(),
            parcels: std::collections::HashMap::new(),
        }
    }

    /// Enables a filestore through a temporary folder in the fake session.
    pub fn with_filestore(mut self) -> FakeSession {
        let filestore_tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = crate::filestore::init(
            &filestore_tempdir,
            std::time::Duration::MAX,
        ).unwrap();

        self.filestore = Some(filestore);
        self.filestore_tempdir = Some(filestore_tempdir);

        self
    }

    /// Yields the number of replies that this session sent so far.
    pub fn reply_count(&self) -> usize {
        self.replies.len()
    }

    /// Retrieves a reply corresponding to the given id.
    ///
    /// The identifier corresponding to the first response is 0, the second one
    /// is 1 and so on.
    ///
    /// This method will panic if a reply with the specified `id` does not exist
    /// or if it exists but has a wrong type.
    pub fn reply<R>(&self, id: usize) -> &R
    where
        R: crate::response::Item + 'static,
    {
        match self.replies().nth(id) {
            Some(reply) => reply,
            None => panic!("no reply #{}", id),
        }
    }

    /// Constructs an iterator over session replies.
    ///
    /// The iterator will panic (but not immediately) if some reply has an
    /// incorrect type.
    pub fn replies<R>(&self) -> impl Iterator<Item = &R>
    where
        R: crate::response::Item + 'static
    {
        self.replies.iter().map(|reply| {
            reply.downcast_ref().expect("unexpected reply type")
        })
    }

    /// Yields the number of parcels sent so far to the specified sink.
    pub fn parcel_count(&self, sink: Sink) -> usize {
        match self.parcels.get(&sink) {
            Some(parcels) => parcels.len(),
            None => 0,
        }
    }

    /// Retrieves a parcel with the given id sent to a particular sink.
    ///
    /// The identifier corresponding to the first parcel to the particular sink
    /// is 0, to the second one (to the same sink) is 1 and so on.
    ///
    /// This method will panic if a reply with the specified `id` to the given
    /// `sink` does not exist or if it exists but has wrong type.
    pub fn parcel<I>(&self, sink: Sink, id: usize) -> &I
    where
        I: crate::response::Item + 'static,
    {
        match self.parcels(sink).nth(id) {
            Some(parcel) => parcel,
            None => panic!("no parcel #{} for sink '{:?}'", id, sink),
        }
    }

    /// Constructs an iterator over session parcels for the given sink.
    ///
    /// The iterator will panic (but not immediately) if some parcels have an
    /// incorrect type.
    pub fn parcels<I>(&self, sink: Sink) -> impl Iterator<Item = &I>
    where
        I: crate::response::Item + 'static,
    {
        // Since the empty iterator (as defined in the standard library) is a
        // specific type, it cannot be returned in one branch but not in another
        // branch.
        //
        // Instead, we use the fact that `Option` is an iterator and then we
        // squash it with `Iterator::flatten`.
        let parcels = self.parcels.get(&sink).into_iter().flatten();

        parcels.map(move |parcel| match parcel.downcast_ref() {
            Some(parcel) => parcel,
            None => panic!("unexpected parcel type in sink '{:?}'", sink),
        })
    }
}

impl crate::session::Session for FakeSession {

    fn args(&self) -> &crate::args::Args {
        &self.args
    }

    fn reply<I>(&mut self, item: I) -> crate::session::Result<()>
    where
        I: crate::response::Item + 'static,
    {
        self.replies.push(Box::new(item));

        Ok(())
    }

    fn send<I>(&mut self, sink: Sink, item: I) -> crate::session::Result<()>
    where
        I: crate::response::Item + 'static,
    {
        let parcels = self.parcels.entry(sink).or_insert_with(Vec::new);
        parcels.push(Box::new(item));

        Ok(())
    }

    fn heartbeat(&mut self) {
    }

    fn filestore_store(
        &self,
        file_id: &str,
        part: crate::filestore::Part,
    ) -> crate::session::Result<crate::filestore::Status> {
        let filestore = self.filestore.as_ref()
            .ok_or(crate::session::FilestoreUnavailableError)?;

        filestore.store(&crate::filestore::Id {
            flow_id: 0xFA4E,
            file_id: String::from(file_id),
        }, part)
            .map_err(|error| crate::session::Error {
                kind: crate::session::ErrorKind::FilestoreStoreFailure,
                error: Box::new(error),
            })
    }

    fn filestore_path(
        &self,
        file_id: &str,
    ) -> crate::session::Result<std::path::PathBuf> {
        let filestore = self.filestore.as_ref()
            .ok_or(crate::session::FilestoreUnavailableError)?;

        filestore.path(&crate::filestore::Id {
            flow_id: 0xFA4E,
            file_id: String::from(file_id),
        })
            .map_err(|error| crate::session::Error {
                kind: crate::session::ErrorKind::FilestoreInvalidPath,
                error: Box::new(error),
            })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn without_filestore_store() {
        let session = FakeSession::new();

        use crate::session::Session as _;
        let error = session.filestore_store("foo", crate::filestore::Part {
            offset: 0,
            content: b"BARBAZ".to_vec(),
            file_len: b"BARBAZ".len() as u64,
            file_sha256: [0x00; 32],
        }).unwrap_err();
        assert_eq!(error.kind, crate::session::ErrorKind::FilestoreUnavailable);
    }

    #[test]
    fn without_filestore_path() {
        let session = FakeSession::new();

        use crate::session::Session as _;
        let error = session.filestore_path("foo")
            .unwrap_err();
        assert_eq!(error.kind, crate::session::ErrorKind::FilestoreUnavailable);
    }

    #[test]
    fn with_filestore() {
        use crate::session::Session as _;

        let session = FakeSession::new()
            .with_filestore();

        session.filestore_store("foo", crate::filestore::Part {
            offset: 0,
            content: b"BARBAZ".to_vec(),
            file_len: b"BARBAZ".len() as u64,
            file_sha256: [
                0xeb, 0x65, 0x7a, 0x64, 0x57, 0x46, 0xe8, 0xf0,
                0xfe, 0x60, 0xc6, 0x20, 0x1a, 0xf3, 0xab, 0x10,
                0x50, 0x24, 0x16, 0xcc, 0xb1, 0xad, 0x91, 0xad,
                0x42, 0x27, 0xd6, 0xf0, 0x39, 0x2f, 0x77, 0x6d,
            ],
        }).unwrap();

        let path = session.filestore_path("foo")
            .unwrap();

        assert_eq!(std::fs::read(path).unwrap(), b"BARBAZ");
    }
}
