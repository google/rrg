// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Utilities for abort reporting.

/// Handle to a file with persisted request for abort recovery.
///
/// This is created with the [`create_request_file`] function and should be used
/// by request processing logic.
#[derive(Debug)]
pub struct RequestFileCreated {
    /// Path to the request file.
    path: std::path::PathBuf,
    /// Created request file (used to hold the lock).
    file: std::fs::File,
}

/// Persists given request information at the specified path.
///
/// Once request processing is finished, [`RequestFileCreated::remove`] should
/// be called to cleanup the file. If the cleanup is not called (e.g. due to
/// panic or other unexpected abortion), future agent startup will pickup the
/// file (with [`open_request_file`]) and report the problem to the server.
pub fn create_request_file<P: AsRef<std::path::Path>>(
    path: P,
    request_id: crate::RequestId,
) -> std::io::Result<RequestFileCreated> {
    let path = path.as_ref();

    // TODO(@panhania): We should make this file "private" (similar to what
    // we do with filestore directories).
    let mut file = std::fs::File::create_new(path)?;

    let mut request_proto = rrg_proto::abort::Request::new();
    request_proto.set_flow_id(request_id.flow_id());
    request_proto.set_request_id(request_id.request_id());

    use protobuf::Message as _;
    request_proto.write_to_writer(&mut file)
        .map_err(std::io::Error::other)?;

    file.sync_all()?;
    file.lock()?;

    Ok(RequestFileCreated {
        path: path.to_path_buf(),
        file,
    })
}

impl RequestFileCreated {

    /// Removes the persisted request information from the filesystem.
    ///
    /// This should be only used if the request processing has been finished.
    pub fn remove(self) -> std::io::Result<()> {
        // TODO(@panhania): Still attempt to delete the file even if unlock
        // fails.
        self.file.unlock()?;
        drop(self.file);

        std::fs::remove_file(&self.path)?;

        Ok(())
    }
}

/// Handle to a file with persisted request for abort recovery.
///
/// This is created with the [`open_request_file`] function and should be used
/// by the agent startup logic.
#[derive(Debug)]
pub struct RequestFileOpened {
    /// Path the the request file.
    path: std::path::PathBuf,
    /// An identifier of the flow issuing the request.
    flow_id: u64,
    /// A server-issued identifier of the request (unique within the flow).
    request_id: u64,
    /// Time at which the request was received.
    request_time: std::time::SystemTime,
}

/// Opens previously persisted (if not deleted) request information from the
/// specified path.
///
/// This should be called during the agent startup to verify that no requests
/// were abort. In that case, [`std::io::ErrorKind::NotFound`] is returned.
/// Otherwise, the [`RequestFileOpened::abort`] should be used to send the
/// abort information to the GRR server.
///
/// Once the information is sent, [`RequestFileOpened::remove`] should be used
/// to cleanup the file. Otherwise, future agent startups will pickup the file
/// again.
pub fn open_request_file<P: AsRef<std::path::Path>>(
    path: P,
) -> std::io::Result<RequestFileOpened> {
    let path = path.as_ref();

    let mut file = std::fs::File::open(path)?;

    use protobuf::Message as _;
    let request_proto = rrg_proto::abort::Request::parse_from_reader(&mut file)
        .map_err(|error| std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error,
        ))?;

    let request_time = file.metadata().and_then(|metadata| metadata.modified())
        .unwrap_or_else(|error| {
            log::error! {
                "could not retrieve time for '{}': {error}",
                path.display(),
            };
            std::time::UNIX_EPOCH
        });

    Ok(RequestFileOpened {
        path: path.to_path_buf(),
        flow_id: request_proto.flow_id(),
        request_id: request_proto.request_id(),
        request_time,
    })
}

impl RequestFileOpened {

    /// Returns the information about the abort retrieved from the file.
    pub fn abort(&self) -> Abort {
        Abort {
            flow_id: self.flow_id,
            request_id: self.request_id,
            request_time: self.request_time,
            startup_time: std::time::SystemTime::now(),
        }
    }

    /// Removes the persisted request information from the filesystem.
    ///
    /// This should be only used if the abort information has been sent.
    pub fn remove(self) -> std::io::Result<()> {
        std::fs::remove_file(&self.path)?;

        Ok(())
    }
}

/// Information about the agent abort.
pub struct Abort {
    /// An identifier of the flow issuing the request.
    flow_id: u64,
    /// A server-issued identifier of the request (unique within the flow).
    request_id: u64,
    /// Time at which the request was received.
    request_time: std::time::SystemTime,
    /// Time at which the agent started and noticed the abortion.
    startup_time: std::time::SystemTime,
}

impl crate::response::Item for Abort {

    type Proto = rrg_proto::abort::Abort;

    fn into_proto(self) -> rrg_proto::abort::Abort {
        let mut proto = rrg_proto::abort::Abort::new();
        proto.set_flow_id(self.flow_id);
        proto.set_request_id(self.request_id);
        proto.set_request_time(self.request_time.into());
        proto.set_startup_time(self.startup_time.into());

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn no_abort() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let request_file_path = tempdir.path().join("foo");

        let request_id = crate::RequestId {
            flow_id: rand::random(),
            request_id: rand::random(),
        };

        let request_file_path_copy = request_file_path.clone();
        std::thread::spawn(move || {
            let request_file = create_request_file(request_file_path_copy, request_id)
                .unwrap();

            if false {
                panic!();
            }

            request_file.remove()
                .unwrap();
        }).join().unwrap();

        // The thread did not panic, so there should be no request file.
        let error = open_request_file(&request_file_path)
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn aborted() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let request_file_path = tempdir.path().join("foo");

        let request_id = crate::RequestId {
            flow_id: rand::random(),
            request_id: rand::random(),
        };

        let request_file_path_copy = request_file_path.clone();
        std::thread::spawn(move || {
            let request_file = create_request_file(request_file_path_copy, request_id)
                .unwrap();

            if true {
                panic!();
            }

            request_file.remove()
                .unwrap();
        }).join().unwrap_err();

        // The thread panicked, so we can retrieve the request file as it should
        // not be removed.
        let request_file = open_request_file(&request_file_path)
            .unwrap();

        assert_eq!(request_file.flow_id, request_id.flow_id());
        assert_eq!(request_file.request_id, request_id.request_id());
        // We cannot use more concrete timestamps (e.g. before and after the
        // computation thread was started) because the filesystem clock and the
        // system time might not be in a perfect sync.
        assert!(request_file.request_time >= std::time::UNIX_EPOCH);

        request_file.remove()
            .unwrap();

        assert!(!std::fs::exists(&request_file_path).unwrap());
    }
}
