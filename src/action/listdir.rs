// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the list directory action.
//!
//! A list directory action stats all files in the provided directory.

use crate::session::{self, Session};
use rrg_proto::{ListDirRequest, StatEntry, path_spec::PathType,
                path_spec::Options, micros};

use std::fs::{self, Metadata};
use std::path::{PathBuf, Path};
use std::fmt::{Display, Formatter};
use log::warn;
use std::time::SystemTime;

/// An error type for failures that can occur during the listdir action.
#[derive(Debug)]
enum Error {
    /// A failure occurred during the attempt to list a directory.
    ListDir(std::io::Error),
}

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            ListDir(ref error) => Some(error),
        }
    }
}

impl Display for Error {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        use Error::*;

        match *self {
            ListDir(ref error) => {
                write!(fmt, "unable to list directory: {}", error)
            }
        }
    }
}

impl From<Error> for session::Error {

    fn from(error: Error) -> session::Error {
        session::Error::action(error)
    }
}

/// A response type for the list directory action.
pub struct Response {
    path: PathBuf,
    metadata: Metadata,
}

/// A request type for the list directory action.
pub struct Request {
    path: PathBuf,
}

/// Returns the last access time of provided `Metadata`.
fn get_access_time(metadata: &Metadata) -> Option<SystemTime> {
    match metadata.accessed() {
        Ok(atime) => Some(atime),
        Err(err) => {
            warn!("unable to get last access time: {}", err);
            None
        }
    }
}

/// Returns the last modification time of provided `Metadata`.
fn get_modification_time(metadata: &Metadata) -> Option<SystemTime> {
    match metadata.modified() {
        Ok(mtime) => Some(mtime),
        Err(err) => {
            warn!("unable to get last modification time: {}", err);
            None
        }
    }
}

/// Returns the creation time of provided `Metadata`.
fn get_creation_time(metadata: &Metadata) -> Option<SystemTime> {
    match metadata.created() {
        Ok(btime) => Some(btime),
        Err(err) => {
            warn!("unable to get creation time: {}", err);
            None
        }
    }
}

/// Returns the last status change time of provided `Metadata`.
#[cfg(target_os = "linux")]
fn get_status_change_time(metadata: &Metadata) -> Option<SystemTime> {
    use std::time::{Duration, UNIX_EPOCH};
    use std::os::unix::fs::MetadataExt;

    UNIX_EPOCH.checked_add(Duration::from_secs(metadata.ctime() as u64))
}

/// Reads a symbolic link, returning the path to the file that the link points to.
#[cfg(target_os = "linux")]
fn get_symlink(metadata: &Metadata, file_path: &Path) -> Option<PathBuf> {
    if !metadata.file_type().is_symlink() { return None; }

    match fs::read_link(file_path) {
        Ok(file) => Some(file),
        Err(error) => {
            warn!("unable to read symlink: {}", error);
            None
        }
    }
}

/// Fills all fields of `Response` using path to the file.
fn fill_response(file_path: &Path) -> Result<Response, Error> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(file_path)
        .map_err(Error::ListDir)?;

    Ok(Response {
        path: file_path.to_path_buf(),
        metadata: metadata,
    })
}

pub fn handle<S>(session: &mut S, request: Request) -> session::Result<()>
where
    S: Session,
{
    let entries = crate::fs::list_dir(&request.path)
        .map_err(Error::ListDir)?;

    for entry in entries {
        session.reply(Response {
            path: entry.path,
            metadata: entry.metadata,
        })?;
    }

    Ok(())
}

/// Fills `st_linux_flags` field.
#[cfg(target_os = "linux")]
fn get_linux_flags(path: &Path) -> Option<u32> {
    use std::os::raw::c_long;
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return None,
    };
    let mut linux_flags: c_long = 0;
    let linux_flags_ptr: *mut c_long = &mut linux_flags;
    unsafe {
        match ioctls::fs_ioc_getflags(file.as_raw_fd(), linux_flags_ptr) {
            0 => Some(linux_flags as u32),
            _ => None,
        }
    }
}

impl super::Request for Request {

    type Proto = ListDirRequest;

    fn from_proto(proto: Self::Proto) -> Result<Request, session::ParseError> {
        use std::convert::TryInto as _;

        let path = proto.pathspec
            .ok_or(session::MissingFieldError::new("path spec"))?
            .try_into().map_err(session::ParseError::malformed)?;

        Ok(Request {
            path: path,
        })
    }
}

/// Converts idiomatic `SystemTime` to `u64` for the protocol buffer.
fn get_time_since_unix_epoch(sys_time: &Option<SystemTime>) -> Option<u64> {
    match sys_time {
        Some(time) => match micros(*time) {
            Ok(time) => Some(time),
            Err(error) => {
                warn!("failed to convert time: {}", error);
                None
            }
        }
        None => None,
    }
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("StatEntry");

    type Proto = StatEntry;

    fn into_proto(self) -> Self::Proto {
        use rrg_proto::convert::IntoLossy as _;

        StatEntry {
            pathspec: Some(self.path.into()),
            ..self.metadata.into_lossy()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Request;
    use tempfile::tempdir;

    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt;

    /// Fills `ListDirRequest` with provided fields.
    fn fill_proto_request(path_options: Option<i32>,
                          pathtype: Option<i32>,
                          path: Option<String>) -> ListDirRequest {
        ListDirRequest {
            pathspec: Some(rrg_proto::PathSpec {
                path_options,
                pathtype,
                path,
                ..Default::default()
            }),
            iterator: None,
        }
    }

    #[test]
    fn test_empty_pathspec_field() {
        let request: Result<super::Request, _> =
            Request::from_proto(ListDirRequest {
                pathspec: None,
                iterator: None,
            });
        assert!(request.is_err());
    }

    #[test]
    fn test_empty_path_options() {
        let request: Result<super::Request, _> = Request::from_proto(
            fill_proto_request(None, Some(PathType::Os as i32),
                               Some(String::from("/"))));
        assert!(request.is_ok());
    }

    #[test]
    fn test_ok_path_options() {
        let request: Result<super::Request, _> = Request::from_proto(
            fill_proto_request(Some(Options::CaseLiteral as i32),
                               Some(PathType::Os as i32),
                               Some(String::from("/"))));
        assert!(request.is_ok());
    }

    #[test]
    fn test_unset_pathtype() {
        let request: Result<super::Request, _> = Request::from_proto(
            fill_proto_request(None, Some(PathType::Unset as i32),
                               Some(String::from("/"))));
        assert!(request.is_err());
    }

    #[test]
    fn test_unsupported_pathtype() {
        let request: Result<super::Request, _> = Request::from_proto(
            fill_proto_request(None, Some(PathType::Tsk as i32),
                               Some(String::from("/"))));
        assert!(request.is_err());
    }

    #[test]
    fn test_empty_path() {
        let request: Result<super::Request, _> = Request::from_proto(
            fill_proto_request(None, Some(PathType::Os as i32), None));
        assert!(request.is_err());
    }

    #[test]
    fn test_empty_dir() {
        let dir = tempdir().unwrap();
        let request = super::Request {
            path: PathBuf::from(dir.path()),
        };
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());
        assert_eq!(session.reply_count(), 0);
    }

    #[test]
    fn test_nonexistent_path() {
        let dir = tempdir().unwrap();
        let request = super::Request {
            path: PathBuf::from(dir.path().join("nonexistent_subdir")),
        };
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_err());
    }

    #[test]
    fn test_lexicographical_order() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path();
        std::fs::File::create(dir_path.join("юникод")).unwrap();
        std::fs::File::create(dir_path.join("unicode")).unwrap();
        std::fs::File::create(dir_path.join("file")).unwrap();
        std::fs::File::create(dir_path.join("afile")).unwrap();
        std::fs::File::create(dir_path.join("Datei")).unwrap();
        std::fs::File::create(dir_path.join("snake_case")).unwrap();
        std::fs::File::create(dir_path.join("CamelCase")).unwrap();
        let request = super::Request {
            path: PathBuf::from(&dir_path),
        };
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());

        let mut replies = session.replies().collect::<Vec<&Response>>();
        replies.sort_by_key(|reply| reply.path.clone());

        assert_eq!(replies.len(), 7);
        assert_eq!(&replies[0].path,
                   &dir_path.join("CamelCase"));
        assert_eq!(&replies[1].path,
                   &dir_path.join("Datei"));
        assert_eq!(&replies[2].path,
                   &dir_path.join("afile"));
        assert_eq!(&replies[3].path,
                   &dir_path.join("file"));
        assert_eq!(&replies[4].path,
                   &dir_path.join("snake_case"));
        assert_eq!(&replies[5].path,
                   &dir_path.join("unicode"));
        assert_eq!(&replies[6].path,
                   &dir_path.join("юникод"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_dir_response() {
        use std::os::linux::fs::MetadataExt as _;

        let dir = tempdir().unwrap();
        let dir_path = dir.path();
        let inner_dir_path = &dir_path.join("dir");
        std::fs::create_dir(&inner_dir_path).unwrap();
        let request = super::Request {
            path: PathBuf::from(&dir_path),
        };
        let mut session = session::test::Fake::new();
        handle(&mut session, request).unwrap();
        assert_eq!(session.reply_count(), 1);
        let inner_dir = &session.reply::<Response>(0);
        assert_eq!(&inner_dir.path, inner_dir_path);
        assert_eq!(inner_dir.metadata.uid(), users::get_current_uid());
        assert_eq!(inner_dir.metadata.gid(), users::get_current_gid());
        assert_eq!(inner_dir.metadata.dev(),
                   dir_path.metadata().unwrap().dev());
        assert_eq!(inner_dir.metadata.mode() & 0o40000, 0o40000);
        assert_eq!(inner_dir.metadata.nlink(), 2);

        assert!(inner_dir.metadata.accessed().unwrap() <= SystemTime::now());
        assert!(inner_dir.metadata.modified().unwrap() <= SystemTime::now());
        assert!(inner_dir.metadata.created().unwrap() <= SystemTime::now());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_symlink_response() {
        use std::os::linux::fs::MetadataExt as _;

        let dir = tempdir().unwrap();
        let dir_path = dir.path();
        let file_path = dir_path.join("file");
        std::fs::File::create(&file_path).unwrap();
        let sl_path = dir_path.join("symlink");
        std::os::unix::fs::symlink(&file_path, &sl_path).unwrap();
        let request = super::Request {
            path: PathBuf::from(&dir_path),
        };
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());

        let mut replies = session.replies().collect::<Vec<&Response>>();
        replies.sort_by_key(|reply| reply.path.clone());

        assert_eq!(replies.len(), 2);
        let symlink = replies[1];
        assert_eq!(&symlink.path, &sl_path);
        assert_eq!(symlink.metadata.mode() & 0o120000, 0o120000);
        assert_eq!(symlink.metadata.nlink(), 1);
        assert!(symlink.metadata.accessed().unwrap() <= SystemTime::now());
        assert!(symlink.metadata.modified().unwrap() <= SystemTime::now());
        assert!(symlink.metadata.created().unwrap() <= SystemTime::now());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_file_response_linux() {
        use std::os::linux::fs::MetadataExt as _;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let dir_path = dir.path();
        let file_path = dir_path.join("file");
        std::fs::File::create(&file_path).unwrap();
        std::fs::set_permissions(&file_path,
                                 PermissionsExt::from_mode(0o664)).unwrap();
        let request = super::Request {
            path: PathBuf::from(&dir_path),
        };
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());
        assert_eq!(session.reply_count(), 1);
        let file = &session.reply::<Response>(0);
        assert_eq!(file.path, file_path);
        assert_eq!(file.metadata.size(), 0);
        assert_eq!(file.metadata.mode(), 0o100664);
        assert_eq!(file.metadata.uid(), users::get_current_uid());
        assert_eq!(file.metadata.gid(), users::get_current_gid());
        assert_eq!(file.metadata.dev(),
                   dir_path.metadata().unwrap().dev());
        assert_eq!(file.metadata.nlink(), 1);
        assert!(file.metadata.accessed().unwrap() <= SystemTime::now());
        assert!(file.metadata.modified().unwrap() <= SystemTime::now());
        assert!(file.metadata.created().unwrap() <= SystemTime::now());
    }

    #[test]
    fn test_file_response() {
        use std::os::linux::fs::MetadataExt as _;

        let dir = tempdir().unwrap();
        let dir_path = dir.path();
        let file_path = dir_path.join("file");
        std::fs::File::create(&file_path).unwrap();
        let request = super::Request {
            path: PathBuf::from(&dir_path),
        };
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());
        assert_eq!(session.reply_count(), 1);
        let file = &session.reply::<Response>(0);
        assert_eq!(file.path, file_path);
        assert_eq!(file.metadata.size(), 0);
        assert!(file.metadata.accessed().unwrap() <= SystemTime::now());
        assert!(file.metadata.modified().unwrap() <= SystemTime::now());
        assert!(file.metadata.created().unwrap() <= SystemTime::now());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_st_flags_linux() {
        use std::os::linux::fs::MetadataExt as _;

        let dir = tempdir().unwrap();
        let dir_path = dir.path();
        let file_path = dir_path.join("file");
        std::fs::File::create(&file_path).unwrap();
        let request = super::Request {
            path: PathBuf::from(&dir_path),
        };
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());
        assert_eq!(session.reply_count(), 1);
        let file = &session.reply::<Response>(0);
        assert_eq!(file.path, file_path);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_flags_non_existing_path() {
        let path_buf = PathBuf::from("some non existing path");
        assert!(get_linux_flags(&path_buf).is_none());
    }

    #[test]
    fn test_unicode_paths() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path();
        std::fs::File::create(dir_path.join("❤ℝℝG❤")).unwrap();
        std::fs::File::create(dir_path.join("файл")).unwrap();
        std::fs::File::create(dir_path.join("ファイル")).unwrap();
        std::fs::File::create(dir_path.join("αρχείο")).unwrap();
        std::fs::File::create(dir_path.join("फ़ाइल")).unwrap();
        let request = super::Request {
            path: PathBuf::from(&dir_path),
        };
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());
        assert_eq!(session.reply_count(), 5);
        let file = &session.reply::<Response>(0);
        assert_eq!(file.metadata.size(), 0);
        assert!(file.metadata.accessed().unwrap() <= SystemTime::now());
        assert!(file.metadata.modified().unwrap() <= SystemTime::now());
        assert!(file.metadata.created().unwrap() <= SystemTime::now());
        let file = &session.reply::<Response>(1);
        assert_eq!(file.metadata.size(), 0);
        assert!(file.metadata.accessed().unwrap() <= SystemTime::now());
        assert!(file.metadata.modified().unwrap() <= SystemTime::now());
        assert!(file.metadata.created().unwrap() <= SystemTime::now());
        let file = &session.reply::<Response>(2);
        assert_eq!(file.metadata.size(), 0);
        assert!(file.metadata.accessed().unwrap() <= SystemTime::now());
        assert!(file.metadata.modified().unwrap() <= SystemTime::now());
        assert!(file.metadata.created().unwrap() <= SystemTime::now());
        let file = &session.reply::<Response>(3);
        assert_eq!(file.metadata.size(), 0);
        assert!(file.metadata.accessed().unwrap() <= SystemTime::now());
        assert!(file.metadata.modified().unwrap() <= SystemTime::now());
        assert!(file.metadata.created().unwrap() <= SystemTime::now());
        let file = &session.reply::<Response>(4);
        assert_eq!(file.metadata.size(), 0);
        assert!(file.metadata.accessed().unwrap() <= SystemTime::now());
        assert!(file.metadata.modified().unwrap() <= SystemTime::now());
        assert!(file.metadata.created().unwrap() <= SystemTime::now());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_fill_response_nonexistent_path() {
        let dir = tempdir().unwrap();
        let nonexistent_path = PathBuf::from(dir.path()
            .join("nonexistent_subdir"));
        assert!(!nonexistent_path.exists());
        assert!(fill_response(&nonexistent_path).is_err());
    }
}
