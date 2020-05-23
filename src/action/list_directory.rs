// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the list directory action.
//!
//! A list directory action stats all files in the provided directory.

use crate::session::{self, Session};
use rrg_proto::{ListDirRequest, StatEntry};

use ioctls;
use std::fs::{self, File, Metadata};
use std::path::PathBuf;
use std::os::raw::c_long;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::fmt::{Display, Formatter};
use log::warn;

#[derive(Debug)]
enum Error {
    ReadPath(std::io::Error),
}

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            ReadPath(ref error) => Some(error),
        }
    }
}

impl Display for Error {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        use Error::*;

        match *self {
            ReadPath(ref error) => {
                write!(fmt, "unable to read path: {}", error)
            }
        }
    }
}

impl From<Error> for session::Error {

    fn from(error: Error) -> session::Error {
        session::Error::action(error)
    }
}

#[derive(Debug)]
enum ParseError {
    UnsupportedValue(String, String),
}

impl std::error::Error for ParseError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseError::*;

        match *self {
            UnsupportedValue(ref _field, ref _value) => None,
        }
    }
}

impl Display for ParseError {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        use ParseError::*;

        match *self {
            UnsupportedValue(ref field, ref value) => {
                write!(fmt, "value {} in {} field is not supported",
                       value, field)
            }
        }
    }
}

impl From<ParseError> for session::Error {

    fn from(error: ParseError) -> session::Error {
        session::Error::action(error)
    }
}


/// A response type for the list directory action.
pub struct Response {
    mode: u64,
    ino: u32,
    dev: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    size: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    blocks: u32,
    blksize: u32,
    rdev: u32,
    flags_linux: u32,
    symlink: Option<String>,
    pathspec: PathSpec,
}

/// A request type for the list directory action.
pub struct Request {
    pathspec: PathSpec,
}

enum PathOption {
    CaseInsensitive,
    CaseLiteral,
    Regex,
    Recursive,
}

struct PathSpec {
    path_options: Option<PathOption>,
    path: PathBuf,
}

fn fill_response(metadata: &Metadata, file_path: &PathBuf) -> Response {
    Response {
        mode: metadata.mode().into(),
        ino: metadata.ino() as u32,
        dev: metadata.dev() as u32,
        nlink: metadata.nlink() as u32,
        uid: metadata.uid() as u32,
        gid: metadata.gid() as u32,
        size: metadata.size(),
        atime: metadata.atime() as u64,
        mtime: metadata.mtime() as u64,
        ctime: metadata.ctime() as u64,
        blocks: metadata.blocks() as u32,
        blksize: metadata.blksize() as u32,
        rdev: metadata.rdev() as u32,
        flags_linux:
        get_linux_flags(file_path).unwrap_or_default() as u32,
        symlink: if metadata.file_type().is_symlink() {
            match fs::read_link(file_path) {
                Ok(file) => Some(file.to_string_lossy().to_string()),
                Err(error) => {
                    warn!("unable to read symlink: {}", error);
                    None
                },
            }
        } else {
            None
        },
        pathspec: PathSpec {
            path_options: Some(PathOption::CaseLiteral),
            path: file_path.clone(),
        },
    }
}

pub fn handle<S: Session>(session: &mut S, request: Request)
                          -> session::Result<()> {
    let dir_path = &request.pathspec.path;
    let mut paths: Vec<PathBuf> = dir_path.read_dir()
        .map_err(Error::ReadPath)?.filter_map(|entry| entry.ok())
        .map(|entry| entry.path()).collect();
    paths.sort();

    for file_path in &paths {
        let metadata = fs::symlink_metadata(file_path)
            .map_err(Error::ReadPath)?;
        session.reply(fill_response(&metadata, file_path))?;
    }

    Ok(())
}

/// Converts integer from proto to human-readable enum type
fn get_enum_path_options(option: &Option<i32>) -> Option<PathOption> {
    match option {
        Some(poption) => match poption {
            0 => Some(PathOption::CaseInsensitive),
            1 => Some(PathOption::CaseLiteral),
            2 => Some(PathOption::Recursive),
            3 => Some(PathOption::Regex),
            _ => None
        },
        _ => None,
    }
}

fn get_path(path: &Option<String>) -> PathBuf {
    match path {
        Some(string_path) if !string_path.is_empty() => {
            PathBuf::from(string_path)
        }
        _ => PathBuf::from("/"),
    }
}

/// Fills st_linux_flags field
fn get_linux_flags(path: &PathBuf) -> Option<c_long> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return None,
    };
    let mut linux_flags: c_long = 0;
    let linux_flags_ptr: *mut c_long = &mut linux_flags;
    unsafe {
        match ioctls::fs_ioc_getflags(file.as_raw_fd(), linux_flags_ptr) {
            0 => Some(linux_flags),
            _ => None,
        }
    }
}

/// Converts enum type back to integer to pass to the proto
fn get_int_path_options(pathspec: &PathSpec) -> Option<i32> {
    match pathspec.path_options {
        Some(PathOption::CaseInsensitive) => Some(0),
        Some(PathOption::CaseLiteral) => Some(1),
        Some(PathOption::Recursive) => Some(2),
        Some(PathOption::Regex) => Some(3),
        _ => None
    }
}

impl super::Request for Request {

    type Proto = ListDirRequest;

    fn from_proto(proto: Self::Proto) -> Result<Request, session::ParseError> {
        let missing = session::MissingFieldError::new;
        let pathspec = proto.pathspec.ok_or(missing("path spec"))?;
        let path_type = pathspec.pathtype
            .ok_or(missing("path type"))?;
        if path_type != 0 {
            return Err(session::ParseError::malformed
                (ParseError::UnsupportedValue
                    (String::from("path type"), path_type.to_string())));
        }
        Ok(Request {
            pathspec: PathSpec {
                path_options: get_enum_path_options(&pathspec.path_options),
                path: get_path(&pathspec.path),
            }
        })
    }
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("StatEntry");

    type Proto = StatEntry;

    fn into_proto(self) -> Self::Proto {
        StatEntry {
            st_mode: Some(self.mode),
            st_ino: Some(self.ino),
            st_dev: Some(self.dev),
            st_nlink: Some(self.nlink),
            st_uid: Some(self.uid),
            st_gid: Some(self.gid),
            st_size: Some(self.size),
            st_atime: Some(self.atime),
            st_mtime: Some(self.mtime),
            st_ctime: Some(self.ctime),
            st_blocks: Some(self.blocks),
            st_blksize: Some(self.blksize),
            st_rdev: Some(self.rdev),
            st_flags_osx: None,
            st_flags_linux: Some(self.flags_linux),
            symlink: match self.symlink {
                Some(s) => Some(s),
                None => None
            },
            registry_type: None,
            resident: None,
            pathspec: Some(rrg_proto::PathSpec {
                path_options: get_int_path_options(&self.pathspec),
                // represents OS path type (other types are not supported)
                pathtype: Some(0),
                path: Some(self.pathspec.path.to_string_lossy().to_string()),
                mount_point: None,
                stream_name: None,
                file_size_override: None,
                inode: None,
                is_virtualroot: None,
                nested_path: None,
                ntfs_id: None,
                ntfs_type: None,
                offset: None,
                recursion_depth: None,
            }),
            registry_data: None,
            st_crtime: None,
            ext_attrs: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Request;
    use tempfile::tempdir;
    use std::os::unix::fs::PermissionsExt;

    /// Fills ListDirRequest with provided fields
    fn fill_proto_request(path_options: Option<i32>,
                          pathtype: Option<i32>,
                          path: Option<String>) -> ListDirRequest {
        ListDirRequest {
            pathspec: Some(rrg_proto::PathSpec {
                path_options,
                pathtype,
                path,
                mount_point: None,
                stream_name: None,
                file_size_override: None,
                inode: None,
                is_virtualroot: None,
                nested_path: None,
                ntfs_id: None,
                ntfs_type: None,
                offset: None,
                recursion_depth: None,
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
        let request: Result<super::Request, _> = Request::from_proto
            (fill_proto_request(None, Some(0), Some(String::from("/"))));
        assert!(request.is_ok());
    }

    #[test]
    fn test_unset_pathtype() {
        let request: Result<super::Request, _> = Request::from_proto
            (fill_proto_request(None, Some(-1), Some(String::from("/"))));
        assert!(request.is_err());
    }

    #[test]
    fn test_unsupported_pathtype() {
        let request: Result<super::Request, _> = Request::from_proto
            (fill_proto_request(None, Some(1), Some(String::from("/"))));
        assert!(request.is_err());
    }


    #[test]
    fn test_empty_pathtype() {
        let request: Result<super::Request, _> = Request::from_proto
            (fill_proto_request(None, None, Some(String::from("/"))));
        assert!(request.is_err());
    }

    #[test]
    fn test_empty_path() {
        let request: Result<super::Request, _> = Request::from_proto
            (fill_proto_request(None, Some(0), None));
        assert!(&request.is_ok());
        assert_eq!(request.unwrap().pathspec.path, PathBuf::from("/"));
    }

    #[test]
    fn test_empty_dir() {
        let dir = tempdir().unwrap();
        let request = super::Request {
            pathspec: PathSpec {
                path_options: None,
                path: PathBuf::from(dir.path()),
            }
        };
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());
        assert_eq!(session.reply_count(), 0);
    }

    #[test]
    fn test_nonexistent_path() {
        let dir = tempdir().unwrap();
        let request = super::Request {
            pathspec: PathSpec {
                path_options: None,
                path: PathBuf::from(dir.path().join("nonexistent_subdir")),
            }
        };
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_err());
    }

    #[test]
    fn test_lexicographical_order() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path();
        std::fs::File::create(dir_path.join("❤ℝℝG❤")).unwrap();
        std::fs::File::create(dir_path.join("файл")).unwrap();
        std::fs::File::create(dir_path.join("file")).unwrap();
        std::fs::File::create(dir_path.join("Datei")).unwrap();
        std::fs::File::create(dir_path.join("αρχείο")).unwrap();
        std::fs::File::create(dir_path.join("फ़ाइल")).unwrap();
        let request = super::Request {
            pathspec: PathSpec {
                path_options: None,
                path: PathBuf::from(&dir_path),
            }
        };
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());
        assert_eq!(&session.reply::<Response>(0).pathspec.path,
                   &dir_path.join("Datei"));
        assert_eq!(&session.reply::<Response>(1).pathspec.path,
                   &dir_path.join("file"));
        assert_eq!(&session.reply::<Response>(2).pathspec.path,
                   &dir_path.join("αρχείο"));
        assert_eq!(&session.reply::<Response>(3).pathspec.path,
                   &dir_path.join("файл"));
        assert_eq!(&session.reply::<Response>(4).pathspec.path,
                   &dir_path.join("फ़ाइल"));
        assert_eq!(&session.reply::<Response>(5).pathspec.path,
                   &dir_path.join("❤ℝℝG❤"));
    }

    #[test]
    fn test_dir_response() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path();
        let inner_dir_path = &dir_path.join("dir");
        std::fs::create_dir(&inner_dir_path).unwrap();
        let request = super::Request {
            pathspec: PathSpec {
                path_options: None,
                path: PathBuf::from(&dir_path),
            }
        };
        let mut session = session::test::Fake::new();
        handle(&mut session, request).unwrap();
        assert_eq!(session.reply_count(), 1);
        let inner_dir = &session.reply::<Response>(0);
        assert_eq!(&inner_dir.pathspec.path, inner_dir_path);
        assert!(inner_dir.symlink.is_none());
        assert_eq!(inner_dir.uid, users::get_current_uid());
        assert_eq!(inner_dir.gid, users::get_current_uid());
        assert_eq!(inner_dir.dev,
                   dir_path.metadata().unwrap().dev() as u32);
        assert_eq!(inner_dir.mode, 0o40775);
        assert_eq!(inner_dir.nlink, 2);
    }

    #[test]
    fn test_symlink_response() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path();
        let file_path = dir_path.join("file");
        std::fs::File::create(&file_path).unwrap();
        let sl_path = dir_path.join("symlink");
        std::os::unix::fs::symlink(&file_path, &sl_path).unwrap();
        let request = super::Request {
            pathspec: PathSpec {
                path_options: None,
                path: PathBuf::from(&dir_path),
            }
        };
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());
        assert_eq!(session.reply_count(), 2);
        let symlink = &session.reply::<Response>(1);
        assert_eq!(&symlink.pathspec.path, &sl_path);
        assert!(&symlink.symlink.is_some());
        assert_eq!(&symlink.symlink.as_ref().unwrap().as_str(),
                   &file_path.to_str().unwrap());
        assert_eq!(symlink.mode, 0o120777);
        assert_eq!(symlink.nlink, 1);
    }

    #[test]
    fn test_file_response() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path();
        let file_path = dir_path.join("file");
        std::fs::File::create(&file_path).unwrap();
        std::fs::set_permissions(&file_path,
                                 PermissionsExt::from_mode(0o664)).unwrap();
        let request = super::Request {
            pathspec: PathSpec {
                path_options: None,
                path: PathBuf::from(&dir_path),
            }
        };
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());
        assert_eq!(session.reply_count(), 1);
        let file = &session.reply::<Response>(0);
        assert_eq!(file.pathspec.path, file_path);
        assert_eq!(file.size, 0);
        assert_eq!(file.mode, 0o100664);
        assert_eq!(file.uid, users::get_current_uid());
        assert_eq!(file.gid, users::get_current_uid());
        assert_eq!(file.dev,
                   dir_path.metadata().unwrap().dev() as u32);
        assert_eq!(file.nlink, 1);
        assert!(file.symlink.is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_st_flags_linux() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path();
        let file_path = dir_path.join("file");
        std::fs::File::create(&file_path).unwrap();
        let request = super::Request {
            pathspec: PathSpec {
                path_options: None,
                path: PathBuf::from(&dir_path),
            }
        };
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, request).is_ok());
        assert_eq!(session.reply_count(), 1);
        let file = &session.reply::<Response>(0);
        assert_eq!(file.pathspec.path, file_path);
        assert_ne!(file.flags_linux, 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_flags_non_existing_path() {
        let path_buf = PathBuf::from("some non existing path");
        assert!(get_linux_flags(&path_buf).is_none());
    }
}
