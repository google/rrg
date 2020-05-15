// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the list directory action.

use crate::session::{self, Session};
use rrg_proto::{ListDirRequest, StatEntry};

use ioctls;
use std::fs::{self, File};
use std::path::PathBuf;
use std::os::raw::c_long;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
enum Error {
    MissingFieldError(String),
    ReadPathError(std::io::Error),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            MissingFieldError(ref _field) => None,
            ReadPathError(ref error) => Some(error),
        }
    }
}

impl Display for Error {
    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        use Error::*;

        match *self {
            MissingFieldError(ref field) => {
                write!(fmt, "{} field should be filled", field)
            }
            ReadPathError(ref error) => {
                write!(fmt, "Unable to read path: {}", error)
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
    st_mode: u64,
    st_ino: u32,
    st_dev: u32,
    st_nlink: u32,
    st_uid: u32,
    st_gid: u32,
    st_size: u64,
    st_atime: u64,
    st_mtime: u64,
    st_ctime: u64,
    st_blocks: u32,
    st_blksize: u32,
    st_rdev: u32,
    st_flags_linux: u32,
    symlink: Option<String>,
    pathspec: PathSpec,
}

/// A request type for the list directory action.
pub struct Request {
    pathspec: PathSpec,
}

enum PathType {
    Unset,
    OS,
    TSK,
    Registry,
    TMPFile,
    NTFS,
}

enum PathOption {
    CaseInsensitive,
    CaseLiteral,
    Regex,
    Recursive,
}

struct PathSpec {
    path_options: Option<PathOption>,
    pathtype: PathType,
    path: PathBuf,
}

pub fn handle<S: Session>(session: &mut S, request: Request)
                          -> session::Result<()> {
    let dir_path = &request.pathspec.path;
    // In case if Result<DirEntry> matches the error branch, we won't give
    // any info about that file, but other info isn't effected:
    let (dir_entries, _): (Vec<_>, Vec<_>) = match dir_path.read_dir() {
        Ok(dir_iter) => dir_iter,
        Err(error) =>
            return Err(session::Error::from(Error::ReadPathError(error))),
    }.partition(Result::is_ok);
    // Code won't panic because of unwrap(). We made the partition above
    let mut paths: Vec<PathBuf> = dir_entries.into_iter().map(Result::unwrap)
        .map(|entry| entry.path()).collect();
    paths.sort();
    for file_path in &paths {
        let umetadata = match fs::symlink_metadata(file_path) {
            Ok(metadata) => metadata,
            Err(error) =>
                return Err(session::Error::from(Error::ReadPathError(error))),
        };
        session.reply(Response {
            st_mode: umetadata.mode().into(),
            st_ino: umetadata.ino() as u32,
            st_dev: umetadata.dev() as u32,
            st_nlink: umetadata.nlink() as u32,
            st_uid: umetadata.uid() as u32,
            st_gid: umetadata.gid() as u32,
            st_size: umetadata.size(),
            st_atime: umetadata.atime() as u64,
            st_mtime: umetadata.mtime() as u64,
            st_ctime: umetadata.ctime() as u64,
            st_blocks: umetadata.blocks() as u32,
            st_blksize: umetadata.blksize() as u32,
            st_rdev: umetadata.rdev() as u32,
            st_flags_linux:
            get_linux_flags(file_path).unwrap_or_default() as u32,
            symlink: match umetadata.file_type().is_symlink() {
                true => match fs::read_link(file_path) {
                    Ok(file) => Some(file.to_string_lossy().to_string()),
                    _ => None,
                }
                false => None
            },
            pathspec: PathSpec {
                path_options: Some(PathOption::CaseLiteral),
                pathtype: PathType::OS,
                path: file_path.clone(),
            },
        })?;
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

/// Converts integer from proto to human-readable enum type
fn get_enum_path_type(option: &Option<i32>) -> Option<PathType> {
    match option {
        Some(ptype) => match ptype {
            -1 => Some(PathType::Unset),
            0 => Some(PathType::OS),
            1 => Some(PathType::TSK),
            2 => Some(PathType::Registry),
            3 => Some(PathType::TMPFile),
            4 => Some(PathType::NTFS),
            _ => None,
        },
        _ => None,
    }
}

fn get_path(path: &Option<String>) -> PathBuf {
    match path {
        Some(string_path) => {
            if string_path.is_empty() {
                PathBuf::from("/")
            } else {
                PathBuf::from(string_path)
            }
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
        };
    }
    Some(linux_flags)
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

/// Converts enum type back to integer to pass to the proto
fn get_int_path_type(pathspec: &PathSpec) -> Option<i32> {
    match pathspec.pathtype {
        PathType::Unset => Some(-1),
        PathType::OS => Some(0),
        PathType::TSK => Some(1),
        PathType::Registry => Some(2),
        PathType::TMPFile => Some(3),
        PathType::NTFS => Some(4),
    }
}

impl super::Request for Request {
    type Proto = ListDirRequest;

    fn from_proto(proto: Self::Proto) -> Result<Request, session::ParseError> {
        Ok(Request {
            pathspec: match proto.pathspec {
                Some(pathspec) => PathSpec {
                    path_options:
                    get_enum_path_options(&pathspec.path_options),
                    pathtype: match
                    get_enum_path_type(&pathspec.pathtype) {
                        Some(path_type) => path_type,
                        None => return
                            Err(session::ParseError::malformed
                                (Error::MissingFieldError
                                    (String::from("path type"))))
                    },
                    path: get_path(&pathspec.path),
                },
                None => return Err(session::ParseError::malformed
                    (Error::MissingFieldError
                        (String::from("pathspec")))),
            }
        })
    }
}

impl super::Response for Response {
    const RDF_NAME: Option<&'static str> = Some("StatEntry");

    type Proto = StatEntry;

    fn into_proto(self) -> Self::Proto {
        StatEntry {
            st_mode: Some(self.st_mode),
            st_ino: Some(self.st_ino),
            st_dev: Some(self.st_dev),
            st_nlink: Some(self.st_nlink),
            st_uid: Some(self.st_uid),
            st_gid: Some(self.st_gid),
            st_size: Some(self.st_size),
            st_atime: Some(self.st_atime),
            st_mtime: Some(self.st_mtime),
            st_ctime: Some(self.st_ctime),
            st_blocks: Some(self.st_blocks),
            st_blksize: Some(self.st_blksize),
            st_rdev: Some(self.st_rdev),
            st_flags_osx: None,
            st_flags_linux: Some(self.st_flags_linux),
            symlink: match self.symlink {
                Some(s) => Some(s),
                None => None
            },
            registry_type: None,
            resident: None,
            pathspec: Some(rrg_proto::PathSpec {
                path_options: get_int_path_options(&self.pathspec),
                pathtype: get_int_path_type(&self.pathspec),
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
