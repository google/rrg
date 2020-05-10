use crate::session::{self, Session, Error};
use rrg_proto::{ListDirRequest, StatEntry};

use ioctls;
use std::fs::{self, File};
use std::path::PathBuf;
use std::os::raw::c_long;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::action(e)
    }
}

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

pub struct Request {
    pathspec: Option<PathSpec>,
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
    pathtype: Option<PathType>,
    path: Option<PathBuf>,
}

pub fn handle<S: Session>(session: &mut S, request: Request)
                          -> session::Result<()> {
    let path = &request.pathspec.unwrap().path.unwrap();
    let mut paths: Vec<_> = path.read_dir().unwrap()
        .map(|entry| entry.unwrap().path()).collect();
    paths.sort();
    for file_path in &paths {
        let umetadata = fs::symlink_metadata(file_path)?;
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
                true => Some(fs::read_link(file_path).
                    unwrap().to_str().unwrap().to_string()),
                false => None
            },
            pathspec: PathSpec {
                path_options: Some(PathOption::CaseLiteral),
                pathtype: Some(PathType::OS),
                path: Some(file_path.clone()),
            },
        })?;
    }
    Ok(())
}

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

fn get_path(path: &Option<String>) -> Option<PathBuf> {
    match path {
        Some(string_path) => Some(PathBuf::from(string_path)),
        _ => None,
    }
}

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

fn get_int_path_options(pathspec: &PathSpec) -> Option<i32> {
    match pathspec.path_options {
        Some(PathOption::CaseInsensitive) => Some(0),
        Some(PathOption::CaseLiteral) => Some(1),
        Some(PathOption::Recursive) => Some(2),
        Some(PathOption::Regex) => Some(3),
        _ => None
    }
}

fn get_int_path_type(pathspec: &PathSpec) -> Option<i32> {
    match pathspec.pathtype {
        Some(PathType::OS) => Some(0),
        Some(PathType::TSK) => Some(1),
        Some(PathType::Registry) => Some(2),
        Some(PathType::TMPFile) => Some(3),
        Some(PathType::NTFS) => Some(4),
        _ => Some(-1),
    }
}

impl super::Request for Request {
    type Proto = ListDirRequest;

    fn from_proto(proto: Self::Proto) -> Self {
        Request {
            pathspec: match proto.pathspec {
                Some(pathspec) =>
                    Some(PathSpec {
                        path_options:
                        get_enum_path_options(&pathspec.path_options),
                        pathtype: get_enum_path_type(&pathspec.pathtype),
                        path: get_path(&pathspec.path),
                    }),
                None => None,
            }
        }
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
                path: Some(self.pathspec.path.unwrap()
                    .to_str().unwrap().to_string()),
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
