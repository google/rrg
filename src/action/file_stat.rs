// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the file stat action.
//!
//! A file stat action responses with stat of a given file

use crate::session::{self, Session, Error};
use rrg_proto::{GetFileStatRequest, StatEntry};

use ioctls;
use std::fs::{self, File, Metadata};
use std::path::PathBuf;
use std::os::raw::c_long;
use std::os::unix::io::AsRawFd;
use xattr;
use log::warn;
use std::time::{SystemTime, UNIX_EPOCH};

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::action(e)
    }
}

pub struct Response {
    mode: Option<u64>,
    inode: Option<u32>,
    device: Option<u32>,
    hard_links: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    size: Option<u64>,
    access_time: Option<SystemTime>,
    modification_time: Option<SystemTime>,
    status_change_time: Option<SystemTime>,
    blocks_number: Option<u32>,
    block_size: Option<u32>,
    represented_device: Option<u32>,
    flags_linux: Option<u32>,
    symlink: Option<String>,
    pathspec: PathSpec,
    extended_attributes: Vec<rrg_proto::stat_entry::ExtAttr>,
}

pub struct Request {
    pathspec: Option<PathSpec>,
    collect_ext_attrs: Option<bool>,
    follow_symlink: Option<bool>,
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
    nested_path: Option<Box<PathSpec>>,
    path_options: Option<PathOption>,
    pathtype: Option<PathType>,
    path: Option<PathBuf>,
}


impl Default for PathSpec {
    fn default() -> PathSpec {
        PathSpec {
            nested_path: None,
            path_options: None,
            pathtype: None,
            path: None,
        }
    }
}

pub fn handle<S: Session>(session: &mut S, request: Request) -> session::Result<()> {
    let original_path = collapse_pathspec(request.pathspec.unwrap());

    let follow_symlink = match request.follow_symlink {
        Some(s) => s,
        None => false,
    };

    let collect_ext_attrs = match request.collect_ext_attrs {
        Some(s) => s,
        None => false,
    };

    let destination = if follow_symlink {
        fs::canonicalize(&original_path)?
    } else {
        original_path.clone()
    };

    let mut response = form_response(&original_path, &destination)?;
    if collect_ext_attrs {
        response.extended_attributes = get_ext_attrs(&destination);
    }

    session.reply(response)?;
    Ok(())
}

fn get_ext_attrs(path: &PathBuf) -> Vec<rrg_proto::stat_entry::ExtAttr> {
    let xattrs = xattr::list(path).unwrap();

    let mut result = vec![];
    for attr in xattrs {
        result.push(rrg_proto::stat_entry::ExtAttr {
            name: Some(attr.to_str().unwrap().as_bytes().to_vec()),
            value: xattr::get(path, attr).unwrap(),
        });
    }
    result
}

fn get_time_option<E: std::fmt::Display>(time: Result<SystemTime, E>) -> Option<SystemTime> {
    match time {
        Ok(time_value) => Some(time_value),
        Err(err) => {
            warn!("Unable to get time value: {}", err);
            None
        }
    }
}

fn get_time_since_unix_epoch(sys_time: &Option<SystemTime>) -> Option<u64> {
    return sys_time.map_or(None, |time| time.duration_since(UNIX_EPOCH)
        .map_or(None, |dur| Some(dur.as_secs())));
}

#[cfg(target_os = "linux")]
fn get_status_change_time(metadata: &Metadata) -> Option<SystemTime> {
    use std::time::Duration;
    use std::os::unix::fs::MetadataExt;

    UNIX_EPOCH.checked_add(Duration::from_secs(metadata.ctime() as u64))
}

#[cfg(target_os = "linux")]
fn form_response(original_path: &PathBuf, destination: &PathBuf)
                 -> Result<Response, std::io::Error> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(destination)?;
    let original_metadata = fs::symlink_metadata(original_path)?;

    Ok(Response {
        mode: Some(metadata.mode() as u64),
        inode: Some(metadata.ino() as u32),
        device: Some(metadata.dev() as u32),
        hard_links: Some(metadata.nlink() as u32),
        uid: Some(metadata.uid() as u32),
        gid: Some(metadata.gid() as u32),
        size: Some(metadata.size() as u64),
        access_time: get_time_option(metadata.accessed()),
        modification_time: get_time_option(metadata.modified()),
        status_change_time: get_status_change_time(&metadata),
        blocks_number: Some(metadata.blocks() as u32),
        block_size: Some(metadata.blksize() as u32),
        represented_device: Some(metadata.rdev() as u32),
        flags_linux: get_linux_flags(destination),

        symlink: match original_metadata.file_type().is_symlink() {
            true => Some(fs::read_link(original_path).
                unwrap().to_str().unwrap().to_string()),
            false => None
        },

        pathspec: PathSpec {
            nested_path: None,
            path_options: Some(PathOption::CaseLiteral),
            pathtype: Some(PathType::OS),
            path: Some(original_path.clone()),
        },

        extended_attributes: vec![],
    })
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

fn collapse_pathspec(pathspec: PathSpec) -> PathBuf {
    fn recursive_collapse(pathspec: PathSpec) -> PathBuf {
        match pathspec.path {
            Some(path) => {
                match pathspec.nested_path {
                    Some(nested_path_box) => path.join(recursive_collapse(*nested_path_box)),
                    None => path,
                }
            }
            None => PathBuf::default()
        }
    }

    let mut result = recursive_collapse(pathspec);
    if !result.has_root() {
        result = PathBuf::from("/").join(result);
    }
    result
}

fn get_path(path: &Option<String>) -> Option<PathBuf> {
    match path {
        Some(string_path) => Some(PathBuf::from(string_path)),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn get_linux_flags(path: &PathBuf) -> Option<u32> {
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

impl From<rrg_proto::PathSpec> for PathSpec {
    fn from(proto: rrg_proto::PathSpec) -> PathSpec {
        PathSpec {
            nested_path: match proto.nested_path {
                Some(pathspec) => Some(Box::new(Self::from(*pathspec))),
                None => None,
            },

            path_options: get_enum_path_options(&proto.path_options),
            pathtype: get_enum_path_type(&proto.pathtype),
            path: get_path(&proto.path),
        }
    }
}

impl super::Request for Request {
    type Proto = GetFileStatRequest;

    fn from_proto(proto: Self::Proto) -> Result<Self, session::ParseError> {
        match proto.pathspec {
            Some(proto_pathspec) => Ok(Request {
                pathspec: Some(PathSpec::from(proto_pathspec)),
                collect_ext_attrs: proto.collect_ext_attrs,
                follow_symlink: proto.follow_symlink,
            }),

            None => Err(session::ParseError::from(
                session::MissingFieldError::new("path spec"))),
        }
    }
}

impl super::Response for Response {
    const RDF_NAME: Option<&'static str> = Some("StatEntry");

    type Proto = StatEntry;

    fn into_proto(self) -> Self::Proto {
        StatEntry {
            st_mode: self.mode,
            st_ino: self.inode,
            st_dev: self.device,
            st_nlink: self.hard_links,
            st_uid: self.uid,
            st_gid: self.gid,
            st_size: self.size,
            st_atime: get_time_since_unix_epoch(&self.access_time),
            st_mtime: get_time_since_unix_epoch(&self.modification_time),
            st_ctime: get_time_since_unix_epoch(&self.status_change_time),
            st_blocks: self.blocks_number,
            st_blksize: self.block_size,
            st_rdev: self.represented_device,
            st_flags_osx: None,
            st_flags_linux: self.flags_linux,
            symlink: self.symlink,
            registry_type: None,
            resident: None,

            pathspec: Some(rrg_proto::PathSpec {
                path_options: get_int_path_options(&self.pathspec),
                pathtype: get_int_path_type(&self.pathspec),
                path: Some(self.pathspec.path.unwrap()
                    .to_str().unwrap().to_string()),
                ..Default::default()
            }),

            registry_data: None,
            st_crtime: None,
            ext_attrs: self.extended_attributes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Request;
    use tempfile::tempdir;

    #[test]
    fn test_path_collapse() {
        let pathspec = PathSpec {
            nested_path: Some(Box::new(
                PathSpec {
                    nested_path: Some(Box::new(
                        PathSpec {
                            path: Some(PathBuf::from("file")),
                            ..Default::default()
                        }
                    )),
                    path: Some(PathBuf::from("to")),
                    ..Default::default()
                })),
            path: Some(PathBuf::from("path")),
            ..Default::default()
        };

        assert_eq!(collapse_pathspec(pathspec), PathBuf::from("/path/to/file"));

        let pathspec = PathSpec {
            nested_path: Some(Box::new(
                PathSpec {
                    nested_path: Some(Box::new(
                        PathSpec {
                            path: Some(PathBuf::from("on/device")),
                            ..Default::default()
                        }
                    )),
                    path: Some(PathBuf::from("some/file")),
                    ..Default::default()
                })),
            path: Some(PathBuf::from("path/to")),
            ..Default::default()
        };

        assert_eq!(collapse_pathspec(pathspec), PathBuf::from("/path/to/some/file/on/device"));
    }

    #[test]
    fn test_empty_request() {
        let request: Result<super::Request, _> =
            Request::from_proto(GetFileStatRequest::default());
        assert!(request.is_err());
    }

    #[test]
    fn test_no_error_with_existing_file() {
        let dir = tempdir().unwrap();

        let file_path = dir.path().join("temp_file.txt");
        fs::File::create(file_path.to_path_buf()).unwrap();
        let response = form_response(&file_path, &file_path);
        assert!(response.is_ok());
    }

    #[test]
    fn test_file_does_not_exist() {
        let dir = tempdir().unwrap();

        let file_path = dir.path().join("temp_file.txt");
        let response = form_response(&file_path, &file_path);
        assert!(response.is_err());
    }

    #[test]
    fn test_mode_and_size() {
        let new_size = 42;
        let new_mode = 0o100444;

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("temp_file.txt");
        let file = fs::File::create(file_path.to_path_buf()).unwrap();

        file.set_len(new_size).unwrap();
        let mut permissions = fs::metadata(&file_path).unwrap().permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions).unwrap();

        let response = form_response(&file_path, &file_path);

        assert!(response.is_ok());

        let response = response.unwrap();
        assert!(response.size.is_some());
        assert_eq!(response.size.unwrap(), new_size);

        assert!(response.mode.is_some());
        assert_eq!(response.mode.unwrap(), new_mode);
    }

    #[test]
    fn test_hard_link() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("temp_file.txt");
        let hard_link_path = dir.path().join("hard_link.txt");
        fs::File::create(file_path.to_path_buf()).unwrap();
        fs::hard_link(&file_path, &hard_link_path).unwrap();

        let file_response = form_response(&file_path, &file_path);
        let link_response = form_response(&hard_link_path, &hard_link_path);

        assert!(file_response.is_ok());
        assert!(link_response.is_ok());

        let file_response = file_response.unwrap();
        let link_response = link_response.unwrap();

        assert!(file_response.hard_links.is_some());
        assert_eq!(file_response.hard_links.unwrap(), 2);

        assert!(link_response.hard_links.is_some());
        assert_eq!(link_response.hard_links.unwrap(), 2);

        assert!(file_response.inode.is_some());
        assert!(link_response.inode.is_some());
        assert_eq!(file_response.inode.unwrap(), link_response.inode.unwrap());
    }

    #[test]
    fn test_extended_attributes() {
        fn check_attribute(attribute: &rrg_proto::stat_entry::ExtAttr,
                           name: &str, value: Vec<u8>) {
            assert!(attribute.name.is_some());
            assert_eq!(attribute.name.clone().unwrap(), name.as_bytes().to_vec());
            assert!(attribute.value.is_some());
            assert_eq!(attribute.value.clone().unwrap(), value);
        }

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("temp_file");
        fs::File::create(file_path.to_path_buf()).unwrap();
        xattr::set(&file_path, "user.simple_name", &[0, 28, 42]).unwrap();
        xattr::set(&file_path, "user.ⓤⓝⓘⓒⓞⓓⓔ ⓝⓐⓜⓔ", &[0, 1]).unwrap();
        xattr::set(&file_path, "user.без значения", &[]).unwrap();

        let extended_attributes = get_ext_attrs(&file_path);

        assert_eq!(extended_attributes.len(), 3);

        check_attribute(&extended_attributes[0], "user.simple_name", vec![0, 28, 42]);
        check_attribute(&extended_attributes[1], "user.ⓤⓝⓘⓒⓞⓓⓔ ⓝⓐⓜⓔ", vec![0, 1]);
        check_attribute(&extended_attributes[2], "user.без значения", vec![]);
    }
}
