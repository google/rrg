// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the file stat action.
//!
//! A file stat action responses with stat of a given file

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime};

use log::warn;
use rrg_proto::{GetFileStatRequest, path_spec::Options, path_spec::PathType, PathSpec, StatEntry};

use crate::session::{self, Error, Session};

impl From<std::io::Error> for Error {

    fn from(e: std::io::Error) -> Error {
        Error::action(e)
    }
}

#[derive(Debug)]
pub struct Response {
    mode: u64,
    inode: u32,
    device: u32,
    hard_links: u32,
    uid: u32,
    gid: u32,
    size: u64,
    access_time: Option<SystemTime>,
    modification_time: Option<SystemTime>,
    status_change_time: Option<SystemTime>,
    block_count: u32,
    block_size: u32,
    represented_device: u32,
    flags_linux: Option<u32>,
    symlink: Option<PathBuf>,
    path: PathBuf,
    extended_attributes: Vec<ExtAttr>,
}

#[derive(Debug)]
pub struct Request {
    path: PathBuf,
    collect_ext_attrs: bool,
    follow_symlink: bool,
}

#[derive(Debug)]
pub struct ExtAttr {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl Into<rrg_proto::stat_entry::ExtAttr> for ExtAttr {

    fn into(self) -> rrg_proto::stat_entry::ExtAttr {
        rrg_proto::stat_entry::ExtAttr {
            name: Some(self.name),
            value: Some(self.value),
        }
    }
}

pub fn handle<S: Session>(session: &mut S, request: Request) -> session::Result<()> {
    let destination = if request.follow_symlink {
        fs::canonicalize(&request.path)?
    } else {
        request.path.clone()
    };

    let mut response = form_response(&request.path, &destination)?;
    if request.collect_ext_attrs {
        response.extended_attributes = get_ext_attrs(&destination);
    }

    session.reply(response)?;
    Ok(())
}

#[cfg(target_family = "unix")]
fn get_ext_attrs(path: &Path) -> Vec<ExtAttr> {
    use std::os::unix::ffi::OsStringExt;

    let xattrs = match xattr::list(path) {
        Ok(xattr_list) => xattr_list,
        Err(err) => {
            warn!("Unable to get extended attributes: {}", err);
            return vec![]
        }
    };

    let mut result = vec![];
    for attr in xattrs {
        match xattr::get(path, &attr) {
            Ok(attr_value) => result.push(ExtAttr {
                name: attr.into_vec(),
                value: attr_value.unwrap_or_default(),
            }),

            Err(err) => warn!("Unable to get an extended attribute: {}", err),
        }
    }
    result
}

#[cfg(not(target_family = "unix"))]
fn get_ext_attrs(_path: &Path) -> Vec<ExtAttr> {
    vec![]
}

#[cfg(target_os = "linux")]
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
    match sys_time {
        Some(time_value) => match rrg_proto::micros(*time_value) {
            Ok(micros_value) => Some(micros_value),
            Err(error) => {
                warn!("failed to convert time: {}", error);
                None
            }
        }
        None => None
    }
}

#[cfg(target_os = "linux")]
fn get_status_change_time(metadata: &fs::Metadata) -> Option<SystemTime> {
    use std::time::Duration;
    use std::os::unix::fs::MetadataExt;
    use std::time::UNIX_EPOCH;

    UNIX_EPOCH.checked_add(Duration::from_secs(metadata.ctime() as u64))
}

#[cfg(target_os = "linux")]
fn form_response(original_path: &Path, destination: &Path)
                 -> Result<Response, std::io::Error> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(destination)?;
    let original_metadata = fs::symlink_metadata(original_path)?;

    Ok(Response {
        mode: metadata.mode() as u64,
        inode: metadata.ino() as u32,
        device: metadata.dev() as u32,
        hard_links: metadata.nlink() as u32,
        uid: metadata.uid() as u32,
        gid: metadata.gid() as u32,
        size: metadata.size() as u64,
        access_time: get_time_option(metadata.accessed()),
        modification_time: get_time_option(metadata.modified()),
        status_change_time: get_status_change_time(&metadata),
        block_count: metadata.blocks() as u32,
        block_size: metadata.blksize() as u32,
        represented_device: metadata.rdev() as u32,
        flags_linux: get_linux_flags(destination),

        symlink: match original_metadata.file_type().is_symlink() {
            true => Some(fs::read_link(original_path).unwrap()),
            false => None
        },

        path: original_path.to_owned(),

        extended_attributes: vec![],
    })
}

#[cfg(not(target_os = "linux"))]
fn form_response(_original_path: &PathBuf, _destination: &PathBuf)
                 -> Result<Response, session::Error> {
    Err(session::Error::Dispatch(
        String::from("This functionality has not yet been implemented for your platform.")))
}

fn collapse_pathspec(pathspec: PathSpec) -> PathBuf {
    fn recursive_collapse(pathspec: PathSpec) -> PathBuf {
        match pathspec.path {
            Some(path) => {
                let path_buf = PathBuf::from(path);
                match pathspec.nested_path {
                    Some(nested_path_box) => path_buf.join(recursive_collapse(*nested_path_box)),
                    None => path_buf,
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

#[cfg(target_os = "linux")]
fn get_linux_flags(path: &Path) -> Option<u32> {
    use std::os::raw::c_long;
    use std::os::unix::io::AsRawFd;
    use std::fs::File;

    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            warn!("Unable to get linux flags: {}", err);
            return None;
        }
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

    type Proto = GetFileStatRequest;

    fn from_proto(proto: Self::Proto) -> Result<Self, session::ParseError> {
        match proto.pathspec {
            Some(pathspec) => Ok(Request {
                path: collapse_pathspec(pathspec),
                collect_ext_attrs: proto.collect_ext_attrs.unwrap_or(false),
                follow_symlink: proto.follow_symlink.unwrap_or(false),
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
            st_mode: Some(self.mode),
            st_ino: Some(self.inode),
            st_dev: Some(self.device),
            st_nlink: Some(self.hard_links),
            st_uid: Some(self.uid),
            st_gid: Some(self.gid),
            st_size: Some(self.size),
            st_atime: get_time_since_unix_epoch(&self.access_time),
            st_mtime: get_time_since_unix_epoch(&self.modification_time),
            st_ctime: get_time_since_unix_epoch(&self.status_change_time),
            st_blocks: Some(self.block_count),
            st_blksize: Some(self.block_size),
            st_rdev: Some(self.represented_device),
            st_flags_osx: None,
            st_flags_linux: self.flags_linux,

            symlink: match self.symlink {
                Some(path) => Some(path.to_str().unwrap().to_string()),
                None => None
            },

            registry_type: None,
            resident: None,

            pathspec: Some(PathSpec {
                path_options: Some(Options::CaseLiteral as i32),
                pathtype: Some(PathType::Os as i32),
                path: Some(self.path.to_str().unwrap().to_string()),
                ..Default::default()
            }),

            registry_data: None,
            st_crtime: None,
            ext_attrs: self.extended_attributes.into_iter()
                .map(|attr| attr.into()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::action::Request;

    use super::*;

    #[test]
    fn test_path_collapse() {
        let pathspec = PathSpec {
            nested_path: Some(Box::new(
                PathSpec {
                    nested_path: Some(Box::new(
                        PathSpec {
                            path: Some(String::from("file")),
                            ..Default::default()
                        }
                    )),
                    path: Some(String::from("to")),
                    ..Default::default()
                })),
            path: Some(String::from("path")),
            ..Default::default()
        };

        assert_eq!(collapse_pathspec(pathspec), PathBuf::from("/path/to/file"));

        let pathspec = PathSpec {
            nested_path: Some(Box::new(
                PathSpec {
                    nested_path: Some(Box::new(
                        PathSpec {
                            path: Some(String::from("on/device")),
                            ..Default::default()
                        }
                    )),
                    path: Some(String::from("some/file")),
                    ..Default::default()
                })),
            path: Some(String::from("path/to")),
            ..Default::default()
        };

        assert_eq!(collapse_pathspec(pathspec), PathBuf::from("/path/to/some/file/on/device"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_empty_request() {
        let request: Result<super::Request, _> =
            Request::from_proto(GetFileStatRequest::default());
        assert!(request.is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_no_error_with_existing_file() {
        let dir = tempdir().unwrap();

        let file_path = dir.path().join("temp_file.txt");
        fs::File::create(file_path.to_path_buf()).unwrap();
        let response = form_response(&file_path, &file_path);
        assert!(response.is_ok());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_file_does_not_exist() {
        let dir = tempdir().unwrap();

        let file_path = dir.path().join("temp_file.txt");
        let response = form_response(&file_path, &file_path);
        assert!(response.is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
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
        assert_eq!(response.size, new_size);
        assert_eq!(response.mode, new_mode);
    }

    #[test]
    #[cfg(target_os = "linux")]
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

        assert_eq!(file_response.hard_links, 2);
        assert_eq!(link_response.hard_links, 2);
        assert_eq!(file_response.inode, link_response.inode);
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn test_extended_attributes() {
        fn check_attribute(attribute: &ExtAttr,
                           name: &str, value: Vec<u8>) {
            assert_eq!(attribute.name.clone(), name.as_bytes().to_vec());
            assert_eq!(attribute.value.clone(), value);
        }

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("temp_file");
        fs::File::create(file_path.to_path_buf()).unwrap();
        xattr::set(&file_path, "user.simple_name", &[0, 28, 42]).unwrap();
        xattr::set(&file_path, "user.ⓤⓝⓘⓒⓞⓓⓔ ⓝⓐⓜⓔ", &[0, 1]).unwrap();
        xattr::set(&file_path, "user.без значения", &[]).unwrap();

        let mut extended_attributes = get_ext_attrs(&file_path);
        extended_attributes.sort_by(|a, b| a.name.partial_cmp(&b.name).unwrap());

        assert_eq!(extended_attributes.len(), 3);

        check_attribute(&extended_attributes[0], "user.simple_name", vec![0, 28, 42]);
        check_attribute(&extended_attributes[1], "user.без значения", vec![]);
        check_attribute(&extended_attributes[2], "user.ⓤⓝⓘⓒⓞⓓⓔ ⓝⓐⓜⓔ", vec![0, 1]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_chain_of_symlinks() {
        use std::os::unix;

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("temp_file.txt");
        fs::File::create(file_path.to_path_buf()).unwrap();

        let chain_length = 5;
        unix::fs::symlink(&file_path, dir.path().join("symlink 0")).unwrap();

        for i in 1..chain_length {
            unix::fs::symlink(dir.path().join(format!("symlink {}", i - 1)),
                              dir.path().join(format!("symlink {}", i))).unwrap();
        }

        let last_symlink = dir.path().join(format!("symlink {}", chain_length - 1));
        let previous_symlink = dir.path().join(format!("symlink {}", chain_length - 2));

        let response = form_response(&last_symlink,
                                     &fs::canonicalize(&last_symlink).unwrap());
        let original_response = form_response(&file_path, &file_path);

        assert!(response.is_ok());
        let response = response.unwrap();

        assert!(original_response.is_ok());
        let original_response = original_response.unwrap();

        assert!(response.symlink.is_some());
        assert!(original_response.symlink.is_none());
        assert_eq!(response.symlink.unwrap(), previous_symlink);

        assert_eq!(response.mode, original_response.mode);
        assert_eq!(response.inode, original_response.inode);
        assert_eq!(response.device, original_response.device);
        assert_eq!(response.hard_links, original_response.hard_links);
        assert_eq!(response.uid, original_response.uid);
        assert_eq!(response.gid, original_response.gid);
        assert_eq!(response.size, original_response.size);
        assert_eq!(response.access_time, original_response.access_time);
        assert_eq!(response.modification_time, original_response.modification_time);
        assert_eq!(response.status_change_time, original_response.status_change_time);
        assert_eq!(response.block_count, original_response.block_count);
        assert_eq!(response.block_size, original_response.block_size);
        assert_eq!(response.represented_device, original_response.represented_device);
        assert_eq!(response.flags_linux, original_response.flags_linux);
    }
}
