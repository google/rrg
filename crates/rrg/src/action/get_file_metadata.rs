// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::path::{Path, PathBuf};

use regex::bytes::Regex;

/// Arguments of the `get_file_metadata` action.
pub struct Args {
    /// Root paths to the files to get the metadata of.
    paths: Vec<PathBuf>,
    /// Limit on the depth of recursion when visiting subfolders.
    max_depth: u32,
    /// Whether to collect MD5 digest of the file contents.
    md5: bool,
    /// Whether to collect SHA-1 digest of the file contents.
    sha1: bool,
    /// Whether to collect SHA-256 digest of the file contents.
    sha256: bool,
    //// Regex to restrict the results only to those with matching paths.
    path_pruning_regex: Regex,
    /// Whether to collect canonical path to the file.
    path_canon: bool,
}

/// Result of the `get_file_metadata` action.
struct Item {
    /// Path to the file we retrieve the metadata of.
    path: PathBuf,
    /// Canonical path to the file.
    path_canon: Option<PathBuf>,
    /// Retrieved metadata of the file we retrieved.
    metadata: std::fs::Metadata,
    /// Extended attributes of the file.
    #[cfg(target_family = "unix")]
    ext_attrs: Vec<ospect::fs::ExtAttr>,
    // TODO(@panhania): Add support for file flags (also known as attributes).
    //
    // Collection of them is already implemented in the `ospect` crate, but it
    // is no clear which protobuf message should include them and whether we
    // should have separate fields for each platform or to cram everything into
    // one.
    //
    // It is also not clear how the field should be named as on Linux this
    // feature is called "attributes" (not to be confused with file extended
    // attributes!) and on macOS it is called "flags".
    /// Path to the file pointed by a symlink (if available).
    symlink: Option<PathBuf>,
    /// Digest of the file contents.
    digest: Digest,
}

/// Handles invocations of the `get_file_metadata` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    // We log warnings here instead of the `digest` method to avoid repeated
    // messages in case of multiple files or (potential) child files.
    if args.md5 && !cfg!(feature = "action-get_file_metadata-md5") {
        log::warn!("MD5 digest requested but not supported");
    }
    if args.sha1 && !cfg!(feature = "action-get_file_metadata-sha1") {
        log::warn!("SHA-1 digest requested but not supported");
    }
    if args.sha256 && !cfg!(feature = "action-get_file_metadata-sha256") {
        log::warn!("SHA-256 digest requested but not supported");
    }

    for path in &args.paths {
        log::debug!("collecting metadata for '{}'", path.display());

        if path.is_relative() {
            use std::io::{Error, ErrorKind};

            let error = Error::new(ErrorKind::InvalidInput, "relative path");
            return Err(crate::session::Error::action(error));
        }

        let metadata = match path.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                log::error! {
                    "failed to collect metadata for '{}': {error}",
                    path.display(),
                };
                continue
            }
        };

        #[cfg(target_family = "unix")]
        let ext_attrs = match ospect::fs::ext_attrs(path) {
            Ok(ext_attrs) => ext_attrs.filter_map(|ext_attr| match ext_attr {
                Ok(ext_attr) => Some(ext_attr),
                Err(error) => {
                    log::error! {
                        "failed to read an extended attribute for '{}': {error}",
                        path.display(),
                    };

                    None
                }
            }).collect(),
            Err(error) => {
                log::error! {
                    "failed to list extended attributes for '{}': {error}",
                    path.display(),
                };

                Vec::default()
            }
        };

        let symlink = if metadata.is_symlink() {
            match std::fs::read_link(path) {
                Ok(symlink) => Some(symlink),
                Err(error) => {
                    log::error! {
                        "failed to read symlink target for '{}': {error}",
                        path.display(),
                    };

                    None
                }
            }
        } else {
            None
        };

        let path_canon = if args.path_canon {
            match path.canonicalize() {
                Ok(path_canon) => Some(path_canon),
                Err(error) => {
                    log::error! {
                        "failed to canonicalize path '{}': {error}",
                        path.display(),
                    };

                    None
                }
            }
        } else {
            None
        };

        session.reply(Item {
            path: path.clone(),
            path_canon,
            metadata,
            #[cfg(target_family = "unix")]
            ext_attrs,
            symlink,
            digest: digest(&path, &args),
        })?;

        if args.max_depth > 0 {
            let entries = match crate::fs::walk_dir(&path) {
                Ok(entries) => entries,
                Err(error) => {
                    log::error! {
                        "failed to start recursive walk for '{}': {error}",
                        path.display(),
                    };
                    continue
                }
            };

            log::debug! {
                "walking children of '{}' (max depth: {}, pruning regex: '{}')",
                path.display(),
                args.max_depth,
                args.path_pruning_regex,
            };

            for entry in entries
                .with_max_depth(args.max_depth)
                .prune(|entry| {
                    let path_bytes = entry.path.as_os_str().as_encoded_bytes();
                    args.path_pruning_regex.is_match(&path_bytes)
                })
            {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => {
                        log::error!("failed to read directory entry: {error}");
                        continue
                    }
                };

                #[cfg(target_family = "unix")]
                let ext_attrs = match ospect::fs::ext_attrs(&entry.path) {
                    Ok(ext_attrs) => ext_attrs.filter_map(|ext_attr| match ext_attr {
                        Ok(ext_attr) => Some(ext_attr),
                        Err(error) => {
                            log::error! {
                                "failed to read an extended attribute for '{}': {error}",
                                entry.path.display()
                            };

                            None
                        }
                    }).collect(),
                    Err(error) => {
                        log::error! {
                            "failed to list extended attributes for '{}': {error}",
                            entry.path.display()
                        };

                        Vec::default()
                    }
                };

                let symlink = if entry.metadata.is_symlink() {
                    match std::fs::read_link(&entry.path) {
                        Ok(symlink) => Some(symlink),
                        Err(error) => {
                            log::error! {
                                "failed to read symlink target for '{}': {error}",
                                entry.path.display()
                            };

                            None
                        }
                    }
                } else {
                    None
                };

                let path_canon = if args.path_canon {
                    match entry.path.canonicalize() {
                        Ok(path_canon) => Some(path_canon),
                        Err(error) => {
                            log::error! {
                                "failed to canonicalize path '{}': {error}",
                                entry.path.display(),
                            };

                            None
                        }
                    }
                } else {
                    None
                };

                let digest = digest(&entry.path, &args);

                log::debug!("sending metadata for '{}'", entry.path.display());

                session.reply(Item {
                    path: entry.path,
                    path_canon,
                    metadata: entry.metadata,
                    #[cfg(target_family = "unix")]
                    ext_attrs,
                    symlink,
                    digest,
                })?;
            }
        }
    }

    Ok(())
}

/// Record with digest information of the file contents.
#[derive(Default)]
struct Digest {
    /// MD5 digest of the file contents.
    #[cfg(feature = "action-get_file_metadata-md5")]
    md5: Option<[u8; 16]>,
    /// SHA-1 digest of the file contents.
    #[cfg(feature = "action-get_file_metadata-sha1")]
    sha1: Option<[u8; 20]>,
    /// SHA-256 digest of the file contents.
    #[cfg(feature = "action-get_file_metadata-sha256")]
    sha256: Option<[u8; 32]>,
}

/// Computes the digest record of the file contents using requested algorithms.
fn digest(path: &Path, args: &Args) -> Digest {
    if !(args.md5 || args.sha1 || args.sha256) {
        // If no digests were requested, we do not need to read the file.
        return Digest::default();
    }

    let mut file = match std::fs::File::open(path) {
        Ok(file) => std::io::BufReader::new(file),
        Err(error) => {
            log::error!("failed to open '{}' for digest: {error}", path.display());
            return Digest::default();
        }
    };

    #[cfg(feature = "action-get_file_metadata-md5")]
    let mut md5_hasher = if args.md5 {
        Some(<md5::Md5 as md5::Digest>::new())
    } else {
        None
    };

    #[cfg(feature = "action-get_file_metadata-sha1")]
    let mut sha1_hasher = if args.sha1 {
        Some(<sha1::Sha1 as sha1::Digest>::new())
    } else {
        None
    };

    #[cfg(feature = "action-get_file_metadata-sha256")]
    let mut sha256_hasher = if args.sha256 {
        Some(<sha2::Sha256 as sha2::Digest>::new())
    } else {
        None
    };

    loop {
        use std::io::BufRead as _;

        let buf = match file.fill_buf() {
            Ok(buf) if buf.is_empty() => break,
            Ok(buf) => buf,
            Err(error) => {
                log::error!("failed to read content of '{}' for digest: {error}", path.display());
                return Digest::default();
            }
        };

        #[cfg(feature = "action-get_file_metadata-md5")]
        if let Some(ref mut md5_hasher) = md5_hasher {
            <_ as md5::Digest>::update(md5_hasher, buf);
        }

        #[cfg(feature = "action-get_file_metadata-sha1")]
        if let Some(ref mut sha1_hasher) = sha1_hasher {
            <_ as sha1::Digest>::update(sha1_hasher, buf);
        }

        #[cfg(feature = "action-get_file_metadata-sha256")]
        if let Some(ref mut sha256_hasher) = sha256_hasher {
            <_ as sha2::Digest>::update(sha256_hasher, buf);
        }

        let buf_len = buf.len();
        file.consume(buf_len);
    }

    Digest {
        #[cfg(feature = "action-get_file_metadata-md5")]
        md5: md5_hasher.map(<_ as md5::Digest>::finalize).map(<[u8; 16]>::from),
        #[cfg(feature = "action-get_file_metadata-sha1")]
        sha1: sha1_hasher.map(<_ as sha1::Digest>::finalize).map(<[u8; 20]>::from),
        #[cfg(feature = "action-get_file_metadata-sha256")]
        sha256: sha256_hasher.map(<_ as sha2::Digest>::finalize).map(<[u8; 32]>::from),
    }
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_file_metadata::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let paths = proto.take_paths().into_iter()
            .map(PathBuf::try_from)
            // TOOO(@panhania): Improve error handling (it is not obvious which
            // path caused the error right now).
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ParseArgsError::invalid_field("path", error))?;

        let path_pruning_regex = Regex::new(proto.path_pruning_regex())
            .map_err(|error| ParseArgsError::invalid_field("path_pruning_regex", error))?;

        Ok(Args {
            paths,
            path_canon: proto.path_canonical(),
            max_depth: proto.max_depth(),
            md5: proto.md5(),
            sha1: proto.sha1(),
            sha256: proto.sha256(),
            path_pruning_regex,
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_file_metadata::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = rrg_proto::get_file_metadata::Result::default();
        proto.set_path(self.path.into());
        proto.set_metadata(self.metadata.into());

        #[cfg(target_family = "unix")]
        {
            for ext_attr in self.ext_attrs {
                proto.mut_ext_attrs().push(ext_attr.into());
            }
        }

        if let Some(symlink) = self.symlink {
            proto.set_symlink(symlink.into());
        }

        #[cfg(feature = "action-get_file_metadata-md5")]
        if let Some(md5) = self.digest.md5 {
            proto.set_md5(md5.to_vec());
        }
        #[cfg(feature = "action-get_file_metadata-sha1")]
        if let Some(sha1) = self.digest.sha1 {
            proto.set_sha1(sha1.to_vec());
        }
        #[cfg(feature = "action-get_file_metadata-sha256")]
        if let Some(sha256) = self.digest.sha256 {
            proto.set_sha256(sha256.to_vec());
        }

        if let Some(path_canon) = self.path_canon {
            proto.set_path_canonical(path_canon.into());
        }

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn handle_non_existent() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let args = Args {
            paths: vec![tempdir.path().join("foo")],
            max_depth: 0,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 0);
    }

    #[test]
    fn handle_relative() {
        let args = Args {
            paths: vec![PathBuf::from("foo/bar/baz")],
            max_depth: 0,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_err());
    }

    #[test]
    fn handle_regular_file() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::File::create(tempdir.join("foo"))
            .unwrap();

        let args = Args {
            paths: vec![tempdir.join("foo").to_path_buf()],
            max_depth: 0,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempdir.join("foo"));
        assert_eq!(item.metadata.is_file(), true);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn handle_symlink() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::File::create(tempdir.join("file"))
            .unwrap();
        std::os::unix::fs::symlink(tempdir.join("file"), tempdir.join("link"))
            .unwrap();

        let args = Args {
            paths: vec![tempdir.join("link")],
            max_depth: 0,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempdir.join("link"));
        assert_eq!(item.metadata.is_symlink(), true);
        assert_eq!(item.symlink, Some(tempdir.join("file")));
    }

    #[cfg(feature = "test-setfattr")]
    #[cfg(target_os = "linux")]
    #[test]
    fn handle_ext_attrs() {
        let tempfile = tempfile::NamedTempFile::new()
            .unwrap();

        assert! {
            std::process::Command::new("setfattr")
                .arg("--no-dereference")
                .arg("--name").arg("user.foo")
                .arg("--value").arg("bar")
                .arg(tempfile.path().as_os_str())
                .status().unwrap()
                .success()
        };

        let args = Args {
            paths: vec![tempfile.path().to_path_buf()],
            max_depth: 0,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempfile.path());
        assert_eq!(item.ext_attrs.len(), 1);
        assert_eq!(item.ext_attrs[0].name, "user.foo");
        assert_eq!(item.ext_attrs[0].value, b"bar");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn handle_ext_attrs() {
        let tempfile = tempfile::NamedTempFile::new()
            .unwrap();

        assert! {
            std::process::Command::new("xattr")
                .arg("-w")
                .arg("user.foo")
                .arg("bar")
                .arg(tempfile.path().to_path_buf())
                .status().unwrap()
                .success()
        };

        let args = Args {
            paths: vec![tempfile.path().to_owned()],
            max_depth: 0,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempfile.path());
        assert_eq!(item.ext_attrs.len(), 1);
        assert_eq!(item.ext_attrs[0].name, "user.foo");
        assert_eq!(item.ext_attrs[0].value, b"bar");
    }

    #[test]
    fn handle_dir_max_depth_0() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::File::create(tempdir.join("foo"))
            .unwrap();
        std::fs::File::create(tempdir.join("bar"))
            .unwrap();

        let args = Args {
            paths: vec![tempdir.to_path_buf()],
            max_depth: 0,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let paths = session.replies::<Item>()
            .map(|item| item.path.clone())
            .collect::<Vec<_>>();

        assert!(paths.contains(&tempdir.to_path_buf()));
        assert!(!paths.contains(&tempdir.join("foo")));
        assert!(!paths.contains(&tempdir.join("bar")));
    }

    #[test]
    fn handle_dir_max_depth_1() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::File::create(tempdir.join("file1"))
            .unwrap();
        std::fs::File::create(tempdir.join("file2"))
            .unwrap();

        std::fs::create_dir(tempdir.join("subdir"))
            .unwrap();

        std::fs::File::create(tempdir.join("subdir").join("file1"))
            .unwrap();
        std::fs::File::create(tempdir.join("subdir").join("file2"))
            .unwrap();

        let args = Args {
            paths: vec![tempdir.to_path_buf()],
            max_depth: 1,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let items_by_path = session.replies::<Item>()
            .map(|item| (item.path.clone(), item))
            .collect::<std::collections::HashMap<_, _>>();

        assert!(items_by_path.contains_key(tempdir));
        assert!(items_by_path[tempdir].metadata.is_dir());

        assert!(items_by_path.contains_key(&tempdir.join("file1")));
        assert!(items_by_path[&tempdir.join("file1")].metadata.is_file());

        assert!(items_by_path.contains_key(&tempdir.join("file2")));
        assert!(items_by_path[&tempdir.join("file2")].metadata.is_file());

        assert!(items_by_path.contains_key(&tempdir.join("subdir")));
        assert!(items_by_path[&tempdir.join("subdir")].metadata.is_dir());

        assert!(!items_by_path.contains_key(&tempdir.join("subdir").join("file1")));
        assert!(!items_by_path.contains_key(&tempdir.join("subdir").join("file2")));
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn handle_dir_max_depth_1_symlinks() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::File::create(tempdir.join("file"))
            .unwrap();

        std::os::unix::fs::symlink(tempdir.join("file"), tempdir.join("link"))
            .unwrap();

        let args = Args {
            paths: vec![tempdir.to_path_buf()],
            max_depth: 1,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let items_by_path = session.replies::<Item>()
            .map(|item| (item.path.clone(), item))
            .collect::<std::collections::HashMap::<_, _>>();

        assert!(items_by_path.contains_key(tempdir));
        assert!(items_by_path.contains_key(&tempdir.join("file")));
        assert!(items_by_path.contains_key(&tempdir.join("link")));

        let item_link = items_by_path[&tempdir.join("link")];
        assert!(item_link.metadata.is_symlink());
        assert_eq!(item_link.symlink, Some(tempdir.join("file")));
    }

    #[cfg(feature = "test-setfattr")]
    #[cfg(target_os = "linux")]
    #[test]
    fn handle_dir_max_depth_1_ext_attrs() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::File::create(tempdir.join("file1"))
            .unwrap();
        std::fs::File::create(tempdir.join("file2"))
            .unwrap();

        assert! {
            std::process::Command::new("setfattr")
                .arg("--no-dereference")
                .arg("--name").arg("user.attr1")
                .arg("--value").arg("value1")
                .arg(tempdir.join("file1"))
                .status().unwrap()
                .success()
        };
        assert! {
            std::process::Command::new("setfattr")
                .arg("--no-dereference")
                .arg("--name").arg("user.attr2")
                .arg("--value").arg("value2")
                .arg(tempdir.join("file2"))
                .status().unwrap()
                .success()
        };

        let args = Args {
            paths: vec![tempdir.to_path_buf()],
            max_depth: 1,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let items_by_path = session.replies::<Item>()
            .map(|item| (item.path.clone(), item))
            .collect::<std::collections::HashMap::<_, _>>();

        assert!(items_by_path.contains_key(tempdir));
        assert!(items_by_path.contains_key(&tempdir.join("file1")));
        assert!(items_by_path.contains_key(&tempdir.join("file2")));

        let item_file1 = items_by_path[&tempdir.join("file1")];
        assert_eq!(item_file1.ext_attrs.len(), 1);
        assert_eq!(item_file1.ext_attrs[0].name, "user.attr1");
        assert_eq!(item_file1.ext_attrs[0].value, b"value1");

        let item_file2 = items_by_path[&tempdir.join("file2")];
        assert_eq!(item_file2.ext_attrs.len(), 1);
        assert_eq!(item_file2.ext_attrs[0].name, "user.attr2");
        assert_eq!(item_file2.ext_attrs[0].value, b"value2");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn handle_dir_max_depth_1_ext_attrs() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::File::create(tempdir.join("file1"))
            .unwrap();
        std::fs::File::create(tempdir.join("file2"))
            .unwrap();

        assert! {
            std::process::Command::new("xattr")
                .arg("-w")
                .arg("user.attr1")
                .arg("value1")
                .arg(tempdir.join("file1"))
                .status().unwrap()
                .success()
        };
        assert! {
            std::process::Command::new("xattr")
                .arg("-w")
                .arg("user.attr2")
                .arg("value2")
                .arg(tempdir.join("file2"))
                .status().unwrap()
                .success()
        };

        let args = Args {
            paths: vec![tempdir.to_path_buf()],
            max_depth: 1,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let items_by_path = session.replies::<Item>()
            .map(|item| (item.path.clone(), item))
            .collect::<std::collections::HashMap::<_, _>>();

        assert!(items_by_path.contains_key(tempdir));
        assert!(items_by_path.contains_key(&tempdir.join("file1")));
        assert!(items_by_path.contains_key(&tempdir.join("file2")));

        let item_file1 = items_by_path[&tempdir.join("file1")];
        assert_eq!(item_file1.ext_attrs.len(), 1);
        assert_eq!(item_file1.ext_attrs[0].name, "user.attr1");
        assert_eq!(item_file1.ext_attrs[0].value, b"value1");

        let item_file2 = items_by_path[&tempdir.join("file2")];
        assert_eq!(item_file2.ext_attrs.len(), 1);
        assert_eq!(item_file2.ext_attrs[0].name, "user.attr2");
        assert_eq!(item_file2.ext_attrs[0].value, b"value2");
    }

    #[cfg(feature = "action-get_file_metadata-md5")]
    #[test]
    fn handle_md5_file() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::write(tempdir.join("file"), "hello\n")
            .unwrap();

        let args = Args {
            paths: vec![tempdir.join("file")],
            max_depth: 0,
            md5: true,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.digest.md5, Some([
            // Pre-computed by the `md5sum` tool.
            0xb1, 0x94, 0x6a, 0xc9, 0x24, 0x92, 0xd2, 0x34,
            0x7c, 0x62, 0x35, 0xb4, 0xd2, 0x61, 0x11, 0x84,
        ]));
    }

    #[cfg(feature = "action-get_file_metadata-md5")]
    #[test]
    fn handle_md5_dir() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::write(tempdir.join("nonempty"), "hello\n")
            .unwrap();
        std::fs::write(tempdir.join("empty"), "")
            .unwrap();

        let args = Args {
            paths: vec![tempdir.to_path_buf()],
            max_depth: 1,
            md5: true,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let items_by_path = session.replies::<Item>()
            .map(|item| (item.path.clone(), item))
            .collect::<std::collections::HashMap<_, _>>();

        assert!(items_by_path.contains_key(tempdir));
        assert_eq!(items_by_path[tempdir].digest.md5, None);

        assert!(items_by_path.contains_key(&tempdir.join("nonempty")));
        assert_eq!(items_by_path[&tempdir.join("nonempty")].digest.md5, Some([
            // Pre-computed by the `md5sum` tool.
            0xb1, 0x94, 0x6a, 0xc9, 0x24, 0x92, 0xd2, 0x34,
            0x7c, 0x62, 0x35, 0xb4, 0xd2, 0x61, 0x11, 0x84,
        ]));

        assert!(items_by_path.contains_key(&tempdir.join("empty")));
        assert_eq!(items_by_path[&tempdir.join("empty")].digest.md5, Some([
            // Pre-computed by the `md5sum` tool.
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
            0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
        ]));
    }

    #[cfg(feature = "action-get_file_metadata-sha1")]
    #[test]
    fn handle_sha1_file() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::write(tempdir.join("file"), "hello\n")
            .unwrap();

        let args = Args {
            paths: vec![tempdir.join("file")],
            max_depth: 0,
            md5: false,
            sha1: true,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.digest.sha1, Some([
            // Pre-computed by the `sha1sum` tool.
            0xf5, 0x72, 0xd3, 0x96, 0xfa, 0xe9, 0x20, 0x66, 0x28, 0x71,
            0x4f, 0xb2, 0xce, 0x00, 0xf7, 0x2e, 0x94, 0xf2, 0x25, 0x8f,
        ]));
    }

    #[cfg(feature = "action-get_file_metadata-sha1")]
    #[test]
    fn handle_sha1_dir() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::write(tempdir.join("nonempty"), "hello\n")
            .unwrap();
        std::fs::write(tempdir.join("empty"), "")
            .unwrap();

        let args = Args {
            paths: vec![tempdir.to_path_buf()],
            max_depth: 1,
            md5: false,
            sha1: true,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let items_by_path = session.replies::<Item>()
            .map(|item| (item.path.clone(), item))
            .collect::<std::collections::HashMap<_, _>>();

        assert!(items_by_path.contains_key(tempdir));
        assert_eq!(items_by_path[tempdir].digest.sha1, None);

        assert!(items_by_path.contains_key(&tempdir.join("nonempty")));
        assert_eq!(items_by_path[&tempdir.join("nonempty")].digest.sha1, Some([
            // Pre-computed by the `sha1sum` tool.
            0xf5, 0x72, 0xd3, 0x96, 0xfa, 0xe9, 0x20, 0x66, 0x28, 0x71,
            0x4f, 0xb2, 0xce, 0x00, 0xf7, 0x2e, 0x94, 0xf2, 0x25, 0x8f,
        ]));

        assert!(items_by_path.contains_key(&tempdir.join("empty")));
        assert_eq!(items_by_path[&tempdir.join("empty")].digest.sha1, Some([
            // Pre-computed by the `sha1sum` tool.
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
            0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ]));
    }

    #[cfg(feature = "action-get_file_metadata-sha256")]
    #[test]
    fn handle_sha255_file() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::write(tempdir.join("file"), "hello\n")
            .unwrap();

        let args = Args {
            paths: vec![tempdir.join("file")],
            max_depth: 0,
            md5: false,
            sha1: false,
            sha256: true,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.digest.sha256, Some([
            // Pre-computed by the `sha256sum` tool.
            0x58, 0x91, 0xb5, 0xb5, 0x22, 0xd5, 0xdf, 0x08,
            0x6d, 0x0f, 0xf0, 0xb1, 0x10, 0xfb, 0xd9, 0xd2,
            0x1b, 0xb4, 0xfc, 0x71, 0x63, 0xaf, 0x34, 0xd0,
            0x82, 0x86, 0xa2, 0xe8, 0x46, 0xf6, 0xbe, 0x03,
        ]));
    }

    #[cfg(feature = "action-get_file_metadata-sha256")]
    #[test]
    fn handle_sha256_dir() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::write(tempdir.join("nonempty"), "hello\n")
            .unwrap();
        std::fs::write(tempdir.join("empty"), "")
            .unwrap();

        let args = Args {
            paths: vec![tempdir.to_path_buf()],
            max_depth: 1,
            md5: false,
            sha1: false,
            sha256: true,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let items_by_path = session.replies::<Item>()
            .map(|item| (item.path.clone(), item))
            .collect::<std::collections::HashMap<_, _>>();

        assert!(items_by_path.contains_key(tempdir));
        assert_eq!(items_by_path[tempdir].digest.sha256, None);

        assert!(items_by_path.contains_key(&tempdir.join("nonempty")));
        assert_eq!(items_by_path[&tempdir.join("nonempty")].digest.sha256, Some([
            // Pre-computed by the `sha256sum` tool.
            0x58, 0x91, 0xb5, 0xb5, 0x22, 0xd5, 0xdf, 0x08,
            0x6d, 0x0f, 0xf0, 0xb1, 0x10, 0xfb, 0xd9, 0xd2,
            0x1b, 0xb4, 0xfc, 0x71, 0x63, 0xaf, 0x34, 0xd0,
            0x82, 0x86, 0xa2, 0xe8, 0x46, 0xf6, 0xbe, 0x03,
        ]));

        assert!(items_by_path.contains_key(&tempdir.join("empty")));
        assert_eq!(items_by_path[&tempdir.join("empty")].digest.sha256, Some([
            // Pre-computed by the `sha256sum` tool.
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ]));
    }

    #[test]
    fn handle_path_pruning_regex_filtered() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::create_dir(tempdir.join("foo"))
            .unwrap();
        std::fs::create_dir(tempdir.join("bar"))
            .unwrap();

        std::fs::File::create(tempdir.join("foo").join("quux"))
            .unwrap();
        std::fs::File::create(tempdir.join("foo").join("norf"))
            .unwrap();
        std::fs::File::create(tempdir.join("bar").join("thud"))
            .unwrap();
        std::fs::File::create(tempdir.join("bar").join("blargh"))
            .unwrap();

        let args = Args {
            paths: vec![tempdir.to_path_buf()],
            max_depth: u32::MAX,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new(&format! {
                "^{tempdir}($|{sep}bar($|{sep}.*$))",
                tempdir = regex::escape(tempdir.to_str().unwrap()),
                sep = regex::escape(std::path::MAIN_SEPARATOR_STR),
            }).unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let paths = session.replies::<Item>()
            .map(|item| &item.path)
            .collect::<Vec<_>>();

        assert_eq!(paths.len(), 4);
        assert!(paths.contains(&&tempdir.to_path_buf()));
        assert!(paths.contains(&&tempdir.join("bar")));
        assert!(paths.contains(&&tempdir.join("bar").join("thud")));
        assert!(paths.contains(&&tempdir.join("bar").join("blargh")));
    }

    #[test]
    fn handle_path_pruning_regex_pruned() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::create_dir(tempdir.join("foo"))
            .unwrap();
        std::fs::create_dir(tempdir.join("bar"))
            .unwrap();

        // In this test we verify that paths are actually pruned, not merely
        // filtered. We prune searching for paths containing `ba*`. In case of
        // filtering paths like `foo/bar` would be returned. However, with pru-
        // ning, such path should not be returned as during traversal path `foo`
        // does not match and is discared with its entire subtree.

        std::fs::File::create(tempdir.join("foo").join("bar"))
            .unwrap();
        std::fs::File::create(tempdir.join("foo").join("baz"))
            .unwrap();
        std::fs::File::create(tempdir.join("bar").join("baz"))
            .unwrap();
        std::fs::File::create(tempdir.join("bar").join("quux"))
            .unwrap();

        let args = Args {
            paths: vec![tempdir.to_path_buf()],
            max_depth: u32::MAX,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new(&format! {
                "^{tempdir}($|{sep}.*ba.*$)",
                tempdir = regex::escape(tempdir.to_str().unwrap()),
                sep = regex::escape(std::path::MAIN_SEPARATOR_STR),
            }).unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let paths = session.replies::<Item>()
            .map(|item| &item.path)
            .collect::<Vec<_>>();

        assert_eq!(paths.len(), 4);
        assert!(paths.contains(&&tempdir.to_path_buf()));
        assert!(paths.contains(&&tempdir.join("bar")));
        assert!(paths.contains(&&tempdir.join("bar").join("baz")));
        assert!(paths.contains(&&tempdir.join("bar").join("quux")));
    }

    #[test]
    // Paths with arbitrary bytes are possible only on Linux.
    #[cfg(target_os = "linux")]
    fn handle_path_pruning_regex_arbitrary_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::create_dir(tempdir.join(OsStr::from_bytes(b"\xFF\xAA\xBB")))
            .unwrap();
        std::fs::create_dir(tempdir.join(OsStr::from_bytes(b"\xBA\xDD\xDD")))
            .unwrap();

        std::fs::File::create(tempdir.join(OsStr::from_bytes(b"\xFF\xAA\xBB/A")))
            .unwrap();
        std::fs::File::create(tempdir.join(OsStr::from_bytes(b"\xFF\xAA\xBB/B")))
            .unwrap();
        std::fs::File::create(tempdir.join(OsStr::from_bytes(b"\xBA\xDD\xDD/C")))
            .unwrap();
        std::fs::File::create(tempdir.join(OsStr::from_bytes(b"\xBA\xDD\xDD/D")))
            .unwrap();

        let args = Args {
            paths: vec![tempdir.to_path_buf()],
            max_depth: u32::MAX,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new(&format! {
                "(?-u)^{tempdir}($|/\\xFF\\xAA\\xBB($|/.*$))",
                tempdir = regex::escape(tempdir.to_str().unwrap()),
            }).unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let paths = session.replies::<Item>()
            .map(|item| &item.path)
            .collect::<Vec<_>>();

        dbg!(&paths);
        assert_eq!(paths.len(), 4);
        assert!(paths.contains(&&tempdir.to_path_buf()));
        assert!(paths.contains(&&tempdir.join(OsStr::from_bytes(b"\xFF\xAA\xBB"))));
        assert!(paths.contains(&&tempdir.join(OsStr::from_bytes(b"\xFF\xAA\xBB/A"))));
        assert!(paths.contains(&&tempdir.join(OsStr::from_bytes(b"\xFF\xAA\xBB/B"))));
    }

    #[test]
    fn handle_many_regular_files() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::File::create(tempdir.join("file1"))
            .unwrap();
        std::fs::File::create(tempdir.join("file2"))
            .unwrap();
        std::fs::File::create(tempdir.join("file3"))
            .unwrap();

        let args = Args {
            paths: vec![
                tempdir.join("file1").to_path_buf(),
                tempdir.join("file2").to_path_buf(),
                tempdir.join("file3").to_path_buf(),
            ],
            max_depth: 0,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 3);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempdir.join("file1"));
        assert_eq!(item.metadata.is_file(), true);

        let item = session.reply::<Item>(1);
        assert_eq!(item.path, tempdir.join("file2"));
        assert_eq!(item.metadata.is_file(), true);

        let item = session.reply::<Item>(2);
        assert_eq!(item.path, tempdir.join("file3"));
        assert_eq!(item.metadata.is_file(), true);
    }

    #[test]
    fn handle_many_dirs_max_depth_1() {
        let tempdir_1 = tempfile::tempdir()
            .unwrap();
        let tempdir_1 = tempdir_1.path();

        let tempdir_2 = tempfile::tempdir()
            .unwrap();
        let tempdir_2 = tempdir_2.path();

        std::fs::File::create(tempdir_1.join("file11"))
            .unwrap();
        std::fs::File::create(tempdir_1.join("file12"))
            .unwrap();
        std::fs::File::create(tempdir_2.join("file21"))
            .unwrap();
        std::fs::File::create(tempdir_2.join("file22"))
            .unwrap();

        let args = Args {
            paths: vec![
                tempdir_1.to_path_buf(),
                tempdir_2.to_path_buf(),
            ],
            max_depth: 1,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let items_by_path = session.replies::<Item>()
            .map(|item| (item.path.clone(), item))
            .collect::<std::collections::HashMap<_, _>>();

        assert!(items_by_path.contains_key(tempdir_1));
        assert!(items_by_path[tempdir_1].metadata.is_dir());

        assert!(items_by_path.contains_key(&tempdir_1.join("file11")));
        assert!(items_by_path[&tempdir_1.join("file11")].metadata.is_file());

        assert!(items_by_path.contains_key(&tempdir_1.join("file12")));
        assert!(items_by_path[&tempdir_1.join("file12")].metadata.is_file());

        assert!(items_by_path.contains_key(tempdir_2));
        assert!(items_by_path[tempdir_2].metadata.is_dir());

        assert!(items_by_path.contains_key(&tempdir_2.join("file21")));
        assert!(items_by_path[&tempdir_2.join("file21")].metadata.is_file());

        assert!(items_by_path.contains_key(&tempdir_2.join("file22")));
        assert!(items_by_path[&tempdir_2.join("file22")].metadata.is_file());
    }

    #[test]
    fn handle_many_files_one_non_existing() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();

        std::fs::File::create(tempdir.join("existing1"))
            .unwrap();
        std::fs::File::create(tempdir.join("existing2"))
            .unwrap();

        let args = Args {
            paths: vec![
                tempdir.join("existing1").to_path_buf(),
                tempdir.join("nonexisting").to_path_buf(),
                tempdir.join("existing2").to_path_buf(),
            ],
            max_depth: 0,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: false,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 2);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempdir.join("existing1"));

        let item = session.reply::<Item>(1);
        assert_eq!(item.path, tempdir.join("existing2"));
    }

    #[test]
    fn handle_path_canon() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();
        let tempdir_canon = tempdir.canonicalize()
            .unwrap();

        std::fs::create_dir(tempdir.join("dir"))
            .unwrap();
        std::fs::File::create(tempdir.join("dir").join("file"))
            .unwrap();

        let args = Args {
            paths: vec![
                tempdir.join(".").join("dir").join("..").join("dir").join("file"),
            ],
            max_depth: 0,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: true,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, tempdir.join(".").join("dir").join("..").join("dir").join("file"));
        assert_eq!(item.path_canon, Some(tempdir_canon.join("dir").join("file")));
    }

    #[test]
    fn handle_path_canon_max_depth_1() {
        let tempdir = tempfile::tempdir()
            .unwrap();
        let tempdir = tempdir.path();
        let tempdir_canon = tempdir.canonicalize()
            .unwrap();

        std::fs::create_dir(tempdir.join("dir"))
            .unwrap();
        std::fs::File::create(tempdir.join("dir").join("file1"))
            .unwrap();
        std::fs::File::create(tempdir.join("dir").join("file2"))
            .unwrap();

        let args = Args {
            paths: vec![tempdir.join("dir").join("..").join("dir")],
            max_depth: 1,
            md5: false,
            sha1: false,
            sha256: false,
            path_pruning_regex: Regex::new("").unwrap(),
            path_canon: true,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let paths_canon = session.replies::<Item>()
            .map(|item| item.path_canon.clone().unwrap())
            .collect::<Vec<_>>();

        assert!(paths_canon.contains(&tempdir_canon.join("dir")));
        assert!(paths_canon.contains(&tempdir_canon.join("dir").join("file1")));
        assert!(paths_canon.contains(&tempdir_canon.join("dir").join("file2")));
    }
}
