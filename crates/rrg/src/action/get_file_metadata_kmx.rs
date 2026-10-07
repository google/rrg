// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

enum VolumePath {
    // Absolute path to the raw volume file (e.g. `\\?\Volume{...}`.
    Direct(std::path::PathBuf),
    // Absolute path to the mount point of a volume (e.g. `C:\`).
    Mount(std::path::PathBuf),
}

/// Arguments of the `get_file_metadata_kmx` action.
pub struct Args {
    volume_path: VolumePath,
    path: keramics_formats::ntfs::NtfsPath,
    /// Limit on the depth of recursion when visiting subfolders.
    max_depth: u32,
}

/// Result of the `get_file_metadata_kmx` action.
pub struct Item {
    path: keramics_formats::ntfs::NtfsPath,
    modified: Option<std::time::SystemTime>,
    accessed: Option<std::time::SystemTime>,
    created: Option<std::time::SystemTime>,
    len: u64,
}

/// Handles invocations of the `get_file_metadata_kmx` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let volume_path = match args.volume_path {
        VolumePath::Direct(path) => path,
        #[cfg(target_os = "windows")]
        VolumePath::Mount(path) => {
            log::debug!("inferring direct volume path from mount: {}", path.display());

            ospect::fs::windows::raw_device_path(&path)
                .map_err(crate::session::Error::action)?
        }
        #[cfg(not(target_os = "windows"))]
        VolumePath::Mount(_path) => return Err(crate::session::Error::action(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "volume path inference not supported on Windows",
        ))),
    };

    log::debug!("opening NTFS volume at '{}'", volume_path.display());

    let volume = std::fs::File::open(&volume_path)
        .map_err(|error| crate::session::Error::action(error))?;
    let volume_data_stream: keramics_core::DataStreamReference = {
        std::sync::Arc::new(std::sync::RwLock::new(volume))
    };

    log::debug!("parsing NTFS volume at '{}'", volume_path.display());

    let mut ntfs = keramics_formats::ntfs::NtfsFileSystem::new();
    ntfs.read_data_stream(&volume_data_stream)
        .map_err(|error| crate::session::Error::action(error))?;

    log::debug!("collecting metadata for '{:?}'", args.path);

    let file_entry = match ntfs.get_file_entry_by_path(&args.path) {
        Ok(Some(file_entry)) => file_entry,
        Ok(None) => {
            log::error! {
                "no metadata for '{:?}'",
                args.path,
            };
            return Ok(())
        }
        Err(error) => {
            log::error! {
                "failed to collect metadata for '{:?}': {error}",
                args.path,
            };
            return Ok(())
        }
    };

    struct Queued {
        path: keramics_formats::ntfs::NtfsPath,
        entry: keramics_formats::ntfs::NtfsFileEntry,
        depth: u32,
    }

    let mut queue = std::collections::VecDeque::new();
    queue.push_back(Queued {
        path: args.path,
        entry: file_entry,
        depth: 0,
    });

    while let Some(mut cur) = queue.pop_front() {
        let modified = match cur.entry.get_modification_time() {
            Some(keramics_datetime::DateTime::Filetime(time)) => {
                let time = filetime_to_system_time(&time);
                if time.is_none() {
                    log::error!("unsupported modification time for '{:?}'", cur.path);
                }
                time
            }
            Some(time) => {
                log::error!("unexpected modification time type '{time:?}' for {:?}", cur.path);
                None
            },
            None => {
                log::error!("missing modification time for '{:?}", cur.path);
                None
            }
        };
        let accessed = match cur.entry.get_access_time() {
            Some(keramics_datetime::DateTime::Filetime(time)) => {
                let time = filetime_to_system_time(&time);
                if time.is_none() {
                    log::error!("unsupported access time for '{:?}'", cur.path);
                }
                time
            }
            Some(time) => {
                log::error!("unexpected access time type '{time:?}' for {:?}", cur.path);
                None
            },
            None => {
                log::error!("missing access time for '{:?}", cur.path);
                None
            }
        };
        let created = match cur.entry.get_creation_time() {
            Some(keramics_datetime::DateTime::Filetime(time)) => {
                let time = filetime_to_system_time(&time);
                if time.is_none() {
                    log::error!("unsupported creation time for '{:?}'", cur.path);
                }
                time
            }
            Some(time) => {
                log::error!("unexpected creation time type '{time:?}' for {:?}", cur.path);
                None
            },
            None => {
                log::error!("missing creation time for '{:?}", cur.path);
                None
            }
        };

        log::debug!("sending metadata for '{:?}'", cur.path);

        session.reply(Item {
            path: cur.path.clone(),
            modified,
            accessed,
            created,
            len: cur.entry.get_size(),
        })?;

        // https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;

        if cur.depth < args.max_depth && (
            // We do not want to descend to reparse points (e.g. symlinks) to
            // avoid cycles.
            // TODO(@panhania): Add `is_reparse_point` accessor to Keramics.
            (cur.entry.get_file_attribute_flags() & FILE_ATTRIBUTE_REPARSE_POINT) == 0 ||
            // ... except the case where we are a root directory which is a
            // reparse point but we still want to be able to list it.
            cur.entry.is_root_directory()
        ) {
            let sub_entry_count = match cur.entry.get_number_of_sub_file_entries() {
                Ok(sub_entry_count) => sub_entry_count,
                Err(error) => {
                    log::error! {
                        "failed to get number of children for '{:?}': {error}",
                        cur.path,
                    };
                    continue
                }
            };

            log::debug!("listing {sub_entry_count} children of '{:?}'", cur.path);

            for index in 0..sub_entry_count {
                let sub_entry = match cur.entry.get_sub_file_entry_by_index(index) {
                    Ok(sub_entry) => sub_entry,
                    Err(error) => {
                        log::error! {
                            "failed to list child {index} of '{:?}': {error}",
                            cur.path,
                        };
                        // If we failed to list a child, we assume there is
                        // something wrong with the entry and we do not try to
                        // read the remaining children.
                        break
                    }
                };

                let mut sub_path;
                match sub_entry.get_name() {
                    Some(name) => {
                        sub_path = cur.path.clone();
                        sub_path.push(name.clone());
                    }
                    None => {
                        log::error! {
                            "no name for child {index} of {:?}",
                            cur.path,
                        };
                        continue
                    }
                }

                queue.push_back(Queued {
                    path: sub_path,
                    entry: sub_entry,
                    depth: cur.depth + 1,
                });
            }
        }
    }

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_file_metadata_kmx::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let volume_path = if !proto.volume_mount_path().raw_bytes().is_empty() {
            let volume_mount_path = proto.take_volume_mount_path()
                .try_into()
                .map_err(|error| ParseArgsError::invalid_field("volume mount path", error))?;

            VolumePath::Mount(volume_mount_path)
        } else {
            let volume_path = proto.take_volume_path()
                .try_into()
                .map_err(|error| ParseArgsError::invalid_field("volume path", error))?;

            VolumePath::Direct(volume_path)
        };

        // TODO: Do not go through UTF-8 conversion.
        let path = str::from_utf8(proto.path().raw_bytes())
            .map_err(|error| ParseArgsError::invalid_field("path", error))?;
        let path = keramics_formats::ntfs::NtfsPath::from(path);

        Ok(Args {
            volume_path,
            // TODO: Read this from the proto.
            max_depth: 0,
            path,
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_file_metadata_kmx::Result;

    fn into_proto(self) -> Self::Proto {
        use rrg_proto::into_timestamp;

        // TODO: Use lossless conversion (preferably in Keramics directly).
        let path = std::path::PathBuf::from_iter(
            self.path.components.iter()
                .map(|comp| String::from_utf16_lossy(&comp.elements))
        );

        let mut proto = rrg_proto::get_file_metadata_kmx::Result::new();
        proto.set_path(path.into());
        proto.mut_metadata().set_size(self.len);
        if let Some(accessed) = self.accessed {
            proto.mut_metadata().set_access_time(into_timestamp(accessed));
        }
        if let Some(modified) = self.modified {
            proto.mut_metadata().set_modification_time(into_timestamp(modified));
        }
        if let Some(created) = self.created {
            proto.mut_metadata().set_creation_time(into_timestamp(created));
        }

        proto
    }
}

/// Converts the given Keramices [`Filetime`] object to Rust's [`SystemTime`].
///
/// [`Filetime`]: keramics_datetime::Filetime
/// [`SystemTime`]: std::time::SystemTime
fn filetime_to_system_time(
    filetime: &keramics_datetime::Filetime,
) -> Option<std::time::SystemTime> {
    // So, we have the last write time in 100-nanosecond intervals since Windows
    // epoch, i.e. January 1, 1601 [1]. A difference between that and the UNIX
    // epoch is 11,644,473,600 seconds [2, 3].
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
    // [2]: https://learn.microsoft.com/en-us/windows/win32/sysinfo/converting-a-time-t-value-to-a-file-time
    // [3]: https://devblogs.microsoft.com/oldnewthing/20220602-00/?p=106706
    let epoch_win_secs = filetime.timestamp / (1_000_000_000 / 100);
    let epoch_win_nanos = filetime.timestamp % (1_000_000_000 / 100) * 100;
    let epoch_win_since = {
        std::time::Duration::from_secs(epoch_win_secs) +
        std::time::Duration::from_nanos(epoch_win_nanos)
    };
    let epoch_unix_since = epoch_win_since
        // Windows epoch is before the UNIX one, so it is possible to underflow
        // here.
        .checked_sub(std::time::Duration::from_secs(11_644_473_600))?;

    std::time::SystemTime::UNIX_EPOCH
        // Generally this should not overflow as on UNIX-es we are adding to 0
        // and on Windows we are pretty much transmuting back to what we started
        // with. But in practice if we pass max filetime value, it trips over so
        // we need to back ourselves up.
        .checked_add(epoch_unix_since)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_non_existent() {
        let ntfs_file = tempntfs::create(|_| Ok(()))
            .unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\idonotexist"),
            max_depth: 0,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 0);
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_regular_file() {
        let timestamp_pre = std::time::SystemTime::now();

        let ntfs_file = tempntfs::create(|ntfs_path| {
            std::fs::write(ntfs_path.join("foo"), b"Lorem ipsum.")?;

            Ok(())
        }).unwrap();

        let timestamp_post = std::time::SystemTime::now();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\foo"),
            max_depth: 0,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, keramics_formats::ntfs::NtfsPath::from("\\foo"));
        assert_eq!(item.len, b"Lorem ipsum.".len() as u64);
        // TODO: Add assertions about the file type.

        assert!(item.accessed.unwrap() >= timestamp_pre);
        assert!(item.accessed.unwrap() <= timestamp_post);

        assert!(item.modified.unwrap() >= timestamp_pre);
        assert!(item.modified.unwrap() <= timestamp_post);

        assert!(item.created.unwrap() >= timestamp_pre);
        assert!(item.created.unwrap() <= timestamp_post);
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_dir() {
        let ntfs_file = tempntfs::create(|ntfs_path| {
            std::fs::create_dir(ntfs_path.join("foo"))?;

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\foo"),
            max_depth: 0,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, keramics_formats::ntfs::NtfsPath::from("\\foo"));
        // TODO: Add assertions about the file type.
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_dir_max_depth_0() {
        let ntfs_file = tempntfs::create(|ntfs_path| {
            std::fs::File::create_new(ntfs_path.join("foo"))
                .unwrap();
            std::fs::File::create_new(ntfs_path.join("bar"))
                .unwrap();

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\"),
            max_depth: 0,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        let paths = session.replies::<Item>()
            .map(|item| item.path.clone())
            .collect::<Vec<_>>();

        assert!(paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\")));
        assert!(!paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\foo")));
        assert!(!paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\bar")));
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_dir_max_depth_1() {
        let ntfs_file = tempntfs::create(|ntfs_path| {
            std::fs::File::create_new(ntfs_path.join("file1"))
                .unwrap();
            std::fs::File::create_new(ntfs_path.join("file2"))
                .unwrap();

            std::fs::create_dir(ntfs_path.join("subdir"))
                .unwrap();

            std::fs::File::create(ntfs_path.join("subdir").join("file1"))
                .unwrap();
            std::fs::File::create(ntfs_path.join("subdir").join("file2"))
                .unwrap();

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\"),
            max_depth: 1,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        let paths = session.replies::<Item>()
            .map(|item| item.path.clone())
            .collect::<Vec<_>>();

        // TODO: Add assertions about the file type.
        assert!(paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\")));
        assert!(paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\file1")));
        assert!(paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\file2")));
        assert!(paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\subdir")));
        assert!(!paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\subdir\\file1")));
        assert!(!paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\subdir\\file2")));
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_dir_max_depth_1_symlinks() {
        let ntfs_file = tempntfs::create(|ntfs_path| {
            std::fs::File::create_new(ntfs_path.join("file"))
                .unwrap();

            std::os::unix::fs::symlink(
                ntfs_path.join("file"),
                ntfs_path.join("link"),
            ).unwrap();

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\"),
            max_depth: 1,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        let paths = session.replies::<Item>()
            .map(|item| item.path.clone())
            .collect::<Vec<_>>();

        // TODO: Add assertions about the file type.
        assert!(paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\")));
        assert!(paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\file")));
        assert!(paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\link")));
    }

    #[cfg_attr(not(all(target_os = "linux", feature = "test-libguestfs")), ignore)]
    #[test]
    fn handle_dir_max_depth_1_symlinks_circular() {
        let ntfs_file = tempntfs::create(|ntfs_path| {
            std::fs::create_dir(ntfs_path.join("subdir"))
                .unwrap();

            std::os::unix::fs::symlink(
                ntfs_path.join("subdir"),
                ntfs_path.join("subdir").join("link"),
            ).unwrap();

            Ok(())
        }).unwrap();

        let args = Args {
            volume_path: VolumePath::Direct(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\"),
            max_depth: u32::MAX,
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        let paths = session.replies::<Item>()
            .map(|item| item.path.clone())
            .collect::<Vec<_>>();

        // TODO: Add assertions about the file type.
        assert!(paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\")));
        assert!(paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\subdir")));
        assert!(paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\subdir\\link")));
        assert!(!paths.contains(&keramics_formats::ntfs::NtfsPath::from("\\subdir\\link\\link")));
    }
}
