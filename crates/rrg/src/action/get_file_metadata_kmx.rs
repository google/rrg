// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Arguments of the `get_file_metadata_kmx` action.
pub struct Args {
    volume_path: Option<std::path::PathBuf>,
    path: keramics_formats::ntfs::NtfsPath,
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
    // TODO: Add support for inferring the volume from path.
    let Some(volume_path) = args.volume_path else {
        return Err(crate::session::Error::action(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "volume path must be provided",
        )));
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

    let modified = match file_entry.get_modification_time() {
        Some(keramics_datetime::DateTime::Filetime(time)) => {
            let time = filetime_to_system_time(time);
            if time.is_none() {
                log::error!("unsupported modification time for '{:?}'", args.path);
            }
            time
        }
        Some(time) => {
            log::error!("unexpected modification time type '{time:?}' for {:?}", args.path);
            None
        },
        None => {
            log::error!("missing modification time for '{:?}", args.path);
            None
        }
    };
    let accessed = match file_entry.get_access_time() {
        Some(keramics_datetime::DateTime::Filetime(time)) => {
            let time = filetime_to_system_time(time);
            if time.is_none() {
                log::error!("unsupported access time for '{:?}'", args.path);
            }
            time
        }
        Some(time) => {
            log::error!("unexpected access time type '{time:?}' for {:?}", args.path);
            None
        },
        None => {
            log::error!("missing access time for '{:?}", args.path);
            None
        }
    };
    let created = match file_entry.get_creation_time() {
        Some(keramics_datetime::DateTime::Filetime(time)) => {
            let time = filetime_to_system_time(time);
            if time.is_none() {
                log::error!("unsupported creation time for '{:?}'", args.path);
            }
            time
        }
        Some(time) => {
            log::error!("unexpected creation time type '{time:?}' for {:?}", args.path);
            None
        },
        None => {
            log::error!("missing creation time for '{:?}", args.path);
            None
        }
    };

    log::debug!("sending metadata for '{:?}'", args.path);

    session.reply(Item {
        path: args.path,
        modified,
        accessed,
        created,
        len: file_entry.get_size(),
    })?;

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_file_metadata_kmx::Args;

    fn from_proto(proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        // TODO: Do not go through UTF-8 conversion.
        let path = str::from_utf8(proto.path().raw_bytes())
            .map_err(|error| ParseArgsError::invalid_field("path", error))?;
        let path = keramics_formats::ntfs::NtfsPath::from(path);

        Ok(Args {
            volume_path: None,
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
            volume_path: Some(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\idonotexist"),
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
            volume_path: Some(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\foo"),
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
            volume_path: Some(ntfs_file.path().to_path_buf()),
            path: keramics_formats::ntfs::NtfsPath::from("\\foo"),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.path, keramics_formats::ntfs::NtfsPath::from("\\foo"));
        // TODO: Add assertions about the file type.
    }
}
