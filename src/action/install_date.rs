// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the install date action.
//!
//! The install date action uses various heuristics to detect the operating
//! system install date.

use std::time::{SystemTime, Duration};

use log::error;
use crate::session::{self, Session};

#[cfg(target_family = "unix")]
use std::{fs, path::Path};

#[cfg(target_os = "windows")]
use winreg::RegKey;

/// A response type for the install date action.
struct Response {
    /// Install date of the operating system, or `None` if the attemps to
    /// obtain install date failed.
    time: Option<SystemTime>,
}

impl super::Response for Response {

    // TODO: change to RDFDatetime when the client will be capable to send
    // "raw" strings without wrapping them into protobuf
    const RDF_NAME: Option<&'static str> = Some("DataBlob");

    type Proto = u64;

    fn into_proto(self) -> Self::Proto {
        let time = match self.time {
            Some(time) => time,
            None => {
                error!("cannot get install date, all methods failed");
                std::time::UNIX_EPOCH
            },
        };
        let since_epoch = match time.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration,
            Err(err) => {
                error!(
                    "install date is {} seconds earlier than Unix epoch",
                    err.duration().as_secs()
                );
                Duration::from_secs(0)
            },
        };
        since_epoch.as_secs()
    }
}

/// Iterates over files given it `iter`, checking their modification times.
///
/// If the function cannot get modification time from all the files (e. g.
/// they all don't exist), the return value is `None`. Otherwise, the
/// modification time of the first file is returned.
#[cfg(target_family = "unix")]
fn get_modified_time<P, It>(iter: It) -> Option<SystemTime>
where
    P: AsRef<Path>,
    It: Iterator<Item = P>,
{
    for path in iter {
        let time = fs::metadata(path).and_then(|metadata| metadata.modified());
        if let Ok(time) = time {
            return Some(time);
        }
    }

    None
}

/// Contains utilities to work with ext2/3/4 filesystems. Currently, it is used
/// to run `dumpe2fs`, parse its output and get filesystem creation time.
#[cfg(target_os = "linux")]
mod e2fs_utils {
    use std::io::{Cursor, Read, BufRead, BufReader};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{self, SystemTime};

    use chrono::prelude::*;
    use proc_mounts::MountList;

    /// Returns the file name of the device that is mounted as root file
    /// system.
    ///
    /// This function returns `None` in case of errors.
    fn get_root_device() -> Option<PathBuf> {
        let mount_list = MountList::new().ok()?;
        mount_list.get_mount_by_dest("/").map(|info| info.source.clone())
    }

    /// Parses `dumpe2fs` output to get the filesystem creation time.
    ///
    /// This function returns `None` in case of errors.
    fn parse_creation_time_from_dumpe2fs<R>(output: R) -> Option<SystemTime>
    where
        R: Read,
    {
        let reader = BufReader::new(output);
        for line in reader.lines() {
            const FIELD_NAME: &'static str = "Filesystem created:";
            let line = line.ok()?;
            if !line.starts_with(FIELD_NAME) {
                continue;
            }
            let line = line[FIELD_NAME.len() + 1 ..].trim();
            let local_time = Local.datetime_from_str(line, "%c").ok()?;
            let utc_time = local_time.with_timezone(&Utc);
            let time_since_epoch =
                (utc_time - Utc.timestamp(0, 0)).to_std().ok()?;
            return Some(time::UNIX_EPOCH + time_since_epoch);
        }
        None
    }

    /// Launches `dumpe2fs`, captures its output and obtains filesystem
    /// creation time.
    ///
    /// This function returns `None` in case of errors.
    pub fn creation_time_from_dumpe2fs() -> Option<SystemTime> {
        let output = Command::new("dumpe2fs")
            .arg(get_root_device()?)
            .stdout(Stdio::piped())
            .spawn().ok()?
            .wait_with_output().ok()?;
        if !output.status.success() {
            return None;
        }
        parse_creation_time_from_dumpe2fs(Cursor::new(output.stdout))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Cursor;

        #[test]
        fn test_parse_creation_time() {
            let correct = DateTime::parse_from_rfc3339("2020-05-31T19:02:03Z")
                .unwrap().with_timezone(&Utc);
            let creation_time = correct.with_timezone(&Local)
                .format("%c").to_string();
            let input = String::from(
                "Line 1\n\
                 Line 2\n\
                 Filesystem created:    "
            ) + &creation_time + "\n";
            let cursor = Cursor::new(input.as_bytes());
            let parsed = parse_creation_time_from_dumpe2fs(cursor).unwrap();
            let parsed = DateTime::<Utc>::from(parsed);
            assert_eq!(parsed, correct);
        }
    }
}

/// Obtains system install date using various heuristics.
///
/// This function returns `None` in case of errors.
#[cfg(target_os = "linux")]
fn get_install_time() -> Option<SystemTime> {
    // First, check the creation time of the root. This method works on
    // Linux >= 4.11.
    let time = fs::metadata("/").and_then(|metadata| metadata.created());
    if let Ok(time) = time {
        return Some(time);
    }

    // Then, try to detect filesystem creation time using dumpe2fs. This
    // works only on ext2/3/4 filesystems.
    let time = e2fs_utils::creation_time_from_dumpe2fs();
    if let Some(time) = time {
        return Some(time);
    }

    // Then, search for various files that were potentially modified only
    // on installation:
    // * /var/log/installer/: This works well on Debian-based systems, if the
    //   installation logs were not purged.
    // * /root/install.log: The location of installation logs for RHEL-based
    //   distributions.
    // * /etc/hostname: In most cases, we may assume that the hostname didn't
    //   change after installation.
    // * /lost+found: This method was used by Python version on GRR client, so
    //   leaving it here.
    const CANDIDATES: [&str; 5] = [
        "/var/log/installer/syslog",
        "/var/log/installer/status",
        "/root/install.log",
        "/etc/hostname",
        "/lost+found",
    ];
    if let Some(time) = get_modified_time(CANDIDATES.iter()) {
        return Some(time);
    }

    // We tried our best and all the methods have failed, so just give up.
    None
}

/// Obtains system install date using various heuristics.
///
/// This function returns `None` in case of errors.
#[cfg(target_os = "macos")]
fn get_install_time() -> Option<SystemTime> {
    // Here, we use the same way as Python version of GRR client does. We just
    // check the modification time for some of the paths
    const CANDIDATES: [&str; 3] = [
        "/var/log/CDIS.custom",
        "/var",
        "/private",
    ];
    get_modified_time(CANDIDATES.iter())
}

/// Obtains system install date using various heuristics.
///
/// This function returns `None` in case of errors.
#[cfg(target_os = "windows")]
fn get_install_time() -> Option<SystemTime> {
    // Don't use winreg::enums::KEY_WOW64_64KEY since it breaks on Windows 2000
    let hklm = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    let install_time = hklm
        .open_subkey("Software\\Microsoft\\Windows NT\\CurrentVersion").ok()?
        .get_value::<u32, _>("InstallDate").ok()?;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(install_time.into()))
}

/// Handles requests for the install date action.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    session.reply(Response {time: get_install_time()})?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use humantime::Timestamp;

    #[test]
    fn test_install_date() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());
        assert_eq!(session.reply_count(), 1);
        let response: &Response = session.reply(0);
        let time = response.time.unwrap();

        // We assume here that the tests won't be run for very old systems
        // installed before 01.01.2000.
        let lower_limit: Timestamp = "2000-01-01T00:00:00Z".parse().unwrap();
        let lower_limit: SystemTime = lower_limit.into();
        // The upper limit for the install date is the current date.
        let upper_limit = SystemTime::now();

        assert!(time >= lower_limit);
        assert!(time <= upper_limit);
    }
}
