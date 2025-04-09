// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Arguments of the `list_utmp_users` action.
#[cfg(target_os = "linux")]
pub struct Args {
    /// Path to the file to use as a source for `utmp` records.
    ///
    /// Typically this should be `/var/log/wtmp`.
    path: std::path::PathBuf,
}

/// Result of the `list_utmp_users` action.
#[cfg(target_os = "linux")]
pub struct Item {
    /// Name of an individual user retrieved from `utmp` records.
    username: std::ffi::OsString,
}

/// Handles invocations of the `list_utmp_users` action.
#[cfg(target_os = "linux")]
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let mut file = std::fs::File::open(&args.path)
        .map_err(crate::session::Error::action)?;

    let mut usernames = std::collections::HashSet::new();

    loop {
        use std::io::Read as _;

        let mut buf = [0u8; std::mem::size_of::<libc::utmpx>()];
        match file.read_exact(&mut buf) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(error) => {
                return Err(crate::session::Error::action(error));
            }
        }

        const TYPE_OFFSET: usize = std::mem::offset_of!(libc::utmpx, ut_type);
        const TYPE_SIZE: usize = std::mem::size_of::<libc::c_short>();

        let type_bytes = <_>::try_from(&buf[TYPE_OFFSET..TYPE_OFFSET + TYPE_SIZE])
            .expect("invalid type of utmp");
        // According to [1], `utmp` uses litle-endian byte order. However, it
        // might be the case that it actually uses native-endian. This should be
        // verified and adjusted if needed.
        //
        // [1]: https://github.com/libyal/dtformats/blob/main/documentation/Utmp%20login%20records%20format.asciidoc
        let r#type = libc::c_short::from_le_bytes(type_bytes);

        if r#type != libc::USER_PROCESS {
            continue;
        }

        const USER_OFFSET: usize = std::mem::offset_of!(libc::utmpx, ut_user);

        let user = std::ffi::CStr::from_bytes_until_nul(&buf[USER_OFFSET..])
            .map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error)
            })
            .map_err(crate::session::Error::action)?;

        use std::os::unix::ffi::OsStrExt as _;
        let user = std::ffi::OsStr::from_bytes(user.to_bytes());

        // TODO: https://github.com/rust-lang/rust/issues/60896 - Refactor once
        //``hash_set_entry` is stabilized.
        if !usernames.contains(user) {
            usernames.insert(user.to_owned());
        }
    }

    for username in usernames {
        session.reply(Item {
            username,
        })?;
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn handle<S>(_: &mut S, _: ()) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use std::io::{Error, ErrorKind};
    Err(crate::session::Error::action(Error::from(ErrorKind::Unsupported)))
}

#[cfg(target_os = "linux")]
impl crate::request::Args for Args {

    type Proto = rrg_proto::list_utmp_users::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let path = std::path::PathBuf::try_from(proto.take_path())
            .map_err(|error| ParseArgsError::invalid_field("path", error))?;

        Ok(Args {
            path,
        })
    }
}

#[cfg(target_os = "linux")]
impl crate::response::Item for Item {

    type Proto = rrg_proto::list_utmp_users::Result;

    fn into_proto(self) -> Self::Proto {
        use std::os::unix::ffi::OsStringExt as _;

        let mut proto = rrg_proto::list_utmp_users::Result::new();
        proto.set_username(self.username.into_vec());

        proto
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    // Looks like `utmp` entries can have different size depending on the
    // platform (e.g. on `aarch64` it has a size of 400 bytes) and so `x86_64`
    // samples will not work there.
    #[cfg_attr(not(target_arch = "x86_64"), ignore)]
    fn handle_custom_utmp_file() {
        use std::io::Write as _;

        let mut file = tempfile::NamedTempFile::new()
            .unwrap();

        // Actual non`USERS_PROCESS` entry.
        file.write(&[
            &b"\x02\0\0\0\0\0\0\0\x7e\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7e\x7e\0\0"[..],
            &b"reboot\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\06\x2e10\x2e11\x2d1rfoobar\x2damd64\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\x3b\x1f\xc0g\xcf\x20\x0d\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0"[..],
        ].concat()).unwrap();

        // Actual `USER_PROCESS` entry.
        file.write(&[
            &b"\x07\0\0\0p\x0d\0\0tty2\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0foobarquux"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0tty2"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0I\x1f\xc0"[..],
            &b"g\x1c\xb5\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
            &b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..],
        ].concat()).unwrap();

        file.flush().unwrap();

        let args = Args {
            path: file.path().to_path_buf(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert_eq!(session.reply_count(), 1);
        assert_eq!(session.reply::<Item>(0).username, "foobarquux");
    }

    #[test]
    fn handle_var_log_wtmp_no_dupes() {
        let args = Args {
            path: "/var/log/wtmp".into(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let replies = session.replies::<Item>()
            .collect::<Vec<_>>();

        let mut replies_dedup = replies.clone();
        replies_dedup.sort_by_key(|item| &item.username);
        replies_dedup.dedup_by_key(|item| &item.username);

        assert_eq!(replies.len(), replies_dedup.len());
    }
}
