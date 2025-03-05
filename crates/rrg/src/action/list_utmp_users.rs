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
    fn handle_var_log_wtmp_logged_in_user() {
        let args = Args {
            path: "/var/log/wtmp".into(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let username_env = std::env::var_os("USER")
            .expect("no $USER env var");

        assert! {
            session.replies::<Item>().any(|item| {
                item.username == username_env
            })
        }
    }
}
