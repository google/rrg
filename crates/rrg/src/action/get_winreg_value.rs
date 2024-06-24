// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#[cfg(target_family = "windows")]
/// Arguments of the `get_winreg_value` action.
pub struct Args {
    /// Root predefined key of the value to get.
    root: winreg::PredefinedKey,
    /// Key relative to `root` of the value to get (e.g. `SOFTWARE\Microsoft`).
    key: std::ffi::OsString,
    /// Name of the value to get.
    value_name: std::ffi::OsString,
}

/// A result of the `get_winreg_value` action.
#[cfg(target_family = "windows")]
struct Item {
    /// Root predefined key of the retrieved value.
    root: winreg::PredefinedKey,
    /// Key relative to `root` of the retrieved value.
    key: std::ffi::OsString,
    /// Retrieved value.
    value: winreg::Value,
}

/// Handles invocations of the `get_winreg_value` action.
#[cfg(target_family = "unix")]
pub fn handle<S>(_: &mut S, _: ()) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use std::io::{Error, ErrorKind};
    Err(crate::session::Error::action(Error::from(ErrorKind::Unsupported)))
}

/// Handles invocations of the `get_winreg_value` action.
#[cfg(target_family = "windows")]
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let key = args.root.open(&args.key)
        .map_err(crate::session::Error::action)?;

    let value_data = key.value_data(&args.value_name)
        .map_err(crate::session::Error::action)?;

    session.reply(Item {
        root: args.root,
        key: args.key,
        value: winreg::Value {
            name: args.value_name,
            data: value_data,
        }
    })?;

    Ok(())
}

#[cfg(target_family = "windows")]
impl crate::request::Args for Args {

    type Proto = rrg_proto::get_winreg_value::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        let root = match proto.root.enum_value() {
            Ok(root) => winreg::PredefinedKey::try_from(root),
            Err(value) => Err(rrg_proto::ParseWinregPredefinedKeyError { value }),
        }.map_err(|error| {
            crate::request::ParseArgsError::invalid_field("root", error)
        })?;

        Ok(Args {
            root,
            key: std::ffi::OsString::from(proto.take_key()),
            value_name: std::ffi::OsString::from(proto.take_name()),
        })
    }
}

#[cfg(target_family = "windows")]
impl crate::response::Item for Item {

    type Proto = rrg_proto::get_winreg_value::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = rrg_proto::get_winreg_value::Result::new();
        proto.set_root(self.root.into());
        proto.set_key(self.key.to_string_lossy().into_owned());
        proto.set_value(self.value.into());

        proto
    }
}

#[cfg(test)]
#[cfg(target_family = "windows")]
mod tests {

    use super::*;

    #[test]
    fn handle_non_existent() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from("FOOWARE\\Linux\\GNU"),
            value_name: std::ffi::OsString::from("Version"),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_err());
    }

    #[test]
    fn handle_string() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
            value_name: std::ffi::OsString::from("CurrentType"),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());
        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.root, winreg::PredefinedKey::LocalMachine);
        assert_eq!(item.key, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
        assert_eq!(item.value.name, "CurrentType");
        assert!(matches!(item.value.data, winreg::ValueData::String(_)));
    }

    #[test]
    fn handle_bytes() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
            value_name: std::ffi::OsString::from("DigitalProductId"),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());
        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.root, winreg::PredefinedKey::LocalMachine);
        assert_eq!(item.key, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
        assert_eq!(item.value.name, "DigitalProductId");
        assert!(matches!(item.value.data, winreg::ValueData::Bytes(_)));
    }
}
