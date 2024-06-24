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
    todo!()
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
