// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Arguments of the `list_winreg_keys` action.
#[cfg(target_family = "windows")]
pub struct Args {
    /// Root predefined key of the key to list subkeys of.
    root: winreg::PredefinedKey,
    /// Key relative to `root` to list subkeys of.
    key: std::ffi::OsString,
}

/// A result of the `list_winreg_keys` action.
#[cfg(target_family = "windows")]
struct Item {
    /// Root predefined key of the listed subkey.
    root: winreg::PredefinedKey,
    /// Key relative to `root` of the listed subkey.
    key: std::ffi::OsString,
    /// Listed subkey.
    subkey: std::ffi::OsString,
}

/// Handles invocations of the `list_winreg_keys` action.
#[cfg(target_family = "windows")]
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    todo!()
}

/// Handles invocations of the `list_winreg_keys` action.
#[cfg(target_family = "unix")]
pub fn handle<S>(_: &mut S, _: ()) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use std::io::{Error, ErrorKind};
    Err(crate::session::Error::action(Error::from(ErrorKind::Unsupported)))
}

#[cfg(target_family = "windows")]
impl crate::request::Args for Args {

    type Proto = rrg_proto::list_winreg_keys::Args;

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
        })
    }
}

#[cfg(target_family = "windows")]
impl crate::response::Item for Item {

    type Proto = rrg_proto::list_winreg_keys::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = rrg_proto::list_winreg_keys::Result::new();
        proto.set_root(self.root.into());
        proto.set_key(self.key.to_string_lossy().into_owned());
        proto.set_subkey(self.subkey.to_string_lossy().into_owned());

        proto
    }
}
