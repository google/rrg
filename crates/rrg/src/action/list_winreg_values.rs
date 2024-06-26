/// Arguments of the `list_winreg_values` action.
#[cfg(target_family = "windows")]
pub struct Args {
    /// Root predefined key of the key to list values of.
    root: winreg::PredefinedKey,
    /// Key relative to `root` to list values of.
    key: std::ffi::OsString,
}

/// A result of the `list_winreg_values` action.
#[cfg(target_family = "windows")]
struct Item {
    /// Root predefined key of the listed value.
    root: winreg::PredefinedKey,
    /// Key relative to `root` of the listed value.
    key: std::ffi::OsString,
    /// Listed value.
    value: winreg::Value,
}

/// Handles invocations of the `list_winreg_values` action.
#[cfg(target_family = "windows")]
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let key = args.root.open(&args.key)
        .map_err(crate::session::Error::action)?;

    let info = key.info()
        .map_err(crate::session::Error::action)?;

    for value in info.values() {
        let value = match value {
            Ok(value) => value,
            Err(error) => {
                log::error! {
                    "failed to list value for key '{:?}': {}",
                    args.key, error,
                };
                continue;
            }
        };

        session.reply(Item {
            root: args.root,
            // TODO(@panhania): Add support for case-correcting the key.
            key: args.key.clone(),
            value,
        })?;
    }

    Ok(())
}

/// Handles invocations of the `list_winreg_values` action.
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
            key: std::ffi::OsString::from("FOOWARE"),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_err());
    }

    #[test]
    fn handle_ok() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let value_names = session.replies::<Item>()
            .map(|item| item.value.name.clone())
            .collect::<Vec<_>>();

        assert!(value_names.contains(&"CurrentBuild".into()));
        assert!(value_names.contains(&"CurrentType".into()));
        assert!(value_names.contains(&"CurrentVersion".into()));
    }
}
