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
    /// Limit on the depth of recursion when visiting subkeys.
    max_depth: u32,
}

/// A result of the `list_winreg_keys` action.
#[cfg(target_family = "windows")]
struct Item {
    /// Root predefined key of the listed subkey.
    root: winreg::PredefinedKey,
    /// Key relative to `root` of the listed subkey.
    key: std::ffi::OsString,
    /// Listed subkey relative to `root` and `key`.
    subkey: std::ffi::OsString,
}

/// Handles invocations of the `list_winreg_keys` action.
#[cfg(target_family = "windows")]
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let key = args.root.open(&args.key)
        .map_err(crate::session::Error::action)?;

    /// Single "stack frame" of the recursive key listing procedure.
    struct PendingKey {
        /// Handle to the key specified in the `key_rel_name`.
        key: winreg::OpenKey,
        /// Name of the `key` relative to the key from which we started.
        key_rel_name: std::ffi::OsString,
        /// Current depth of the recursive walk.
        depth: u32,
    }

    // `pending_keys` represents our recursion stack. We implement the walk this
    // way rather than using the traditional recursion to avoid stack overflow
    // issues in case of deep registry hierarchies.
    let mut pending_keys = Vec::new();
    pending_keys.push(PendingKey {
        key,
        key_rel_name: std::ffi::OsString::new(),
        depth: 0,
    });

    loop {
        let PendingKey {
            key,
            key_rel_name,
            depth,
        } = match pending_keys.pop() {
            Some(pending_key) => pending_key,
            None => break,
        };

        let key_info = match key.info() {
            Ok(key_info) => key_info,
            Err(error) => {
                log::error! {
                    "failed to obtain information for key {:?}: {}",
                    winreg::path::join(&args.key, &key_rel_name), error,
                };
                continue
            }
        };

        for subkey_name in key_info.subkeys() {
            let subkey_name = match subkey_name {
                Ok(subkey_name) => subkey_name,
                Err(error) => {
                    log::error! {
                        "failed to list subkey for key '{:?}': {}",
                        winreg::path::join(&args.key, &key_rel_name), error,
                    };
                    continue
                }
            };
            let subkey_rel_name = winreg::path::join(&key_rel_name, &subkey_name);

            if depth + 1 < args.max_depth {
                match key.open(&subkey_name) {
                    Ok(subkey) => {
                        pending_keys.push(PendingKey {
                            key: subkey,
                            key_rel_name: subkey_rel_name.clone(),
                            depth: depth + 1,
                        });
                    }
                    Err(error) => {
                        log::error! {
                            "failed to open subkey '{:?}': {}",
                            winreg::path::join(&key_rel_name, &subkey_name), error,
                        };
                    }
                }
            }

            session.reply(Item {
                root: args.root,
                // TODO(@panhania): Add support for case-correcting the key.
                key: args.key.clone(),
                subkey: subkey_rel_name,
            })?;
        }
    }

    Ok(())
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
            max_depth: proto.max_depth(),
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

#[cfg(test)]
#[cfg(target_family = "windows")]
mod tests {

    use super::*;

    #[test]
    fn handle_non_existent() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from("FOOWARE"),
            max_depth: 1,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_err());
    }

    #[test]
    fn handle_root_only_ok() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from(""),
            max_depth: 1,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let subkeys_uppercase = session.replies::<Item>()
            .map(|item| item.subkey.to_ascii_uppercase())
            .collect::<Vec<_>>();

        assert!(subkeys_uppercase.contains(&"HARDWARE".into()));
        assert!(subkeys_uppercase.contains(&"SOFTWARE".into()));
        assert!(subkeys_uppercase.contains(&"SYSTEM".into()));
    }

    #[test]
    fn handle_ok() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from("SOFTWARE"),
            max_depth: 1,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());
        assert! {
            session.replies::<Item>()
                .find(|item| item.subkey.to_ascii_uppercase() == "MICROSOFT")
                .is_some()
        }
    }

    #[test]
    fn handle_max_depth_2() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from(""),
            max_depth: 2,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let subkeys_uppercase = session.replies::<Item>()
            .map(|item| item.subkey.to_ascii_uppercase())
            .collect::<Vec<_>>();

        assert!(subkeys_uppercase.contains(&"HARDWARE".into()));
        assert!(subkeys_uppercase.contains(&"HARDWARE\\DEVICEMAP".into()));
        assert!(subkeys_uppercase.contains(&"SOFTWARE".into()));
        assert!(subkeys_uppercase.contains(&"SOFTWARE\\MICROSOFT".into()));

        assert!(!subkeys_uppercase.contains(&"SOFTWARE\\MICROSOFT\\WINDOWS".into()));
        assert!(!subkeys_uppercase.contains(&"SOFTWARE\\MICROSOFT\\WINDOWS".into()));
    }

    #[test]
    fn handle_max_depth_3() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from(""),
            max_depth: 3,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let subkeys_uppercase = session.replies::<Item>()
            .map(|item| item.subkey.to_ascii_uppercase())
            .collect::<Vec<_>>();

        assert!(subkeys_uppercase.contains(&"HARDWARE".into()));
        assert!(subkeys_uppercase.contains(&"HARDWARE\\DEVICEMAP".into()));
        assert!(subkeys_uppercase.contains(&"HARDWARE\\DEVICEMAP\\VIDEO".into()));
        assert!(subkeys_uppercase.contains(&"SOFTWARE".into()));
        assert!(subkeys_uppercase.contains(&"SOFTWARE\\MICROSOFT".into()));
        assert!(subkeys_uppercase.contains(&"SOFTWARE\\MICROSOFT\\WINDOWS".into()));
    }

    #[test]
    fn handle_max_depth_default() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from(""),
            max_depth: Default::default(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        let subkeys_uppercase = session.replies::<Item>()
            .map(|item| item.subkey.to_ascii_uppercase())
            .collect::<Vec<_>>();

        assert!(subkeys_uppercase.contains(&"HARDWARE".into()));
        assert!(subkeys_uppercase.contains(&"SOFTWARE".into()));

        assert!(!subkeys_uppercase.contains(&"HARDWARE\\DEVICEMAP".into()));
        assert!(!subkeys_uppercase.contains(&"SOFTWARE\\MICROSOFT".into()));
    }

    #[test]
    fn handle_root_preserved() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from(""),
            max_depth: 3,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        for reply in session.replies::<Item>() {
            assert_eq!(reply.root, winreg::PredefinedKey::LocalMachine);
        }
    }

    #[test]
    fn handle_key_preserved() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from("HARDWARE\\DEVICEMAP"),
            max_depth: 3,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        for reply in session.replies::<Item>() {
            assert_eq!(reply.key, "HARDWARE\\DEVICEMAP");
        }
    }
}
