// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Arguments of the `list_winreg_values` action.
#[cfg(target_family = "windows")]
pub struct Args {
    /// Root predefined key of the key to list values of.
    root: winreg::PredefinedKey,
    /// Key relative to `root` to list values of.
    key: std::ffi::OsString,
    /// Limit on the depth of recursion when visiting subkeys.
    max_depth: u32,
}

/// A result of the `list_winreg_values` action.
#[cfg(target_family = "windows")]
#[derive(Debug)]
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

    /// Single "stack frame" of the recursive value listing procedure.
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
                key: key_join(&args.key, &key_rel_name),
                value,
            })?;
        }

        if depth < args.max_depth {
            for subkey_name in info.subkeys() {
                let subkey_name = match subkey_name {
                    Ok(subkey_name) => subkey_name,
                    Err(error) => {
                        log::error! {
                            "failed to list subkey for key '{:?}': {}",
                            key_join(&args.key, &key_rel_name), error,
                        };
                        continue
                    }
                };
                let subkey_rel_name = key_join(&key_rel_name, &subkey_name);

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
                            key_join(&key_rel_name, &subkey_name), error,
                        };
                    }
                }
            }
        }
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

    type Proto = rrg_proto::list_winreg_values::Args;

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
            max_depth: 0, // TODO(@panhania): Read this from the proto.
        })
    }
}

#[cfg(target_family = "windows")]
impl crate::response::Item for Item {

    type Proto = rrg_proto::list_winreg_values::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = rrg_proto::list_winreg_values::Result::new();
        proto.set_root(self.root.into());
        proto.set_key(self.key.to_string_lossy().into_owned());
        proto.set_value(self.value.into());

        proto
    }
}

// TODO(@panhania): This is copied from similar function for a sibiling action.
// This should be refactored to a separate common utility.

/// Adjoins `left` and `right` using Windows registry key separator (`\`).
///
/// This is simlar to [`std::path::Path::join`] but for Windows registry keys.
fn key_join<S>(left: &S, right: &S) -> std::ffi::OsString
where
    S: AsRef<std::ffi::OsStr>,
{
    let left = left.as_ref();
    let right = right.as_ref();

    let mut result = std::ffi::OsString::new();
    result.push(left);
    if !left.is_empty() && !right.is_empty() {
        result.push("\\");
    }
    result.push(right);
    result
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
            max_depth: 0,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_err());
    }

    #[test]
    fn handle_ok() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
            max_depth: 0,
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

    #[test]
    fn handle_max_depth_0() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from("HARDWARE\\Description\\System"),
            max_depth: 0,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert! {
            session.replies::<Item>()
                .find(|item| {
                    item.key == "HARDWARE\\Description\\System" &&
                    item.value.name == "Identifier"
                })
                .is_some() // Okay, depth 0.
        }
        assert! {
            session.replies::<Item>()
                .find(|item| {
                    item.key == "HARDWARE\\Description\\System\\BIOS"
                })
                .is_none() // Not okay, depth 1.
        }
    }

    #[test]
    fn handle_max_depth_1() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from("HARDWARE\\Description\\System"),
            max_depth: 1,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert! {
            session.replies::<Item>()
                .find(|item| {
                    item.key == "HARDWARE\\Description\\System" &&
                    item.value.name == "Identifier"
                })
                .is_some() // Okay, depth 0.
        }
        assert! {
            session.replies::<Item>()
                .find(|item| {
                    item.key == "HARDWARE\\Description\\System\\BIOS" &&
                    item.value.name == "BIOSVendor"
                })
                .is_some() // Okay, depth 1.
        }
        assert! {
            session.replies::<Item>()
                .find(|item| {
                    item.key == "HARDWARE\\Description\\System\\BIOS" &&
                    item.value.name == "BIOSVendor"
                })
                .is_some() // Okay, depth 1.
        }
    }

    #[test]
    fn handle_max_depth_2() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from("HARDWARE"),
            max_depth: 2,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert! {
            session.replies::<Item>()
                .find(|item| {
                    item.key == "HARDWARE\\Description\\System" &&
                    item.value.name == "Identifier"
                })
                .is_some() // Okay, depth 2.
        }
        assert! {
            session.replies::<Item>()
                .find(|item| {
                    item.key == "HARDWARE\\Description\\System\\BIOS"
                })
                .is_none() // Not okay, depth 3.
        }
    }

    #[test]
    fn handle_max_depth_3() {
        let args = Args {
            root: winreg::PredefinedKey::LocalMachine,
            key: std::ffi::OsString::from("HARDWARE"),
            max_depth: 3,
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());

        assert! {
            session.replies::<Item>()
                .find(|item| {
                    item.key == "HARDWARE\\Description\\System" &&
                    item.value.name == "Identifier"
                })
                .is_some() // Okay, depth 2.
        }
        assert! {
            session.replies::<Item>()
                .find(|item| {
                    item.key == "HARDWARE\\Description\\System\\BIOS" &&
                    item.value.name == "BIOSVendor"
                })
                .is_some() // Okay, depth 3.
        }
        assert! {
            session.replies::<Item>()
                .find(|item| {
                    item.key == "HARDWARE\\Description\\System\\BIOS" &&
                    item.value.name == "BIOSVersion"
                })
                .is_some() // Okay, depth 3.
        }
    }

    // TODO(@panhania): Remove tests below once `key_join` is refactored to a
    // separate module.

    #[test]
    fn key_join_both_empty() {
        let empty = std::ffi::OsString::new();
        assert_eq!(key_join(&empty, &empty), "");
    }

    #[test]
    fn key_join_left_empty() {
        let empty = std::ffi::OsString::new();
        let foo = std::ffi::OsString::from("foo");
        assert_eq!(key_join(&empty, &foo), "foo");
    }

    #[test]
    fn key_join_right_empty() {
        let empty = std::ffi::OsString::new();
        let foo = std::ffi::OsString::from("foo");
        assert_eq!(key_join(&foo, &empty), "foo");
    }

    #[test]
    fn key_join_both_not_empty() {
        let foo = std::ffi::OsString::from("foo");
        let bar = std::ffi::OsString::from("bar");
        assert_eq!(key_join(&foo, &bar), "foo\\bar");
    }
}
