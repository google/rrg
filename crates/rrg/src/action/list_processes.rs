// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Arguments of the `list_processes` action.
pub struct Args {
}

/// Result of the `list_processes` action.
#[cfg(target_os = "macos")]
struct Item {
    metadata: ospect::proc::macos::Metadata,
    exe: Option<std::path::PathBuf>,
    args: Vec<std::ffi::OsString>,
}

#[cfg(target_os = "macos")]
pub fn handle<S>(session: &mut S, _args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    for metadata in ospect::proc::macos::all()
        .map_err(crate::session::Error::action)?
    {
        let metadata = match metadata {
            Ok(metadata) => metadata,
            Err(error) => {
                log::error! {
                    "failed to collect process metadata: {error}"
                };
                continue
            }
        };

        let exe = match metadata.exe() {
            Ok(exe) => Some(exe),
            Err(error) => {
                log::error! {
                    "failed to retrieve exe for process '{}': {error}",
                    metadata.id(),
                }
                None
            }
        };

        let args = match metadata.args() {
            Ok(args) => args.collect::<Vec<_>>(),
            Err(error) => {
                log::error! {
                    "failed to retrieve args for process '{}': {error}",
                    metadata.id(),
                }
                Vec::default()
            }
        };

        session.reply(Item {
            metadata,
            exe,
            args,
        })?;
    }

    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn handle<S>(_session: &mut S, _args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use std::io::{Error, ErrorKind};
    Err(crate::session::Error::action(Error::from(ErrorKind::Unsupported)))
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::list_processes::Args;

    fn from_proto(_proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        Ok(Args {})
    }
}

#[cfg(target_os = "macos")]
impl crate::response::Item for Item {

    type Proto = rrg_proto::list_processes::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = Self::Proto::new();
        proto.set_pid(self.metadata.id());
        proto.set_ppid(self.metadata.parent_id());
        proto.set_name(self.metadata.name().to_string_lossy().into_owned());

        if let Some(exe) = self.exe {
            proto.set_exe(exe.into());
        }

        proto.set_args(self.args.into_iter().map(|arg| {
            arg.to_string_lossy().into_owned()
        }).collect());

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    // `list_processes` is implemented only for macOS.
    #[cfg(target_os = "macos")]
    #[test]
    fn self_exists() {
        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, Args {}).is_ok());

        assert! {
            session.replies::<Item>()
                .find(|item| item.metadata.id() == std::process::id())
                .is_some()
        };
    }
}
