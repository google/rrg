// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// A result of the `list_mounts` action.
struct Item {
    // Information about the individual filesystem mount.
    mount: ospect::fs::Mount,
}

// Handles invocations of the `list_mounts` action.
pub fn handle<S>(session: &mut S, _: ()) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let mounts = ospect::fs::mounts()
        .map_err(crate::session::Error::action)?;

    for mount in mounts {
        let mount = match mount {
            Ok(mount) => mount,
            Err(error) => {
                log::warn!("failed to obtain mount information: {}", error);
                continue;
            }
        };

        session.reply(Item {
            mount,
        })?;
    }

    Ok(())
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::v2::list_mounts::Result;

    fn into_proto(self) -> rrg_proto::v2::list_mounts::Result {
        let mut proto = rrg_proto::v2::list_mounts::Result::default();
        proto.set_mount(self.mount.into());

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_if_any_filesystem_exists() {
        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());
        assert_ne!(session.reply_count(), 0);
    }
}
