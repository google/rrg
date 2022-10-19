// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the memory size action.
//!
//! The memory size action returns the RAM size in bytes.

use sysinfo::SystemExt;
use crate::session::{self, Session};

pub struct Response {
    memory_size: u64
}

pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    let mut system = sysinfo::System::new();
    system.refresh_system();
    session.reply(Response {
        memory_size: system.get_total_memory() * 1024
    })?;
    Ok(())
}

/// A response type for the memory size action.
impl super::Item for Response {

    const RDF_NAME: &'static str = "ByteSize";

    type Proto = protobuf::well_known_types::StringValue;
    // TODO: Fix serialization issues.

    fn into_proto(self) -> Self::Proto {
        let mut proto = protobuf::well_known_types::StringValue::new();
        proto.set_value(self.memory_size.to_string());

        proto
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());

        assert_eq!(session.reply_count(), 1);

        let memory_size = session.reply::<Response>(0).memory_size;
        assert!(memory_size > 0);
    }
}
