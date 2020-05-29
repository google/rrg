// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the `GetMemorySize` action.
//!
//! The `GetMemorySize` action returns the RAM size in bytes.

use sysinfo::SystemExt;
use crate::session::{self, Session};

pub struct Response {
    memory_size: u64
}

pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    let mut system = sysinfo::System::new();
    system.refresh_all();
    session.reply(Response {
        memory_size: system.get_total_memory() * 1024
    })?;
    Ok(())
}

/// A response type for the `GetMemorySize` action.
impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("ByteSize");

    type Proto = String;

    fn into_proto(self) -> Self::Proto {
        self.memory_size.to_string()
    }
}