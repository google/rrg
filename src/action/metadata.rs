// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use crate::metadata::{Metadata};
use crate::session::{self, Session};

pub struct Response {
    metadata: Metadata,
}

pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    session.reply(Response {
        metadata: Metadata::from_cargo(),
    })?;

    Ok(())
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("ClientInformation");

    type Proto = rrg_proto::ClientInformation;

    fn into_proto(self) -> rrg_proto::ClientInformation {
        self.metadata.into()
    }
}
