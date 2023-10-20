// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// A result of the `list_mounts` action.
struct Item {
    // TODO(@panhania): Add actual data.
}

// Handles invocations of the `list_mounts` action.
pub fn handle<S>(_session: &mut S, _: ()) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    todo!()
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::v2::list_mounts::Result;

    fn into_proto(self) -> rrg_proto::v2::list_mounts::Result {
        todo!()
    }
}
