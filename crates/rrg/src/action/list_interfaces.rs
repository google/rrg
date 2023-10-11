// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// A result of the `list_interfaces` action.
struct Item {
    // TODO(@panhania): Add the interface type.
}

// Handles invocations of the `list_interfaces` action.
pub fn handle<S>(session: &mut S, _: ()) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let error = std::io::Error::from(std::io::ErrorKind::Unsupported);
    Err(crate::session::Error::action(error))
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::v2::list_interfaces::Result;

    fn into_proto(self) -> rrg_proto::v2::list_interfaces::Result {
        todo!()
    }
}
