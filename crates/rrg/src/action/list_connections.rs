// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

pub fn handle<S>(_session: &mut S, _: ()) -> crate::session::Result<()> {
    let error = std::io::Error::from(std::io::ErrorKind::Unsupported);
    Err(crate::session::Error::action(error))
}
