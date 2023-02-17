// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Returns an iterator yielding identifiers of all processes on the system.
pub fn ids() -> std::io::Result<impl Iterator<Item = std::io::Result<u32>>> {
    // TOOD(@panhania): Implement this method.
    Err::<std::iter::Empty<_>, _>(std::io::ErrorKind::Unsupported.into())
}
