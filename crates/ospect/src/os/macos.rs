// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Returns the time at which the system was installed.
pub fn installed() -> std::io::Result<std::time::SystemTime> {
    crate::os::unix::installed()
}
