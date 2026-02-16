// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::path::Path;

pub fn create_dir_private_all<P>(path: P) -> std::io::Result<()>
where
    P: AsRef<Path>,
{
    let mut root_dir_builder = std::fs::DirBuilder::new();
    root_dir_builder.recursive(true);

    use std::os::unix::fs::DirBuilderExt as _;
    root_dir_builder.mode(0o700);

    root_dir_builder.create(path)
}
