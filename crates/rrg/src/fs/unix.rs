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
    // We need `u32::from` because `DirBuilderExt::mode` takes `u32` but libc
    // flags use `mode_t` which varies by platform (e.g. it is `u16` on Apple
    // systems).
    root_dir_builder.mode(u32::from(libc::S_IRWXU));

    root_dir_builder.create(path)
}
