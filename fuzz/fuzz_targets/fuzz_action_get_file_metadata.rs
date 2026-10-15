// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_utils::{BoundedVec, FuzzSession, MemFd, FuzzRegex, make_proto_path, MAX_FUZZ_BUFFER_SIZE};
use rrg::action::get_file_metadata;
use arbitrary::Arbitrary;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    file_content: BoundedVec<u8, MAX_FUZZ_BUFFER_SIZE>,
    max_depth: u32,
    md5: bool,
    sha1: bool,
    sha256: bool,
    path_canonical: bool,
    path_pruning_regex: FuzzRegex,
    contents_regex: FuzzRegex,
}

fuzz_target!(|input: FuzzInput| {
    let memfd = match MemFd::new(&input.file_content) {
        Some(fd) => fd,
        None => return,
    };

    let mut session = FuzzSession::new();
    let mut args = rrg_proto::get_file_metadata::Args::new();
    args.mut_paths().push(make_proto_path(&memfd.path));
    args.set_max_depth(input.max_depth);
    args.set_md5(input.md5);
    args.set_sha1(input.sha1);
    args.set_sha256(input.sha256);
    args.set_path_canonical(input.path_canonical);
    args.set_path_pruning_regex(input.path_pruning_regex.0);
    args.set_contents_regex(input.contents_regex.0);

    use rrg::request::Args as _;
    let Ok(args) = get_file_metadata::Args::from_proto(args) else {
        return
    };
    let _ = get_file_metadata::handle(&mut session, args);
});
