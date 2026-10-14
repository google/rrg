// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_utils::{BoundedVec, FuzzSession, MemFd, FuzzRegex, make_proto_path, MAX_FUZZ_BUFFER_SIZE};
use rrg::action::grep_file_contents;
use arbitrary::Arbitrary;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    file_content: BoundedVec<u8, MAX_FUZZ_BUFFER_SIZE>,
    pattern: FuzzRegex,
}

fuzz_target!(|input: FuzzInput| {
    let memfd = match MemFd::new(&input.file_content) {
        Some(fd) => fd,
        None => return,
    };

    let mut session = FuzzSession::new();
    let mut args = rrg_proto::grep_file_contents::Args::new();
    args.set_path(make_proto_path(&memfd.path));
    args.set_regex(input.pattern.0);

    use rrg::request::Args as _;
    let Ok(args) = grep_file_contents::Args::from_proto(args) else {
        return
    };
    let _ = grep_file_contents::handle(&mut session, args);
});
