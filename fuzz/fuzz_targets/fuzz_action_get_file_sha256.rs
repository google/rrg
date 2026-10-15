// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_utils::{BoundedVec, FuzzSession, MemFd, make_proto_path, MAX_FUZZ_BUFFER_SIZE, MAX_FUZZ_VEC_LEN};
use rrg::action::get_file_sha256;
use arbitrary::Arbitrary;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    file_content: BoundedVec<u8, MAX_FUZZ_BUFFER_SIZE>,
    offsets: BoundedVec<u64, MAX_FUZZ_VEC_LEN>,
    length: u64,
}

fuzz_target!(|input: FuzzInput| {
    let memfd = match MemFd::new(&input.file_content) {
        Some(fd) => fd,
        None => return,
    };

    let mut session = FuzzSession::new();

    let mut args = rrg_proto::get_file_sha256::Args::new();
    args.set_path(make_proto_path(&memfd.path));
    args.set_offsets(input.offsets.into());
    args.set_length(input.length);

    use rrg::request::Args as _;
    let Ok(args) = get_file_sha256::Args::from_proto(args) else {
        return
    };
    let _ = get_file_sha256::handle(&mut session, args);
});
