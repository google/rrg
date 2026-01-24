// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_utils::{FuzzSession, MemFd, make_proto_path};
use rrg::action::get_file_contents;
use rrg_proto::rrg::Request as RequestProto;
use rrg::Request;
use arbitrary::Arbitrary;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    file_content: Vec<u8>,
    offset: u64,
    length: u64,
}

fuzz_target!(|input: FuzzInput| {
    let memfd = match MemFd::new(&input.file_content) {
        Some(fd) => fd,
        None => return,
    };

    let mut session = FuzzSession::new();

    let mut args = rrg_proto::get_file_contents::Args::new();

    args.mut_paths().push(make_proto_path(&memfd.path));

    args.set_offset(input.offset);
    args.set_length(input.length);

    let mut proto = RequestProto::new();
    proto.set_request_id(12345);
    proto.set_action(rrg_proto::rrg::Action::GET_FILE_CONTENTS);
    proto.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());

    if let Ok(request) = Request::try_from(proto) {
        if let Ok(internal_args) = request.args() {
            let _ = get_file_contents::handle(&mut session, internal_args);
        }
    }
});
