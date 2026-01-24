// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_utils::{FuzzSession, MemFd, FuzzRegex, make_proto_path};
use rrg::action::grep_file_contents;
use rrg_proto::rrg::Request as RequestProto;
use rrg::Request;
use arbitrary::Arbitrary;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    file_content: Vec<u8>,
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

    let mut proto = RequestProto::new();
    proto.set_request_id(12345);
    proto.set_action(rrg_proto::rrg::Action::GREP_FILE_CONTENTS);
    proto.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());

    if let Ok(request) = Request::try_from(proto) {
        if let Ok(internal_args) = request.args() {
            let _ = grep_file_contents::handle(&mut session, internal_args);
        }
    }
});
