// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_utils::{FuzzSession, MemFd, FuzzRegex, make_proto_path};
use rrg::action::get_file_metadata;
use rrg_proto::rrg::Request as RequestProto;
use rrg::Request;
use arbitrary::Arbitrary;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    file_content: Vec<u8>,
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

    let mut proto = RequestProto::new();
    proto.set_request_id(12345);
    proto.set_action(rrg_proto::rrg::Action::GET_FILE_METADATA);
    proto.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());

    if let Ok(request) = Request::try_from(proto) {
        if let Ok(internal_args) = request.args() {
            let _ = get_file_metadata::handle(&mut session, internal_args);
        }
    }
});
