// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_utils::{BoundedVec, FuzzSession, MemFd, make_proto_path, MAX_FUZZ_BUFFER_SIZE, MAX_FUZZ_VEC_LEN};
use rrg::action::get_file_sha256;
use rrg_proto::rrg::Request as RequestProto;
use rrg::RequestUnvalidated;
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

    use protobuf::Message as _;
    let mut proto = RequestProto::new();
    proto.set_request_id(12345);
    proto.set_action(rrg_proto::rrg::Action::GET_FILE_SHA256);
    proto.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());

    let message = fleetspeak::Message {
        service: String::from("GRR"),
        kind: Some(String::from("rrg.Request")),
        data: proto.write_to_bytes().unwrap(),
    };

    let Ok(request) = RequestUnvalidated::parse(&message) else {
        return
    };
    // TODO(@panhania): Reduce nesting with `let .. else`.
    if let Ok(request) = request.validate() {
        if let Ok(internal_args) = request.args() {
            let _ = get_file_sha256::handle(&mut session, internal_args);
        }
    }
});
