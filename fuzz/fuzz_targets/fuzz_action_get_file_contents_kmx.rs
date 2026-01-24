// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_utils::{FuzzSession, MemFd, make_proto_path};
use rrg::action::get_file_contents_kmx;
use rrg_proto::rrg::Request as RequestProto;
use rrg::Request;

fuzz_target!(|data: &[u8]| {
    if data.len() < 512 {
        return;
    }

    let memfd = match MemFd::new(data) {
        Some(fd) => fd,
        None => return,
    };

    let mut session = FuzzSession::new();

    let mut args = rrg_proto::get_file_contents_kmx::Args::new();
    args.set_volume_path(make_proto_path(&memfd.path));

    // Paths to probe inside that images.
    let probe_paths = vec![".", "$MFT", "$Bitmap", "Windows", "Users", "secret.txt"];
    for p in probe_paths {
        let mut path_proto = rrg_proto::fs::Path::new();
        path_proto.set_raw_bytes(p.as_bytes().to_vec());
        args.mut_paths().push(path_proto);
    }

    args.set_offset(0);
    args.set_length(1024);

    let mut proto = RequestProto::new();
    proto.set_request_id(12345);
    proto.set_action(rrg_proto::rrg::Action::GET_FILE_CONTENTS_KMX);
    proto.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());

    if let Ok(request) = Request::try_from(proto) {
        if let Ok(internal_args) = request.args() {
            let _ = get_file_contents_kmx::handle(&mut session, internal_args);
        }
    }
});
