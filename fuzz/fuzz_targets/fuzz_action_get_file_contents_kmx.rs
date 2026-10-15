// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_utils::{BoundedVec, FuzzSession, MemFd, make_proto_path, MAX_FUZZ_BUFFER_SIZE};
use rrg::action::get_file_contents_kmx;

fuzz_target!(|data: BoundedVec<u8, MAX_FUZZ_BUFFER_SIZE>| {
    let memfd = match MemFd::new(&data) {
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

    args.set_length(1024);

    use rrg::request::Args as _;
    let Ok(args) = get_file_contents_kmx::Args::from_proto(args) else {
        return
    };
    let _ = get_file_contents_kmx::handle(&mut session, args);
});
