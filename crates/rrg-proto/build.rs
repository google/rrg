// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::path::PathBuf;

const PROTOS_V2: &'static [&'static str] = &[
    "../../proto/rrg.proto",
    "../../proto/rrg/blob.proto",
    "../../proto/rrg/fs.proto",
    "../../proto/rrg/net.proto",
    "../../proto/rrg/os.proto",
    "../../proto/rrg/startup.proto",
    "../../proto/rrg/action/get_file_contents.proto",
    "../../proto/rrg/action/get_file_metadata.proto",
    "../../proto/rrg/action/get_filesystem_timeline.proto",
    "../../proto/rrg/action/get_system_metadata.proto",
    "../../proto/rrg/action/list_connections.proto",
    "../../proto/rrg/action/list_interfaces.proto",
    "../../proto/rrg/action/list_mounts.proto",
];

fn main() {
    let outdir: PathBuf = std::env::var("OUT_DIR")
        .expect("no output directory")
        .into();

    for proto in PROTOS_V2 {
        println!("cargo:rerun-if-changed={}", proto);
    }

    let proto_out_dir = outdir.join("proto-v2");
    std::fs::create_dir_all(&proto_out_dir).unwrap();

    protobuf_codegen_pure::Codegen::new()
        .out_dir(&proto_out_dir)
        .include("../../vendor/protobuf/src")
        .include("../../proto")
        .inputs(PROTOS_V2)
        .customize(protobuf_codegen_pure::Customize {
            gen_mod_rs: Some(true),
            ..Default::default()
        })
        .run().unwrap();
}
