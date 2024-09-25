// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::path::PathBuf;

const PROTOS: &'static [&'static str] = &[
    "../../proto/rrg.proto",
    "../../proto/rrg/blob.proto",
    "../../proto/rrg/fs.proto",
    "../../proto/rrg/net.proto",
    "../../proto/rrg/os.proto",
    "../../proto/rrg/startup.proto",
    "../../proto/rrg/winreg.proto",
    "../../proto/rrg/action/get_file_contents.proto",
    "../../proto/rrg/action/get_file_hash.proto",
    "../../proto/rrg/action/get_file_metadata.proto",
    "../../proto/rrg/action/get_filesystem_timeline.proto",
    "../../proto/rrg/action/get_system_metadata.proto",
    "../../proto/rrg/action/get_winreg_value.proto",
    "../../proto/rrg/action/grep_file_contents.proto",
    "../../proto/rrg/action/list_connections.proto",
    "../../proto/rrg/action/list_interfaces.proto",
    "../../proto/rrg/action/list_mounts.proto",
    "../../proto/rrg/action/list_winreg_keys.proto",
    "../../proto/rrg/action/list_winreg_values.proto",
    "../../proto/rrg/action/query_wmi.proto",
];

fn main() {
    let outdir: PathBuf = std::env::var("OUT_DIR")
        .expect("no output directory")
        .into();

    for proto in PROTOS {
        println!("cargo:rerun-if-changed={}", proto);
    }

    let proto_out_dir = outdir.join("proto");
    std::fs::create_dir_all(&proto_out_dir).unwrap();

    let customize = protobuf_codegen::Customize::default()
        .gen_mod_rs(true)
        .generate_accessors(true);

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(&proto_out_dir)
        .include("../../proto")
        .inputs(PROTOS)
        .customize(customize)
        .run().unwrap();
}
