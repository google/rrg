// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::path::PathBuf;

const PROTOS: &'static [&'static str] = &[
    "../../vendor/grr/grr/proto/grr_response_proto/semantic.proto",
    "../../vendor/grr/grr/proto/grr_response_proto/sysinfo.proto",
    "../../vendor/grr/grr/proto/grr_response_proto/knowledge_base.proto",
    "../../vendor/grr/grr/proto/grr_response_proto/jobs.proto",
    "../../vendor/grr/grr/proto/grr_response_proto/timeline.proto",
    "../../vendor/grr/grr/proto/grr_response_proto/anomaly.proto",
    "../../vendor/grr/grr/proto/grr_response_proto/export.proto",
    "../../vendor/grr/grr/proto/grr_response_proto/objects.proto",
    "../../vendor/grr/grr/proto/grr_response_proto/output_plugin.proto",
    "../../vendor/grr/grr/proto/grr_response_proto/flows.proto",
    "../../vendor/grr/grr/proto/grr_response_proto/user.proto",
];

fn main() {
    let outdir: PathBuf = std::env::var("OUT_DIR")
        .expect("no output directory")
        .into();


    let proto_out_dir = outdir.join("proto");
    std::fs::create_dir_all(&proto_out_dir).unwrap();

    protobuf_codegen_pure::Codegen::new()
        .out_dir(&proto_out_dir)
        .include("../../vendor/grr/grr/proto")
        .include("../../vendor/protobuf/src")
        .inputs(PROTOS)
        .customize(protobuf_codegen_pure::Customize {
            gen_mod_rs: Some(true),
            ..Default::default()
        })
        .run().unwrap();
}