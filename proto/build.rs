// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::path::PathBuf;

const PROTOS: &'static [&'static str] = &[
    "vendor/grr/grr/proto/grr_response_proto/semantic.proto",
    "vendor/grr/grr/proto/grr_response_proto/sysinfo.proto",
    "vendor/grr/grr/proto/grr_response_proto/knowledge_base.proto",
    "vendor/grr/grr/proto/grr_response_proto/jobs.proto",
    "vendor/grr/grr/proto/grr_response_proto/timeline.proto",
    "vendor/grr/grr/proto/grr_response_proto/anomaly.proto",
    "vendor/grr/grr/proto/grr_response_proto/export.proto",
    "vendor/grr/grr/proto/grr_response_proto/objects.proto",
    "vendor/grr/grr/proto/grr_response_proto/output_plugin.proto",
    "vendor/grr/grr/proto/grr_response_proto/flows.proto",
    "vendor/grr/grr/proto/grr_response_proto/sysinfo.proto",
    "vendor/grr/grr/proto/grr_response_proto/user.proto",
];

fn main() {
    let outdir: PathBuf = std::env::var("OUT_DIR")
        .expect("no output directory")
        .into();

    let proto_out_dir = outdir.join("proto");
    std::fs::create_dir_all(&proto_out_dir).unwrap();

    protobuf_codegen_pure::run(protobuf_codegen_pure::Args {
        out_dir: &proto_out_dir.to_string_lossy(),
        includes: &[
            "vendor/grr/grr/proto",
            "vendor/protobuf/src"
        ],
        input: PROTOS,
        ..Default::default()
    }).unwrap();

    std::fs::write(proto_out_dir.join("mod.rs"), b"
        pub mod anomaly;
        pub mod jobs;
        pub mod export;
        pub mod flows;
        pub mod objects;
        pub mod output_plugin;
        pub mod sysinfo;
        pub mod timeline;
        pub mod user;
        pub mod knowledge_base;
    ").unwrap();
}
