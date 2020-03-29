// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::fs::File;
use std::io::{Read, Write, Result};

const PROTOS: &'static [&'static str] = &[
    "grr/grr/proto/grr_response_proto/semantic.proto",
    "grr/grr/proto/grr_response_proto/knowledge_base.proto",
    "grr/grr/proto/grr_response_proto/jobs.proto",
];

const INCLUDES: &'static [&'static str] = &[
    "grr/grr/proto",
];

fn main() -> Result<()> {
    let tempdir = tempfile::tempdir()?;

    let mut patched_paths = Vec::new();
    let mut patched_includes = Vec::new();

    for path in PROTOS {
        let patched_path = tempdir.path().join(path);
        let patched_path_dir = patched_path.parent().unwrap();
        std::fs::create_dir_all(patched_path_dir)?;

        let mut proto = File::open(&path).unwrap();
        let mut patched_proto = File::create(&patched_path).unwrap();

        patch(&mut proto, &mut patched_proto)?;

        patched_paths.push(patched_path);
    }

    for path in INCLUDES {
        let patched_path = tempdir.path().join(path);
        patched_includes.push(patched_path);
    }

    prost_build::compile_protos(&patched_paths, &patched_includes)
}

fn patch<R, W>(input: &mut R, output: &mut W) -> Result<()>
where
    R: Read,
    W: Write,
{
    let reader = std::io::BufReader::new(input);
    for line in std::io::BufRead::lines(reader) {
        let line = line?;

        writeln!(output, "{}", line)?;
        if line.starts_with("syntax =") {
            writeln!(output, "package grr;")?;
        }
    }

    Ok(())
}
