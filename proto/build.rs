// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::path::Path;
use std::io::{Read, Write, Result};

const PROTOS: &'static [&'static str] = &[
    "grr/grr/proto/grr_response_proto/semantic.proto",
    "grr/grr/proto/grr_response_proto/knowledge_base.proto",
    "grr/grr/proto/grr_response_proto/jobs.proto",
];

const INCLUDES: &'static [&'static str] = &[
    "grr/grr/proto",
];

fn main() {
    let tempdir = tempfile::tempdir()
        .expect("failed to create temp dir");

    let mut protos = Vec::new();
    let mut includes = Vec::new();

    for path_before in PROTOS {
        let path_after = tempdir.path().join(path_before);

        patch_path(&path_before, &path_after)
            .expect(&format!("failed to patch file '{}'", path_before));

        protos.push(path_after);
    }

    for path_before in INCLUDES {
        let path_after = tempdir.path().join(path_before);
        includes.push(path_after);
    }

    prost_build::compile_protos(&protos, &includes)
        .expect("failed to compile proto files");
}

fn patch_path<PI, PO>(input: PI, output: PO) -> Result<()>
where
    PI: AsRef<Path>,
    PO: AsRef<Path>,
{
    let mut input = file::open(&input)?;
    let mut output = file::create(&output)?;

    patch_buffer(&mut input, &mut output)
}

fn patch_buffer<R, W>(input: &mut R, output: &mut W) -> Result<()>
where
    R: Read,
    W: Write,
{
    let mut buffer = String::new();
    input.read_to_string(&mut buffer)?;

    for line in buffer.lines() {
        writeln!(output, "{}", line)?;
        if line.starts_with("syntax =") {
            writeln!(output, "package grr;")?;
        }
    }

    Ok(())
}

mod file {
    use std::fs::File;
    use std::io::Result;
    use std::path::Path;

    pub fn open<P: AsRef<Path>>(path: P) -> Result<File> {
        File::open(path)
    }

    pub fn create<P: AsRef<Path>>(path: P) -> Result<File> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }

        File::create(path)
    }
}
