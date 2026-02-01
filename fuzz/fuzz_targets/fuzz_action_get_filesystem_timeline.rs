// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_utils::{FuzzSession, make_proto_path};
use rrg::action::get_filesystem_timeline;
use rrg_proto::rrg::Request as RequestProto;
use rrg::Request;
use arbitrary::Arbitrary;
use std::fs;
use std::os::unix::fs::symlink;
use tempfile::TempDir;

#[derive(Debug, Arbitrary)]
struct FsEntry {
    path: String, // Relative path, e.g., "a/b/c.txt"
    is_dir: bool,
    is_symlink: bool,
    content: Vec<u8>,
}

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    entries: Vec<FsEntry>,
}

// Creates a temporary directory and populates it with the given entries.
fn create_test_tree(entries: &[FsEntry]) -> Option<TempDir> {
    let temp_dir = TempDir::new().ok()?;
    let root_path = temp_dir.path();

    for entry in entries {
        // Prevent directory traversal ("../") and absolute paths to keep fuzzing safe.
        if entry.path.contains("..") || entry.path.starts_with('/') {
            continue;
        }
        // Remove nulls which panic Rust's file APIs.
        let safe_path = entry.path.replace('\0', "");
        if safe_path.is_empty() {
            continue;
        }

        let full_path = root_path.join(&safe_path);

        // Best Effort: If 'parent' cannot be created (e.g. because part of the
        // path is already a file), we ignore the error. The fuzzer generates
        // conflicting paths constantly;
        if let Some(parent) = full_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if entry.is_dir {
            let _ = fs::create_dir(&full_path);
        } else if entry.is_symlink {
            if let Ok(target) = std::str::from_utf8(&entry.content) {
                // Ignore errors (e.g. if symlink exists)
                let _ = symlink(target, &full_path);
            }
        } else {
            let _ = fs::write(&full_path, &entry.content);
        }
    }

    Some(temp_dir)
}

fuzz_target!(|input: FuzzInput| {
    // Create a real directory tree in RAM (/tmp).
    let temp_dir = match create_test_tree(&input.entries) {
        Some(d) => d,
        None => return,
    };

    let mut session = FuzzSession::new();
    let mut args = rrg_proto::get_filesystem_timeline::Args::new();
    args.set_root(make_proto_path(temp_dir.path().to_str().unwrap()));

    let mut proto = RequestProto::new();
    proto.set_request_id(12345);
    proto.set_action(rrg_proto::rrg::Action::GET_FILESYSTEM_TIMELINE);
    proto.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());

    if let Ok(request) = Request::try_from(proto) {
        if let Ok(internal_args) = request.args() {
            let _ = get_filesystem_timeline::handle(&mut session, internal_args);
        }
    }
    // temp_dir is automatically dropped here, cleaning up the files
});
