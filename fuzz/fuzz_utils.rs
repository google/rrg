// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use arbitrary::{Arbitrary, Unstructured, Result};
use std::os::unix::io::FromRawFd;
use std::fs::File;
use std::ffi::CString;
use std::io::Write;
use std::time::Duration;

// A wrapper around String that generates mostly-valid Regexes.
// This helps fuzzers pass the parsing stage and reach the scanning logic.
#[derive(Debug, Clone)]
pub struct FuzzRegex(pub String);

// Memory backed file descriptor to accelerate fuzzing
pub struct MemFd {
    pub fd: i32,
    pub path: String,
}

// Mock RRG session for fuzzing
pub struct FuzzSession {
    args: rrg::args::Args,
    filestore: rrg::filestore::Filestore,
    _filestore_tempdir: tempfile::TempDir,
}

pub fn make_proto_path(s: &str) -> rrg_proto::fs::Path {
    let mut p = rrg_proto::fs::Path::new();
    p.set_raw_bytes(s.as_bytes().to_vec());
    p
}

impl<'a> Arbitrary<'a> for FuzzRegex {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        // 10% chance to be empty (no regex filtering).
        if u.ratio(1, 10)? {
            return Ok(FuzzRegex(String::new()));
        }

        // A pool of valid regex components
        let patterns = [
            ".*", "\\d+", "[a-z]+", "\\w{3,5}", "^start", "end$",
            "foo|bar", "(a|b)+", "[^0-9]", "\\s+"
        ];

        // 80% chance to pick a valid syntax (Single or Combined).
        if u.ratio(8, 10)? {
            let count = u.int_in_range(1..=3)?;
            let mut s = String::new();
            for _ in 0..count {
                let p = patterns[u.choose_index(patterns.len())?];
                s.push_str(p);
            }
            return Ok(FuzzRegex(s));
        }

        // 10% chance to use raw random string (Tests invalid regex errors).
        let s: String = u.arbitrary()?;
        Ok(FuzzRegex(s.replace('\0', "")))
    }
}

impl MemFd {
    pub fn new(content: &[u8]) -> Option<Self> {
        let cname = CString::new("fuzzfd").unwrap();
        // SAFETY: We provide a valid pointer to a null-terminated string and
        // use flag `1` (MFD_CLOEXEC), ensuring the FD is closed on exec to avoid pollution,
        // as actions use linked libraries not spawned processes
        let fd = unsafe { libc::memfd_create(cname.as_ptr(), 1) };

        if fd == -1 {
            return None;
        }

        // SAFETY: We just created the file descriptor, so it is valid and we
        // have exclusive ownership of it.
        let mut file = unsafe { File::from_raw_fd(fd) };
        if file.write_all(content).is_err() {
            return None;
        }

        std::mem::forget(file);

        let path = format!("/proc/self/fd/{}", fd);
        Some(Self { fd, path })
    }

    pub fn path_proto(&self) -> rrg_proto::fs::Path {
        let mut p = rrg_proto::fs::Path::new();
        p.set_raw_bytes(self.path.as_bytes().to_vec());
        p
    }
}

impl Drop for MemFd {
    fn drop(&mut self) {
        // SAFETY: We own the file descriptor and we are in the destructor, so
        // it is safe to close it to avoid leaks.
        unsafe { libc::close(self.fd) };
    }
}

impl FuzzSession {
    pub fn new() -> Self {
        let temp_dir = tempfile::Builder::new().tempdir().unwrap();
        let args = rrg::args::Args {
            heartbeat_rate: Duration::ZERO,
            ping_rate: Duration::ZERO,
            command_verification_key: None,
            verbosity: log::LevelFilter::Off,
            log_to_stdout: false,
            log_to_file: None,
            filestore_dir: Some(temp_dir.path().to_path_buf()),
            filestore_ttl: Duration::from_secs(3600),
        };

        let filestore = rrg::filestore::Filestore::init(
            &args.filestore_dir.clone().unwrap(),
            args.filestore_ttl,
        ).unwrap();

        Self {
            args,
            filestore,
            _filestore_tempdir: temp_dir,
        }
    }
}

impl rrg::session::Session for FuzzSession {
    fn args(&self) -> &rrg::args::Args {
        &self.args
    }

    fn filestore(&self) -> rrg::session::Result<&rrg::filestore::Filestore> {
        Ok(&self.filestore)
    }

    fn reply<I: rrg::Item + 'static>(&mut self, _: I) -> rrg::session::Result<()> { Ok(()) }
    fn send<I: rrg::Item + 'static>(&mut self, _: rrg::Sink, _: I) -> rrg::session::Result<()> { Ok(()) }
    fn heartbeat(&mut self) {}
}
