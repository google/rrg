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

// Empirical upper bound on buffer size.
//
// In production, RRG actions stream and process arbitrary data sizes as intended.
// During fuzzing, unbounded buffers cause linear read and hash loops (like `std::io::Read`
// and SHA-256 in `get_file_contents` or `get_file_sha256`) to cause false positives
pub const MAX_FUZZ_BUFFER_SIZE: usize = 64 * 1024;

// Empirical upper bound on vector size.
//
// Action handlers (such as `execute_signed_command`, `get_filesystem_timeline`, and
// multi-action dispatch) iterate over input lists without built-in caps. This bound
// keeps execution bounded to avoid timeouts.
pub const MAX_FUZZ_VEC_LEN: usize = 16;

// One temp dir across fuzz iterations to avoid disk churn.
static FUZZ_TEMPDIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();

// A wrapper around String that generates mostly-valid Regexes.
// This helps fuzzers pass the parsing stage and reach the scanning logic.
#[derive(Debug, Clone)]
pub struct FuzzRegex(pub String);

// A wrapper around Vec<T> to limit the vector length Arbitrary can generate
#[derive(Debug, Clone)]
pub struct BoundedVec<T, const N: usize>(pub Vec<T>);

// Memory backed file descriptor to accelerate fuzzing
pub struct MemFd {
    pub fd: i32,
    pub path: String,
}

// Mock RRG session for fuzzing
pub struct FuzzSession {
    args: rrg::args::Args,
    filestore: rrg::filestore::Filestore,
}

fn get_fuzz_tempdir() -> &'static tempfile::TempDir {
    FUZZ_TEMPDIR.get_or_init(|| {
        tempfile::Builder::new()
            .prefix("rrg_fuzz_")
            .tempdir()
            .expect("failed to create fuzz tempdir")
    })
}

pub fn make_proto_path(s: &str) -> rrg_proto::fs::Path {
    let mut p = rrg_proto::fs::Path::new();
    p.set_raw_bytes(s.as_bytes().to_vec());
    p
}

impl<'a, T: Arbitrary<'a>, const N: usize> Arbitrary<'a> for BoundedVec<T, N> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(0..=N)?;
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(T::arbitrary(u)?);
        }
        Ok(Self(vec))
    }
}

impl<T, const N: usize> std::ops::Deref for BoundedVec<T, N> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, const N: usize> From<BoundedVec<T, N>> for Vec<T> {
    fn from(bounded: BoundedVec<T, N>) -> Self {
        bounded.0
    }
}

impl<T, const N: usize> IntoIterator for BoundedVec<T, N> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T, const N: usize> AsRef<[T]> for BoundedVec<T, N> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
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
    pub fn new<const N: usize>(content: &BoundedVec<u8, N>) -> Option<Self> {
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
        let temp_dir = get_fuzz_tempdir();
        let args = rrg::args::Args {
            heartbeat_rate: Duration::ZERO,
            ping_rate: Duration::ZERO,
            command_verification_key: None,
            verbosity: log::LevelFilter::Off,
            log_to_stdout: false,
            log_to_file: None,
            request_file: None,
            filestore_dir: Some(temp_dir.path().to_path_buf()),
            filestore_ttl: Duration::from_secs(3600),
        };

        let filestore = rrg::filestore::Filestore::init(
            temp_dir.path(),
            args.filestore_ttl,
        ).unwrap();

        Self {
            args,
            filestore,
        }
    }
}

impl rrg::session::Session for FuzzSession {
    fn args(&self) -> &rrg::args::Args {
        &self.args
    }

    fn filestore_store(
        &self,
        file_sha256: [u8; 32],
        part: rrg::filestore::Part,
    ) -> rrg::session::Result<rrg::filestore::Status> {

        self.filestore.store(rrg::filestore::Id {
            flow_id: 0xFA4E,
            file_sha256,
        }, part)
            .map_err(rrg::session::Error::action)
    }

    fn filestore_path(
        &self,
        file_sha256: [u8; 32],
    ) -> rrg::session::Result<std::path::PathBuf> {
        self.filestore.path(rrg::filestore::Id {
            flow_id: 0xFA4E,
            file_sha256,
        })
            .map_err(rrg::session::Error::action)
    }

    fn reply<I: rrg::Item + 'static>(&mut self, _: I) -> rrg::session::Result<()> { Ok(()) }
    fn send<I: rrg::Item + 'static>(&mut self, _: rrg::Sink, _: I) -> rrg::session::Result<()> { Ok(()) }
    fn heartbeat(&mut self) {}
}
