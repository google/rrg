// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#![no_main]

use std::num::NonZeroU64;
use std::path::PathBuf;
use std::time::Duration;

use arbitrary::Arbitrary;
use fuzz_utils::{BoundedVec, MAX_FUZZ_BUFFER_SIZE, MAX_FUZZ_VEC_LEN};
use libfuzzer_sys::fuzz_target;
use rrg::action::dump_process_memory::{MappedRegion, MemoryReader, Permissions, RegionFilter};
use rrg::action::scan_memory_yara::scan_regions;
use yara_x::Compiler;
use yara_x::blocks::Scanner;

/// In-memory MemoryReader that slices synthetic byte slices in RAM.
/// Bypasses `/proc/*/mem` and allows fast, isolated fuzzing.
struct FuzzMemory<'a> {
    data: &'a [u8],
}

impl MemoryReader for FuzzMemory<'_> {
    fn read_chunk(&mut self, offset: u64, length: u64) -> std::io::Result<Vec<u8>> {
        let offset = offset as usize;
        let length = length as usize;
        if offset >= self.data.len() {
            return Ok(Vec::new());
        }
        let end = (offset.saturating_add(length)).min(self.data.len());
        Ok(self.data[offset..end].to_vec())
    }
}

#[derive(Debug, Arbitrary)]
struct FuzzRegion {
    start: u64,
    size: u16,
    read: bool,
    write: bool,
    execute: bool,
    shared: bool,
    private: bool,
    has_path: bool,
    path_str: String,
}

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    rule_source: String,
    memory_data: BoundedVec<u8, MAX_FUZZ_BUFFER_SIZE>,
    regions: BoundedVec<FuzzRegion, MAX_FUZZ_VEC_LEN>,
    chunk_size: u16,
    chunk_overlap: u16,
    max_matches_per_pattern: Option<u8>,
    timeout_ms: Option<u16>,
    skip_mapped_files: bool,
    skip_shared_regions: bool,
    skip_executable_regions: bool,
    skip_readonly_regions: bool,
}

fuzz_target!(|input: FuzzInput| {
    // Compile YARA rule from arbitrary input string
    let mut compiler = Compiler::new();
    if compiler.add_source(input.rule_source.as_str()).is_err() {
        return;
    }
    let rules = compiler.build();

    let mut mapped_regions = Vec::new();
    for r in input.regions {
        let start = if input.memory_data.is_empty() {
            0
        } else {
            r.start % (input.memory_data.len() as u64)
        };
        let end = start.saturating_add(r.size as u64);
        if start >= end {
            continue;
        }

        let mut region = MappedRegion::from_bounds(start, end);
        region.permissions = Permissions {
            read: r.read,
            write: r.write,
            execute: r.execute,
            shared: r.shared,
            private: r.private,
        };
        if r.has_path {
            region.path = Some(PathBuf::from(r.path_str.replace('\0', "")));
        }
        mapped_regions.push(region);
    }

    mapped_regions.sort_unstable_by_key(|reg| reg.start_address());

    let filter = RegionFilter {
        skip_mapped_files: input.skip_mapped_files,
        skip_shared_regions: input.skip_shared_regions,
        skip_executable_regions: input.skip_executable_regions,
        skip_readonly_regions: input.skip_readonly_regions,
    };
    let filtered_regions = mapped_regions.into_iter().filter(|reg| filter.matches(reg));

    let mut mem = FuzzMemory {
        data: &input.memory_data,
    };

    let chunk_size = NonZeroU64::new((input.chunk_size as u64).max(1)).unwrap();
    let chunk_overlap = input.chunk_overlap as u64;
    let timeout = input.timeout_ms.map(|t| Duration::from_millis(t as u64));
    let max_matches = input.max_matches_per_pattern.map(|m| m as usize);

    let mut scanner = Scanner::new(&rules);
    if let Some(timeout) = timeout {
        scanner.set_timeout(timeout);
    }
    if let Some(limit) = max_matches {
        scanner.max_matches_per_pattern(limit);
    }

    if scan_regions(
        filtered_regions,
        &mut scanner,
        &mut mem,
        chunk_size,
        chunk_overlap,
    )
    .is_ok()
    {
        let _ = scanner.finish();
    }
});
