// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#![no_main]

use std::path::PathBuf;

use arbitrary::Arbitrary;
use fuzz_utils::{BoundedVec, FuzzSession, MAX_FUZZ_BUFFER_SIZE, MAX_FUZZ_VEC_LEN};
use libfuzzer_sys::fuzz_target;
use rrg::action::dump_process_memory::{
    dump_regions, sort_by_priority, MappedRegion, MemoryReader, Permissions, RegionFilter,
};

/// An in-memory implementation of `MemoryReader` that serves chunks from a synthetic byte slice.
/// This completely bypasses `/proc/*/mem` and allows ultra-fast fuzzing strictly in RAM.
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
    memory_data: BoundedVec<u8, MAX_FUZZ_BUFFER_SIZE>,
    regions: BoundedVec<FuzzRegion, MAX_FUZZ_VEC_LEN>,
    priority_offsets: BoundedVec<u64, MAX_FUZZ_VEC_LEN>,
    skip_mapped_files: bool,
    skip_shared_regions: bool,
    skip_executable_regions: bool,
    skip_readonly_regions: bool,
    total_size_limit: Option<u32>,
}

fuzz_target!(|input: FuzzInput| {
    let mut mapped_regions = Vec::new();
    for r in input.regions {
        // Bound the address start so regions realistically overlap with memory_data
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

    // Sort regions by start address as required by `sort_by_priority` and `dump_regions`
    mapped_regions.sort_unstable_by_key(|reg| reg.start_address());

    let filter = RegionFilter {
        skip_mapped_files: input.skip_mapped_files,
        skip_shared_regions: input.skip_shared_regions,
        skip_executable_regions: input.skip_executable_regions,
        skip_readonly_regions: input.skip_readonly_regions,
    };

    let filtered_regions = mapped_regions.into_iter().filter(|reg| filter.matches(reg));
    let ordered_regions = sort_by_priority(filtered_regions, input.priority_offsets.into());

    let mut session = FuzzSession::new();
    let mut mem = FuzzMemory {
        data: &input.memory_data,
    };
    let mut total_size_left = input.total_size_limit.map(|v| v as u64).unwrap_or(u64::MAX);

    let _ = dump_regions(
        &mut session,
        ordered_regions.into_iter(),
        &mut mem,
        12345,
        &mut total_size_left,
    );
});
