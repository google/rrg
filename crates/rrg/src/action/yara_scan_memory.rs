// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use crate::action::dump_process_memory::{
    MappedRegion, MappedRegionIter, MemoryReader, ReadableProcessMemory,
};
use std::error::Error;
use std::time::Duration;

use yara_x::Compiler;
use yara_x::blocks::Scanner;

/// Arguments of the `yara_scan_memory` action.
#[derive(Default)]
pub struct Args {
    /// PIDs of the processs whose memory we are interested in.
    pids: Vec<u32>,

    /// YARA signature source to scan for.
    signature: String,

    scan_timeout: Duration,

    // Set this flag to avoid dumping mapped files.
    skip_mapped_files: bool,
    // Set this flag to avoid dumping shared memory regions.
    skip_shared_regions: bool,
    // Set this flag to avoid dumping executable memory regions.
    skip_executable_regions: bool,
    // Set this flag to avoid dumping readonly memory regions.
    skip_readonly_regions: bool,

    chunk_size: u64,
    chunk_overlap_size: u64,
}

use crate::request::ParseArgsError;
impl crate::request::Args for Args {
    type Proto = rrg_proto::dump_process_memory::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Self, ParseArgsError> {
        todo!()
    }
}

impl Args {
    /// Whether `region` should be dumped according to `self`'s filtering parameters.
    fn should_dump(&self, region: &MappedRegion) -> bool {
        if self.skip_shared_regions && region.permissions.shared {
            return false;
        }
        if self.skip_executable_regions && region.permissions.execute {
            return false;
        }
        if self.skip_mapped_files && region.inode.is_some() || region.path.is_some() {
            return false;
        }
        if self.skip_readonly_regions
            && region.permissions.read
            && !region.permissions.write
            && !region.permissions.execute
        {
            return false;
        }
        true
    }
}

// Unfortunately need to recreate some of the yara rule struct hierarchy
// as they depend on the lifetime of the Compiler struct,
// whereas rrg action items need to be 'static.
#[derive(Debug)]
struct Rule {
    identifier: String,
    patterns: Vec<Pattern>,
}

impl From<yara_x::Rule<'_, '_>> for Rule {
    fn from(value: yara_x::Rule) -> Self {
        Self {
            identifier: value.identifier().to_owned(),
            patterns: value
                .patterns()
                .map(Pattern::from)
                .filter(|pattern| !pattern.matches.is_empty())
                .collect(),
        }
    }
}

#[derive(Debug)]
struct Pattern {
    identifier: String,
    matches: Vec<Match>,
}

impl From<yara_x::Pattern<'_, '_>> for Pattern {
    fn from(value: yara_x::Pattern) -> Self {
        Self {
            identifier: value.identifier().to_owned(),
            matches: value.matches().map(Match::from).collect(),
        }
    }
}

#[derive(Debug)]
struct Match {
    range: std::ops::Range<usize>,
    data: Vec<u8>,
}

impl From<yara_x::Match<'_, '_>> for Match {
    fn from(value: yara_x::Match) -> Self {
        Self {
            range: value.range(),
            data: value.data().to_owned(),
        }
    }
}

#[derive(Debug)]
struct ErrorItem {
    pid: u32,
    inner: RegionScanError,
}

#[derive(Debug)]
enum RegionScanError {
    /// Failed to open the process' memory for reading.
    OpenProcessMemory(std::io::Error),
    /// There was an error while reading the contents of memory
    MemoryRead(std::io::Error),
    /// There was an error (e.g. a timeout) when scanning memory
    Scan(yara_x::ScanError),
}

struct OkItem {
    pid: u32,
    matches: Vec<Rule>,
}

fn scan_region<M: MemoryReader>(
    region: &MappedRegion,
    scanner: &mut Scanner,
    memory: &mut M,
) -> Result<(), RegionScanError> {
    let buf = memory
        .read_chunk(region.start_address(), region.size())
        .map_err(RegionScanError::MemoryRead)?;
    scanner
        .scan(region.start_address() as usize, &buf)
        .map_err(RegionScanError::Scan)?;
    Ok(())
}

/// Result of the `dump_process_memory` action.
type Item = Result<OkItem, ErrorItem>;

impl crate::response::Item for Item {
    type Proto = rrg_proto::dump_process_memory::Result;

    fn into_proto(self) -> Self::Proto {
        todo!()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn handle<S>(_session: &mut S, _args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use std::io::{Error, ErrorKind};
    Err(crate::session::Error::action(Error::from(
        ErrorKind::Unsupported,
    )))
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn handle<S>(session: &mut S, mut args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let rules = {
        let mut compiler = Compiler::new();
        compiler
            .add_source(args.signature.as_str())
            .map_err(crate::session::Error::action)?;
        compiler.build()
    };
    let mut scanner = Scanner::new(&rules);
    scanner.set_timeout(args.scan_timeout);

    // Circumvent borrow checker complaint about partial moves with `take`
    let pids = std::mem::take(&mut args.pids);
    for pid in pids {
        let regions = match MappedRegionIter::from_pid(pid) {
            Ok(regions) => regions,
            Err(cause) => {
                session.reply(Err(ErrorItem {
                    pid,
                    inner: RegionScanError::OpenProcessMemory(cause),
                }))?;
                continue;
            }
        };
        let mut memory = match ReadableProcessMemory::open(pid) {
            Ok(memory) => memory,
            Err(cause) => {
                session.reply(Err(ErrorItem {
                    pid,
                    inner: RegionScanError::OpenProcessMemory(cause),
                }))?;
                continue;
            }
        };

        // ParseRegionErrors are internal errors, so wrap them in `Error::action`
        // and bail early if any error is encountered.
        let regions: Vec<MappedRegion> = regions
            .map(|reg| reg.map_err(crate::session::Error::action))
            .collect::<Result<_, _>>()?;

        let mut scanner = Scanner::new(&rules);
        scanner.set_timeout(args.scan_timeout);
        for region in regions.into_iter().filter(|reg| args.should_dump(reg)) {
            if let Err(inner) = scan_region(&region, &mut scanner, &mut memory) {
                session.reply(Err(ErrorItem { pid, inner }))?;
            }
        }

        match scanner.finish() {
            Ok(results) => {
                let matches = results.matching_rules().map(Rule::from).collect();
                session.reply(Ok(OkItem { pid, matches }))?;
            }
            Err(error) => {
                session.reply(Err(ErrorItem {
                    pid,
                    inner: RegionScanError::Scan(error),
                }))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::dump_process_memory::FakeProcessMemory;

    const EXAMPLE_RULE_SRC: &str = r#"
    rule ExampleRule {
        strings:
            $text = "text here"
            $hex = { E2 34 A1 C8 23 FB }
            $regex = /some regular expression: \w+/
        condition:
            $text or $hex or $regex
    }
    "#;

    fn compile_source(src: &str) -> yara_x::Rules {
        let mut compiler = Compiler::new();
        compiler
            .add_source(src)
            .expect("failed to compile rule file");
        compiler.build()
    }

    #[test]
    fn test_rule_scanning() {
        let contents = b"text hereUNRELATEDtext here".to_vec();
        let unrelated_idx = b"text here".len();
        let second_text_idx = unrelated_idx + b"UNRELATED".len();
        let regions = [
            MappedRegion::from_bounds(0, unrelated_idx as u64),
            MappedRegion::from_bounds(unrelated_idx as u64, second_text_idx as u64),
            MappedRegion::from_bounds(second_text_idx as u64, contents.len() as u64),
        ];

        let rules = compile_source(EXAMPLE_RULE_SRC);
        let mut scanner = Scanner::new(&rules);

        let mut memory = FakeProcessMemory { contents };
        for region in regions {
            scan_region(&region, &mut scanner, &mut memory).expect("failed to scan region");
        }
        let results = scanner.finish().expect("failed to finish scan");
        dbg!(&results);

        let matching: Vec<Rule> = results.matching_rules().map(Rule::from).collect();
        dbg!(&matching);
        assert_eq!(matching.len(), 1);
        let rule = &matching[0];
        assert_eq!(rule.identifier, "ExampleRule");
        assert_eq!(rule.patterns.len(), 1);
        let pat = &rule.patterns[0];
        assert_eq!(pat.identifier, "$text");
        assert_eq!(pat.matches.len(), 2);
        assert_eq!(pat.matches[0].data, b"text here");
        assert_eq!(pat.matches[0].range, (0..unrelated_idx));
        assert_eq!(pat.matches[1].data, b"text here");
        assert_eq!(
            pat.matches[1].range,
            (second_text_idx..memory.contents.len())
        );
    }
}
