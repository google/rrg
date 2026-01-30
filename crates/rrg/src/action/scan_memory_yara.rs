// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use crate::action::dump_process_memory::{MappedRegion, MemoryReader};
use std::time::Duration;

use yara_x::Compiler;
use yara_x::blocks::Scanner;

use rrg_proto::scan_memory_yara as proto;

/// Arguments of the `scan_memory_yara` action.
#[derive(Default)]
pub struct Args {
    /// PIDs of the processes whose memory we are interested in.
    pids: Vec<u32>,

    /// YARA signature source to use for scanning.
    signature: String,

    /// Maximum time spent scanning a single process.
    timeout: Option<Duration>,

    /// Set this flag to avoid scanning mapped files.
    skip_mapped_files: bool,
    /// Set this flag to avoid scanning shared memory regions.
    skip_shared_regions: bool,
    /// Set this flag to avoid scanning executable memory regions.
    skip_executable_regions: bool,
    /// Set this flag to avoid scanning readonly memory regions.
    skip_readonly_regions: bool,

    /// Length of the chunks used to read large memory regions, in bytes.
    chunk_size: u64,
    /// Overlap across chunks, in bytes. A larger overlap decreases
    /// the chance of missing a string located across chunk boundaries
    /// that would otherwise match.
    chunk_overlap: u64,
}

use crate::request::ParseArgsError;
impl crate::request::Args for Args {
    type Proto = proto::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Self, ParseArgsError> {
        const DEFAULT_CHUNK_SIZE: u64 = 50 * 1024 * 1024; // 50 MiB
        const DEFAULT_CHUNK_OVERLAP: u64 = 10 * 1024 * 1024; // 10 MiB

        let mut timeout: Option<Duration> = None;
        if proto.has_timeout() {
            timeout = Some(proto.take_timeout().into())
        }

        Ok(Self {
            pids: proto.pids,
            signature: proto.signature,
            timeout,
            skip_mapped_files: proto.skip_mapped_files,
            skip_shared_regions: proto.skip_shared_regions,
            skip_executable_regions: proto.skip_executable_regions,
            skip_readonly_regions: proto.skip_readonly_regions,
            chunk_size: proto.chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE),
            chunk_overlap: proto.chunk_overlap.unwrap_or(DEFAULT_CHUNK_OVERLAP),
        })
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
        if self.skip_mapped_files && (region.inode.is_some() || region.path.is_some()) {
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

// Unfortunately need to recreate some of the YARA structs in our code
// as they depend on the lifetime of the Compiler struct, whereas RRG
// action items need to be 'static. Additionally, we want to send
// matching data to the blob store, instead of sending it back inline
// in responses.

#[derive(Debug)]
struct Rule {
    identifier: String,
    patterns: Vec<Pattern>,
}

#[derive(Debug)]
struct Pattern {
    identifier: String,
    matches: Vec<Match>,
}

#[derive(Debug)]
struct Match {
    /// Address range in the process' address space at which the match was found.
    range: std::ops::Range<usize>,
    /// SHA-256 digest of the matching bytes that were sent to the blob sink.
    blob_sha256: [u8; 32],
}

impl From<yara_x::Rule<'_, '_>> for Rule {
    fn from(rule: yara_x::Rule<'_, '_>) -> Self {
        Self {
            identifier: rule.identifier().to_string(),
            patterns: rule.patterns().map(Into::into).collect(),
        }
    }
}

impl From<Rule> for proto::Rule {
    fn from(rule: Rule) -> Self {
        let mut ret = Self::new();
        ret.set_identifier(rule.identifier);
        ret.set_patterns(rule.patterns.into_iter().map(From::from).collect());
        ret
    }
}

impl From<yara_x::Pattern<'_, '_>> for Pattern {
    fn from(pattern: yara_x::Pattern<'_, '_>) -> Self {
        Self {
            identifier: pattern.identifier().to_string(),
            matches: pattern.matches().map(Into::into).collect(),
        }
    }
}

impl From<Pattern> for proto::Pattern {
    fn from(value: Pattern) -> Self {
        let mut ret = proto::Pattern::new();
        ret.set_identifier(value.identifier);
        ret.set_matches(value.matches.into_iter().map(From::from).collect());
        ret
    }
}

impl From<yara_x::Match<'_, '_>> for Match {
    fn from(r#match: yara_x::Match<'_, '_>) -> Self {
        use sha2::Digest as _;
        let blob_sha256 = sha2::Sha256::digest(r#match.data()).into();
        Match {
            range: r#match.range(),
            blob_sha256,
        }
    }
}

impl From<Match> for proto::Match {
    fn from(value: Match) -> Self {
        let mut ret = proto::Match::new();
        ret.set_offset(value.range.start as u64);
        ret.set_data_sha256(value.blob_sha256.to_vec());
        ret
    }
}

#[derive(Debug)]
enum Error {
    /// Failed to open the process' memory for reading.
    OpenProcessMemory(std::io::Error),
    /// There was an error (e.g. a timeout) when scanning memory
    Scan(yara_x::ScanError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to scan process memory: ")?;
        match self {
            Error::OpenProcessMemory(error) => {
                write!(f, "failed to open process memory for reading: {}", error)
            }
            Error::Scan(error) => {
                write!(f, "error during scanning: {}", error)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::OpenProcessMemory(error) => Some(error),
            Error::Scan(scan_error) => Some(scan_error),
        }
    }
}

#[derive(Debug)]
struct ErrorItem {
    /// PID of the process that we encountered an error scanning.
    pid: u32,
    /// Actual error that occurred when scanning `pid`.
    error: Error,
}

#[derive(Debug)]
struct OkItem {
    /// PID of the process this item belongs to.
    pid: u32,
    /// YARA rules that matched when scanning this process' memory.
    matching_rules: Vec<Rule>,
}

/// Result of the `scan_memory_yara` action for one single process.
type Item = Result<OkItem, ErrorItem>;

impl crate::response::Item for Item {
    type Proto = proto::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = Self::Proto::new();
        match self {
            Err(ErrorItem { pid, error }) => {
                proto.set_pid(pid);
                proto.set_error(error.to_string());
            }
            Ok(OkItem {
                pid,
                matching_rules,
            }) => {
                proto.set_pid(pid);
                proto.set_matching_rules(matching_rules.into_iter().map(Into::into).collect());
            }
        }
        proto
    }
}

/// Reads and scans a single region of memory, breaking it up into chunks of `chunk_size` with an overlap of
/// `chunk_overlap`. Only returns an error if scanning failed; read errors are ignored.
fn scan_region<M: MemoryReader>(
    region: &MappedRegion,
    scanner: &mut Scanner,
    memory: &mut M,
    chunk_size: u64,
    chunk_overlap: u64,
) -> Result<(), Error> {
    let mut offset = region.start_address();
    while offset < region.end_address() {
        let remaining = region.end_address() - offset;
        let length = remaining.min(chunk_size + chunk_overlap);
        // Any process will most likely have at least one region
        // that cannot be read successfully, so there's no point
        // in reporting an error to the user if that happens,
        // just ignore it and continue.
        if let Ok(buf) = memory.read_chunk(offset, length) {
            scanner.scan(offset as usize, &buf).map_err(Error::Scan)?;
        }
        offset = offset.saturating_add(chunk_size);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn handle<S>(session: &mut S, mut args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use crate::action::dump_process_memory::{MappedRegionIter, ReadableProcessMemory};

    let rules = {
        let mut compiler = Compiler::new();
        compiler
            .add_source(args.signature.as_str())
            .map_err(crate::session::Error::action)?;
        compiler.build()
    };

    // Circumvent borrow checker complaint about partial moves with `take`
    let pids = std::mem::take(&mut args.pids);
    for pid in pids {
        let regions = match MappedRegionIter::from_pid(pid) {
            Ok(regions) => regions,
            Err(cause) => {
                session.reply(Err(ErrorItem {
                    pid,
                    error: Error::OpenProcessMemory(cause),
                }))?;
                continue;
            }
        };
        let mut memory = match ReadableProcessMemory::open(pid) {
            Ok(memory) => memory,
            Err(cause) => {
                session.reply(Err(ErrorItem {
                    pid,
                    error: Error::OpenProcessMemory(cause),
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
        if let Some(timeout) = args.timeout {
            scanner.set_timeout(timeout);
        }

        if let Err(error) = regions
            .into_iter()
            .filter(|reg| args.should_dump(reg))
            .try_for_each(|region| {
                scan_region(
                    &region,
                    &mut scanner,
                    &mut memory,
                    args.chunk_size,
                    args.chunk_overlap,
                )
            })
        {
            session.reply(Err(ErrorItem { pid, error }))?;
            continue;
        }

        match scanner.finish() {
            Ok(results) => {
                for r#match in results
                    .matching_rules()
                    .flat_map(|rule| rule.patterns())
                    .flat_map(|pattern| pattern.matches())
                {
                    session.send(
                        crate::Sink::Blob,
                        crate::blob::Blob::from(r#match.data().to_vec()),
                    )?;
                }
                session.reply(Ok(OkItem {
                    pid,
                    matching_rules: results.matching_rules().map(Into::into).collect(),
                }))?;
            }
            Err(error) => {
                session.reply(Err(ErrorItem {
                    pid,
                    error: Error::Scan(error),
                }))?;
            }
        }
    }
    Ok(())
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

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod tests {
    use super::*;
    use crate::action::dump_process_memory::tests::FakeProcessMemory;

    fn compile(src: &str) -> yara_x::Rules {
        let mut compiler = Compiler::new();
        compiler
            .add_source(src)
            .expect("failed to compile rule file");
        compiler.build()
    }

    #[test]
    fn scans_regions() {
        let contents = b"text hereUNRELATEDtext here".to_vec();
        let unrelated_idx = b"text here".len();
        let second_text_idx = unrelated_idx + b"UNRELATED".len();
        let regions = [
            MappedRegion::from_bounds(0, unrelated_idx as u64),
            MappedRegion::from_bounds(unrelated_idx as u64, second_text_idx as u64),
            MappedRegion::from_bounds(second_text_idx as u64, contents.len() as u64),
        ];

        let rules = compile(
            r#"
            rule ExampleRule {
                strings:
                    $text = "text here"
                    $hex = { E2 34 A1 C8 23 FB }
                    $regex = /some regular expression: \w+/
                condition:
                    $text or $hex or $regex
            }"#,
        );
        let mut scanner = Scanner::new(&rules);

        let mut memory = FakeProcessMemory { contents };
        for region in regions {
            scan_region(&region, &mut scanner, &mut memory, 1000, 1000)
                .expect("failed to scan region");
        }
        let results = scanner.finish().expect("failed to finish scan");

        let rule = results.matching_rules().next().expect("no matching rule");
        assert_eq!(rule.identifier(), "ExampleRule");
        let pattern = rule
            .patterns()
            .next()
            .expect("no patterns in matching rule");
        assert_eq!(pattern.identifier(), "$text");
        let matches = pattern.matches().collect::<Vec<_>>();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].data(), b"text here");
        assert_eq!(matches[0].range(), (0..unrelated_idx));
        assert_eq!(matches[1].data(), b"text here");
        assert_eq!(matches[1].range(), (second_text_idx..memory.contents.len()));
    }

    #[test]
    fn catches_matches_at_chunk_boundaries() {
        let rules = compile(
            r#"
            rule TestRule {
                strings:
                    $text = "wololo"
                condition:
                    $text
            }"#,
        );

        let mut contents = vec![0u8; 1024];
        const CHUNK_SIZE: usize = 512;
        const CHUNK_OVERLAP: usize = 128;
        // Insert a match at chunk boundaries to ensure they're caught by the overlap
        contents[(CHUNK_SIZE - 3)..(CHUNK_SIZE + 3)].copy_from_slice(b"wololo");
        // Also insert a match at the very end
        contents.extend_from_slice(b"wololo");

        let mut scanner = Scanner::new(&rules);
        let region = MappedRegion::from_bounds(0, contents.len() as u64);
        let mut memory = FakeProcessMemory { contents };
        scan_region(
            &region,
            &mut scanner,
            &mut memory,
            CHUNK_SIZE as u64,
            CHUNK_OVERLAP as u64,
        )
        .expect("failed to scan region");
        let results = scanner.finish().expect("failed to finish scan");

        let rule = results.matching_rules().next().expect("rule did not match");
        let pattern = rule.patterns().next().expect("pattern did not match");
        assert_eq!(pattern.identifier(), "$text");
        assert_eq!(pattern.matches().count(), 2);
    }

    #[test]
    fn scan_this_process_memory() {
        // Hold onto some memory.
        // The resulting rule should match in the program
        // text and/or in the heap contents.
        let mem = b"mypreciousssss".to_vec();

        // Force the memory to be allocated with a compiler hint
        std::hint::black_box(mem.as_ptr());

        let mut session = crate::session::FakeSession::new();
        let args = Args {
            pids: vec![std::process::id()],
            signature: r#"
            rule ExampleRule {
                strings:
                    $regex = /mypreciouss*/
                condition:
                    $regex
            }
            "#
            .to_string(),
            // Set limit to keep unit test time reasonable
            timeout: Some(Duration::from_secs(30)),
            chunk_size: 100 * 1024 * 1024,
            chunk_overlap: 50 * 1024 * 1024,
            ..Default::default()
        };

        handle(&mut session, args).unwrap();

        let reply = session
            .replies::<Item>()
            .next()
            .expect("handle did not produce any replies")
            .as_ref()
            .expect("handle produced non-ok reply");
        assert!(!reply.matching_rules.is_empty(), "scan rule did not match");

        // Check that the string was found and sent to blob sink
        assert!(
            session
                .parcels::<crate::blob::Blob>(crate::Sink::Blob)
                .any(|parcel| parcel.as_bytes() == mem)
        );

        // Drop explicitly so mem is not optimized away for being unused.
        drop(mem);
    }

    #[test]
    fn applies_timeout() {
        let mut session = crate::session::FakeSession::new();

        // Hold a malicious string in memory that slows down scanning
        let mut malicious_string = vec![b'a'; 10000];
        malicious_string.push(b'z');

        let args = Args {
            pids: vec![std::process::id()],
            signature: r#"
            rule slow {
                strings:
                    $regex = /(a+)+z/
                condition:
                    $regex
            }"#
            .to_string(),
            timeout: Some(Duration::from_millis(500)),
            chunk_size: 10000,
            chunk_overlap: 500,
            ..Default::default()
        };

        handle(&mut session, args).unwrap();

        assert!(
            session
                .replies::<Item>()
                .filter_map(|item| item.as_ref().err())
                .any(|err| matches!(err.error, Error::Scan(yara_x::ScanError::Timeout)))
        );
    }
}
