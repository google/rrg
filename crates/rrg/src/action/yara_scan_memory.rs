// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use crate::action::dump_process_memory::{
    MappedRegion, MappedRegionIter, MemoryReader, ReadableProcessMemory,
};
use std::time::Duration;

use yara_x::Compiler;
use yara_x::blocks::Scanner;

/// Arguments of the `yara_scan_memory` action.
#[derive(Default)]
pub struct Args {
    /// PIDs of the processes whose memory we are interested in.
    pids: Vec<u32>,

    /// YARA signature source to use for scanning.
    signature: String,

    /// Maximum time spent scanning a single process.
    scan_timeout: Option<Duration>,

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
    type Proto = rrg_proto::yara_scan_memory::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Self, ParseArgsError> {
        const DEFAULT_CHUNK_SIZE: u64 = 50 * 1024 * 1024; // 50MB
        const DEFAULT_CHUNK_OVERLAP: u64 = 10 * 1024 * 1024; // 10MB

        let mut scan_timeout: Option<Duration> = None;
        if proto.has_scan_timeout() {
            scan_timeout = Some(proto.take_scan_timeout().into())
        }

        Ok(Self {
            pids: proto.pids,
            signature: proto.signature,
            scan_timeout,
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

// Unfortunately need to recreate some of the Yara structs in our code
// as they depend on the lifetime of the Compiler struct,
// whereas rrg action items need to be 'static.
// Additionally, we want to send matching data to the blob store, instead of sending it back
// inline in responses.

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
    /// Sha256 digest of the matching bytes that were sent to the blob sink.
    blob_sha256: [u8; 32],
}

impl Rule {
    /// Converts a [yara_x::Rule] to a [Rule], sending any matching data to the blob store
    /// and storing the blob's Sha256 hash in the corresponding [Match].
    fn blobify<S: crate::session::Session>(
        rule: yara_x::Rule<'_, '_>,
        session: &mut S,
    ) -> crate::session::Result<Self> {
        use sha2::Digest as _;
        let patterns = rule
            .patterns()
            .map(|pattern| {
                let matches = pattern
                    .matches()
                    .map(|mat| {
                        let blob_sha256 = sha2::Sha256::digest(mat.data()).into();
                        let blob = crate::blob::Blob::from(mat.data().to_vec());
                        session.send(crate::Sink::Blob, blob)?;
                        Ok(Match {
                            range: mat.range(),
                            blob_sha256,
                        })
                    })
                    .collect::<crate::session::Result<_>>()?;
                Ok(Pattern {
                    identifier: pattern.identifier().to_owned(),
                    matches,
                })
            })
            .collect::<crate::session::Result<_>>()?;
        Ok(Self {
            identifier: rule.identifier().to_owned(),
            patterns,
        })
    }
}

impl From<Rule> for rrg_proto::yara_scan_memory::Rule {
    fn from(rule: Rule) -> Self {
        use rrg_proto::yara_scan_memory as proto;

        let mut ret = Self::new();
        ret.set_identifier(rule.identifier);
        ret.set_patterns(
            rule.patterns
                .into_iter()
                .map(|pattern| {
                    let mut ret = proto::Pattern::new();
                    ret.set_identifier(pattern.identifier);
                    ret.set_matches(
                        pattern
                            .matches
                            .into_iter()
                            .map(|mat| {
                                let mut ret = proto::Match::new();
                                ret.set_offset(mat.range.start as u64);
                                ret.set_data_sha256(mat.blob_sha256.to_vec());
                                ret
                            })
                            .collect(),
                    );
                    ret
                })
                .collect(),
        );
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

/// Result of the `yara_scan_memory` action for one single process.
type Item = Result<OkItem, ErrorItem>;

impl crate::response::Item for Item {
    type Proto = rrg_proto::yara_scan_memory::Result;

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
        // that cannot be read succesfully, so there's no point
        // in reporting an error to the user if that happens,
        // just ignore it and continue.
        if let Ok(buf) = memory.read_chunk(offset, length) {
            scanner.scan(offset as usize, &buf).map_err(Error::Scan)?;
        }
        offset += chunk_size;
    }
    Ok(())
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
        if let Some(timeout) = args.scan_timeout {
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
                let matching_rules = results
                    .matching_rules()
                    .map(|rule| Rule::blobify(rule, session))
                    .collect::<crate::session::Result<Vec<_>>>()?;
                session.reply(Ok(OkItem {
                    pid,
                    matching_rules,
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

#[cfg(all(test, any(target_os = "linux", target_os = "windows")))]
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
    fn scans_regions() {
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
        let rules = compile_source(
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
            scan_timeout: Some(Duration::from_secs(5)),
            chunk_size: 100 * 1024 * 1024,
            chunk_overlap: 50 * 1024 * 1024,
            ..Default::default()
        };

        handle(&mut session, args).unwrap();

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
            scan_timeout: Some(Duration::from_millis(500)),
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
