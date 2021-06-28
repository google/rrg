// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Defines an internal type for client side file finder action and provides
//! a function converting proto format of the request
//! `rrg_proto::FileFinderArgs` to the internal format.

use crate::session::{
    parse_enum, time_from_micros, ParseError, ProtoEnum, RegexParseError,
};
use log::info;
use rrg_proto::{
    FileFinderAccessTimeCondition, FileFinderAction, FileFinderArgs,
    FileFinderCondition, FileFinderContentsLiteralMatchCondition,
    FileFinderContentsRegexMatchCondition, FileFinderDownloadActionOptions,
    FileFinderExtFlagsCondition, FileFinderHashActionOptions,
    FileFinderInodeChangeTimeCondition, FileFinderModificationTimeCondition,
    FileFinderSizeCondition, FileFinderStatActionOptions,
};
use std::convert::TryFrom;
use std::fmt::Write;

type HashActionOversizedFilePolicy =
    rrg_proto::file_finder_hash_action_options::OversizedFilePolicy;
type DownloadActionOversizedFilePolicy =
    rrg_proto::file_finder_download_action_options::OversizedFilePolicy;
type RegexMatchMode =
    rrg_proto::file_finder_contents_regex_match_condition::Mode;
type LiteralMatchMode =
    rrg_proto::file_finder_contents_literal_match_condition::Mode;
type ActionType = rrg_proto::file_finder_action::Action;
type ConditionType = rrg_proto::file_finder_condition::Type;
type XDevMode = rrg_proto::file_finder_args::XDev;
type PathType = rrg_proto::path_spec::PathType;

#[derive(Debug)]
pub struct Request {
    /// A list of paths to glob that supports `**` path recursion and
    /// alternatives in form of `{a,b}`.
    pub path_queries: Vec<String>,
    /// Stat options. Stat has to be executed on any kind of request.
    pub stat_options: StatActionOptions,
    /// Additional action to be performed. Stat action is always performed.
    pub action: Option<Action>,
    /// Conditions that must be met by found file for the action to
    /// be performed on it.
    pub conditions: Vec<Condition>,
    /// File content matching conditions that must be met for the action to
    /// be performed.
    pub contents_match_conditions: Vec<ContentsMatchCondition>,
    /// Work with all kinds of files - not only with regular ones.
    pub process_non_regular_files: bool,
    /// Should symbolic links be followed by recursive search.
    pub follow_links: bool,
    /// Behavior for crossing devices when searching the filesystem.
    pub xdev_mode: XDevMode,
}

#[derive(Debug)]
pub enum Action {
    /// Get the hash of the file.
    Hash(HashActionOptions),
    /// Download the file.
    Download(DownloadActionOptions),
}

#[derive(Debug)]
pub struct StatActionOptions {
    /// Should symbolic link be resolved if it is a target of the action.
    pub follow_symlink: bool,
    /// Should linux extended file attributes be collected.
    pub collect_ext_attrs: bool,
}

#[derive(Debug)]
pub struct HashActionOptions {
    /// Maximum file size in bytes acceptable by the action.
    pub max_size: u64,
    /// Action to perform when requested file is bigger than `max_size`.
    pub oversized_file_policy: HashActionOversizedFilePolicy,
}

#[derive(Debug)]
pub struct DownloadActionOptions {
    /// Maximum file size in bytes acceptable by the action.
    pub max_size: u64,
    /// Action to perform when requested file is bigger than `max_size`.
    pub oversized_file_policy: DownloadActionOversizedFilePolicy,
    /// If true, look in any defined external file stores for files before
    /// downloading them, and offer any new files to external stores. This
    /// should be true unless the external checks are misbehaving.
    pub use_external_stores: bool,
    /// Number of bytes per chunk that the downloaded file is divided into.
    pub chunk_size: u64,
}

#[derive(Debug)]
pub enum Condition {
    ModificationTime {
        min: Option<std::time::SystemTime>,
        max: Option<std::time::SystemTime>,
    },
    AccessTime {
        min: Option<std::time::SystemTime>,
        max: Option<std::time::SystemTime>,
    },
    InodeChangeTime {
        min: Option<std::time::SystemTime>,
        max: Option<std::time::SystemTime>,
    },
    Size {
        min: Option<u64>,
        max: Option<u64>,
    },
    ExtFlags {
        linux_bits_set: Option<u32>,
        linux_bits_unset: Option<u32>,
        osx_bits_set: Option<u32>,
        osx_bits_unset: Option<u32>,
    },
}

#[derive(Debug, PartialEq)]
pub enum MatchMode {
    AllHits,
    FirstHit,
}

#[derive(Debug)]
pub struct ContentsMatchCondition {
    pub regex: regex::bytes::Regex,
    pub mode: MatchMode,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub start_offset: u64,
    pub length: u64,
}

impl From<FileFinderStatActionOptions> for StatActionOptions {
    fn from(proto: FileFinderStatActionOptions) -> StatActionOptions {
        StatActionOptions {
            follow_symlink: proto.resolve_links(),
            collect_ext_attrs: proto.collect_ext_attrs(),
        }
    }
}

fn into_action(proto: FileFinderAction) -> Result<Option<Action>, ParseError> {
    // `FileFinderAction::action_type` defines which action will be performed.
    // Only options from the selected action are read.
    Ok(Some(match parse_enum(proto.action_type)? {
        ActionType::Stat => return Ok(None),
        ActionType::Hash => Action::try_from(proto.hash.unwrap_or_default())?,
        ActionType::Download => {
            Action::try_from(proto.download.unwrap_or_default())?
        }
    }))
}

impl TryFrom<FileFinderHashActionOptions> for Action {
    type Error = ParseError;

    fn try_from(
        proto: FileFinderHashActionOptions,
    ) -> Result<Self, Self::Error> {
        Ok(Action::Hash(HashActionOptions {
            oversized_file_policy: parse_enum(proto.oversized_file_policy)?,
            max_size: proto.max_size(),
        }))
    }
}

impl TryFrom<FileFinderDownloadActionOptions> for Action {
    type Error = ParseError;

    fn try_from(
        proto: FileFinderDownloadActionOptions,
    ) -> Result<Self, Self::Error> {
        Ok(Action::Download(DownloadActionOptions {
            oversized_file_policy: parse_enum(proto.oversized_file_policy)?,
            max_size: proto.max_size(),
            use_external_stores: proto.use_external_stores(),
            chunk_size: proto.chunk_size(),
        }))
    }
}

impl ProtoEnum<ActionType> for ActionType {
    fn default() -> Self {
        FileFinderAction::default().action_type()
    }
    fn from_i32(val: i32) -> Option<Self> {
        ActionType::from_i32(val)
    }
}

impl ProtoEnum<HashActionOversizedFilePolicy>
    for HashActionOversizedFilePolicy
{
    fn default() -> Self {
        FileFinderHashActionOptions::default().oversized_file_policy()
    }
    fn from_i32(val: i32) -> Option<Self> {
        HashActionOversizedFilePolicy::from_i32(val)
    }
}

impl ProtoEnum<DownloadActionOversizedFilePolicy>
    for DownloadActionOversizedFilePolicy
{
    fn default() -> Self {
        FileFinderDownloadActionOptions::default().oversized_file_policy()
    }
    fn from_i32(val: i32) -> Option<Self> {
        DownloadActionOversizedFilePolicy::from_i32(val)
    }
}

impl ProtoEnum<XDevMode> for XDevMode {
    fn default() -> Self {
        FileFinderArgs::default().xdev()
    }
    fn from_i32(val: i32) -> Option<Self> {
        XDevMode::from_i32(val)
    }
}

impl ProtoEnum<ConditionType> for ConditionType {
    fn default() -> Self {
        FileFinderCondition::default().condition_type()
    }
    fn from_i32(val: i32) -> Option<Self> {
        ConditionType::from_i32(val)
    }
}

impl ProtoEnum<RegexMatchMode> for RegexMatchMode {
    fn default() -> Self {
        FileFinderContentsRegexMatchCondition::default().mode()
    }
    fn from_i32(val: i32) -> Option<Self> {
        RegexMatchMode::from_i32(val)
    }
}

impl From<RegexMatchMode> for MatchMode {
    fn from(proto: RegexMatchMode) -> Self {
        match proto {
            RegexMatchMode::FirstHit => MatchMode::FirstHit,
            RegexMatchMode::AllHits => MatchMode::AllHits,
        }
    }
}

impl ProtoEnum<LiteralMatchMode> for LiteralMatchMode {
    fn default() -> Self {
        FileFinderContentsLiteralMatchCondition::default().mode()
    }
    fn from_i32(val: i32) -> Option<Self> {
        LiteralMatchMode::from_i32(val)
    }
}

impl From<LiteralMatchMode> for MatchMode {
    fn from(proto: LiteralMatchMode) -> Self {
        match proto {
            LiteralMatchMode::FirstHit => MatchMode::FirstHit,
            LiteralMatchMode::AllHits => MatchMode::AllHits,
        }
    }
}

fn get_modification_time_condition(
    proto: &Option<FileFinderModificationTimeCondition>,
) -> Result<Option<Condition>, ParseError> {
    if let Some(options) = proto {
        let min = match options.min_last_modified_time {
            Some(micros) => Some(time_from_micros(micros)?),
            None => None,
        };
        let max = match options.max_last_modified_time {
            Some(micros) => Some(time_from_micros(micros)?),
            None => None,
        };

        if min.is_some() || max.is_some() {
            return Ok(Some(Condition::ModificationTime { min, max }));
        }
    }
    Ok(None)
}

fn get_access_time_condition(
    proto: &Option<FileFinderAccessTimeCondition>,
) -> Result<Option<Condition>, ParseError> {
    if let Some(options) = proto {
        let min = match options.min_last_access_time {
            Some(micros) => Some(time_from_micros(micros)?),
            None => None,
        };
        let max = match options.max_last_access_time {
            Some(micros) => Some(time_from_micros(micros)?),
            None => None,
        };

        if min.is_some() || max.is_some() {
            return Ok(Some(Condition::AccessTime { min, max }));
        }
    }
    Ok(None)
}

fn get_inode_change_time_condition(
    proto: &Option<FileFinderInodeChangeTimeCondition>,
) -> Result<Option<Condition>, ParseError> {
    if let Some(options) = proto {
        let min = match options.min_last_inode_change_time {
            Some(micros) => Some(time_from_micros(micros)?),
            None => None,
        };
        let max = match options.max_last_inode_change_time {
            Some(micros) => Some(time_from_micros(micros)?),
            None => None,
        };

        if min.is_some() || max.is_some() {
            return Ok(Some(Condition::InodeChangeTime { min, max }));
        }
    }
    Ok(None)
}

fn get_size_condition(
    proto: &Option<FileFinderSizeCondition>,
) -> Option<Condition> {
    if let Some(options) = proto {
        let min = options.min_file_size;
        let max = if options.max_file_size() < u64::MAX {
            Some(options.max_file_size())
        } else {
            None
        };

        if min.is_some() || max.is_some() {
            return Some(Condition::Size { min, max });
        }
    }
    None
}

fn get_ext_flags_condition(
    proto: &Option<FileFinderExtFlagsCondition>,
) -> Option<Condition> {
    if let Some(options) = proto {
        if options.linux_bits_set.is_some()
            || options.linux_bits_unset.is_some()
            || options.osx_bits_set.is_some()
            || options.osx_bits_unset.is_some()
        {
            return Some(Condition::ExtFlags {
                linux_bits_set: options.linux_bits_set,
                linux_bits_unset: options.linux_bits_unset,
                osx_bits_set: options.osx_bits_set,
                osx_bits_unset: options.osx_bits_unset,
            });
        }
    }
    None
}

fn parse_regex(bytes: &Vec<u8>) -> Result<regex::bytes::Regex, ParseError> {
    let str = match std::str::from_utf8(bytes.as_slice()) {
        Ok(v) => Ok(v),
        Err(e) => Err(ParseError::Malformed(Box::new(e))),
    }?;

    match regex::bytes::Regex::new(str) {
        Ok(v) => Ok(v),
        Err(e) => Err(RegexParseError {
            raw_data: bytes.clone(),
            error: e,
        }
        .into()),
    }
}

fn constant_literal_to_regex(
    bytes: &Vec<u8>,
) -> Result<regex::bytes::Regex, ParseError> {
    let mut str = String::new();
    for b in bytes {
        // Unwrap used on a string which can't return I/O error.
        write!(&mut str, r"\x{:x}", b).unwrap();
    }
    match regex::bytes::Regex::new(&str) {
        Ok(v) => Ok(v),
        Err(e) => Err(RegexParseError {
            raw_data: bytes.clone(),
            error: e,
        }
        .into()),
    }
}

fn get_contents_regex_match_condition(
    proto: &Option<FileFinderContentsRegexMatchCondition>,
) -> Result<Option<ContentsMatchCondition>, ParseError> {
    let options = match proto {
        Some(options) => options,
        None => return Ok(None),
    };

    let bytes_before = options.bytes_before() as u64;
    let bytes_after = options.bytes_after() as u64;
    let start_offset = options.start_offset();
    let length = options.length();
    let mode = MatchMode::from(parse_enum::<RegexMatchMode>(options.mode)?);

    let regex = match &options.regex {
        Some(v) => parse_regex(&v)?,
        None => return Ok(None),
    };

    Ok(Some(ContentsMatchCondition {
        regex,
        mode,
        bytes_before,
        bytes_after,
        start_offset,
        length,
    }))
}

/// Literal match is performed by generating a regex condition as they have
/// the same semantics.
fn get_contents_literal_match_condition(
    proto: &Option<FileFinderContentsLiteralMatchCondition>,
) -> Result<Option<ContentsMatchCondition>, ParseError> {
    let options = match proto {
        Some(options) => options,
        None => return Ok(None),
    };

    let bytes_before = options.bytes_before() as u64;
    let bytes_after = options.bytes_after() as u64;
    let start_offset = options.start_offset();
    let length = options.length();
    let mode = MatchMode::from(parse_enum::<LiteralMatchMode>(options.mode)?);

    if options.xor_in_key.is_some() || options.xor_out_key.is_some() {
        return Err(ParseError::malformed(
            "File Finder request does not support xor_in_key and xor_out_key options.",
        ));
    }

    let regex = match &options.literal {
        Some(v) => constant_literal_to_regex(&v)?,
        None => return Ok(None),
    };

    Ok(Some(ContentsMatchCondition {
        regex,
        mode,
        bytes_before,
        bytes_after,
        start_offset,
        length,
    }))
}

fn get_conditions(
    proto: &Vec<FileFinderCondition>,
) -> Result<Vec<Condition>, ParseError> {
    let mut conditions = vec![];
    for proto_condition in proto {
        conditions.extend(get_condition(proto_condition)?);
    }
    Ok(conditions)
}

fn get_condition(
    proto: &FileFinderCondition,
) -> Result<Option<Condition>, ParseError> {
    if proto.condition_type.is_none() {
        return Ok(None);
    }

    Ok(match parse_enum(proto.condition_type)? {
        ConditionType::ModificationTime => {
            get_modification_time_condition(&proto.modification_time)?
        }
        ConditionType::AccessTime => {
            get_access_time_condition(&proto.access_time)?
        }
        ConditionType::InodeChangeTime => {
            get_inode_change_time_condition(&proto.inode_change_time)?
        }
        ConditionType::Size => get_size_condition(&proto.size),
        ConditionType::ExtFlags => get_ext_flags_condition(&proto.ext_flags),
        ConditionType::ContentsRegexMatch => None,
        ConditionType::ContentsLiteralMatch => None,
    })
}

fn get_contents_match_conditions(
    proto: &Vec<FileFinderCondition>,
) -> Result<Vec<ContentsMatchCondition>, ParseError> {
    let mut conditions = vec![];
    for proto_condition in proto {
        conditions.extend(get_contents_match_condition(proto_condition)?);
    }
    Ok(conditions)
}

// TODO: maybe it can return Option instead of Vec now
fn get_contents_match_condition(
    proto: &FileFinderCondition,
) -> Result<Option<ContentsMatchCondition>, ParseError> {
    if proto.condition_type.is_none() {
        return Ok(None);
    }

    Ok(match parse_enum(proto.condition_type)? {
        ConditionType::ContentsRegexMatch => {
            get_contents_regex_match_condition(&proto.contents_regex_match)?
        }
        ConditionType::ContentsLiteralMatch => {
            get_contents_literal_match_condition(&proto.contents_literal_match)?
        }
        _ => None,
    })
}

impl super::super::Request for Request {
    type Proto = FileFinderArgs;

    fn from_proto(proto: FileFinderArgs) -> Result<Request, ParseError> {
        info!("File Finder: proto request: {:#?}", &proto);
        if !matches!(proto.pathtype(), PathType::Os) {
            return Err(ParseError::malformed(
                "File Finder does not support path types other than `Os`.",
            ));
        }

        let follow_links = proto.follow_links();
        let process_non_regular_files = proto.process_non_regular_files();
        let xdev_mode = parse_enum(proto.xdev)?;
        let conditions = get_conditions(&proto.conditions)?;
        let contents_match_conditions =
            get_contents_match_conditions(&proto.conditions)?;

        let (action, stat_options) =
            match proto.action {
                Some(action) => (
                    into_action(action.clone())?,
                    StatActionOptions::from(action.stat.unwrap_or_default()),
                ),
                None => return Err(ParseError::malformed(
                    "File Finder request does not contain action definition.",
                )),
            };

        Ok(Request {
            path_queries: proto.paths,
            stat_options,
            action,
            conditions,
            contents_match_conditions,
            follow_links,
            process_non_regular_files,
            xdev_mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Request as _;

    #[test]
    fn test_empty_request() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();

        assert!(request.path_queries.is_empty());
        assert!(request.conditions.is_empty());
        assert_eq!(request.process_non_regular_files, false);
        assert_eq!(request.follow_links, false);
        assert_eq!(request.xdev_mode, XDevMode::Local);
    }

    #[test]
    fn test_basic_root_parameters() {
        let request = Request::from_proto(FileFinderArgs {
            paths: vec!["abc".to_string(), "cba".to_string()],
            process_non_regular_files: Some(true),
            follow_links: Some(true),
            xdev: Some(rrg_proto::file_finder_args::XDev::Always as i32),
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(
            request.path_queries,
            vec!["abc".to_string(), "cba".to_string()]
        );
        assert_eq!(request.process_non_regular_files, true);
        assert_eq!(request.follow_links, true);
        assert_eq!(request.xdev_mode, XDevMode::Always);
    }

    #[test]
    fn test_fails_on_non_os_path_type() {
        let err = Request::from_proto(FileFinderArgs {
            paths: vec!["abc".to_string(), "cba".to_string()],
            process_non_regular_files: Some(true),
            follow_links: Some(true),
            pathtype: Some(PathType::Registry as i32),
            xdev: Some(rrg_proto::file_finder_args::XDev::Always as i32),
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap_err();

        match err {
            ParseError::Malformed(_) => {}
            e @ _ => panic!("Unexpected error type: {:?}", e),
        }
    }

    #[test]
    fn test_default_stats_action() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.stat_options.follow_symlink, false);
        assert_eq!(request.stat_options.collect_ext_attrs, false);
    }

    #[test]
    fn test_stats_action() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                stat: Some(FileFinderStatActionOptions {
                    resolve_links: Some(true),
                    collect_ext_attrs: Some(true),
                }),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.stat_options.follow_symlink, true);
        assert_eq!(request.stat_options.collect_ext_attrs, true);
    }

    #[test]
    fn test_default_hash_action() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Hash as i32),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();

        match request.action.unwrap() {
            Action::Hash(options) => {
                assert_eq!(
                    options.oversized_file_policy,
                    HashActionOversizedFilePolicy::Skip
                );
                assert_eq!(options.max_size, 500000000);
            }
            v @ _ => panic!("Unexpected action type: {:?}", v),
        }
        assert_eq!(request.stat_options.collect_ext_attrs, false);
        assert_eq!(request.stat_options.follow_symlink, false);
    }

    #[test]
    fn test_hash_action() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Hash as i32),
                hash: Some(FileFinderHashActionOptions {
                    collect_ext_attrs: Some(true),
                    oversized_file_policy: Some(
                        HashActionOversizedFilePolicy::HashTruncated as i32,
                    ),
                    max_size: Some(123456),
                }),
                stat: Some(FileFinderStatActionOptions {
                    collect_ext_attrs: Some(true),
                    resolve_links: Some(true),
                }),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();

        match request.action.unwrap() {
            Action::Hash(options) => {
                assert_eq!(
                    options.oversized_file_policy,
                    HashActionOversizedFilePolicy::HashTruncated
                );
                assert_eq!(options.max_size, 123456);
            }
            v @ _ => panic!("Unexpected action type: {:?}", v),
        }
        assert_eq!(request.stat_options.collect_ext_attrs, true);
        assert_eq!(request.stat_options.follow_symlink, true);
    }

    #[test]
    fn test_default_download_action() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Download as i32),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();

        match request.action.unwrap() {
            Action::Download(options) => {
                assert_eq!(options.max_size, 500000000);
                assert_eq!(
                    options.oversized_file_policy,
                    DownloadActionOversizedFilePolicy::Skip
                );
                assert_eq!(options.use_external_stores, true);
                assert_eq!(options.chunk_size, 524288);
            }
            v @ _ => panic!("Unexpected action type: {:?}", v),
        }
        assert_eq!(request.stat_options.collect_ext_attrs, false);
        assert_eq!(request.stat_options.follow_symlink, false);
    }

    #[test]
    fn test_download_action() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Download as i32),
                download: Some(FileFinderDownloadActionOptions {
                    max_size: Some(12345),
                    collect_ext_attrs: Some(true),
                    oversized_file_policy: Some(
                        DownloadActionOversizedFilePolicy::DownloadTruncated
                            as i32,
                    ),
                    use_external_stores: Some(false),
                    chunk_size: Some(5432),
                }),
                stat: Some(FileFinderStatActionOptions {
                    collect_ext_attrs: Some(true),
                    resolve_links: Some(true),
                }),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();

        match request.action.unwrap() {
            Action::Download(options) => {
                assert_eq!(options.max_size, 12345);
                assert_eq!(
                    options.oversized_file_policy,
                    DownloadActionOversizedFilePolicy::DownloadTruncated
                );
                assert_eq!(options.use_external_stores, false);
                assert_eq!(options.chunk_size, 5432);
            }
            v @ _ => panic!("Unexpected action type: {:?}", v),
        }
        assert_eq!(request.stat_options.collect_ext_attrs, true);
        assert_eq!(request.stat_options.follow_symlink, true);
    }

    #[test]
    fn test_error_on_parsing_unknown_enum_value() {
        let err = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(345 as i32),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap_err();

        match err {
            ParseError::Malformed(_) => {}
            e @ _ => panic!("Unexpected error type: {:?}", e),
        }
    }

    #[test]
    fn test_default_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert!(request.conditions.is_empty())
    }

    #[test]
    fn test_default_modification_time_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::ModificationTime as i32),
                modification_time: Some(FileFinderModificationTimeCondition {
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert!(request.conditions.is_empty());
    }

    #[test]
    fn test_modification_time_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::ModificationTime as i32),
                modification_time: Some(FileFinderModificationTimeCondition {
                    min_last_modified_time: Some(123),
                    max_last_modified_time: Some(234),
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::ModificationTime { min, max } => {
                assert_eq!(min.unwrap(), time_from_micros(123).unwrap());
                assert_eq!(max.unwrap(), time_from_micros(234).unwrap());
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }

    #[test]
    fn test_default_access_time_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::AccessTime as i32),
                access_time: Some(FileFinderAccessTimeCondition {
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert!(request.conditions.is_empty());
    }

    #[test]
    fn test_access_time_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::AccessTime as i32),
                access_time: Some(FileFinderAccessTimeCondition {
                    min_last_access_time: Some(123),
                    max_last_access_time: Some(234),
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::AccessTime { min, max } => {
                assert_eq!(min.unwrap(), time_from_micros(123).unwrap());
                assert_eq!(max.unwrap(), time_from_micros(234).unwrap());
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }

    #[test]
    fn test_default_inode_change_time_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::InodeChangeTime as i32),
                inode_change_time: Some(FileFinderInodeChangeTimeCondition {
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert!(request.conditions.is_empty());
    }

    #[test]
    fn test_inode_change_time_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::InodeChangeTime as i32),
                inode_change_time: Some(FileFinderInodeChangeTimeCondition {
                    min_last_inode_change_time: Some(123),
                    max_last_inode_change_time: Some(234),
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::InodeChangeTime { min, max } => {
                assert_eq!(min.unwrap(), time_from_micros(123).unwrap());
                assert_eq!(max.unwrap(), time_from_micros(234).unwrap());
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }

    #[test]
    fn test_default_size_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::Size as i32),
                size: Some(FileFinderSizeCondition {
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::Size { min, max } => {
                assert!(min.is_none());
                assert_eq!(max.unwrap(), 20000000);
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }

    #[test]
    fn test_size_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::Size as i32),
                size: Some(FileFinderSizeCondition {
                    min_file_size: Some(345),
                    max_file_size: Some(456),
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::Size { min, max } => {
                assert_eq!(min.unwrap(), 345);
                assert_eq!(max.unwrap(), 456);
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }

    #[test]
    fn test_default_ext_flags_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::ExtFlags as i32),
                ext_flags: Some(FileFinderExtFlagsCondition {
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 0);
    }

    #[test]
    fn test_ext_flags_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::ExtFlags as i32),
                ext_flags: Some(FileFinderExtFlagsCondition {
                    linux_bits_set: Some(111),
                    linux_bits_unset: Some(222),
                    osx_bits_set: Some(333),
                    osx_bits_unset: Some(444),
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::ExtFlags {
                linux_bits_set,
                linux_bits_unset,
                osx_bits_set,
                osx_bits_unset,
            } => {
                assert_eq!(linux_bits_set.unwrap(), 111);
                assert_eq!(linux_bits_unset.unwrap(), 222);
                assert_eq!(osx_bits_set.unwrap(), 333);
                assert_eq!(osx_bits_unset.unwrap(), 444);
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }

    #[test]
    fn test_default_contents_regex_match_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::ContentsRegexMatch as i32),
                contents_regex_match: Some(
                    FileFinderContentsRegexMatchCondition {
                        ..Default::default()
                    },
                ),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 0);
    }

    #[test]
    fn test_contents_regex_match_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::ContentsRegexMatch as i32),
                contents_regex_match: Some(
                    FileFinderContentsRegexMatchCondition {
                        regex: Some(vec![97, 98, 99]),
                        mode: Some(RegexMatchMode::AllHits as i32),
                        bytes_before: Some(4),
                        bytes_after: Some(7),
                        start_offset: Some(15),
                        length: Some(42),
                    },
                ),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.contents_match_conditions.len(), 1);

        let condition = request.contents_match_conditions.first().unwrap();
        assert_eq!(condition.regex.as_str(), "abc");
        assert_eq!(condition.mode, MatchMode::AllHits);
        assert_eq!(condition.bytes_before, 4);
        assert_eq!(condition.bytes_after, 7);
        assert_eq!(condition.start_offset, 15);
        assert_eq!(condition.length, 42);
    }

    #[test]
    fn test_invalid_utf8_sequence_error() {
        let err = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::ContentsRegexMatch as i32),
                contents_regex_match: Some(
                    FileFinderContentsRegexMatchCondition {
                        regex: Some(vec![255, 255, 255]),
                        mode: Some(RegexMatchMode::AllHits as i32),
                        bytes_before: Some(4),
                        bytes_after: Some(7),
                        start_offset: Some(15),
                        length: Some(42),
                    },
                ),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(err, ParseError::Malformed(_)));
    }

    #[test]
    fn test_default_contents_literal_match_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(
                    ConditionType::ContentsLiteralMatch as i32,
                ),
                contents_literal_match: Some(
                    FileFinderContentsLiteralMatchCondition {
                        ..Default::default()
                    },
                ),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 0);
    }

    #[test]
    fn test_contents_literal_match_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(
                    ConditionType::ContentsLiteralMatch as i32,
                ),
                contents_literal_match: Some(
                    FileFinderContentsLiteralMatchCondition {
                        literal: Some(vec![99, 98, 97]),
                        mode: Some(LiteralMatchMode::AllHits as i32),
                        start_offset: Some(6),
                        length: Some(8),
                        bytes_before: Some(15),
                        bytes_after: Some(18),
                        xor_in_key: None,
                        xor_out_key: None,
                    },
                ),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.contents_match_conditions.len(), 1);
        let condition = request.contents_match_conditions.first().unwrap();
        assert_eq!(condition.regex.as_str(), r"\x63\x62\x61");
        assert_eq!(condition.mode, MatchMode::AllHits);
        assert_eq!(condition.start_offset, 6);
        assert_eq!(condition.length, 8);
        assert_eq!(condition.bytes_before, 15);
        assert_eq!(condition.bytes_after, 18);
    }
}
