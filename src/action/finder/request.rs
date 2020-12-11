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
use regex::Regex;
use rrg_proto::{
    FileFinderAccessTimeCondition, FileFinderAction, FileFinderArgs,
    FileFinderCondition, FileFinderContentsLiteralMatchCondition,
    FileFinderContentsRegexMatchCondition, FileFinderDownloadActionOptions,
    FileFinderExtFlagsCondition, FileFinderHashActionOptions,
    FileFinderInodeChangeTimeCondition, FileFinderModificationTimeCondition,
    FileFinderSizeCondition, FileFinderStatActionOptions,
};
use std::convert::TryFrom;

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
    /// Action type to be performed.
    pub action: Action,
    /// Conditions that must be met by found file for the action to
    /// be performed on it.
    pub conditions: Vec<Condition>,
    /// Work with all kinds of files - not only with regular ones.
    pub process_non_regular_files: bool,
    /// Should symbolic links be followed by recursive search.
    pub follow_links: bool,
    /// Behavior for crossing devices when searching the filesystem.
    pub xdev_mode: XDevMode,
}

#[derive(Debug)]
pub enum Action {
    /// Get the metadata of the file.
    Stat(StatActionOptions),
    /// Get the hash of the file.
    Hash(HashActionOptions),
    /// Download the file.
    Download(DownloadActionOptions),
}

#[derive(Debug)]
pub struct StatActionOptions {
    /// Should symbolic link be resolved if it is a target of the action.
    pub resolve_links: bool,
    /// Should linux extended file attributes be collected.
    pub collect_ext_attrs: bool,
}

#[derive(Debug)]
pub struct HashActionOptions {
    /// Maximum file size in bytes acceptable by the action.
    pub max_size: u64,
    /// Action to perform when requested file is bigger than `max_size`.
    pub oversized_file_policy: HashActionOversizedFilePolicy,
    /// Should linux extended file attributes be collected.
    pub collect_ext_attrs: bool,
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
    /// Should linux extended file attributes be collected.
    pub collect_ext_attrs: bool,
    /// Number of bytes per chunk that the downloaded file is divided into.
    pub chunk_size: u64,
}

#[derive(Debug)]
pub enum Condition {
    MinModificationTime(std::time::SystemTime),
    MaxModificationTime(std::time::SystemTime),
    MinAccessTime(std::time::SystemTime),
    MaxAccessTime(std::time::SystemTime),
    MinInodeChangeTime(std::time::SystemTime),
    MaxInodeChangeTime(std::time::SystemTime),
    MinSize(u64),
    MaxSize(u64),
    ExtFlagsLinuxBitsSet(u32),
    ExtFlagsLinuxBitsUnset(u32),
    ExtFlagsOsxBitsSet(u32),
    ExtFlagsOsxBitsUnset(u32),
    ContentsRegexMatch(ContentsRegexMatchConditionOptions),
    ContentsLiteralMatch(ContentsLiteralMatchConditionOptions),
}

#[derive(Debug, PartialEq)]
pub enum MatchMode {
    AllHits,
    FirstHit,
}

#[derive(Debug)]
pub struct ContentsRegexMatchConditionOptions {
    pub regex: Regex,
    pub mode: MatchMode,
    pub bytes_before: u32,
    pub bytes_after: u32,
    pub start_offset: u64,
    pub length: u64,
}

#[derive(Debug)]
pub struct ContentsLiteralMatchConditionOptions {
    pub literal: Vec<u8>,
    pub mode: MatchMode,
    pub start_offset: u64,
    pub length: u64,
    pub bytes_before: u32,
    pub bytes_after: u32,
    pub xor_in_key: u32,
    pub xor_out_key: u32,
}

impl TryFrom<rrg_proto::FileFinderAction> for Action {
    type Error = ParseError;

    fn try_from(
        proto: rrg_proto::FileFinderAction,
    ) -> Result<Self, Self::Error> {
        // `FileFinderAction::action_type` defines which action will be performed.
        // Only options from selected action are read.
        Ok(match parse_enum(proto.action_type)? {
            ActionType::Stat => Action::from(proto.stat.unwrap_or_default()),
            ActionType::Hash => {
                Action::try_from(proto.hash.unwrap_or_default())?
            }
            ActionType::Download => {
                Action::try_from(proto.download.unwrap_or_default())?
            }
        })
    }
}

impl From<FileFinderStatActionOptions> for Action {
    fn from(proto: FileFinderStatActionOptions) -> Action {
        Action::Stat(StatActionOptions {
            resolve_links: proto.resolve_links(),
            collect_ext_attrs: proto.collect_ext_attrs(),
        })
    }
}

impl TryFrom<FileFinderHashActionOptions> for Action {
    type Error = ParseError;

    fn try_from(
        proto: FileFinderHashActionOptions,
    ) -> Result<Self, Self::Error> {
        Ok(Action::Hash(HashActionOptions {
            oversized_file_policy: parse_enum(proto.oversized_file_policy)?,
            collect_ext_attrs: proto.collect_ext_attrs(),
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
            collect_ext_attrs: proto.collect_ext_attrs(),
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

fn get_modification_time_conditions(
    proto: Option<FileFinderModificationTimeCondition>,
) -> Result<Vec<Condition>, ParseError> {
    let mut conditions: Vec<Condition> = vec![];
    if let Some(options) = proto {
        if let Some(micros) = options.min_last_modified_time {
            let time = time_from_micros(micros)?;
            conditions.push(Condition::MinModificationTime(time));
        }
        if let Some(micros) = options.max_last_modified_time {
            let time = time_from_micros(micros)?;
            conditions.push(Condition::MaxModificationTime(time));
        }
    }
    Ok(conditions)
}

fn get_access_time_conditions(
    proto: Option<FileFinderAccessTimeCondition>,
) -> Result<Vec<Condition>, ParseError> {
    let mut conditions: Vec<Condition> = vec![];
    if let Some(options) = proto {
        if let Some(micros) = options.min_last_access_time {
            let time = time_from_micros(micros)?;
            conditions.push(Condition::MinAccessTime(time));
        }
        if let Some(micros) = options.max_last_access_time {
            let time = time_from_micros(micros)?;
            conditions.push(Condition::MaxAccessTime(time));
        }
    }
    Ok(conditions)
}

fn get_inode_change_time_conditions(
    proto: Option<FileFinderInodeChangeTimeCondition>,
) -> Result<Vec<Condition>, ParseError> {
    let mut conditions: Vec<Condition> = vec![];
    if let Some(options) = proto {
        if let Some(micros) = options.min_last_inode_change_time {
            let time = time_from_micros(micros)?;
            conditions.push(Condition::MinInodeChangeTime(time));
        }
        if let Some(micros) = options.max_last_inode_change_time {
            let time = time_from_micros(micros)?;
            conditions.push(Condition::MaxInodeChangeTime(time));
        }
    }
    Ok(conditions)
}

fn get_size_conditions(
    proto: Option<FileFinderSizeCondition>,
) -> Vec<Condition> {
    let mut conditions: Vec<Condition> = vec![];
    if let Some(options) = proto {
        if let Some(size) = options.min_file_size {
            conditions.push(Condition::MinSize(size));
        }
        if options.max_file_size() < u64::MAX {
            conditions.push(Condition::MaxSize(options.max_file_size()));
        }
    }
    conditions
}

fn get_ext_flags_condition(
    proto: Option<FileFinderExtFlagsCondition>,
) -> Vec<Condition> {
    let mut conditions: Vec<Condition> = vec![];
    if let Some(options) = proto {
        if let Some(bits) = options.linux_bits_set {
            conditions.push(Condition::ExtFlagsLinuxBitsSet(bits));
        }
        if let Some(bits) = options.linux_bits_unset {
            conditions.push(Condition::ExtFlagsLinuxBitsUnset(bits));
        }
        if let Some(bits) = options.osx_bits_set {
            conditions.push(Condition::ExtFlagsOsxBitsSet(bits));
        }
        if let Some(bits) = options.osx_bits_unset {
            conditions.push(Condition::ExtFlagsOsxBitsUnset(bits));
        }
    }
    conditions
}

fn parse_regex(bytes: Vec<u8>) -> Result<Regex, ParseError> {
    let str = match std::str::from_utf8(bytes.as_slice()) {
        Ok(v) => Ok(v),
        Err(e) => Err(ParseError::Malformed(Box::new(e))),
    }?;

    match Regex::new(str) {
        Ok(v) => Ok(v),
        Err(e) => Err(RegexParseError {
            raw_data: bytes,
            error: e,
        }
        .into()),
    }
}

fn get_contents_regex_match_condition(
    proto: Option<FileFinderContentsRegexMatchCondition>,
) -> Result<Vec<Condition>, ParseError> {
    let options = match proto {
        Some(options) => options,
        None => return Ok(vec![]),
    };

    let bytes_before = options.bytes_before();
    let bytes_after = options.bytes_after();
    let start_offset = options.start_offset();
    let length = options.length();
    let mode = MatchMode::from(parse_enum::<RegexMatchMode>(options.mode)?);

    let regex = match options.regex {
        None => return Ok(vec![]),
        Some(v) => parse_regex(v)?,
    };

    let ret = ContentsRegexMatchConditionOptions {
        regex,
        mode,
        bytes_before,
        bytes_after,
        start_offset,
        length,
    };

    Ok(vec![Condition::ContentsRegexMatch(ret)])
}

fn get_contents_literal_match_condition(
    proto: Option<FileFinderContentsLiteralMatchCondition>,
) -> Result<Vec<Condition>, ParseError> {
    let options = match proto {
        Some(options) => options,
        None => return Ok(vec![]),
    };

    let bytes_before = options.bytes_before();
    let bytes_after = options.bytes_after();
    let start_offset = options.start_offset();
    let length = options.length();
    let xor_in_key = options.xor_in_key();
    let xor_out_key = options.xor_out_key();
    let mode =
        MatchMode::from(parse_enum::<LiteralMatchMode>(options.mode)?);

    let literal = match options.literal {
        None => return Ok(vec![]),
        Some(v) => v,
    };

    let ret = ContentsLiteralMatchConditionOptions {
        literal,
        mode,
        bytes_before,
        bytes_after,
        start_offset,
        length,
        xor_in_key,
        xor_out_key,
    };

    Ok(vec![Condition::ContentsLiteralMatch(ret)])
}

fn get_conditions(
    proto: FileFinderCondition,
) -> Result<Vec<Condition>, ParseError> {
    if proto.condition_type.is_none() {
        return Ok(vec![]);
    }

    Ok(match parse_enum(proto.condition_type)? {
        ConditionType::ModificationTime => {
            get_modification_time_conditions(proto.modification_time)?
        }
        ConditionType::AccessTime => {
            get_access_time_conditions(proto.access_time)?
        }
        ConditionType::InodeChangeTime => {
            get_inode_change_time_conditions(proto.inode_change_time)?
        }
        ConditionType::Size => get_size_conditions(proto.size),
        ConditionType::ExtFlags => get_ext_flags_condition(proto.ext_flags),
        ConditionType::ContentsRegexMatch => {
            get_contents_regex_match_condition(proto.contents_regex_match)?
        }
        ConditionType::ContentsLiteralMatch => {
            get_contents_literal_match_condition(proto.contents_literal_match)?
        }
    })
}

impl super::super::Request for Request {
    type Proto = FileFinderArgs;

    fn from_proto(proto: FileFinderArgs) -> Result<Request, ParseError> {
        if !matches!(proto.pathtype(), PathType::Os) {
            return Err(ParseError::malformed(
                "File Finder does not support path types other than `Os`.",
            ));
        }

        let follow_links = proto.follow_links();
        let process_non_regular_files = proto.process_non_regular_files();
        let xdev_mode = parse_enum(proto.xdev)?;
        let mut conditions = vec![];
        for proto_condition in proto.conditions {
            conditions.extend(get_conditions(proto_condition)?);
        }

        let action = match proto.action {
            Some(action) => Action::try_from(action)?,
            None => return Err(ParseError::malformed(
                    "File Finder request does not contain action definition.",
                )),
        };

        Ok(Request {
            path_queries: proto.paths,
            action,
            conditions,
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
        }).unwrap_err();

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

        match request.action {
            Action::Stat(options) => {
                assert_eq!(options.collect_ext_attrs, false);
                assert_eq!(options.resolve_links, false);
            }
            v @ _ => panic!("Unexpected action type: {:?}", v),
        }
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

        match request.action {
            Action::Stat(options) => {
                assert_eq!(options.collect_ext_attrs, true);
                assert_eq!(options.resolve_links, true);
            }
            v @ _ => panic!("Unexpected action type: {:?}", v),
        }
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

        match request.action {
            Action::Hash(options) => {
                assert_eq!(options.collect_ext_attrs, false);
                assert_eq!(
                    options.oversized_file_policy,
                    HashActionOversizedFilePolicy::Skip
                );
                assert_eq!(options.max_size, 500000000);
            }
            v @ _ => panic!("Unexpected action type: {:?}", v),
        }
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
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();

        match request.action {
            Action::Hash(options) => {
                assert_eq!(options.collect_ext_attrs, true);
                assert_eq!(
                    options.oversized_file_policy,
                    HashActionOversizedFilePolicy::HashTruncated
                );
                assert_eq!(options.max_size, 123456);
            }
            v @ _ => panic!("Unexpected action type: {:?}", v),
        }
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

        match request.action {
            Action::Download(options) => {
                assert_eq!(options.max_size, 500000000);
                assert_eq!(
                    options.oversized_file_policy,
                    DownloadActionOversizedFilePolicy::Skip
                );
                assert_eq!(options.use_external_stores, true);
                assert_eq!(options.collect_ext_attrs, false);
                assert_eq!(options.chunk_size, 524288);
            }
            v @ _ => panic!("Unexpected action type: {:?}", v),
        }
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
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();

        match request.action {
            Action::Download(options) => {
                assert_eq!(options.max_size, 12345);
                assert_eq!(
                    options.oversized_file_policy,
                    DownloadActionOversizedFilePolicy::DownloadTruncated
                );
                assert_eq!(options.use_external_stores, false);
                assert_eq!(options.collect_ext_attrs, true);
                assert_eq!(options.chunk_size, 5432);
            }
            v @ _ => panic!("Unexpected action type: {:?}", v),
        }
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
    fn test_min_modification_time_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::ModificationTime as i32),
                modification_time: Some(FileFinderModificationTimeCondition {
                    min_last_modified_time: Some(123),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::MinModificationTime(time) => {
                assert_eq!(&time_from_micros(123).unwrap(), time);
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }

    #[test]
    fn test_max_modification_time_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::ModificationTime as i32),
                modification_time: Some(FileFinderModificationTimeCondition {
                    max_last_modified_time: Some(234),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::MaxModificationTime(time) => {
                assert_eq!(&time_from_micros(234).unwrap(), time);
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
    fn test_min_access_time_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::AccessTime as i32),
                access_time: Some(FileFinderAccessTimeCondition {
                    min_last_access_time: Some(123),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::MinAccessTime(time) => {
                assert_eq!(&time_from_micros(123).unwrap(), time);
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }

    #[test]
    fn test_max_access_time_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::AccessTime as i32),
                access_time: Some(FileFinderAccessTimeCondition {
                    max_last_access_time: Some(234),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::MaxAccessTime(time) => {
                assert_eq!(&time_from_micros(234).unwrap(), time);
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
    fn test_min_inode_change_time_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::InodeChangeTime as i32),
                inode_change_time: Some(FileFinderInodeChangeTimeCondition {
                    min_last_inode_change_time: Some(123),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::MinInodeChangeTime(time) => {
                assert_eq!(&time_from_micros(123).unwrap(), time);
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }

    #[test]
    fn test_max_inode_change_time_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::InodeChangeTime as i32),
                inode_change_time: Some(FileFinderInodeChangeTimeCondition {
                    max_last_inode_change_time: Some(234),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::MaxInodeChangeTime(time) => {
                assert_eq!(&time_from_micros(234).unwrap(), time);
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
            Condition::MaxSize(size) => {
                assert_eq!(*size, 20000000);
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }

    #[test]
    fn test_min_size_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::Size as i32),
                size: Some(FileFinderSizeCondition {
                    min_file_size: Some(345),
                    max_file_size: Some(u64::MAX),
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::MinSize(size) => {
                assert_eq!(*size, 345);
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }

    #[test]
    fn test_max_size_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::Size as i32),
                size: Some(FileFinderSizeCondition {
                    max_file_size: Some(798),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::MaxSize(size) => {
                assert_eq!(*size, 798);
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
    fn test_linux_bits_set_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::ExtFlags as i32),
                ext_flags: Some(FileFinderExtFlagsCondition {
                    linux_bits_set: Some(111),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::ExtFlagsLinuxBitsSet(bits) => {
                assert_eq!(*bits, 111);
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }

    #[test]
    fn test_linux_bits_unset_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::ExtFlags as i32),
                ext_flags: Some(FileFinderExtFlagsCondition {
                    linux_bits_unset: Some(222),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::ExtFlagsLinuxBitsUnset(bits) => {
                assert_eq!(*bits, 222);
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }

    #[test]
    fn test_osx_bits_set_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::ExtFlags as i32),
                ext_flags: Some(FileFinderExtFlagsCondition {
                    osx_bits_set: Some(333),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::ExtFlagsOsxBitsSet(bits) => {
                assert_eq!(*bits, 333);
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }

    #[test]
    fn test_osx_bits_unset_condition() {
        let request = Request::from_proto(FileFinderArgs {
            action: Some(FileFinderAction {
                action_type: Some(ActionType::Stat as i32),
                ..Default::default()
            }),
            conditions: vec![FileFinderCondition {
                condition_type: Some(ConditionType::ExtFlags as i32),
                ext_flags: Some(FileFinderExtFlagsCondition {
                    osx_bits_unset: Some(444),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::ExtFlagsOsxBitsUnset(bits) => {
                assert_eq!(*bits, 444);
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

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::ContentsRegexMatch(options) => {
                assert_eq!(options.regex.as_str(), "abc");
                assert_eq!(options.mode, MatchMode::AllHits);
                assert_eq!(options.bytes_before, 4);
                assert_eq!(options.bytes_after, 7);
                assert_eq!(options.start_offset, 15);
                assert_eq!(options.length, 42);
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
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
                        xor_in_key: Some(78),
                        xor_out_key: Some(98),
                    },
                ),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(request.conditions.len(), 1);
        match request.conditions.first().unwrap() {
            Condition::ContentsLiteralMatch(options) => {
                assert_eq!(options.literal, vec![99, 98, 97]);
                assert_eq!(options.mode, MatchMode::AllHits);
                assert_eq!(options.start_offset, 6);
                assert_eq!(options.length, 8);
                assert_eq!(options.bytes_before, 15);
                assert_eq!(options.bytes_after, 18);
                assert_eq!(options.xor_in_key, 78);
                assert_eq!(options.xor_out_key, 98);
            }
            v @ _ => panic!("Unexpected condition type: {:?}", v),
        }
    }
}
