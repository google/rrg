// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Defines an internal type for client side file finder action and provides
//! a function converting proto format of the request
//! `rrg_proto::FileFinderArgs` to the internal format.

use crate::session::{time_from_micros, RegexParseError};
use log::info;
use protobuf::ProtobufEnum;
use std::fmt::Write;

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
    pub xdev_mode: rrg_proto::flows::FileFinderArgs_XDev,
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
    pub oversized_file_policy: rrg_proto::flows::FileFinderHashActionOptions_OversizedFilePolicy,
}

#[derive(Debug)]
pub struct DownloadActionOptions {
    /// Maximum file size in bytes acceptable by the action.
    pub max_size: u64,
    /// Action to perform when requested file is bigger than `max_size`.
    pub oversized_file_policy: rrg_proto::flows::FileFinderDownloadActionOptions_OversizedFilePolicy,
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

impl From<rrg_proto::flows::FileFinderStatActionOptions> for StatActionOptions {
    fn from(proto: rrg_proto::flows::FileFinderStatActionOptions) -> StatActionOptions {
        StatActionOptions {
            follow_symlink: proto.get_resolve_links(),
            collect_ext_attrs: proto.get_collect_ext_attrs(),
        }
    }
}

fn into_action(proto: rrg_proto::flows::FileFinderAction) -> Result<Option<Action>, crate::action::ParseArgsError> {
    // `FileFinderAction::action_type` defines which action will be performed.
    // Only options from the selected action are read.
    use rrg_proto::flows::FileFinderAction_Action::*;
    Ok(Some(match proto.get_action_type() {
        STAT => return Ok(None),
        HASH => Action::try_from(proto.get_hash().to_owned())?,
        DOWNLOAD => Action::try_from(proto.get_download().to_owned())?,
    }))
}

impl TryFrom<rrg_proto::flows::FileFinderHashActionOptions> for Action {
    type Error = crate::action::ParseArgsError;

    fn try_from(
        proto: rrg_proto::flows::FileFinderHashActionOptions,
    ) -> Result<Self, Self::Error> {
        Ok(Action::Hash(HashActionOptions {
            oversized_file_policy: proto.get_oversized_file_policy(),
            max_size: proto.get_max_size(),
        }))
    }
}

impl TryFrom<rrg_proto::flows::FileFinderDownloadActionOptions> for Action {
    type Error = crate::action::ParseArgsError;

    fn try_from(
        proto: rrg_proto::flows::FileFinderDownloadActionOptions,
    ) -> Result<Self, Self::Error> {
        Ok(Action::Download(DownloadActionOptions {
            oversized_file_policy: proto.get_oversized_file_policy(),
            max_size: proto.get_max_size(),
            use_external_stores: proto.get_use_external_stores(),
            chunk_size: proto.get_chunk_size(),
        }))
    }
}

fn get_modification_time_condition(
    proto: &rrg_proto::flows::FileFinderModificationTimeCondition,
) -> Result<Option<Condition>, crate::action::ParseArgsError> {
    let min = if proto.has_min_last_modified_time() {
        Some(time_from_micros(proto.get_min_last_modified_time())
            .map_err(crate::action::ParseArgsError::invalid_field)?)
    } else {
        None
    };

    let max = if proto.has_max_last_modified_time() {
        Some(time_from_micros(proto.get_max_last_modified_time())
            .map_err(crate::action::ParseArgsError::invalid_field)?)
    } else {
        None
    };

    if min.is_some() || max.is_some() {
        return Ok(Some(Condition::ModificationTime { min, max }));
    }
    Ok(None)
}

fn get_access_time_condition(
    proto: &rrg_proto::flows::FileFinderAccessTimeCondition,
) -> Result<Option<Condition>, crate::action::ParseArgsError> {
    let min = if proto.has_min_last_access_time() {
        Some(time_from_micros(proto.get_min_last_access_time())
            .map_err(crate::action::ParseArgsError::invalid_field)?)
    } else {
        None
    };

    let max = if proto.has_max_last_access_time() {
        Some(time_from_micros(proto.get_max_last_access_time())
            .map_err(crate::action::ParseArgsError::invalid_field)?)
    } else {
        None
    };

    if min.is_some() || max.is_some() {
        return Ok(Some(Condition::AccessTime { min, max }));
    }
    Ok(None)
}

fn get_inode_change_time_condition(
    proto: &rrg_proto::flows::FileFinderInodeChangeTimeCondition,
) -> Result<Option<Condition>, crate::action::ParseArgsError> {
    let min = if proto.has_min_last_inode_change_time() {
        Some(time_from_micros(proto.get_min_last_inode_change_time())
            .map_err(crate::action::ParseArgsError::invalid_field)?)
    } else {
        None
    };

    let max = if proto.has_max_last_inode_change_time() {
        Some(time_from_micros(proto.get_max_last_inode_change_time())
            .map_err(crate::action::ParseArgsError::invalid_field)?)
    } else {
        None
    };

    if min.is_some() || max.is_some() {
        return Ok(Some(Condition::InodeChangeTime { min, max }));
    }
    Ok(None)
}

fn get_size_condition(
    proto: &rrg_proto::flows::FileFinderSizeCondition,
) -> Option<Condition> {
    let min = if proto.has_min_file_size() {
        Some(proto.get_min_file_size())
    } else {
        None
    };

    let max = if proto.has_max_file_size() {
        Some(proto.get_max_file_size())
    } else {
        None
    };

    if min.is_some() || max.is_some() {
        return Some(Condition::Size { min, max });
    }
    None
}

fn get_ext_flags_condition(
    proto: &rrg_proto::flows::FileFinderExtFlagsCondition,
) -> Option<Condition> {
    if proto.has_linux_bits_set() || proto.has_linux_bits_unset() ||
       proto.has_osx_bits_set() || proto.has_osx_bits_unset() {
        return Some(Condition::ExtFlags {
            linux_bits_set: Some(proto.get_linux_bits_set()),
            linux_bits_unset: Some(proto.get_linux_bits_unset()),
            osx_bits_set: Some(proto.get_osx_bits_set()),
            osx_bits_unset: Some(proto.get_osx_bits_unset()),
        });
    }
    None
}

fn parse_regex(bytes: &[u8]) -> Result<regex::bytes::Regex, crate::action::ParseArgsError> {
    let str = match std::str::from_utf8(bytes) {
        Ok(v) => Ok(v),
        Err(e) => Err(crate::action::ParseArgsError::invalid_field(e)),
    }?;

    match regex::bytes::Regex::new(str) {
        Ok(v) => Ok(v),
        Err(e) => Err(crate::action::ParseArgsError::invalid_field(RegexParseError {
            raw_data: bytes.to_owned(),
            error: e,
        })),
    }
}

fn constant_literal_to_regex(
    bytes: &[u8],
) -> Result<regex::bytes::Regex, crate::action::ParseArgsError> {
    let mut str = String::new();
    for b in bytes {
        // Unwrap used on a string which can't return I/O error.
        write!(&mut str, r"\x{:x}", b).unwrap();
    }
    match regex::bytes::Regex::new(&str) {
        Ok(v) => Ok(v),
        Err(e) => Err(crate::action::ParseArgsError::invalid_field(RegexParseError {
            raw_data: bytes.to_owned(),
            error: e,
        })),
    }
}

fn get_contents_regex_match_condition(
    proto: &rrg_proto::flows::FileFinderContentsRegexMatchCondition,
) -> Result<Option<ContentsMatchCondition>, crate::action::ParseArgsError> {
    let bytes_before = proto.get_bytes_before() as u64;
    let bytes_after = proto.get_bytes_after() as u64;
    let start_offset = proto.get_start_offset();
    let length = proto.get_length();

    use rrg_proto::flows::FileFinderContentsRegexMatchCondition_Mode::*;
    let mode = match proto.get_mode() {
        ALL_HITS => MatchMode::AllHits,
        FIRST_HIT => MatchMode::FirstHit,
    };

    let regex = if proto.has_regex() {
        parse_regex(proto.get_regex())?
    } else {
        return Ok(None);
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
    proto: &rrg_proto::flows::FileFinderContentsLiteralMatchCondition,
) -> Result<Option<ContentsMatchCondition>, crate::action::ParseArgsError> {
    let bytes_before = proto.get_bytes_before() as u64;
    let bytes_after = proto.get_bytes_after() as u64;
    let start_offset = proto.get_start_offset();
    let length = proto.get_length();

    use rrg_proto::flows::FileFinderContentsLiteralMatchCondition_Mode::*;
    let mode = match proto.get_mode() {
        ALL_HITS => MatchMode::AllHits,
        FIRST_HIT => MatchMode::FirstHit,
    };

    let regex = if proto.has_literal() {
        constant_literal_to_regex(proto.get_literal())?
    } else {
        return Ok(None);
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
    proto: &[rrg_proto::flows::FileFinderCondition],
) -> Result<Vec<Condition>, crate::action::ParseArgsError> {
    let mut conditions = vec![];
    for proto_condition in proto {
        conditions.extend(get_condition(proto_condition)?);
    }
    Ok(conditions)
}

fn get_condition(
    proto: &rrg_proto::flows::FileFinderCondition,
) -> Result<Option<Condition>, crate::action::ParseArgsError> {
    use rrg_proto::flows::FileFinderCondition_Type::*;
    Ok(match proto.get_condition_type() {
        MODIFICATION_TIME => {
            get_modification_time_condition(proto.get_modification_time())?
        }
        ACCESS_TIME => {
            get_access_time_condition(proto.get_access_time())?
        }
        INODE_CHANGE_TIME => {
            get_inode_change_time_condition(proto.get_inode_change_time())?
        }
        SIZE => get_size_condition(proto.get_size()),
        EXT_FLAGS => get_ext_flags_condition(proto.get_ext_flags()),
        CONTENTS_REGEX_MATCH => None,
        CONTENTS_LITERAL_MATCH => None,
    })
}

fn get_contents_match_conditions(
    proto: &[rrg_proto::flows::FileFinderCondition],
) -> Result<Vec<ContentsMatchCondition>, crate::action::ParseArgsError> {
    let mut conditions = vec![];
    for proto_condition in proto {
        conditions.extend(get_contents_match_condition(proto_condition)?);
    }
    Ok(conditions)
}

// TODO: maybe it can return Option instead of Vec now
fn get_contents_match_condition(
    proto: &rrg_proto::flows::FileFinderCondition,
) -> Result<Option<ContentsMatchCondition>, crate::action::ParseArgsError> {
    if !proto.has_condition_type() {
        return Ok(None);
    }

    use rrg_proto::flows::FileFinderCondition_Type::*;
    Ok(match proto.get_condition_type() {
        CONTENTS_REGEX_MATCH => {
            get_contents_regex_match_condition(proto.get_contents_regex_match())?
        }
        CONTENTS_LITERAL_MATCH => {
            get_contents_literal_match_condition(proto.get_contents_literal_match())?
        }
        _ => None,
    })
}

/// An error type for errors where we received an unuspported path type.
#[derive(Debug)]
struct UnsupportedPathTypeError {
    /// The path type that we received but we do not support.
    path_type: rrg_proto::jobs::PathSpec_PathType,
}

impl std::fmt::Display for UnsupportedPathTypeError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "unuspported path type ({})", self.path_type.value())
    }
}

impl std::error::Error for UnsupportedPathTypeError {
}

impl super::super::Args for Request {
    type Proto = rrg_proto::flows::FileFinderArgs;

    fn from_proto(proto: rrg_proto::flows::FileFinderArgs) -> Result<Request, crate::action::ParseArgsError> {
        info!("File Finder: proto request: {:#?}", &proto);
        if proto.get_pathtype() != rrg_proto::jobs::PathSpec_PathType::OS {
            let error = UnsupportedPathTypeError {
                path_type: proto.get_pathtype(),
            };
            return Err(crate::action::ParseArgsError::invalid_field(error));
        }

        let follow_links = proto.get_follow_links();
        let process_non_regular_files = proto.get_process_non_regular_files();
        let xdev_mode = proto.get_xdev();
        let conditions = get_conditions(proto.get_conditions())?;
        let contents_match_conditions =
            get_contents_match_conditions(proto.get_conditions())?;

        let action = into_action(proto.get_action().to_owned())?;
        let stat_options = StatActionOptions::from(proto.get_action().get_stat().to_owned());

        Ok(Request {
            path_queries: proto.get_paths().to_owned(),
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
    use crate::action::Args as _;

    #[test]
    fn test_empty_request() {
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::STAT);

        let request = Request::from_proto(proto).unwrap();

        assert!(request.path_queries.is_empty());
        assert!(request.conditions.is_empty());
        assert_eq!(request.process_non_regular_files, false);
        assert_eq!(request.follow_links, false);
        assert_eq!(request.xdev_mode, rrg_proto::flows::FileFinderArgs_XDev::LOCAL);
    }

    #[test]
    fn test_basic_root_parameters() {
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_paths().push("abc".to_string());
        proto.mut_paths().push("cba".to_string());
        proto.set_process_non_regular_files(true);
        proto.set_follow_links(true);
        proto.set_xdev(rrg_proto::flows::FileFinderArgs_XDev::ALWAYS);
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::STAT);

        let request = Request::from_proto(proto).unwrap();

        assert_eq!(
            request.path_queries,
            vec!["abc".to_string(), "cba".to_string()]
        );
        assert_eq!(request.process_non_regular_files, true);
        assert_eq!(request.follow_links, true);
        assert_eq!(request.xdev_mode, rrg_proto::flows::FileFinderArgs_XDev::ALWAYS);
    }

    #[test]
    fn test_fails_on_non_os_path_type() {
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_paths().push("abc".to_string());
        proto.mut_paths().push("cba".to_string());
        proto.set_process_non_regular_files(true);
        proto.set_follow_links(true);
        proto.set_pathtype(rrg_proto::jobs::PathSpec_PathType::REGISTRY);
        proto.set_xdev(rrg_proto::flows::FileFinderArgs_XDev::ALWAYS);
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::STAT);

        let err = Request::from_proto(proto).unwrap_err();

        match err.kind() {
            crate::action::ParseArgsErrorKind::InvalidField => {}
            e @ _ => panic!("Unexpected error type: {:?}", e),
        }
    }

    #[test]
    fn test_default_stats_action() {
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::STAT);

        let request = Request::from_proto(proto).unwrap();

        assert_eq!(request.stat_options.follow_symlink, false);
        assert_eq!(request.stat_options.collect_ext_attrs, false);
    }

    #[test]
    fn test_stats_action() {
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::STAT);
        proto.mut_action().mut_stat().set_resolve_links(true);
        proto.mut_action().mut_stat().set_collect_ext_attrs(true);

        let request = Request::from_proto(proto).unwrap();

        assert_eq!(request.stat_options.follow_symlink, true);
        assert_eq!(request.stat_options.collect_ext_attrs, true);
    }

    #[test]
    fn test_default_hash_action() {
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::HASH);

        let request = Request::from_proto(proto).unwrap();

        match request.action.unwrap() {
            Action::Hash(options) => {
                assert_eq!(
                    options.oversized_file_policy,
                    rrg_proto::flows::FileFinderHashActionOptions_OversizedFilePolicy::SKIP
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
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::HASH);
        proto.mut_action().mut_hash().set_collect_ext_attrs(true);
        proto.mut_action().mut_hash().set_oversized_file_policy(rrg_proto::flows::FileFinderHashActionOptions_OversizedFilePolicy::HASH_TRUNCATED);
        proto.mut_action().mut_hash().set_max_size(123456);
        proto.mut_action().mut_stat().set_collect_ext_attrs(true);
        proto.mut_action().mut_stat().set_resolve_links(true);

        let request = Request::from_proto(proto).unwrap();

        match request.action.unwrap() {
            Action::Hash(options) => {
                assert_eq!(
                    options.oversized_file_policy,
                    rrg_proto::flows::FileFinderHashActionOptions_OversizedFilePolicy::HASH_TRUNCATED
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
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::DOWNLOAD);

        let request = Request::from_proto(proto).unwrap();

        match request.action.unwrap() {
            Action::Download(options) => {
                assert_eq!(options.max_size, 500000000);
                assert_eq!(
                    options.oversized_file_policy,
                    rrg_proto::flows::FileFinderDownloadActionOptions_OversizedFilePolicy::SKIP
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
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::DOWNLOAD);
        proto.mut_action().mut_download().set_max_size(12345);
        proto.mut_action().mut_download().set_collect_ext_attrs(true);
        proto.mut_action().mut_download().set_oversized_file_policy(rrg_proto::flows::FileFinderDownloadActionOptions_OversizedFilePolicy::DOWNLOAD_TRUNCATED);
        proto.mut_action().mut_download().set_use_external_stores(false);
        proto.mut_action().mut_download().set_chunk_size(5432);
        proto.mut_action().mut_stat().set_collect_ext_attrs(true);
        proto.mut_action().mut_stat().set_resolve_links(true);

        let request = Request::from_proto(proto).unwrap();

        match request.action.unwrap() {
            Action::Download(options) => {
                assert_eq!(options.max_size, 12345);
                assert_eq!(
                    options.oversized_file_policy,
                    rrg_proto::flows::FileFinderDownloadActionOptions_OversizedFilePolicy::DOWNLOAD_TRUNCATED
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
    fn test_modification_time_condition() {
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::STAT);

        let condition = proto.mut_conditions().push_default();
        condition.set_condition_type(rrg_proto::flows::FileFinderCondition_Type::MODIFICATION_TIME);
        condition.mut_modification_time().set_min_last_modified_time(123);
        condition.mut_modification_time().set_max_last_modified_time(234);

        let request = Request::from_proto(proto).unwrap();

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
    fn test_access_time_condition() {
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::STAT);

        let condition = proto.mut_conditions().push_default();
        condition.set_condition_type(rrg_proto::flows::FileFinderCondition_Type::ACCESS_TIME);
        condition.mut_access_time().set_min_last_access_time(123);
        condition.mut_access_time().set_max_last_access_time(234);

        let request = Request::from_proto(proto).unwrap();

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
    fn test_inode_change_time_condition() {
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::STAT);

        let condition = proto.mut_conditions().push_default();
        condition.set_condition_type(rrg_proto::flows::FileFinderCondition_Type::INODE_CHANGE_TIME);
        condition.mut_inode_change_time().set_min_last_inode_change_time(123);
        condition.mut_inode_change_time().set_max_last_inode_change_time(234);

        let request = Request::from_proto(proto).unwrap();

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
    fn test_size_condition() {
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::STAT);

        let condition = proto.mut_conditions().push_default();
        condition.set_condition_type(rrg_proto::flows::FileFinderCondition_Type::SIZE);
        condition.mut_size().set_min_file_size(345);
        condition.mut_size().set_max_file_size(456);

        let request = Request::from_proto(proto).unwrap();

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
    fn test_ext_flags_condition() {
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::STAT);

        let condition = proto.mut_conditions().push_default();
        condition.set_condition_type(rrg_proto::flows::FileFinderCondition_Type::EXT_FLAGS);
        condition.mut_ext_flags().set_linux_bits_set(111);
        condition.mut_ext_flags().set_linux_bits_unset(222);
        condition.mut_ext_flags().set_osx_bits_set(333);
        condition.mut_ext_flags().set_osx_bits_unset(444);

        let request = Request::from_proto(proto).unwrap();

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
    fn test_contents_regex_match_condition() {
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::STAT);

        let condition = proto.mut_conditions().push_default();
        condition.set_condition_type(rrg_proto::flows::FileFinderCondition_Type::CONTENTS_REGEX_MATCH);
        condition.mut_contents_regex_match().set_regex(vec![97, 98, 99]);
        condition.mut_contents_regex_match().set_mode(rrg_proto::flows::FileFinderContentsRegexMatchCondition_Mode::ALL_HITS);
        condition.mut_contents_regex_match().set_bytes_before(4);
        condition.mut_contents_regex_match().set_bytes_after(7);
        condition.mut_contents_regex_match().set_start_offset(15);
        condition.mut_contents_regex_match().set_length(42);

        let request = Request::from_proto(proto).unwrap();

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
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::STAT);

        let condition = proto.mut_conditions().push_default();
        condition.set_condition_type(rrg_proto::flows::FileFinderCondition_Type::CONTENTS_REGEX_MATCH);
        condition.mut_contents_regex_match().set_regex(vec![255, 255, 255]);
        condition.mut_contents_regex_match().set_mode(rrg_proto::flows::FileFinderContentsRegexMatchCondition_Mode::ALL_HITS);
        condition.mut_contents_regex_match().set_bytes_before(4);
        condition.mut_contents_regex_match().set_bytes_after(7);
        condition.mut_contents_regex_match().set_start_offset(15);
        condition.mut_contents_regex_match().set_length(42);

        let err = Request::from_proto(proto).unwrap_err();

        assert!(matches!(err.kind(), crate::action::ParseArgsErrorKind::InvalidField));
    }

    #[test]
    fn test_contents_literal_match_condition() {
        let mut proto = rrg_proto::flows::FileFinderArgs::new();
        proto.mut_action().set_action_type(rrg_proto::flows::FileFinderAction_Action::STAT);

        let condition = proto.mut_conditions().push_default();
        condition.set_condition_type(rrg_proto::flows::FileFinderCondition_Type::CONTENTS_LITERAL_MATCH);
        condition.mut_contents_literal_match().set_literal(vec![99, 98, 97]);
        condition.mut_contents_literal_match().set_mode(rrg_proto::flows::FileFinderContentsLiteralMatchCondition_Mode::ALL_HITS);
        condition.mut_contents_literal_match().set_start_offset(6);
        condition.mut_contents_literal_match().set_length(8);
        condition.mut_contents_literal_match().set_bytes_before(15);
        condition.mut_contents_literal_match().set_bytes_after(18);

        let request = Request::from_proto(proto).unwrap();

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
