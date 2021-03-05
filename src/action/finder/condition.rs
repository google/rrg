use crate::action::finder::file::{get_file_chunks, GetFileChunksConfig};
use crate::action::finder::request::{
    Condition, ContentsMatchCondition, MatchMode,
};
use crate::fs::linux::flags;
use crate::fs::Entry;
use log::warn;
use rrg_macro::ack;
use rrg_proto::BufferReference;
use std::cmp::{max, min};
use std::fs::Metadata;
#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;

/// Returns true if all conditions were met.
/// If the data required for checking the condition cannot be obtained then
/// the condition is assumed to be met.
pub fn check_conditions(conditions: &Vec<Condition>, entry: &Entry) -> bool {
    conditions.into_iter().all(|c| check_condition(c, &entry))
}

/// Returns positions of matches from all conditions when all
/// `match_conditions` found at least 1 match. Returns empty `Vec` otherwise.
/// If the file content cannot be obtained the condition is assumed to
/// be not met.
pub fn find_matches(
    match_conditions: &Vec<ContentsMatchCondition>,
    entry: &Entry,
) -> Vec<BufferReference> {
    let mut ret = vec![];
    for match_condition in match_conditions {
        let mut matches = matches(match_condition, &entry);
        if matches.is_empty() {
            return vec![];
        }
        ret.append(&mut matches);
    }

    ret
}

/// Checks is the condition is met by the entry.
/// In case of simple conditions if the data required for checking the condition
/// cannot be obtained then the condition is assumed to be met.
fn check_condition(condition: &Condition, entry: &Entry) -> bool {
    match condition {
        Condition::ModificationTime { min, max } => {
            let actual = ack! {
                entry.metadata.modified(),
                error: "failed to obtain modification time"
            };
            match actual {
                Some(actual) => is_in_range(&actual, (min, max)),
                None => true,
            }
        }

        Condition::AccessTime { min, max } => {
            let actual = ack! {
                entry.metadata.accessed(),
                error: "failed to obtain access time"
            };
            match actual {
                Some(actual) => is_in_range(&actual, (min, max)),
                None => true,
            }
        }

        Condition::InodeChangeTime { min, max } => {
            match read_ctime(&entry.metadata) {
                Some(actual) => is_in_range(&actual, (min, max)),
                None => {
                    warn!(
                        "failed to obtain inode change time for file: {}",
                        entry.path.display()
                    );
                    true
                }
            }
        }

        Condition::Size { min, max } => {
            is_in_range(&entry.metadata.len(), (min, max))
        }

        Condition::ExtFlags {
            linux_bits_set,
            linux_bits_unset,
            ..
        } => {
            // TODO(spawek): support osx bits
            let mut ok = true;

            #[cfg(target_family = "unix")]
            if let Ok(flags) = flags(&entry.path) {
                if let Some(linux_bits_set) = linux_bits_set {
                    ok &= flags & linux_bits_set == flags;
                }
                if let Some(linux_bits_unset) = linux_bits_unset {
                    ok &= flags & linux_bits_unset == 0;
                }
            } else {
                warn!(
                    "failed to obtain extended flags for file: {}",
                    entry.path.display()
                );
            };

            ok
        }
    }
}

/// Checks if `value` is in range [`min`, `max`] (inclusive on both ends).
/// If range option is equal `None` then the condition is not checked.
fn is_in_range<T: Ord>(value: &T, range: (&Option<T>, &Option<T>)) -> bool {
    if let Some(min) = &range.0 {
        if value < min {
            return false;
        }
    }
    if let Some(max) = &range.1 {
        if value > max {
            return false;
        }
    }

    true
}

fn matches(
    condition: &ContentsMatchCondition,
    entry: &Entry,
) -> Vec<BufferReference> {
    const BYTES_PER_CHUNK: u64 = 10 * 1024 * 1024;
    const OVERLAP_BYTES: u64 = 1024 * 1024;

    let chunks = get_file_chunks(
        &entry.path,
        &GetFileChunksConfig {
            start_offset: condition.start_offset,
            max_read_bytes: condition.length,
            bytes_per_chunk: BYTES_PER_CHUNK,
            overlap_bytes: OVERLAP_BYTES,
        },
    );
    let chunks = match chunks {
        Some(chunks) => chunks,
        None => return vec![],
    };

    let mut matches = vec![];
    let mut offset = condition.start_offset;

    for chunk in chunks {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                warn!(
                    "failed to read chunk from file: {}, error: {}",
                    entry.path.display(),
                    err
                );
                return vec![];
            }
        };
        for m in condition.regex.find_iter(chunk.as_slice()) {
            let start = max(m.start() as u64 - condition.bytes_before, 0);
            let end =
                min(m.end() as u64 + condition.bytes_after, chunk.len() as u64);
            let data = chunk[(start as usize)..(end as usize)].to_vec();

            matches.push(BufferReference {
                offset: Some(offset + start),
                length: Some(end - start),
                callback: None,
                data: Some(data),
                pathspec: Some(entry.path.clone().into()),
            });

            match condition.mode {
                MatchMode::FirstHit => return matches,
                MatchMode::AllHits => (),
            }
        }
        offset += BYTES_PER_CHUNK - OVERLAP_BYTES;
    }

    matches
}

/// Reads inode change time from metadata.
fn read_ctime(metadata: &Metadata) -> Option<std::time::SystemTime> {
    let time = std::time::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(metadata.ctime() as u64))?;
    time.checked_add(std::time::Duration::from_nanos(
        metadata.ctime_nsec() as u64
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_is_in_range() {
        assert!(is_in_range(&2, (&Some(1), &Some(3))));
        assert!(is_in_range(&2, (&Some(2), &Some(2))));
        assert!(is_in_range(&2, (&Some(2), &None)));
        assert!(is_in_range(&2, (&None, &Some(2))));
        assert!(is_in_range(&2, (&None, &None)));
        assert!(!is_in_range(&2, (&Some(3), &None)));
        assert!(!is_in_range(&2, (&None, &Some(1))));
    }

    #[test]
    fn test_read_ctime() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "test").unwrap();

        let metadata = path.metadata().unwrap();
        let ctime = read_ctime(&metadata).unwrap();
        let mtime = metadata.modified().unwrap();
        assert_eq!(ctime, mtime);
    }

    #[test]
    fn test_size_condition() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "test123456").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path,
        };

        assert!(check_condition(
            &Condition::Size {
                min: None,
                max: None,
            },
            &entry
        ));
        assert!(check_condition(
            &Condition::Size {
                min: Some(10),
                max: Some(10),
            },
            &entry
        ));
        assert!(!check_condition(
            &Condition::Size {
                min: Some(11),
                max: None,
            },
            &entry
        ));
        assert!(!check_condition(
            &Condition::Size {
                min: None,
                max: Some(9),
            },
            &entry
        ));
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn test_extflags_condition() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "test").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path: path.clone(),
        };

        let flags = flags(&path).unwrap();
        assert_ne!(flags, 0);

        assert!(check_condition(
            &Condition::ExtFlags {
                linux_bits_set: None,
                linux_bits_unset: None,
                osx_bits_set: None,
                osx_bits_unset: None
            },
            &entry
        ));
        assert!(check_condition(
            &Condition::ExtFlags {
                linux_bits_set: Some(flags),
                linux_bits_unset: Some(flags.reverse_bits()),
                osx_bits_set: None,
                osx_bits_unset: None
            },
            &entry
        ));
        assert!(!check_condition(
            &Condition::ExtFlags {
                linux_bits_set: Some(flags.reverse_bits()),
                linux_bits_unset: None,
                osx_bits_set: None,
                osx_bits_unset: None
            },
            &entry
        ));
        assert!(!check_condition(
            &Condition::ExtFlags {
                linux_bits_set: None,
                linux_bits_unset: Some(flags),
                osx_bits_set: None,
                osx_bits_unset: None
            },
            &entry
        ));
    }

    #[test]
    fn test_modification_time_condition() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "test").unwrap();

        let metadata = path.metadata().unwrap();
        let modify_time = metadata.modified().unwrap();
        let pre_modify_time = modify_time - Duration::from_nanos(1);
        let post_modify_time = modify_time + Duration::from_nanos(1);

        let entry = Entry { metadata, path };

        assert!(check_condition(
            &Condition::ModificationTime {
                min: None,
                max: None,
            },
            &entry
        ));
        assert!(check_condition(
            &Condition::ModificationTime {
                min: Some(pre_modify_time),
                max: Some(post_modify_time),
            },
            &entry
        ));
        assert!(!check_condition(
            &Condition::ModificationTime {
                min: Some(post_modify_time),
                max: None,
            },
            &entry
        ));
        assert!(!check_condition(
            &Condition::ModificationTime {
                min: None,
                max: Some(pre_modify_time),
            },
            &entry
        ));
    }

    #[test]
    fn test_access_time_condition() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "test").unwrap();

        // Wait at least 10ms before reading to ensure that the access time
        // will be updated. Updating access time is dependent on OS
        // configuration, which may cause this test to fail.
        sleep(Duration::from_millis(100));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "test");

        let metadata = path.metadata().unwrap();
        let access_time = metadata.accessed().unwrap();
        assert!(access_time > metadata.modified().unwrap());
        let pre_access_time = access_time - Duration::from_nanos(1);
        let post_access_time = access_time + Duration::from_nanos(1);

        let entry = Entry { metadata, path };

        assert!(check_condition(
            &Condition::AccessTime {
                min: None,
                max: None,
            },
            &entry
        ));
        assert!(check_condition(
            &Condition::AccessTime {
                min: Some(pre_access_time),
                max: Some(post_access_time),
            },
            &entry
        ));
        assert!(!check_condition(
            &Condition::AccessTime {
                min: Some(post_access_time),
                max: None,
            },
            &entry
        ));
        assert!(!check_condition(
            &Condition::AccessTime {
                min: None,
                max: Some(pre_access_time),
            },
            &entry
        ));
    }

    #[test]
    fn test_change_time_condition() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "test").unwrap();

        let modify_time = path.metadata().unwrap().modified().unwrap();

        // Wait at least 10ms before reading to ensure that the change time
        // will be updated. Updating change time is dependent on OS
        // configuration, which may cause this test to fail.
        sleep(Duration::from_millis(1000));
        let mut perms = path.metadata().unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms).unwrap();

        let metadata = path.metadata().unwrap();
        let change_time = read_ctime(&metadata).unwrap();
        assert!(change_time > modify_time);
        let pre_change_time = change_time - Duration::from_nanos(1);
        let post_change_time = change_time + Duration::from_nanos(1);

        let entry = Entry { metadata, path };

        assert!(check_condition(
            &Condition::InodeChangeTime {
                min: None,
                max: None,
            },
            &entry
        ));
        assert!(check_condition(
            &Condition::InodeChangeTime {
                min: Some(pre_change_time),
                max: Some(post_change_time),
            },
            &entry
        ));
        assert!(!check_condition(
            &Condition::InodeChangeTime {
                min: Some(post_change_time),
                max: None,
            },
            &entry
        ));
        assert!(!check_condition(
            &Condition::InodeChangeTime {
                min: None,
                max: Some(pre_change_time),
            },
            &entry
        ));
    }

    #[test]
    fn test_multiple_matching_conditions() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "test").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path,
        };

        assert!(check_conditions(
            &vec![
                Condition::Size {
                    min: None,
                    max: None,
                },
                Condition::Size {
                    min: None,
                    max: None,
                }
            ],
            &entry
        ));
    }

    #[test]
    fn test_not_all_matching_condition() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "test").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path,
        };

        assert!(!check_conditions(
            &vec![
                Condition::Size {
                    min: Some(5),
                    max: None,
                },
                Condition::Size {
                    min: None,
                    max: None,
                }
            ],
            &entry
        ));
    }

    #[test]
    fn test_contents_match_condition() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "123te123st123").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path: path.clone(),
        };

        let matches = matches(
            &ContentsMatchCondition {
                regex: regex::bytes::Regex::new("te.*st").unwrap(),
                mode: MatchMode::AllHits,
                bytes_before: 1,
                bytes_after: 2,
                start_offset: 0,
                length: 1000,
            },
            &entry,
        );
        assert_eq!(matches.len(), 1);

        let m = matches.first().unwrap();
        assert_eq!(m.data.as_ref().unwrap(), &"3te123st12".as_bytes().to_vec());
        assert_eq!(m.length.unwrap(), 10);
        assert_eq!(m.offset.unwrap(), 2);
        assert_eq!(
            m.pathspec.as_ref().unwrap().path.as_ref().unwrap(),
            path.to_str().unwrap()
        );
    }

    #[test]
    fn test_contents_match_condition_start_offset() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "123test123test123").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path: path.clone(),
        };

        let matches = matches(
            &ContentsMatchCondition {
                regex: regex::bytes::Regex::new("test").unwrap(),
                mode: MatchMode::AllHits,
                bytes_before: 0,
                bytes_after: 0,
                start_offset: 6,
                length: 1000,
            },
            &entry,
        );
        assert_eq!(matches.len(), 1);

        let m = matches.first().unwrap();
        assert_eq!(m.data.as_ref().unwrap(), &"test".as_bytes().to_vec());
        assert_eq!(m.length.unwrap(), 4);
        assert_eq!(m.offset.unwrap(), 10);
        assert_eq!(
            m.pathspec.as_ref().unwrap().path.as_ref().unwrap(),
            path.to_str().unwrap()
        );
    }

    #[test]
    fn test_contents_match_condition_length() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "123test123test123").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path: path.clone(),
        };

        let matches = matches(
            &ContentsMatchCondition {
                regex: regex::bytes::Regex::new("test").unwrap(),
                mode: MatchMode::AllHits,
                bytes_before: 0,
                bytes_after: 0,
                start_offset: 0,
                length: 13,
            },
            &entry,
        );
        assert_eq!(matches.len(), 1);

        let m = matches.first().unwrap();
        assert_eq!(m.data.as_ref().unwrap(), &"test".as_bytes().to_vec());
        assert_eq!(m.length.unwrap(), 4);
        assert_eq!(m.offset.unwrap(), 3);
        assert_eq!(
            m.pathspec.as_ref().unwrap().path.as_ref().unwrap(),
            path.to_str().unwrap()
        );
    }

    #[test]
    fn test_contents_match_condition_multiple_matches() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "123test123tttt123").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path: path.clone(),
        };

        let matches = matches(
            &ContentsMatchCondition {
                regex: regex::bytes::Regex::new(r"t\w\wt").unwrap(),
                mode: MatchMode::AllHits,
                bytes_before: 0,
                bytes_after: 0,
                start_offset: 0,
                length: 1000,
            },
            &entry,
        );
        assert_eq!(matches.len(), 2);

        {
            let m = matches.get(0).unwrap();
            assert_eq!(m.data.as_ref().unwrap(), &"test".as_bytes().to_vec());
            assert_eq!(m.length.unwrap(), 4);
            assert_eq!(m.offset.unwrap(), 3);
            assert_eq!(
                m.pathspec.as_ref().unwrap().path.as_ref().unwrap(),
                path.to_str().unwrap()
            );
        }

        {
            let m = matches.get(1).unwrap();
            assert_eq!(m.data.as_ref().unwrap(), &"tttt".as_bytes().to_vec());
            assert_eq!(m.length.unwrap(), 4);
            assert_eq!(m.offset.unwrap(), 10);
            assert_eq!(
                m.pathspec.as_ref().unwrap().path.as_ref().unwrap(),
                path.to_str().unwrap()
            );
        }
    }

    #[test]
    fn test_contents_match_condition_stop_on_first_hit() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "123test123tttt123").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path: path.clone(),
        };

        let matches = matches(
            &ContentsMatchCondition {
                regex: regex::bytes::Regex::new(r"t\w\wt").unwrap(),
                mode: MatchMode::FirstHit,
                bytes_before: 0,
                bytes_after: 0,
                start_offset: 0,
                length: 1000,
            },
            &entry,
        );
        assert_eq!(matches.len(), 1);

        let m = matches.first().unwrap();
        assert_eq!(m.data.as_ref().unwrap(), &"test".as_bytes().to_vec());
        assert_eq!(m.length.unwrap(), 4);
        assert_eq!(m.offset.unwrap(), 3);
        assert_eq!(
            m.pathspec.as_ref().unwrap().path.as_ref().unwrap(),
            path.to_str().unwrap()
        );
    }

    #[test]
    fn test_multiple_contents_match_conditions_ok_case() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "123test123tttt123").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path: path.clone(),
        };

        let matches = find_matches(
            &vec![
                ContentsMatchCondition {
                    regex: regex::bytes::Regex::new(r"test").unwrap(),
                    mode: MatchMode::FirstHit,
                    bytes_before: 0,
                    bytes_after: 0,
                    start_offset: 0,
                    length: 1000,
                },
                ContentsMatchCondition {
                    regex: regex::bytes::Regex::new(r"tttt").unwrap(),
                    mode: MatchMode::FirstHit,
                    bytes_before: 0,
                    bytes_after: 0,
                    start_offset: 0,
                    length: 1000,
                },
            ],
            &entry,
        );
        assert_eq!(matches.len(), 2);

        {
            let m = matches.get(0).unwrap();
            assert_eq!(m.data.as_ref().unwrap(), &"test".as_bytes().to_vec());
            assert_eq!(m.length.unwrap(), 4);
            assert_eq!(m.offset.unwrap(), 3);
            assert_eq!(
                m.pathspec.as_ref().unwrap().path.as_ref().unwrap(),
                path.to_str().unwrap()
            );
        }

        {
            let m = matches.get(1).unwrap();
            assert_eq!(m.data.as_ref().unwrap(), &"tttt".as_bytes().to_vec());
            assert_eq!(m.length.unwrap(), 4);
            assert_eq!(m.offset.unwrap(), 10);
            assert_eq!(
                m.pathspec.as_ref().unwrap().path.as_ref().unwrap(),
                path.to_str().unwrap()
            );
        }
    }

    #[test]
    fn test_multiple_contents_match_conditions_returns_nothing_if_1_condition_fails(
    ) {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("f");
        std::fs::write(&path, "123test123").unwrap();
        let entry = Entry {
            metadata: path.metadata().unwrap(),
            path: path.clone(),
        };

        let matches = find_matches(
            &vec![
                ContentsMatchCondition {
                    regex: regex::bytes::Regex::new(r"test").unwrap(),
                    mode: MatchMode::FirstHit,
                    bytes_before: 0,
                    bytes_after: 0,
                    start_offset: 0,
                    length: 1000,
                },
                ContentsMatchCondition {
                    regex: regex::bytes::Regex::new(r"abcd").unwrap(),
                    mode: MatchMode::FirstHit,
                    bytes_before: 0,
                    bytes_after: 0,
                    start_offset: 0,
                    length: 1000,
                },
            ],
            &entry,
        );
        assert!(matches.is_empty());
    }
}
