// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Utilities for working with the filesystem.
//!
//! This file can be thought as an extension for functionalities missing in the
//! standard `std::fs` module. All functions are portable and should work on all
//! supported platforms (perhaps with limited capabilities).

use std::fs::Metadata;
use std::path::{Path, PathBuf};

/// A path to a filesystem item and associated metadata.
///
/// This type is very similar to standard [`DirEntry`] but its metadata and path
/// is guaranteed to always be there and cheap to retrieve.
///
/// [`DirEntry`]: std::fs::DirEntry
pub struct Entry {
    /// A path to the filesystem item.
    pub path: PathBuf,
    /// Metadata associated with the item.
    pub metadata: Metadata,
}

/// Returns a deep iterator over entries within a directory.
///
/// The iterator will recursively visit all subdirectories under `root` and
/// yield entries for all encountered files.
///
/// Note that symlinked folders or directories mounted to a different device
/// than the root will not be recursively searched. This is done to avoid cycles
/// and undesired traversal of network filesystems (which can be very slow).
///
/// # Errors
///
/// In general, the iterator will ignore all errors encountered along the way.
/// The only exception are the problems encountering when collecting information
/// about the root folder in which case an error is returned instead of the
/// iterator.
///
/// # Examples
///
/// ```no_run
/// let paths = rrg::fs::walk_dir("/").unwrap()
///     .filter_map(Result::ok)
///     .map(|entry| entry.path)
///     .collect::<Vec<_>>();
///
/// assert!(paths.contains(&"/usr".into()));
/// assert!(paths.contains(&"/usr/bin".into()));
/// assert!(paths.contains(&"/usr/lib".into()));
/// ```
pub fn walk_dir<P: AsRef<Path>>(root: P) -> std::io::Result<WalkDir> {
    let root = root.as_ref();

    let iter = ListDir {
        iter: std::fs::read_dir(root)?,
        cur_depth: 1,
    };

    #[cfg(target_family = "unix")]
    let dev = {
        let metadata = std::fs::metadata(root)?;
        std::os::unix::fs::MetadataExt::dev(&metadata)
    };

    Ok(WalkDir {
        max_depth: u32::MAX,
        iter,
        pending_iters: vec![],
        #[cfg(target_family = "unix")]
        dev: dev,
    })
}

/// Iterator over entries in all subdirectories.
///
/// This iterator will recursively descent to all subdirectories and yield
/// entries for every file encountered along the way. However, during the
/// traversal it will not cross device boundaries and enter symlinked
/// directories.
///
/// Note that this iterator always returns an entry. All errors are simply
/// swallowed.
///
/// The iterator can be constructed with the [`walk_dir`] function.
pub struct WalkDir {
    max_depth: u32,
    iter: ListDir,
    pending_iters: Vec<std::io::Result<ListDir>>,
    #[cfg(target_family = "unix")] dev: u64,
}

impl WalkDir {

    /// Limits recursion to the specified `max_depth`.
    ///
    /// # Panics
    ///
    /// Panics if the given limit is zero.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let paths = rrg::fs::walk_dir("/").unwrap().with_max_depth(1)
    ///     .filter_map(Result::ok)
    ///     .map(|entry| entry.path)
    ///     .collect::<Vec<_>>();
    ///
    /// assert!(paths.contains(&"/usr".into()));
    /// assert!(!paths.contains(&"/usr/bin".into()));
    /// assert!(!paths.contains(&"/usr/lib".into()));
    /// ```
    pub fn with_max_depth(mut self, max_depth: u32) -> WalkDir {
        assert!(max_depth > 0);

        self.max_depth = max_depth;
        self
    }

    #[cfg(target_family = "unix")]
    fn is_same_dev(&self, entry: &Entry) -> bool {
        self.dev == std::os::unix::fs::MetadataExt::dev(&entry.metadata)
    }

    #[cfg(target_family = "windows")]
    fn is_same_dev(&self, _entry: &Entry) -> bool {
        true
    }
}

impl std::iter::Iterator for WalkDir {

    type Item = std::io::Result<Entry>;

    fn next(&mut self) -> Option<std::io::Result<Entry>> {
        loop {
            if let Some(entry) = self.iter.next() {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => return Some(Err(error)),
                };

                if entry.metadata.is_dir() && self.is_same_dev(&entry) && self.iter.cur_depth < self.max_depth {
                    self.pending_iters.push({
                        std::fs::read_dir(&entry.path).map(|iter| ListDir {
                            iter,
                            // This cannot ever overflow because the condition
                            // above guarantees that `self.iter.cur_depth` is
                            // less than `u32::MAX`.
                            cur_depth: self.iter.cur_depth + 1,
                        })
                    });
                }

                return Some(Ok(entry));
            }

            let iter = match self.pending_iters.pop() {
                Some(iter) => iter,
                None => return None,
            };

            match iter {
                Ok(iter) => {
                    self.iter = iter;
                    continue;
                },
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

/// Iterator over the entries in a directory.
///
/// Unlike the [`ReadDir`] iterator entries, [`ListDir`] entries are guaranteed
/// to have valid metadata objects attached.
pub struct ListDir {
    cur_depth: u32,
    iter: std::fs::ReadDir,
}

impl std::iter::Iterator for ListDir {

    type Item = std::io::Result<Entry>;

    fn next(&mut self) -> Option<std::io::Result<Entry>> {
        let entry = match self.iter.next() {
            Some(Ok(entry)) => entry,
            Some(Err(error)) => return Some(Err(error)),
            None => return None,
        };

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) => return Some(Err(error)),
        };

        Some(Ok(Entry {
            path: entry.path(),
            metadata,
        }))
    }
}

#[cfg(test)]
mod tests {

    use std::fs::File;

    use super::*;

    #[test]
    fn test_walk_dir_non_existing() {
        let tempdir = tempfile::tempdir().unwrap();

        let iter = walk_dir(tempdir.path().join("foo"));
        assert!(iter.is_err());
    }

    #[test]
    fn walk_dir_not_dir() {
        let tempdir = tempfile::tempdir().unwrap();
        File::create(tempdir.path().join("foo")).unwrap();

        let iter = walk_dir(tempdir.path().join("foo"));
        assert!(iter.is_err());
    }

    #[test]
    fn test_walk_dir_empty() {
        let tempdir = tempfile::tempdir().unwrap();

        let iter = walk_dir(&tempdir).unwrap();
        assert_eq!(iter.count(), 0);
    }

    #[test]
    fn test_walk_dir_with_flat_files() {
        let tempdir = tempfile::tempdir().unwrap();
        File::create(tempdir.path().join("abc")).unwrap();
        File::create(tempdir.path().join("def")).unwrap();
        File::create(tempdir.path().join("ghi")).unwrap();

        let mut results = walk_dir(&tempdir).unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 3);

        assert_eq!(results[0].path, tempdir.path().join("abc"));
        assert!(results[0].metadata.is_file());

        assert_eq!(results[1].path, tempdir.path().join("def"));
        assert!(results[1].metadata.is_file());

        assert_eq!(results[2].path, tempdir.path().join("ghi"));
        assert!(results[2].metadata.is_file());
    }

    #[test]
    fn test_walk_dir_with_flat_dirs() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::create_dir(tempdir.path().join("abc")).unwrap();
        std::fs::create_dir(tempdir.path().join("def")).unwrap();

        let mut results = walk_dir(&tempdir).unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].path, tempdir.path().join("abc"));
        assert!(results[0].metadata.is_dir());

        assert_eq!(results[1].path, tempdir.path().join("def"));
        assert!(results[1].metadata.is_dir());
    }

    #[test]
    fn test_walk_dir_with_nested_dirs() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::create_dir(tempdir.path().join("abc")).unwrap();
        std::fs::create_dir(tempdir.path().join("abc").join("def")).unwrap();

        let mut results = walk_dir(&tempdir).unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].path, tempdir.path().join("abc"));
        assert!(results[0].metadata.is_dir());

        assert_eq!(results[1].path, tempdir.path().join("abc").join("def"));
        assert!(results[1].metadata.is_dir());
    }

    // Both Windows and macOS have limits on the path length. Both of these
    // limits are very low (260 and 1016 respectively), so making the created
    // hierarchy to fit these would render the test quite useless. Hence, we
    // simply ignore it on these platforms.
    #[cfg_attr(target_os = "macos", ignore)]
    #[cfg_attr(target_os = "windows", ignore)]
    #[test]
    fn test_walk_dir_with_deeply_nested_dirs() {
        let tempdir = tempfile::tempdir().unwrap();

        let mut dir = tempdir.path().to_path_buf();
        for _ in 0..512 {
            dir.push("foo");
            std::fs::create_dir(&dir).unwrap();
        }

        let mut results = walk_dir(&tempdir).unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 512);

        for entry in &results {
            assert!(entry.path.starts_with(&tempdir));
            assert!(entry.path.ends_with("foo"));
            assert!(entry.metadata.is_dir());
        }
    }

    #[test]
    fn test_walk_dir_with_files_inside_dir() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::create_dir(tempdir.path().join("foo")).unwrap();
        File::create(tempdir.path().join("foo").join("abc")).unwrap();
        File::create(tempdir.path().join("foo").join("def")).unwrap();

        let mut results = walk_dir(&tempdir).unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 3);

        assert_eq!(results[0].path, tempdir.path().join("foo"));
        assert!(results[0].metadata.is_dir());

        assert_eq!(results[1].path, tempdir.path().join("foo").join("abc"));
        assert!(results[1].metadata.is_file());

        assert_eq!(results[2].path, tempdir.path().join("foo").join("def"));
        assert!(results[2].metadata.is_file());
    }

    // Symlinking is supported only on Unix-like systems.
    #[cfg(target_family = "unix")]
    #[test]
    fn test_walk_dir_with_dir_symlinks() {
        let tempdir = tempfile::tempdir().unwrap();
        let dir = tempdir.path().join("abc");
        let file = dir.join("def");
        let symlink = tempdir.path().join("ghi");

        std::fs::create_dir(&dir).unwrap();
        File::create(&file).unwrap();
        std::os::unix::fs::symlink(&dir, &symlink).unwrap();

        let mut results = walk_dir(&tempdir).unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 3);

        assert_eq!(results[0].path, dir);
        assert!(results[0].metadata.file_type().is_dir());

        assert_eq!(results[1].path, file);
        assert!(results[1].metadata.file_type().is_file());

        assert_eq!(results[2].path, symlink);
        assert!(results[2].metadata.file_type().is_symlink());
    }

    // Symlinking is supported only on Unix-like systems.
    #[cfg(target_family = "unix")]
    #[test]
    fn test_walk_dir_with_circular_symlinks() {
        let tempdir = tempfile::tempdir().unwrap();
        let dir = tempdir.path().join("foo");
        let symlink = tempdir.path().join("foo").join("bar");

        std::fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink(&dir, &symlink).unwrap();

        let mut results = walk_dir(&tempdir).unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].path, dir);
        assert!(results[0].metadata.file_type().is_dir());

        assert_eq!(results[1].path, symlink);
        assert!(results[1].metadata.file_type().is_symlink());
    }

    // macOS mangles Unicode-specific characters in filenames.
    #[cfg_attr(target_os = "macos", ignore)]
    #[test]
    fn test_walk_dir_with_unicode_names() {
        let tempdir = tempfile::tempdir().unwrap();
        File::create(tempdir.path().join("zażółć gęślą jaźń")).unwrap();

        let mut results = walk_dir(&tempdir).unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, tempdir.path().join("zażółć gęślą jaźń"));
    }

    #[test]
    fn test_walk_dir_metadata_size() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::write(tempdir.path().join("foo"), b"123456789").unwrap();

        let mut results = walk_dir(&tempdir).unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata.len(), 9);
    }

    #[test]
    #[should_panic]
    fn walk_dir_with_max_depth_0() {
        let tempdir = tempfile::tempdir().unwrap();

        let _ = walk_dir(tempdir.path()).unwrap()
            .with_max_depth(0);
    }

    #[test]
    fn walk_dir_with_max_depth_1() {
        let tempdir = tempfile::tempdir().unwrap();
        let tempdir = tempdir.path();

        std::fs::create_dir(tempdir.join("abc"))
            .unwrap();
        std::fs::create_dir(tempdir.join("abc").join("def"))
            .unwrap();
        std::fs::create_dir(tempdir.join("ghi"))
            .unwrap();
        std::fs::create_dir(tempdir.join("ghi").join("jkl"))
            .unwrap();
        std::fs::create_dir(tempdir.join("mno"))
            .unwrap();
        std::fs::create_dir(tempdir.join("mno").join("pqr"))
            .unwrap();

        let results = walk_dir(&tempdir).unwrap().with_max_depth(1)
            .filter_map(Result::ok);

        let paths = results.map(|entry| entry.path)
            .collect::<Vec<_>>();

        assert!(paths.contains(&tempdir.join("abc")));
        assert!(paths.contains(&tempdir.join("ghi")));
        assert!(paths.contains(&tempdir.join("mno")));

        assert!(!paths.contains(&tempdir.join("abc").join("def")));
        assert!(!paths.contains(&tempdir.join("ghi").join("jkl")));
        assert!(!paths.contains(&tempdir.join("mno").join("pqr")));
    }

    #[test]
    fn walk_dir_with_max_depth_2() {
        let tempdir = tempfile::tempdir().unwrap();
        let tempdir = tempdir.path();

        std::fs::create_dir(tempdir.join("a"))
            .unwrap();
        std::fs::create_dir(tempdir.join("a").join("b"))
            .unwrap();
        std::fs::create_dir(tempdir.join("a").join("b").join("c"))
            .unwrap();
        std::fs::create_dir(tempdir.join("a").join("b").join("c").join("d"))
            .unwrap();

        let results = walk_dir(tempdir).unwrap().with_max_depth(2)
            .filter_map(Result::ok);

        let paths = results.map(|entry| entry.path)
            .collect::<Vec<_>>();

        assert!(paths.contains(&tempdir.join("a")));
        assert!(paths.contains(&tempdir.join("a").join("b")));

        assert!(!paths.contains(&tempdir.join("a").join("b").join("c")));
        assert!(!paths.contains(&tempdir.join("a").join("b").join("c").join("d")));
    }
}
