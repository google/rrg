use std::fs::Metadata;
use std::path::{Path, PathBuf};

use log::warn;

pub fn walk<P: AsRef<Path>>(root: P) -> std::io::Result<Walk> {
    let iter = std::fs::read_dir(root)?;
    Ok(Walk {
        pending: vec!(WalkDir::from_read_dir(iter)),
    })
}

pub struct Walk {
    // TODO: Add support for stopping at device boundaries.
    pending: Vec<WalkDir>,
}

pub struct WalkEntry {
    path: PathBuf,
    metadata: Metadata,
}

impl Walk {

    fn push(&mut self, entry: &WalkEntry) {
        match std::fs::read_dir(&entry.path) {
            Ok(iter) => {
                self.pending.push(WalkDir::from_read_dir(iter));
            },
            Err(error) => {
                warn!("failed to read '{}': {}", entry.path.display(), error);
            },
        }
    }

    fn pop(&mut self) -> Option<WalkEntry> {
        while let Some(iter) = self.pending.last_mut() {
            for entry in iter {
                return Some(entry);
            }

            self.pending.pop();
        }

        None
    }
}

impl std::iter::Iterator for Walk {

    type Item = WalkEntry;

    fn next(&mut self) -> Option<WalkEntry> {
        let entry = self.pop()?;

        if entry.metadata.is_dir() {
            self.push(&entry);
        }

        Some(entry)
    }
}

/// Iterator over the entries in a directory.
///
/// This iterator is very similar to the standard `ReadDir` iterator, except
/// that it is forgetful and only yields entries that did not cause any errors.
///
/// Unlike the `ReadDir` iterator entries, `WalkDir` entries are guaranteed to
/// have valid metadata objects attached.
struct WalkDir {
    iter: std::fs::ReadDir,
}

impl WalkDir {

    /// Converts a standard `ReadDir` iterator.
    fn from_read_dir(iter: std::fs::ReadDir) -> WalkDir {
        WalkDir {
            iter: iter,
        }
    }
}

impl std::iter::Iterator for WalkDir {

    type Item = WalkEntry;

    fn next(&mut self) -> Option<WalkEntry> {
        for entry in &mut self.iter {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    warn!("directory iteration error: {}", error);
                    continue
                },
            };

            let path = entry.path();
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    warn!("failed to stat '{}': {}", path.display(), error);
                    continue
                },
            };

            return Some(WalkEntry {
                path: path,
                metadata: metadata,
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {

    use std::fs::File;

    use super::*;

    #[test]
    fn test_walk_dir_empty() {
        let tempdir = tempfile::tempdir().unwrap();

        let iter = std::fs::read_dir(&tempdir).unwrap();
        let mut iter = WalkDir::from_read_dir(iter);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_walk_dir_with_files() {
        let tempdir = tempfile::tempdir().unwrap();
        File::create(tempdir.path().join("abc")).unwrap();
        File::create(tempdir.path().join("def")).unwrap();
        File::create(tempdir.path().join("ghi")).unwrap();

        let iter = std::fs::read_dir(&tempdir).unwrap();

        let mut results = WalkDir::from_read_dir(iter).collect::<Vec<_>>();
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
    fn test_walk_dir_with_dirs() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::create_dir(tempdir.path().join("abc")).unwrap();
        std::fs::create_dir(tempdir.path().join("def")).unwrap();

        let iter = std::fs::read_dir(&tempdir).unwrap();

        let mut results = WalkDir::from_read_dir(iter).collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].path, tempdir.path().join("abc"));
        assert!(results[0].metadata.is_dir());

        assert_eq!(results[1].path, tempdir.path().join("def"));
        assert!(results[1].metadata.is_dir());
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_walk_dir_with_links() {
        let tempdir = tempfile::tempdir().unwrap();
        let source = tempdir.path().join("abc");
        let target = tempdir.path().join("def");

        File::create(&source).unwrap();
        std::os::unix::fs::symlink(&source, &target).unwrap();

        let iter = std::fs::read_dir(&tempdir).unwrap();

        let mut results = WalkDir::from_read_dir(iter).collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].path, source);
        assert!(results[0].metadata.file_type().is_file());

        assert_eq!(results[1].path, target);
        assert!(results[1].metadata.file_type().is_symlink());
    }

    // TODO: The iterator should yield information about the root folder on its
    // first tick.

    #[test]
    fn test_walk_empty() {
        let tempdir = tempfile::tempdir().unwrap();

        let mut iter = walk(&tempdir).unwrap();
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_walk_with_flat_files() {
        let tempdir = tempfile::tempdir().unwrap();
        File::create(tempdir.path().join("abc")).unwrap();
        File::create(tempdir.path().join("def")).unwrap();
        File::create(tempdir.path().join("ghi")).unwrap();

        let mut results = walk(&tempdir).unwrap().collect::<Vec<_>>();
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
    fn test_walk_with_flat_dirs() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::create_dir(tempdir.path().join("abc")).unwrap();
        std::fs::create_dir(tempdir.path().join("def")).unwrap();

        let mut results = walk(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].path, tempdir.path().join("abc"));
        assert!(results[0].metadata.is_dir());

        assert_eq!(results[1].path, tempdir.path().join("def"));
        assert!(results[1].metadata.is_dir());
    }

    #[test]
    fn test_walk_with_nested_dirs() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::create_dir(tempdir.path().join("abc")).unwrap();
        std::fs::create_dir(tempdir.path().join("abc").join("def")).unwrap();


        let mut results = walk(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].path, tempdir.path().join("abc"));
        assert!(results[0].metadata.is_dir());

        assert_eq!(results[1].path, tempdir.path().join("abc").join("def"));
        assert!(results[1].metadata.is_dir());
    }

    #[test]
    fn test_walk_with_deeply_nested_dirs() {
        let tempdir = tempfile::tempdir().unwrap();

        let mut dir = tempdir.path().to_path_buf();
        for _ in 0..512 {
            dir.push("foo");
            std::fs::create_dir(&dir).unwrap();
        }

        let mut results = walk(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 512);

        for entry in results {
            assert!(entry.path.starts_with(&tempdir));
            assert!(entry.path.ends_with("foo"));
            assert!(entry.metadata.is_dir());
        }
    }

    #[test]
    fn test_walk_with_files_inside_dir() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::create_dir(tempdir.path().join("foo")).unwrap();
        File::create(tempdir.path().join("foo").join("abc")).unwrap();
        File::create(tempdir.path().join("foo").join("def")).unwrap();

        let mut results = walk(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 3);

        assert_eq!(results[0].path, tempdir.path().join("foo"));
        assert!(results[0].metadata.is_dir());

        assert_eq!(results[1].path, tempdir.path().join("foo").join("abc"));
        assert!(results[1].metadata.is_file());

        assert_eq!(results[2].path, tempdir.path().join("foo").join("def"));
        assert!(results[1].metadata.is_file());
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_walk_with_dir_symlinks() {
        let tempdir = tempfile::tempdir().unwrap();
        let dir = tempdir.path().join("abc");
        let file = dir.join("def");
        let symlink = tempdir.path().join("ghi");

        std::fs::create_dir(&dir).unwrap();
        File::create(&file).unwrap();
        std::os::unix::fs::symlink(&dir, &symlink).unwrap();

        let mut results = walk(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 3);

        assert_eq!(results[0].path, dir);
        assert!(results[0].metadata.file_type().is_dir());

        assert_eq!(results[1].path, file);
        assert!(results[1].metadata.file_type().is_file());

        assert_eq!(results[2].path, symlink);
        assert!(results[2].metadata.file_type().is_symlink());
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_walk_with_circular_symlinks() {
        let tempdir = tempfile::tempdir().unwrap();
        let dir = tempdir.path().join("foo");
        let symlink = tempdir.path().join("foo").join("bar");

        std::fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink(&dir, &symlink).unwrap();

        let mut results = walk(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].path, dir);
        assert!(results[0].metadata.file_type().is_dir());

        assert_eq!(results[1].path, symlink);
        assert!(results[1].metadata.file_type().is_symlink());
    }

    #[test]
    fn test_walk_with_unicode_names() {
        let tempdir = tempfile::tempdir().unwrap();
        File::create(tempdir.path().join("zażółć gęślą jaźń")).unwrap();

        let mut results = walk(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, tempdir.path().join("zażółć gęślą jaźń"));
    }

    #[test]
    fn test_walk_metadata_size() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::write(tempdir.path().join("foo"), b"123456789").unwrap();

        let mut iter = walk(&tempdir).unwrap();

        let entry = iter.next().unwrap();
        assert_eq!(entry.metadata.len(), 9);

        assert!(iter.next().is_none());
    }
}
