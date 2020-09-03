use std::fs::Metadata;
use std::path::{Path, PathBuf};

use log::warn;

pub struct Entry {
    pub path: PathBuf,
    pub metadata: Metadata,
}

pub fn walk_dir<P: AsRef<Path>>(root: P) -> std::io::Result<WalkDir> {
    let metadata = std::fs::symlink_metadata(&root)?;
    let pending = vec!(list_dir(&root)?);

    Ok(WalkDir {
        root: Some(Entry {
            path: root.as_ref().to_path_buf(),
            metadata: metadata,
        }),
        pending: pending,
    })
}

fn list_dir<P: AsRef<Path>>(path: P) -> std::io::Result<ListDir> {
    let iter = std::fs::read_dir(path)?;

    Ok(ListDir {
        iter: iter,
    })
}

pub struct WalkDir {
    // TODO: Add support for stopping at device boundaries.
    root: Option<Entry>,
    pending: Vec<ListDir>,
}

impl WalkDir {

    fn push(&mut self, entry: &Entry) {
        match list_dir(&entry.path) {
            Ok(iter) => {
                self.pending.push(iter);
            },
            Err(error) => {
                warn!("failed to read '{}': {}", entry.path.display(), error);
            },
        }
    }

    fn pop(&mut self) -> Option<Entry> {
        while let Some(iter) = self.pending.last_mut() {
            for entry in iter {
                return Some(entry);
            }

            self.pending.pop();
        }

        None
    }
}

impl std::iter::Iterator for WalkDir {

    type Item = Entry;

    fn next(&mut self) -> Option<Entry> {
        if self.root.is_some() {
            return self.root.take();
        }

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
/// Unlike the `ReadDir` iterator entries, `ListDir` entries are guaranteed to
/// have valid metadata objects attached.
struct ListDir {
    iter: std::fs::ReadDir,
}

impl std::iter::Iterator for ListDir {

    type Item = Entry;

    fn next(&mut self) -> Option<Entry> {
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

            return Some(Entry {
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

    // TODO: Add test case for non-existing directory.

    #[test]
    fn test_list_dir_empty() {
        let tempdir = tempfile::tempdir().unwrap();

        let mut iter = list_dir(&tempdir).unwrap();

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_list_dir_with_files() {
        let tempdir = tempfile::tempdir().unwrap();
        File::create(tempdir.path().join("abc")).unwrap();
        File::create(tempdir.path().join("def")).unwrap();
        File::create(tempdir.path().join("ghi")).unwrap();

        let mut results = list_dir(&tempdir).unwrap().collect::<Vec<_>>();
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
    fn test_list_dir_with_dirs() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::create_dir(tempdir.path().join("abc")).unwrap();
        std::fs::create_dir(tempdir.path().join("def")).unwrap();

        let mut results = list_dir(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].path, tempdir.path().join("abc"));
        assert!(results[0].metadata.is_dir());

        assert_eq!(results[1].path, tempdir.path().join("def"));
        assert!(results[1].metadata.is_dir());
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_list_dir_with_links() {
        let tempdir = tempfile::tempdir().unwrap();
        let source = tempdir.path().join("abc");
        let target = tempdir.path().join("def");

        File::create(&source).unwrap();
        std::os::unix::fs::symlink(&source, &target).unwrap();

        let mut results = list_dir(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].path, source);
        assert!(results[0].metadata.file_type().is_file());

        assert_eq!(results[1].path, target);
        assert!(results[1].metadata.file_type().is_symlink());
    }

    #[test]
    fn test_walk_dir_empty() {
        let tempdir = tempfile::tempdir().unwrap();

        let mut iter = walk_dir(&tempdir).unwrap();

        let entry = iter.next().unwrap();
        assert_eq!(entry.path, tempdir.path());
        assert!(entry.metadata.is_dir());

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_walk_dir_with_flat_files() {
        let tempdir = tempfile::tempdir().unwrap();
        File::create(tempdir.path().join("abc")).unwrap();
        File::create(tempdir.path().join("def")).unwrap();
        File::create(tempdir.path().join("ghi")).unwrap();

        let mut results = walk_dir(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 4);

        assert_eq!(results[0].path, tempdir.path());
        assert!(results[0].metadata.is_dir());

        assert_eq!(results[1].path, tempdir.path().join("abc"));
        assert!(results[1].metadata.is_file());

        assert_eq!(results[2].path, tempdir.path().join("def"));
        assert!(results[2].metadata.is_file());

        assert_eq!(results[3].path, tempdir.path().join("ghi"));
        assert!(results[3].metadata.is_file());
    }

    #[test]
    fn test_walk_dir_with_flat_dirs() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::create_dir(tempdir.path().join("abc")).unwrap();
        std::fs::create_dir(tempdir.path().join("def")).unwrap();

        let mut results = walk_dir(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 3);

        assert_eq!(results[0].path, tempdir.path());
        assert!(results[0].metadata.is_dir());

        assert_eq!(results[1].path, tempdir.path().join("abc"));
        assert!(results[1].metadata.is_dir());

        assert_eq!(results[2].path, tempdir.path().join("def"));
        assert!(results[2].metadata.is_dir());
    }

    #[test]
    fn test_walk_dir_with_nested_dirs() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::create_dir(tempdir.path().join("abc")).unwrap();
        std::fs::create_dir(tempdir.path().join("abc").join("def")).unwrap();

        let mut results = walk_dir(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 3);

        assert_eq!(results[0].path, tempdir.path());
        assert!(results[0].metadata.is_dir());

        assert_eq!(results[1].path, tempdir.path().join("abc"));
        assert!(results[1].metadata.is_dir());

        assert_eq!(results[2].path, tempdir.path().join("abc").join("def"));
        assert!(results[2].metadata.is_dir());
    }

    #[test]
    fn test_walk_dir_with_deeply_nested_dirs() {
        let tempdir = tempfile::tempdir().unwrap();

        let mut dir = tempdir.path().to_path_buf();
        for _ in 0..512 {
            dir.push("foo");
            std::fs::create_dir(&dir).unwrap();
        }

        let mut results = walk_dir(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 513);

        for entry in &results[1..] {
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

        let mut results = walk_dir(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 4);

        assert_eq!(results[0].path, tempdir.path());
        assert!(results[0].metadata.is_dir());

        assert_eq!(results[1].path, tempdir.path().join("foo"));
        assert!(results[1].metadata.is_dir());

        assert_eq!(results[2].path, tempdir.path().join("foo").join("abc"));
        assert!(results[2].metadata.is_file());

        assert_eq!(results[3].path, tempdir.path().join("foo").join("def"));
        assert!(results[3].metadata.is_file());
    }

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

        let mut results = walk_dir(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 4);

        assert_eq!(results[0].path, tempdir.path());
        assert!(results[0].metadata.file_type().is_dir());

        assert_eq!(results[1].path, dir);
        assert!(results[1].metadata.file_type().is_dir());

        assert_eq!(results[2].path, file);
        assert!(results[2].metadata.file_type().is_file());

        assert_eq!(results[3].path, symlink);
        assert!(results[3].metadata.file_type().is_symlink());
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_walk_dir_with_circular_symlinks() {
        let tempdir = tempfile::tempdir().unwrap();
        let dir = tempdir.path().join("foo");
        let symlink = tempdir.path().join("foo").join("bar");

        std::fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink(&dir, &symlink).unwrap();

        let mut results = walk_dir(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 3);

        assert_eq!(results[0].path, tempdir.path());
        assert!(results[0].metadata.file_type().is_dir());

        assert_eq!(results[1].path, dir);
        assert!(results[1].metadata.file_type().is_dir());

        assert_eq!(results[2].path, symlink);
        assert!(results[2].metadata.file_type().is_symlink());
    }

    #[test]
    fn test_walk_dir_with_unicode_names() {
        let tempdir = tempfile::tempdir().unwrap();
        File::create(tempdir.path().join("zażółć gęślą jaźń")).unwrap();

        let mut results = walk_dir(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].path, tempdir.path());
        assert_eq!(results[1].path, tempdir.path().join("zażółć gęślą jaźń"));
    }

    #[test]
    fn test_walk_dir_metadata_size() {
        let tempdir = tempfile::tempdir().unwrap();
        std::fs::write(tempdir.path().join("foo"), b"123456789").unwrap();

        let mut results = walk_dir(&tempdir).unwrap().collect::<Vec<_>>();
        results.sort_by_key(|entry| entry.path.clone());

        assert_eq!(results.len(), 2);
        assert_eq!(results[1].metadata.len(), 9);
    }
}
