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
        self.push(&entry);
        Some(entry)
    }
}

struct WalkDir {
    iter: std::fs::ReadDir,
}

impl WalkDir {

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
