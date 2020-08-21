use std::fs::Metadata;
use std::path::{Path, PathBuf};

use log::warn;

pub fn walk<P: AsRef<Path>>(root: P) -> std::io::Result<Walk> {
    let iter = std::fs::read_dir(root)?;
    Ok(Walk {
        pending: vec!(iter),
    })
}

pub struct Walk {
    // TODO: Add support for stopping at device boundaries.
    pending: Vec<std::fs::ReadDir>,
}

pub struct WalkEntry {
    path: PathBuf,
    metadata: Metadata,
}

impl Walk {

    fn step(&mut self, entry: std::fs::DirEntry) -> Option<WalkEntry> {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                warn!("failed to stat file '{}': {}", path.display(), error);
                return None;
            },
        };

        self.push(&path);

        Some(WalkEntry {
            path: path,
            metadata: metadata,
        })
    }

    fn push(&mut self, path: &Path) {
        match std::fs::read_dir(path) {
            Ok(iter) => {
                self.pending.push(iter);
            },
            Err(error) => {
                warn!("failed to read '{}': {}", path.display(), error);
            },
        }
    }

    fn pop(&mut self) -> Option<std::fs::DirEntry> {
        while let Some(iter) = self.pending.last_mut() {
            for entry in iter {
                match entry {
                    Ok(entry) => return Some(entry),
                    Err(error) => warn!("directory iteration error: {}", error),
                }
            }

            self.pending.pop();
        }

        None
    }
}

impl std::iter::Iterator for Walk {

    type Item = WalkEntry;

    fn next(&mut self) -> Option<WalkEntry> {
        loop {
            let entry = self.pop()?;
            let entry = self.step(entry);
            if entry.is_some() {
                return entry;
            }
        }
    }
}
