// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Returns an iterator yielding identifiers of all processes on the system.
pub fn ids() -> std::io::Result<impl Iterator<Item = std::io::Result<u32>>> {
    Ids::new()
}

/// A Linux-specific implementation of the iterator over process identifiers.
struct Ids {
    /// An iterator over contents of the `/proc` directory.
    iter: std::fs::ReadDir,
}

impl Ids {

    /// Creates a new iterator over system process identifiers.
    fn new() -> std::io::Result<Ids> {
        let iter = std::fs::read_dir("/proc")?;
        Ok(Ids { iter })
    }
}

impl Iterator for Ids {
    type Item = std::io::Result<u32>;

    fn next(&mut self) -> Option<std::io::Result<u32>> {
        use std::str::FromStr as _;

        for entry in &mut self.iter {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => return Some(Err(error)),
            };

            // Processes are represented by directories, so we should skip all
            // that are not to skip unnecessary parsing. Note that according to
            // the documentation on most Unix platforms this function should not
            // make any additional calls to the operating system, so this check
            // is cheap.
            match entry.file_type() {
                Ok(file_type) if file_type.is_dir() => (),
                _ => continue,
            }

            // Because we are interested only in file names that are integers,
            // we can safely discard any that are not valid Unicode names (which
            // should not be the case in general, as all names within the procfs
            // should only use ASCII).
            let file_name = entry.file_name();
            let file_name_str = match file_name.to_str() {
                Some(file_name_str) => file_name_str,
                None => continue,
            };

            // All directories under `/proc` that are integers should correspond
            // to a process, so they are valid pids. Everything else we can just
            // discard.
            let pid = match u32::from_str(file_name_str) {
                Ok(pid) => pid,
                Err(_) => continue,
            };

            return Some(Ok(pid));
        }

        None

    }
}
