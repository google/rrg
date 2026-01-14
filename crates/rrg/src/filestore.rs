use std::path::{Path, PathBuf};

pub struct Filestore {
    path: PathBuf,
}

pub struct Part {
    offset: u64,
    content: Vec<u8>,
    file_len: u64,
    file_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    Complete,
    PendingEof,
    PendingPart {
        offset: u64,
        len: u64,
    },
}

pub struct Id {
    flow_id: u64,
    file_id: String,
}

impl std::fmt::Display for Id {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:X}/{}", self.flow_id, self.file_id)
    }
}

impl Filestore {

    pub fn init(path: &Path) -> std::io::Result<Filestore> {
        log::info!("initializing filestore in '{}'", path.display());
        std::fs::create_dir_all(path)?;

        Ok(Filestore {
            path: path.to_path_buf(),
        })
    }

    pub fn store(&self, id: &Id, part: Part) -> std::io::Result<Status> {
        log::info!("storing part at {} for '{}'", part.offset, id);

        let part_path = self.part_path(id, part.offset);
        let part_path_dir = part_path.parent()
            // This should never happen as part path by construction should not
            // be empty and is always placed in some folder.
            .expect("no part path parent");
        std::fs::create_dir_all(part_path_dir)?;
        std::fs::write(&part_path, &part.content)?;

        if part.offset + part.content.len() as u64 == part.file_len {
            log::info!("creating EOF marker for '{}'", id);

            std::fs::write(self.part_path(id, part.file_len), b"")?;
        }

        log::info!("checking stored parts for '{}'", id);

        struct PartMetadata {
            offset: u64,
            len: u64,
        }
        let mut parts = Vec::<PartMetadata>::new();

        for part_entry in std::fs::read_dir(part_path_dir)? {
            let part_entry = part_entry?;

            let offset = part_entry.file_name()
                .into_string().map_err(|string| std::io::Error::new(
                    std::io::ErrorKind::InvalidFilename,
                    format!("not a valid string: {string:?}")
                ))?
                .parse::<u64>().map_err(|error| std::io::Error::new(
                    std::io::ErrorKind::InvalidFilename,
                    error,
                ))?;

            parts.push(PartMetadata {
                offset,
                len: part_entry.metadata()?.len(),
            });
        }

        parts.sort_by_key(|part| part.offset);

        if let Some(part_first) = parts.first() {
            if part_first.offset != 0 {
                return Ok(Status::PendingPart {
                    offset: 0,
                    len: part_first.offset,
                })
            }
        }
        if let Some(part_last) = parts.last() {
            if part_last.len != 0 {
                return Ok(Status::PendingEof);
            }
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no parts",
            ));
        }

        for (part_curr, part_next) in parts.iter().zip(parts.iter().skip(1)) {
            match (part_curr.offset + part_curr.len).cmp(&part_next.offset) {
                std::cmp::Ordering::Equal => (),
                std::cmp::Ordering::Less => return Ok(Status::PendingPart {
                        offset: part_curr.offset + part_curr.len,
                        len: part_curr.offset + part_curr.len - part_curr.offset,
                }),
                std::cmp::Ordering::Greater => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format! {
                            "part [{}; {}) overlaps with [{}; {})",
                            part_curr.offset,
                            part_curr.offset + part_curr.len,
                            part_next.offset,
                            part_next.offset + part_next.len,
                        },
                    ))
                }
            }
        }

        log::info!("merging parts of '{}'", id);

        let file_path = self.file_path(id);
        let file_path_dir = file_path.parent()
            // This should never happen as file path by construction should not
            // be empty and is always placed in some folder.
            .expect("no file path parent");
        std::fs::create_dir_all(file_path_dir)?;

        let mut file = std::fs::File::create_new(&file_path)?;
        for part in parts.iter() {
            let mut part = std::fs::File::open(&self.part_path(id, part.offset))?;
            std::io::copy(&mut part, &mut file)?;
        }

        log::info!("verifying SHA-256 of '{}' content", id);

        use std::io::Seek as _;
        file.seek(std::io::SeekFrom::Start(0))?;

        use sha2::Digest as _;
        let mut sha256 = sha2::Sha256::new();
        std::io::copy(&mut file, &mut sha256)?;
        let sha256 = <[u8; 32]>::from(sha256.finalize());

        if sha256 != part.file_sha256 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format! {
                    "computed digest ({:?}) doesn't match the expected one ({:?})",
                    sha256,
                    part.file_sha256,
                },
            ));
        }

        Ok(Status::Complete)
    }

    pub fn path(&self, id: &Id) -> std::io::Result<PathBuf> {
        let file_path = self.file_path(id);

        let file_metadata = file_path.metadata()?;
        if !file_metadata.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected file type: {:?}", file_metadata.file_type()),
            ));
        }

        Ok(file_path)
    }

    fn file_path(&self, id: &Id) -> PathBuf {
        self.path
            .join("files")
            .join(id.flow_id.to_string())
            .join(&id.file_id)
    }

    fn part_path(&self, id: &Id, offset: u64) -> PathBuf {
        self.path
            .join("parts")
            .join(id.flow_id.to_string())
            .join(&id.file_id)
            .join(offset.to_string())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn single_file_single_part() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path())
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: String::from("foo"),
        };

        assert_eq! {
            filestore.store(&foo_id, Part {
                offset: 0,
                content: b"FOOBARBAZ".to_vec(),
                file_len: b"FOOBARBAZ".len() as u64,
                file_sha256: sha256(b"FOOBARBAZ"),
            }).unwrap(),
            Status::Complete,
        };

        let foo_contents = std::fs::read(filestore.path(&foo_id).unwrap())
            .unwrap();
        assert_eq!(foo_contents, b"FOOBARBAZ");
    }

    #[test]
    fn store_single_file_multiple_parts() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path())
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: String::from("foo"),
        };

        assert_eq! {
            filestore.store(&foo_id, Part {
                offset: 0,
                content: b"FOO".to_vec(),
                file_len: b"FOOBARBAZ".len() as u64,
                file_sha256: sha256(b"FOOBARBAZ"),
            }).unwrap(),
            Status::PendingEof,
        };
        assert_eq! {
            filestore.store(&foo_id, Part {
                offset: b"FOO".len() as u64,
                content: b"BAR".to_vec(),
                file_len: b"FOOBARBAZ".len() as u64,
                file_sha256: sha256(b"FOOBARBAZ"),
            }).unwrap(),
            Status::PendingEof,
        };
        assert_eq! {
            filestore.store(&foo_id, Part {
                offset: b"FOOBAR".len() as u64,
                content: b"BAZ".to_vec(),
                file_len: b"FOOBARBAZ".len() as u64,
                file_sha256: sha256(b"FOOBARBAZ"),
            }).unwrap(),
            Status::Complete,
        };

        let foo_contents = std::fs::read(filestore.path(&foo_id).unwrap())
            .unwrap();
        assert_eq!(foo_contents, b"FOOBARBAZ");
    }

    #[test]
    fn store_single_file_multiple_parts_reverse_order() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path())
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: String::from("foo"),
        };

        assert_eq! {
            filestore.store(&foo_id, Part {
                offset: b"FOOBAR".len() as u64,
                content: b"BAZ".to_vec(),
                file_len: b"FOOBARBAZ".len() as u64,
                file_sha256: sha256(b"FOOBARBAZ"),
            }).unwrap(),
            Status::PendingPart {
                offset: 0,
                len: b"FOOBAR".len() as u64,
            },
        };
        assert_eq! {
            filestore.store(&foo_id, Part {
                offset: b"FOO".len() as u64,
                content: b"BAR".to_vec(),
                file_len: b"FOOBARBAZ".len() as u64,
                file_sha256: sha256(b"FOOBARBAZ"),
            }).unwrap(),
            Status::PendingPart {
                offset: 0,
                len: b"FOO".len() as u64,
            },
        };
        assert_eq! {
            filestore.store(&foo_id, Part {
                offset: 0,
                content: b"FOO".to_vec(),
                file_len: b"FOOBARBAZ".len() as u64,
                file_sha256: sha256(b"FOOBARBAZ"),
            }).unwrap(),
            Status::Complete,
        };

        let foo_contents = std::fs::read(filestore.path(&foo_id).unwrap())
            .unwrap();
        assert_eq!(foo_contents, b"FOOBARBAZ");
    }

    #[test]
    fn store_multiple_files_single_part() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path())
            .unwrap();

        let foobar_id = Id {
            flow_id: 0xf00,
            file_id: String::from("foobar"),
        };
        let foobaz_id = Id {
            flow_id: 0xf00,
            file_id: String::from("foobaz"),
        };
        let quux_id = Id {
            flow_id: 0xc0000c5,
            file_id: String::from("quux"),
        };

        assert_eq! {
            filestore.store(&foobar_id, Part {
                offset: 0,
                content: b"FOOBAR".to_vec(),
                file_len: b"FOOBAR".len() as u64,
                file_sha256: sha256(b"FOOBAR"),
            }).unwrap(),
            Status::Complete,
        };
        assert_eq! {
            filestore.store(&foobaz_id, Part {
                offset: 0,
                content: b"FOOBAZ".to_vec(),
                file_len: b"FOOBAZ".len() as u64,
                file_sha256: sha256(b"FOOBAZ"),
            }).unwrap(),
            Status::Complete,
        };
        assert_eq! {
            filestore.store(&quux_id, Part {
                offset: 0,
                content: b"QUUX".to_vec(),
                file_len: b"QUUX".len() as u64,
                file_sha256: sha256(b"QUUX"),
            }).unwrap(),
            Status::Complete,
        };

        let foobar_contents = std::fs::read(filestore.path(&foobar_id).unwrap())
            .unwrap();
        assert_eq!(foobar_contents, b"FOOBAR");

        let foobaz_contents = std::fs::read(filestore.path(&foobaz_id).unwrap())
            .unwrap();
        assert_eq!(foobaz_contents, b"FOOBAZ");

        let quux_contents = std::fs::read(filestore.path(&quux_id).unwrap())
            .unwrap();
        assert_eq!(quux_contents, b"QUUX");
    }

    #[test]
    fn store_overlapping_parts() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path())
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: String::from("foo"),
        };

        filestore.store(&foo_id, Part {
            offset: 0,
            content: b"FOO".to_vec(),
            file_len: b"FOOBAR".len() as u64,
            file_sha256: sha256(b"FOOBAR"),
        }).unwrap();

        let error = filestore.store(&foo_id, Part {
            offset: 2,
            content: b"OBAR".to_vec(),
            file_len: b"FOOBAR".len() as u64,
            file_sha256: sha256(b"FOOBAR"),
        }).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn store_invalid_sha256() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path())
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: String::from("foo"),
        };

        let error = filestore.store(&foo_id, Part {
            offset: 0,
            content: b"FOO".to_vec(),
            file_len: b"FOO".len() as u64,
            file_sha256: sha256(b"BAR"),
        }).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    fn sha256(content: &[u8]) -> [u8; 32] {
        use sha2::Digest as _;

        let mut sha256 = sha2::Sha256::new();
        sha256.update(content);
        sha256.finalize()
            .into()
    }
}
