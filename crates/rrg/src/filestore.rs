//! Implementation of the on-disk filestore.
//!
//! Filestore is an abstraction over the platform's filesystem that allows for
//! cross-process multi-part file storage, access and automatic cleanup.

use std::path::{Path, PathBuf};
use std::time::{Duration};

/// Initializes the filestore at the specified path with the given file TTL.
///
/// See [`Filestore::init`] for more details as this function is just a shortcut
/// for it.
pub fn init<P>(path: P, ttl: Duration) -> std::io::Result<Filestore>
where
    P: AsRef<Path>,
{
    Filestore::init(path.as_ref(), ttl)
}

/// Part of the file to be stored in the filestore.
///
/// This is used to initialize a larger file out of smaller parts. See the
/// [`Filestore::store`] method for details.
///
/// Parts must form a file within the filestore TTL limit, otherwise they will
/// be deleted.
pub struct Part {
    /// Offset within the file of the content this part consits of.
    pub offset: u64,
    /// Actual content of the file that this part consists of.
    pub content: Vec<u8>,
    /// Total size of the file (in bytes).
    ///
    /// This is used to determined whether we received all the parts of the
    /// file.
    ///
    /// All parts belonging to the same file are expected to use the same total
    /// length value. In case of discrepancies, arbitrary value will be used.
    pub file_len: u64,
    /// SHA-256 digest of the content of the whole file.
    ///
    /// This is used to verify the integrity of the transferred file once all
    /// parts are ready.
    ///
    /// All parts belonging to the same file are expected to have the same
    /// digest. In case of discrepancies, arbitrary value will be used.
    pub file_sha256: [u8; 32],
}

/// Status of a filestore file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    /// All the parts were delivered, the file is ready to be used.
    ///
    /// One can use [`Filestore::path`] to retrieve the filesystem path to the
    /// completed file.
    Complete,
    /// More parts are needed to complete the transfer.
    ///
    /// The `offset` and `len` values are given for arbitrary part of the file
    /// that is still missing.
    Pending {
        offset: u64,
        len: u64,
    },
}

/// Identifier of a filestore file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Id<'s> {
    /// Identifier of the flow which owns the file.
    pub flow_id: u64,
    /// Name of the file.
    ///
    /// This name must be unique within the flow that owns the file.
    pub file_id: &'s str,
}

impl<'s> std::fmt::Display for Id<'s> {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:X}/{}", self.flow_id, self.file_id)
    }
}

/// Handle to a disk-backed filestore.
pub struct Filestore {
    /// Root folder at which the filestore is initialized.
    path: PathBuf,
}

impl Filestore {

    // Here is an overview example of the folder structure and the nomenclature
    // the code below uses to refer to it.
    //
    // ```
    // • root/         | "root dir"
    // └── parts/      | "parts dir"      (pending)
    // │ └── F1A1A1/   | "flow parts dir" (for flow `F1A1A1`)
    // │ │ └── foo/    | "file parts dir" (for file `F1A1A1/foo`)
    // │ │ │ └── 0     | "part"           (for file `F1A1A1/foo` at offset 0)
    // │ │ │ └── 42    | "part"           (for file `F1A1A1/foo` at offset 42)
    // │ │ └── bar/    | "file parts dir" (for file `F1A1A1/bar`)
    // │ │   └── 0     | "part"           (for file `F1A1A1/bar` at offset 0)
    // │ │   └── 314   | "part"           (for file `F1A1A1/bar` at offset 314)
    // │ └── F2B2B2/   | "flow parts dir" (for flow `F2B2B2`)
    // │   └── bar/    | "file parts dir" (for file `F2B2B2/bar`)
    // │     └── 121   | "file parts dir" (for file `F2B2B2/bar` at offset 121)
    // └── files/      | "files dir"      (complete)
    //   └── F1A1A1/   | "flow files dir" (for flow `F1A1A1`)
    //   │ └── quux    | "file"           (for file `F1A1A1/quux`)
    //   │ └── norf    | "file"           (for file `F1A1A1/norf`)
    //   └── F3C3C3/   | "flow files dir" (for flow `F3C3C3`)
    //     └── thud    | "file"           (for file `F3C3C3/thud`)
    // ```

    /// Initializes the filestore at the specified path with the given file TTL.
    ///
    /// This function will cleanup any outdated files, file parts and no longer
    /// needed folders within the filestore.
    ///
    /// # Errors
    ///
    /// This function will return an error if any underlying disk operation can-
    /// not complete. In such cases there is no guarantee about the state of the
    /// the filestore on disk.
    pub fn init(path: &Path, ttl: Duration) -> std::io::Result<Filestore> {
        log::info!("setting up filestore dir in '{}'", path.display());

        let mut root_dir_builder = std::fs::DirBuilder::new();
        root_dir_builder.recursive(true);

        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            root_dir_builder.mode(0o700);
        }

        // TODO: Restrict folder access on Windows.
        //
        // This seems quite involved process that involves wrangling with the
        // Windows API.

        root_dir_builder.create(path)
            .map_err(|error| std::io::Error::new(error.kind(), format! {
                "could not create root dir at '{}': {error}",
                path.display(),
            }))?;

        let filestore = Filestore {
            path: path.to_path_buf(),
        };

        log::info!("cleaning up outdated filestore files");

        filestore.cleanup_files_dir(ttl)
            .map_err(|error| std::io::Error::new(error.kind(), format! {
                "could not clean up files dir: {error}",
            }))?;
        filestore.cleanup_parts_dir(ttl)
            .map_err(|error| std::io::Error::new(error.kind(), format! {
                "could not clean up parts dir: {error}",
            }))?;

        Ok(filestore)
    }

    /// Stores a part of the specified file in the filestore.
    ///
    /// Returns [`Status::Complete`] if the part completed the file from that
    /// were already stored and the file is now ready to be used (one can use
    /// [`Filestore::path`] method to get the path to the stored file).
    ///
    /// Returns [`Status::Pending`] if more parts need to be stored for the file
    /// to be complete.
    ///
    /// # Errors
    ///
    /// This function will return an error if any underlying disk operation
    /// can't complete. In such cases there is no guarantee about the state of
    /// the file on disk and it should not be used again.
    pub fn store(&self, id: Id, part: Part) -> std::io::Result<Status> {
        log::info!("storing part at {} for '{}'", part.offset, id);

        // Note that in the code below we do not attempt to do any cleanup upon
        // error (e.g. by cleaning the parts we failed to fully write or confirm
        // its checksum).
        //
        // There are two reasons for that:
        //
        // 1. There are _a lot_ of places where things can go wrong. Adding some
        //    file or directory deletion code would make the flow really hard to
        //    follow. Moreover, such cleanups can fail themselves and then it is
        //    not obvious what to do. Retry? Leave in inconsistent state?
        //
        // 2. Leaving the files around gives us and users better debugging op-
        //    portunities to investigate what went wrong.
        //
        // Leaving such files is not the end of the world as the filestore has
        // TTL for all the files and thus these will be eventually cleaned any-
        // way. And given we don't really expect these errors to happen (unless
        // something is _really_ wrong), this is more than fine.

        let part_path = self.part_path(id, part.offset);
        let file_parts_dir_path = part_path.parent()
            // This should never happen as part path by construction should not
            // be empty and is always placed in some folder.
            .expect("no part path parent");
        std::fs::create_dir_all(file_parts_dir_path)
            .map_err(|error| std::io::Error::new(error.kind(), format! {
                "could not create file parts dir at '{}': {error}",
                file_parts_dir_path.display(),
            }))?;
        std::fs::write(&part_path, &part.content)
            .map_err(|error| std::io::Error::new(error.kind(), format! {
                "could not write part to '{}': {error}",
                part_path.display(),
             }))?;

        log::info!("checking stored parts for '{}'", id);

        struct PartMetadata {
            offset: u64,
            len: u64,
        }
        let mut parts = Vec::<PartMetadata>::new();

        for part_entry in std::fs::read_dir(file_parts_dir_path)
            .map_err(|error| std::io::Error::new(error.kind(), format! {
                "could not list file parts dir at '{}': {error}",
                file_parts_dir_path.display(),
            }))?
        {
            let part_entry = part_entry?;

            let offset = part_entry.file_name()
                .into_string().map_err(|string| std::io::Error::new(
                    std::io::ErrorKind::InvalidFilename,
                    format! {
                        "malformed part filename string: {string:?}",
                    },
                ))?
                .parse::<u64>().map_err(|error| std::io::Error::new(
                    std::io::ErrorKind::InvalidFilename,
                    format! {
                        "malformed part filename '{}' format: {error}",
                        part_entry.file_name().display(),
                    },
                ))?;

            let part_metadata = part_entry.metadata()
                .map_err(|error| std::io::Error::new(error.kind(), format! {
                    "could not read part metadata at '{}': {error}",
                    part_entry.path().display(),
                }))?;

            if offset.checked_add(part_metadata.len()).is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format! {
                        "offset {} too big for content of length {} for part at '{}'",
                        offset,
                        part_metadata.len(),
                        part_entry.path().display(),
                    },
                ));
            }

            parts.push(PartMetadata {
                offset,
                len: part_metadata.len(),
            });
        }

        // This can theoretically happen if for whatever reason a part that we
        // written in this call got deleted by the time we listed the folder
        // with parts.
        if parts.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no parts",
            ));
        }

        // There is no guarantee about the order in which the filesystem will
        // yield part entries, so we need to sort them ourselves for checking
        // completeness.
        parts.sort_by_key(|part| part.offset);

        let part_first = parts.first()
            // This should never happen as we verified `parts` length above.
            .expect("no parts");
        if part_first.offset != 0 {
            return Ok(Status::Pending {
                offset: 0,
                len: part_first.offset,
            })
        }

        for (part_curr, part_next) in parts.iter().zip(parts.iter().skip(1)) {
            match (part_curr.offset + part_curr.len).cmp(&part_next.offset) {
                std::cmp::Ordering::Equal => (),
                std::cmp::Ordering::Less => return Ok(Status::Pending {
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

        let part_last = parts.last()
            // This should never happen as we verified `parts` length above.
            .expect("no parts");
        match (part_last.offset + part_last.len).cmp(&part.file_len) {
            std::cmp::Ordering::Equal => (),
            std::cmp::Ordering::Less => return Ok(Status::Pending {
                offset: part_last.offset + part_last.len,
                len: part.file_len - (part_last.offset + part_last.len),
            }),
            std::cmp::Ordering::Greater => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format! {
                    "part [{}; {}) exceedes file length ({})",
                    part_last.offset,
                    part_last.offset + part_last.len,
                    part.file_len,
                },
            )),
        }

        log::info!("merging parts of '{}'", id);

        let file_path = self.file_path(id);
        let flow_files_dir_path = file_path.parent()
            // This should never happen as file path by construction should not
            // be empty and is always placed in some folder.
            .expect("no file path parent");
        std::fs::create_dir_all(flow_files_dir_path)
            .map_err(|error| std::io::Error::new(error.kind(), format! {
                "could not create flow files dir at '{}': {error}",
                flow_files_dir_path.display(),
            }))?;

        let mut file = std::fs::File::create_new(&file_path)
            .map_err(|error| std::io::Error::new(error.kind(), format! {
                "could not create file at '{}': {error}",
                file_path.display(),
            }))?;

        for part in parts.iter() {
            let part_offset = part.offset;

            let mut part = std::fs::File::open(&self.part_path(id, part_offset))
                .map_err(|error| std::io::Error::new(error.kind(), format! {
                    "could not open part at '{}': {error}",
                    self.part_path(id, part.offset).display(),
                }))?;

            std::io::copy(&mut part, &mut file)
                .map_err(|error| std::io::Error::new(error.kind(), format! {
                    "could not copy part at '{}' to file at '{}': {error}",
                    self.part_path(id, part_offset).display(),
                    file_path.display(),
                }))?;
        }

        log::info!("verifying SHA-256 of '{}' content", id);

        use std::io::Seek as _;
        file.seek(std::io::SeekFrom::Start(0))
            .map_err(|error| std::io::Error::new(error.kind(), format! {
                "could not seek file at '{}' for SHA-256 verification: {error}",
                file_path.display(),
            }))?;

        use sha2::Digest as _;
        let mut sha256 = sha2::Sha256::new();
        std::io::copy(&mut file, &mut sha256)
            .map_err(|error| std::io::Error::new(error.kind(), format! {
                "could not read file at '{}' for SHA-256 verification: {error}",
                file_path.display(),
            }))?;
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

        log::info!("deleting merged parts of '{}'", id);
        std::fs::remove_dir_all(file_parts_dir_path)
            .map_err(|error| std::io::Error::new(error.kind(), format! {
                "could not delete merged parts at '{}': {error}",
                file_parts_dir_path.display(),
            }))?;

        Ok(Status::Complete)
    }

    /// Deletes the specified file from the filestore.
    ///
    /// The file must be complete in order to be deleted (file parts cannot be
    /// removed).
    ///
    /// # Errors
    ///
    /// This function will return an error if any underlying disk operation
    /// can't complete. In such cases there is no guarantee about the state of
    /// the file on disk and it should not be used again.
    pub fn delete(&self, id: Id) -> std::io::Result<()> {
        std::fs::remove_file(self.file_path(id))
            .map_err(|error| std::io::Error::new(error.kind(), format! {
                "could not delete file at '{}': {error}",
                self.file_path(id).display(),
            }))?;

        Ok(())
    }

    /// Returns an absolute filesystem path to the specified file.
    ///
    /// The file must be complete in order to be accessed (file parts cannot be
    /// accessed in any way).
    ///
    /// # Errors
    ///
    /// This function will return an error if any underlying disk operation
    /// can't complete. In such cases there is no guarantee about the state of
    /// the file on disk and it should not be used again.
    pub fn path(&self, id: Id) -> std::io::Result<PathBuf> {
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

    fn cleanup_files_dir(&self, ttl: Duration) -> std::io::Result<()> {
        match std::fs::read_dir(self.path.join("files")) {
            Ok(flow_files_dir_entries) => {
                for flow_file_dir_entry in flow_files_dir_entries {
                    let flow_files_dir_entry = flow_file_dir_entry
                        .map_err(|error| std::io::Error::new(error.kind(), format! {
                            "could not read flow files dir entry for '{}': {error}",
                            self.path.join("files").display(),
                        }))?;
                    let flow_files_dir_path = flow_files_dir_entry.path();

                    for file_entry in std::fs::read_dir(&flow_files_dir_path)
                        .map_err(|error| std::io::Error::new(error.kind(), format! {
                            "could not list flow files dir at '{}': {error}",
                            flow_files_dir_path.display(),
                        }))?
                    {
                        let file_entry = file_entry
                            .map_err(|error| std::io::Error::new(error.kind(), format! {
                                "could not read file entry for '{}': {error}",
                                flow_files_dir_path.display(),
                            }))?;
                        let file_path = file_entry.path();

                        if crate::fs::remove_file_if_old(&file_path, ttl)
                            .map_err(|error| std::io::Error::new(error.kind(), format! {
                                "could not clean up file at '{}': {error}",
                                file_path.display(),
                            }))?
                        {
                            log::info!("deleted outdated file '{}'", file_path.display());
                        }
                    }

                    // We also clean empty file and part directories. That can
                    // happen after a file or parts were deleted (be it by an
                    // explicit deletion or by them reaching their TTL).
                    //
                    // It is not strictly necessary but we don't want to pollute
                    // the filesystem without a reason.
                    if crate::fs::remove_dir_if_empty(&flow_files_dir_path)
                        .map_err(|error| std::io::Error::new(error.kind(), format! {
                            "could not clean up flow files dir at '{}': {error}",
                            flow_files_dir_path.display(),
                        }))?
                    {
                        log::info!("deleted empty flow files dir '{}'", flow_files_dir_path.display());
                    }
                }
            }
            // This is fine, files folder might not exist if the filestore was
            // never used to store a file.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(std::io::Error::new(error.kind(), format! {
                "could not read files dir at '{}': {error}",
                self.path.join("files").display(),
            })),
        }

        Ok(())
    }

    fn cleanup_parts_dir(&self, ttl: Duration) -> std::io::Result<()> {
        match std::fs::read_dir(self.path.join("parts")) {
            Ok(flow_parts_dir_entries) => {
                for flow_parts_dir_entry in flow_parts_dir_entries {
                    let flow_parts_dir_entry = flow_parts_dir_entry
                        .map_err(|error| std::io::Error::new(error.kind(), format! {
                            "could not read flow parts dir entry for '{}': {error}",
                            self.path.join("parts").display(),
                        }))?;
                    let flow_parts_dir_path = flow_parts_dir_entry.path();

                    for file_parts_dir_entry in std::fs::read_dir(&flow_parts_dir_path)
                        .map_err(|error| std::io::Error::new(error.kind(), format! {
                            "could not list flow parts dir at '{}': {error}",
                            flow_parts_dir_path.display(),
                        }))?
                    {
                        let file_parts_dir_entry = file_parts_dir_entry
                            .map_err(|error| std::io::Error::new(error.kind(), format! {
                                "could not read file parts dir entry for '{}': {error}",
                                flow_parts_dir_path.display(),
                            }))?;
                        let file_parts_dir_path = file_parts_dir_entry.path();

                        for part_entry in std::fs::read_dir(&file_parts_dir_path)
                            .map_err(|error| std::io::Error::new(error.kind(), format! {
                                "could not list file parts dir at '{}': {error}",
                                file_parts_dir_path.display(),
                            }))?
                        {
                            let part_entry = part_entry
                                .map_err(|error| std::io::Error::new(error.kind(), format! {
                                    "could not read part entry for '{}': {error}",
                                    file_parts_dir_path.display(),
                                }))?;
                            let part_path = part_entry.path();

                            if crate::fs::remove_file_if_old(&part_path, ttl)
                                .map_err(|error| std::io::Error::new(error.kind(), format! {
                                    "could not clean up part at '{}': {error}",
                                    part_path.display(),
                                }))?
                            {
                                log::info!("deleted outdated part '{}'", part_path.display());
                            }
                        }

                        // See similar code for files folder cleanup above for
                        // the rationale.
                        if crate::fs::remove_dir_if_empty(&file_parts_dir_path)
                            .map_err(|error| std::io::Error::new(error.kind(), format! {
                                "could not clean up file parts dir at '{}': {error}",
                                file_parts_dir_path.display(),
                            }))?
                        {
                            log::info!("deleted empty file parts dir '{}'", file_parts_dir_path.display());
                        }
                    }

                    // See similar code for files folder cleanup above for the
                    // rationale.
                    if crate::fs::remove_dir_if_empty(&flow_parts_dir_path)
                        .map_err(|error| std::io::Error::new(error.kind(), format! {
                            "could not clean up flow parts dir at '{}': {error}",
                            flow_parts_dir_path.display(),
                        }))?
                    {
                        log::info!("deleted empty flow parts dir '{}'", flow_parts_dir_path.display());
                    }
                }
            }
            // This is fine, parts folder might not exist if the filestore was
            // never used to store a part.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(std::io::Error::new(error.kind(), format! {
                "could not read parts dir at '{}': {error}",
                self.path.join("parts").display(),
            })),
        }

        Ok(())
    }

    fn file_path(&self, id: Id) -> PathBuf {
        self.path
            .join("files")
            .join(id.flow_id.to_string())
            .join(&id.file_id)
    }

    fn part_path(&self, id: Id, offset: u64) -> PathBuf {
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
    fn init_non_existent() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        Filestore::init(&tempdir.path().join("i_did_not_exist_before"), Duration::MAX)
            .unwrap();
    }

    #[test]
    fn init_twice() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();
        Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();
    }

    #[test]
    fn init_cleanup_empty() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: "foo",
        };

        filestore.store(foo_id, Part {
            offset: 0,
            content: b"FOOBAR".to_vec(),
            file_len: b"FOOBAR".len() as u64,
            file_sha256: sha256(b"FOOBAR"),
        }).unwrap();
        filestore.delete(foo_id).unwrap();

        Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let files_entries = std::fs::read_dir(tempdir.path().join("files"))
            .unwrap();
        assert_eq!(files_entries.count(), 0);

        let parts_entries = std::fs::read_dir(tempdir.path().join("parts"))
            .unwrap();
        assert_eq!(parts_entries.count(), 0);
    }

    #[test]
    fn init_cleanup_outdated_files() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: "foo",
        };

        filestore.store(foo_id, Part {
            offset: 0,
            content: b"FOOBAR".to_vec(),
            file_len: b"FOOBAR".len() as u64,
            file_sha256: sha256(b"FOOBAR"),
        }).unwrap();

        let files_entries = std::fs::read_dir(tempdir.path().join("files"))
            .unwrap();
        assert_eq!(files_entries.count(), 1);

        // We initialize with a TTL of 0 which effectively means that all files
        // are outdated.
        Filestore::init(tempdir.path(), Duration::ZERO)
            .unwrap();

        let files_entries = std::fs::read_dir(tempdir.path().join("files"))
            .unwrap();
        assert_eq!(files_entries.count(), 0);
    }

    #[test]
    fn init_cleanup_outdated_parts() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: "foo",
        };

        filestore.store(foo_id, Part {
            offset: 0,
            content: b"FOO".to_vec(),
            file_len: b"FOOBAR".len() as u64,
            file_sha256: sha256(b"FOOBAR"),
        }).unwrap();

        let parts_entries = std::fs::read_dir(tempdir.path().join("parts"))
            .unwrap();
        assert_eq!(parts_entries.count(), 1);

        // We initialize with a TTL of 0 which effectively means that all parts
        // are outdated.
        Filestore::init(tempdir.path(), Duration::ZERO)
            .unwrap();

        let parts_entries = std::fs::read_dir(tempdir.path().join("parts"))
            .unwrap();
        assert_eq!(parts_entries.count(), 0);
    }

    #[test]
    fn store_single_file_single_part() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: "foo",
        };

        assert_eq! {
            filestore.store(foo_id, Part {
                offset: 0,
                content: b"FOOBARBAZ".to_vec(),
                file_len: b"FOOBARBAZ".len() as u64,
                file_sha256: sha256(b"FOOBARBAZ"),
            }).unwrap(),
            Status::Complete,
        };

        let foo_contents = std::fs::read(filestore.path(foo_id).unwrap())
            .unwrap();
        assert_eq!(foo_contents, b"FOOBARBAZ");
    }

    #[test]
    fn store_single_file_single_part_empty() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: "foo",
        };

        assert_eq! {
            filestore.store(foo_id, Part {
                offset: 0,
                content: b"".to_vec(),
                file_len: 0,
                file_sha256: sha256(b""),
            }).unwrap(),
            Status::Complete,
        };

        let foo_contents = std::fs::read(filestore.path(foo_id).unwrap())
            .unwrap();
        assert_eq!(foo_contents, b"");
    }

    #[test]
    fn store_single_file_multiple_parts() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: "foo",
        };

        assert_eq! {
            filestore.store(foo_id, Part {
                offset: 0,
                content: b"FOO".to_vec(),
                file_len: b"FOOBARBAZ".len() as u64,
                file_sha256: sha256(b"FOOBARBAZ"),
            }).unwrap(),
            Status::Pending {
                offset: b"FOO".len() as u64,
                len: b"BARBAZ".len() as u64,
            },
        };
        assert_eq! {
            filestore.store(foo_id, Part {
                offset: b"FOO".len() as u64,
                content: b"BAR".to_vec(),
                file_len: b"FOOBARBAZ".len() as u64,
                file_sha256: sha256(b"FOOBARBAZ"),
            }).unwrap(),
            Status::Pending {
                offset: b"FOOBAR".len() as u64,
                len: b"BAZ".len() as u64,
            },
        };
        assert_eq! {
            filestore.store(foo_id, Part {
                offset: b"FOOBAR".len() as u64,
                content: b"BAZ".to_vec(),
                file_len: b"FOOBARBAZ".len() as u64,
                file_sha256: sha256(b"FOOBARBAZ"),
            }).unwrap(),
            Status::Complete,
        };

        let foo_contents = std::fs::read(filestore.path(foo_id).unwrap())
            .unwrap();
        assert_eq!(foo_contents, b"FOOBARBAZ");
    }

    #[test]
    fn store_single_file_multiple_parts_reverse_order() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: "foo",
        };

        assert_eq! {
            filestore.store(foo_id, Part {
                offset: b"FOOBAR".len() as u64,
                content: b"BAZ".to_vec(),
                file_len: b"FOOBARBAZ".len() as u64,
                file_sha256: sha256(b"FOOBARBAZ"),
            }).unwrap(),
            Status::Pending {
                offset: 0,
                len: b"FOOBAR".len() as u64,
            },
        };
        assert_eq! {
            filestore.store(foo_id, Part {
                offset: b"FOO".len() as u64,
                content: b"BAR".to_vec(),
                file_len: b"FOOBARBAZ".len() as u64,
                file_sha256: sha256(b"FOOBARBAZ"),
            }).unwrap(),
            Status::Pending {
                offset: 0,
                len: b"FOO".len() as u64,
            },
        };
        assert_eq! {
            filestore.store(foo_id, Part {
                offset: 0,
                content: b"FOO".to_vec(),
                file_len: b"FOOBARBAZ".len() as u64,
                file_sha256: sha256(b"FOOBARBAZ"),
            }).unwrap(),
            Status::Complete,
        };

        let foo_contents = std::fs::read(filestore.path(foo_id).unwrap())
            .unwrap();
        assert_eq!(foo_contents, b"FOOBARBAZ");
    }

    #[test]
    fn store_single_file_multiple_parts_empty() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: "foo",
        };

        assert_eq! {
            filestore.store(foo_id, Part {
                offset: 0,
                content: b"FOO".to_vec(),
                file_len: b"FOOBAR".len() as u64,
                file_sha256: sha256(b"FOO"),
            }).unwrap(),
            Status::Pending {
                offset: b"FOO".len() as u64,
                len: b"BAR".len() as u64,
            },
        };
        assert_eq! {
            filestore.store(foo_id, Part {
                offset: b"FOO".len() as u64,
                content: b"".to_vec(),
                file_len: b"FOOBAR".len() as u64,
                file_sha256: sha256(b"FOOBAR"),
            }).unwrap(),
            Status::Pending {
                offset: b"FOO".len() as u64,
                len: b"BAR".len() as u64,
            },
        };
        assert_eq! {
            filestore.store(foo_id, Part {
                offset: b"FOO".len() as u64,
                content: b"BAR".to_vec(),
                file_len: b"FOOBAR".len() as u64,
                file_sha256: sha256(b"FOOBAR"),
            }).unwrap(),
            Status::Complete,
        };

        let foo_contents = std::fs::read(filestore.path(foo_id).unwrap())
            .unwrap();
        assert_eq!(foo_contents, b"FOOBAR");
    }

    #[test]
    fn store_multiple_files_single_part() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foobar_id = Id {
            flow_id: 0xf00,
            file_id: "foobar",
        };
        let foobaz_id = Id {
            flow_id: 0xf00,
            file_id: "foobaz",
        };
        let quux_id = Id {
            flow_id: 0xc0000c5,
            file_id: "quux",
        };

        assert_eq! {
            filestore.store(foobar_id, Part {
                offset: 0,
                content: b"FOOBAR".to_vec(),
                file_len: b"FOOBAR".len() as u64,
                file_sha256: sha256(b"FOOBAR"),
            }).unwrap(),
            Status::Complete,
        };
        assert_eq! {
            filestore.store(foobaz_id, Part {
                offset: 0,
                content: b"FOOBAZ".to_vec(),
                file_len: b"FOOBAZ".len() as u64,
                file_sha256: sha256(b"FOOBAZ"),
            }).unwrap(),
            Status::Complete,
        };
        assert_eq! {
            filestore.store(quux_id, Part {
                offset: 0,
                content: b"QUUX".to_vec(),
                file_len: b"QUUX".len() as u64,
                file_sha256: sha256(b"QUUX"),
            }).unwrap(),
            Status::Complete,
        };

        let foobar_contents = std::fs::read(filestore.path(foobar_id).unwrap())
            .unwrap();
        assert_eq!(foobar_contents, b"FOOBAR");

        let foobaz_contents = std::fs::read(filestore.path(foobaz_id).unwrap())
            .unwrap();
        assert_eq!(foobaz_contents, b"FOOBAZ");

        let quux_contents = std::fs::read(filestore.path(quux_id).unwrap())
            .unwrap();
        assert_eq!(quux_contents, b"QUUX");
    }

    #[test]
    fn store_overlapping_parts() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: "foo",
        };

        filestore.store(foo_id, Part {
            offset: 0,
            content: b"FOO".to_vec(),
            file_len: b"FOOBAR".len() as u64,
            file_sha256: sha256(b"FOOBAR"),
        }).unwrap();

        let error = filestore.store(foo_id, Part {
            offset: 2,
            content: b"OBAR".to_vec(),
            file_len: b"FOOBAR".len() as u64,
            file_sha256: sha256(b"FOOBAR"),
        }).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn store_offset_overflow() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: "foo",
        };

        let error = filestore.store(foo_id, Part {
            offset: 18_446_744_073_709_551_600,
            content: vec![0xf0; 1337],
            file_len: b"FOOBAR".len() as u64,
            file_sha256: sha256(b"FOOBAR"),
        }).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn store_file_len_underflow() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: "foo",
        };

        let error = filestore.store(foo_id, Part {
            offset: 0,
            content: b"FOOBAR".to_vec(),
            file_len: b"FOO".len() as u64,
            file_sha256: sha256(b"FOO"),
        }).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn store_invalid_sha256() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: "foo",
        };

        let error = filestore.store(foo_id, Part {
            offset: 0,
            content: b"FOO".to_vec(),
            file_len: b"FOO".len() as u64,
            file_sha256: sha256(b"BAR"),
        }).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn delete_single_file() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: "foo",
        };

        filestore.store(foo_id, Part {
            offset: 0,
            content: b"FOOBAR".to_vec(),
            file_len: b"FOOBAR".len() as u64,
            file_sha256: sha256(b"FOOBAR"),
        }).unwrap();

        assert!(filestore.delete(foo_id).is_ok());

        let error = filestore.path(foo_id).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn delete_non_existent() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        let filestore = Filestore::init(tempdir.path(), Duration::MAX)
            .unwrap();

        let foo_id = Id {
            flow_id: 0xf00,
            file_id: "foo",
        };

        let error = filestore.delete(foo_id).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    fn sha256(content: &[u8]) -> [u8; 32] {
        use sha2::Digest as _;

        let mut sha256 = sha2::Sha256::new();
        sha256.update(content);
        sha256.finalize()
            .into()
    }
}
