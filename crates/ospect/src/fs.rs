// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Filesystem inspection functionalities.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

mod sys {
    #[cfg(target_os = "linux")]
    pub use crate::fs::linux::*;

    #[cfg(target_os = "macos")]
    pub use crate::fs::macos::*;

    #[cfg(target_os = "windows")]
    pub use crate::fs::windows::*;
}

/// An extended attribute of a file.
///
/// On Linux, extended attributes can be obtained using [`getfattr`] and set
/// with [`setfattr`] utilities. On macOS, they can be manipulated through the
/// [`xattr`] utility.
///
/// See the [Wikipedia] article for more details.
///
/// [`getfattr`]: https://man7.org/linux/man-pages/man1/getfattr.1.html
/// [`setfattr`]: https://man7.org/linux/man-pages/man1/setfattr.1.html
/// [`xattr`]: https://ss64.com/osx/xattr.html
///
/// [Wikipedia]: https://en.wikipedia.org/wiki/Extended_file_attributes
#[derive(Debug)]
pub struct ExtAttr {
    /// A name of the extended attribute.
    pub name: OsString,
    /// A value of the extended attribute.
    pub value: Vec<u8>,
}

/// Returns an iterator over [extended attributes] of the specified file.
///
/// In case of a symlink this function returns the extended attributes of the
/// link itself and not the file pointed by it.
///
/// [extended attributes]: crate::fs::ExtAttr
///
/// # Errors
///
/// This function will fail if the specified file does not exist, the process
/// does not have permission to access the file, the operation is not supported
/// by the platform or if any other system error is raised.
///
/// Each iterator element is a result itself and errors are possible e.g. when
/// an attribute has been deleted since it was first listed.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
///
/// let ext_attrs = ospect::fs::ext_attrs(Path::new("/tmp/foo"))
///     .unwrap()
///     .map(Result::unwrap);
///
/// for ext_attr in ext_attrs {
///     let name = ext_attr.name.to_string_lossy();
///     let value = String::from_utf8_lossy(&ext_attr.value);
///     println!("{}: {}", name, value);
/// }
/// ```
pub fn ext_attrs<'p>(path: &'p Path) -> std::io::Result<ExtAttrs<'p>> {
    let names = ext_attr_names(path)?;

    Ok(ExtAttrs {
        path: path.as_ref(),
        names: names.into_iter(),
    })
}

/// Iterator over extended attributes of a file.
///
/// The iterator can be constructed with the [`ext_attrs`] function.
///
/// [`ext_attrs`]: crate::fs::ext_attrs
pub struct ExtAttrs<'p> {
    path: &'p Path,
    names: std::vec::IntoIter<OsString>,
}

impl<'p> Iterator for ExtAttrs<'p> {

    type Item = std::io::Result<ExtAttr>;

    fn next(&mut self) -> Option<std::io::Result<ExtAttr>> {
        let name = self.names.next()?;
        let value = match ext_attr_value(self.path, &name) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };

        Some(Ok(ExtAttr { name, value }))
    }
}

/// Collects names of all extended attributes for the specified file.
///
/// The exact behaviour is system-specific:
///
///   * On Linux it uses the [`llistxattr`] call.
///   * On macOS it uses the [`listxattr`] call.
///   * On Windows there are no extended file attributes and the call fails.
///
/// In case of a symlink this function returns the extended attributes of the
/// link itself and not the file pointed by it.
///
/// [`llistxattr`]: https://man7.org/linux/man-pages/man2/listxattr.2.html
/// [`listxattr`]:https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/listxattr.2.html
///
/// # Errors
///
/// This function will fail if the specified file does not exist, the process
/// does not have permission to access the file, the operation is not supported
/// by the platform or if any other system error is raised.
///
/// # Examples
///
/// ```no_run
/// let names = ospect::fs::ext_attr_names("/tmp/foo")
///     .unwrap();
///
/// println!("{} attributes found", names.len());
/// for name in names {
///     println!("'{}'", name.to_string_lossy());
/// }
/// ```
pub fn ext_attr_names<P>(path: P) -> std::io::Result<Vec<OsString>>
where
    P: AsRef<Path>,
{
    self::sys::ext_attr_names(path)
}

/// Collects value of a file extended attribute with the specified name.
///
/// The exact behaviour is system-specific:
///
///   * On Linux it uses the [`lgetxattr`] call.
///   * On macOS it uses the [`getxattr`] call.
///   * On Windows there are no extended attributes and the call fails.
///
/// In case of a symlink this function returns the extended attributes of the
/// link itself and not the file pointed by it.
///
/// [`lgetxattr`]: https://man7.org/linux/man-pages/man2/getxattr.2.html
/// [`getxattr`]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getxattr.2.html#//apple_ref/doc/man/2/getxattr
///
/// # Errors
///
/// This function will fail if the specified file or the attribute do not exist,
/// the process does not have permission to access the file, the opreation is
/// supported by the platform or if any other system error is raised.
///
/// # Examples
///
/// ```no_run
/// let value = ospect::fs::ext_attr_value("/tmp/foo", "user.bar")
///     .unwrap();
///
/// println!("'user.bar': '{}'", String::from_utf8_lossy(&value));
/// ```
pub fn ext_attr_value<P, S>(path: P, name: S) -> std::io::Result<Vec<u8>>
where
    P: AsRef<Path>,
    S: AsRef<OsStr>
{
    self::sys::ext_attr_value(path, name)
}

/// Information about a mounted filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// Name of the mounted device.
    pub name: String,
    /// Mount point, i.e., where the mounted filesystem is available.
    pub path: std::path::PathBuf,
    /// Type of the mounted filesystem (e.g. `ext4`, `ramfs`, `proc`).
    pub fs_type: String,
}

/// Returns an iterator over mounted filesystems information.
///
/// The exact behaviour is system specific:
///
///   * On Linux it parses `/proc/mounts` entries (or alternatives).
///   * On macOS it uses the [`getmntinfo`][1] call.
///   * On Windows it uses [volume managemend functions][2].
///
/// [1]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getmntinfo.3.html
/// [2]: https://learn.microsoft.com/en-us/windows/win32/fileio/volume-management-functions
pub fn mounts() -> std::io::Result<impl Iterator<Item = std::io::Result<Mount>>> {
    self::sys::mounts()
}

/// Information about a mounted raw filesystem.
#[derive(Debug, PartialEq, Eq)]
pub struct RawDeviceMount {
    /// Path to the raw filesystem image.
    /// e.g. /dev/sda1, /dev/mapper/root, /dev/loop0.
    pub image_path: std::path::PathBuf,
    /// Path to which the raw filesystem is mounted.
    pub mountpoint: std::path::PathBuf,
}

/// Returns the mount that contains the file at the given path.
pub fn get_mount(mounts: &[Mount], path: &Path) -> std::io::Result<Mount> {
    // Note: std::path::absolute does not follow symlinks like std::fs::canonicalize does.
    // It also returns C:\-style paths on windows rather than \\?\C:\-style paths.
    let path: PathBuf = std::path::absolute(path)?;
    mounts
        .iter()
        .cloned()
        .filter_map(|mut m| {
            std::path::absolute(&m.path).ok().map(move |abs_path| {
                m.path = abs_path;
                m
            })
        })
        .filter(|m| path.starts_with(&m.path))
        // Filter out dummy and remote filesystems whose names may start with /.
        .max_by_key(|m| m.path.as_os_str().len())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Failed to locate mount for {path:?}"),
            )
        })
}

pub fn get_raw_device(mounts: &[Mount], path: &Path) -> std::io::Result<RawDeviceMount> {
    let mount = get_mount(mounts, path)?;
    #[cfg(not(target_os = "windows"))]
    {
        // Comprehensive list of raw filesystem types supported by RRG.
        const SUPPORTED_FS_TYPES: &[&str] = &["ext2", "ext3", "ext4", "vfat", "ntfs", "fuseblk"];
        if !SUPPORTED_FS_TYPES.contains(&mount.fs_type.as_ref()) {
            return Err(std::io::Error::other(format!(
                "Unsupported filesystem type: {}",
                mount.fs_type
            )));
        }
        Ok(RawDeviceMount {
            image_path: mount.name.into(),
            mountpoint: mount.path.to_path_buf(),
        })
    }
    #[cfg(target_os = "windows")]
    {
        Ok(RawDeviceMount {
            // The "name" of the mount is the volume GUID path: \\?\Volume{...}\
            // Opening \\?\Volume{...}\ opens the directory.
            // Opening \\?\Volume{...} opens the raw bytes of the volume.
            image_path: mount.name.trim_end_matches('\\').into(),
            mountpoint: mount.path.to_path_buf(),
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn ext_attrs_non_existing() {
        let tempdir = tempfile::tempdir().unwrap();

        assert!(ext_attrs(&tempdir.path().join("foo")).is_err());
    }

    #[cfg(all(target_os = "linux", feature = "test-setfattr"))]
    #[test]
    fn ext_attrs_multiple_values() {
        use crate::fs::linux::tests::setfattr;

        let tempfile = tempfile::NamedTempFile::new().unwrap();
        setfattr(tempfile.path(), "user.abc", b"quux");
        setfattr(tempfile.path(), "user.def", b"norf");

        let mut results = ext_attrs(&tempfile.path()).unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        results.sort_by_key(|attr| attr.name.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].name, "user.abc");
        assert_eq!(results[0].value, b"quux");

        assert_eq!(results[1].name, "user.def");
        assert_eq!(results[1].value, b"norf");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ext_attrs_multiple_values() {
        use crate::fs::macos::tests::xattr;

        let tempfile = tempfile::NamedTempFile::new().unwrap();
        xattr(tempfile.path(), "user.abc", b"quux");
        xattr(tempfile.path(), "user.def", b"norf");

        let mut results = ext_attrs(&tempfile.path()).unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        results.sort_by_key(|attr| attr.name.clone());

        assert_eq!(results.len(), 2);

        assert_eq!(results[0].name, "user.abc");
        assert_eq!(results[0].value, b"quux");

        assert_eq!(results[1].name, "user.def");
        assert_eq!(results[1].value, b"norf");
    }

    #[cfg(all(target_os = "linux", feature = "test-setfattr"))]
    #[test]
    fn ext_attrs_empty_value() {
        use crate::fs::linux::tests::setfattr;

        let tempfile = tempfile::NamedTempFile::new().unwrap();
        setfattr(tempfile.path(), "user.abc", b"");

        let results = ext_attrs(&tempfile.path()).unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        assert_eq!(results.len(), 1);

        assert_eq!(results[0].name, "user.abc");
        assert_eq!(results[0].value, b"");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ext_attrs_empty_value() {
        use crate::fs::macos::tests::xattr;

        let tempfile = tempfile::NamedTempFile::new().unwrap();
        xattr(tempfile.path(), "user.abc", b"");

        let results = ext_attrs(&tempfile.path()).unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        assert_eq!(results.len(), 1);

        assert_eq!(results[0].name, "user.abc");
        assert_eq!(results[0].value, b"");
    }

    #[cfg(all(target_os = "linux", feature = "test-setfattr"))]
    #[test]
    fn ext_attrs_bytes_value() {
        use crate::fs::linux::tests::setfattr;

        let tempfile = tempfile::NamedTempFile::new().unwrap();
        setfattr(tempfile.path(), "user.abc", b"\xff\xfe\xff\xfe\xff");

        let results = ext_attrs(&tempfile.path()).unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        assert_eq!(results.len(), 1);

        assert_eq!(results[0].name, "user.abc");
        assert_eq!(results[0].value, b"\xff\xfe\xff\xfe\xff");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ext_attrs_bytes_value() {
        use crate::fs::macos::tests::xattr;

        let tempfile = tempfile::NamedTempFile::new().unwrap();
        xattr(tempfile.path(), "user.abc", b"\xff\xfe\xff\xfe\xff");

        let results = ext_attrs(&tempfile.path()).unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        assert_eq!(results.len(), 1);

        assert_eq!(results[0].name, "user.abc");
        assert_eq!(results[0].value, b"\xff\xfe\xff\xfe\xff");
    }

    // Ideally, we would like to have tests for symlinks but turns out that it
    // is not possible (at least currently) to have extended attributes on them
    // as the kernel simply does not allow that [1].
    //
    // [1]: https://unix.stackexchange.com/questions/16537/extended-attribute-on-symbolic-link

    #[cfg(target_family = "unix")]
    #[test]
    fn mounts_root_exists() {
        let mut mounts = mounts()
            .unwrap()
            .map(Result::unwrap);

        assert!(mounts.find(|mount| mount.path == Path::new("/")).is_some());
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn mounts_system_drive_exists() {
        let mut mounts = mounts()
            .unwrap()
            .map(Result::unwrap);

        let system_drive = std::env::var_os("SystemDrive")
            .unwrap();

        let mut system_drive_path = std::path::PathBuf::new();
        system_drive_path.push(system_drive);
        system_drive_path.push(std::path::MAIN_SEPARATOR_STR);

        assert! {
            mounts.find(|mount| &mount.path == &system_drive_path).is_some()
        };
    }

    fn get_sample_mounts() -> Vec<Mount> {
        vec![
            Mount {
                name: "sysfs".to_string(),
                path: "/sys".parse().unwrap(),
                fs_type: "sysfs".to_string(),
            },
            Mount {
                name: "proc".to_string(),
                path: "/proc".parse().unwrap(),
                fs_type: "proc".to_string(),
            },
            Mount {
                name: "/dev/mapper/root".to_string(),
                path: "/".parse().unwrap(),
                fs_type: "ext4".to_string(),
            },
            Mount {
                name: "tmpfs".to_string(),
                path: "/dev/shm".parse().unwrap(),
                fs_type: "tmpfs".to_string(),
            },
            Mount {
                name: "/dev/sda2".to_string(),
                path: "/boot".parse().unwrap(),
                fs_type: "ext2".to_string(),
            },
            Mount {
                name: "/dev/sda1".to_string(),
                path: "/boot/efi".parse().unwrap(),
                fs_type: "vfat".to_string(),
            },
            Mount {
                name: "/etc/auto.home.local".to_string(),
                path: "/home".parse().unwrap(),
                fs_type: "autofs".to_string(),
            },
        ]
    }

    #[test]
    fn get_mount_empty() {
        assert_eq!(
            get_mount(&[], "/asdf".as_ref()).err().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn get_mount_linux() {
        use std::os::unix::ffi::OsStrExt;

        let mounts = get_sample_mounts();
        assert_eq!(&get_mount(&mounts, "/".as_ref()).unwrap(), &mounts[2]);
        let root_path = "/foo/bar/baz".as_ref();
        assert_eq!(&get_mount(&mounts, root_path).unwrap(), &mounts[2]);
        let home_path = "/home/foo/bar/baz".as_ref();
        assert_eq!(&get_mount(&mounts, home_path).unwrap(), &mounts[6]);
        assert_eq!(&get_mount(&mounts, "/boot".as_ref()).unwrap(), &mounts[4]);
        let boot_path = std::path::PathBuf::from(OsStr::from_bytes(b"/boot/efi\xff\xff\xff"));
        assert_eq!(&get_mount(&mounts, &boot_path).unwrap(), &mounts[4]);
        let efi_path = "/boot/efi/EFI".as_ref();
        assert_eq!(&get_mount(&mounts, efi_path).unwrap(), &mounts[5]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn get_raw_device_linux() {
        use std::os::unix::ffi::OsStrExt;
        let mounts = get_sample_mounts();
        assert!(
            get_raw_device(&mounts, "/home/foo/bar/baz".as_ref())
                .err()
                .unwrap()
                .kind()
                == std::io::ErrorKind::Other
        );
        let boot_path = std::path::PathBuf::from(OsStr::from_bytes(b"/boot/\xff\xff"));
        assert_eq!(
            get_raw_device(&mounts, &boot_path).unwrap(),
            RawDeviceMount {
                image_path: std::path::PathBuf::from("/dev/sda2"),
                mountpoint: std::path::PathBuf::from("/boot"),
            }
        );
        let root_path = "/".as_ref();
        assert_eq!(
            get_raw_device(&mounts, root_path).unwrap(),
            RawDeviceMount {
                image_path: std::path::PathBuf::from("/dev/mapper/root"),
                mountpoint: std::path::PathBuf::from("/"),
            }
        );
    }
}
