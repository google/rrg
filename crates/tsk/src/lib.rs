use core::panic;
// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::cell::RefCell;
use std::ffi::{c_char, c_void};
use std::marker::PhantomData;
use std::ptr::{NonNull, null_mut};
use std::{ffi::CStr, path::Path};

use tsk_sys::{
    TSK_FS_TYPE_ENUM_TSK_FS_TYPE_DETECT, tsk_fs_dir_open, tsk_fs_dir_open_meta, tsk_fs_file_open,
};

pub fn get_tsk_version() -> String {
    // SAFETY: TSK returns a pointer to a static string.
    let cstr = unsafe { CStr::from_ptr(tsk_sys::tsk_version_get_str()) };
    String::from_utf8_lossy(cstr.to_bytes()).to_string()
}

#[derive(Debug)]
pub struct TskError {
    message: String,
}

impl std::fmt::Display for TskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for TskError {}

pub type TskResult<T> = Result<T, TskError>;

/// Path suitable for passing to libTSK functions that deal with paths embedded
/// inside filesystem images.
struct TskPath {
    path: Vec<u8>,
}

impl TskPath {
    #[cfg(target_family = "unix")]
    fn from_path(path: &Path) -> Self {
        use std::os::unix::ffi::OsStrExt as _;
        let mut path: Vec<u8> = path.as_os_str().as_bytes().to_vec();
        path.push(0);
        Self { path }
    }

    #[cfg(target_os = "windows")]
    fn from_path(path: &Path) -> Self {
        let path: Vec<u8> = path
            .to_string_lossy()
            .as_bytes()
            .into_iter()
            .copied()
            .chain(Some(0))
            .collect();
        Self { path }
    }

    fn as_ptr(&self) -> *const c_char {
        self.path.as_ptr().cast()
    }
}

fn try_get_tsk_error() -> TskError {
    let message_ptr = unsafe { tsk_sys::tsk_error_get() };
    if message_ptr.is_null() {
        return TskError {
            message: String::from("unknown"),
        };
    }
    let message = unsafe { CStr::from_ptr(message_ptr) }
        .to_string_lossy()
        .to_string();
    TskError { message }
}

fn get_tsk_result<T>(result: *mut T) -> Result<NonNull<T>, TskError> {
    NonNull::new(result).ok_or_else(try_get_tsk_error)
}

pub struct TskImage {
    pub(crate) inner: NonNull<tsk_sys::TSK_IMG_INFO>,
}

impl TskImage {
    pub fn open(path: &Path) -> TskResult<Self> {
        let path = {
            #[cfg(target_family = "unix")]
            {
                use std::os::unix::ffi::OsStrExt as _;
                let mut path: Vec<c_char> = path
                    .as_os_str()
                    .as_bytes()
                    .iter()
                    .copied()
                    .map(|c| c as c_char)
                    .collect();
                path.push(0);
                path
            }
            #[cfg(target_family = "windows")]
            {
                use std::os::windows::ffi::OsStrExt as _;
                path.as_os_str()
                    .encode_wide()
                    .chain(Some(0))
                    .collect::<Vec<u16>>()
            }
        };
        let tsk_img_result = unsafe {
            tsk_sys::tsk_img_open_sing(
                path.as_ptr(),
                tsk_sys::TSK_IMG_TYPE_ENUM_TSK_IMG_TYPE_RAW_SING,
                0,
            )
        };
        get_tsk_result(tsk_img_result).map(|inner| Self { inner })
    }

    pub fn open_fs(&self) -> TskResult<TskFs> {
        let tsk_fs_result = unsafe {
            tsk_sys::tsk_fs_open_img(self.inner.as_ptr(), 0, TSK_FS_TYPE_ENUM_TSK_FS_TYPE_DETECT)
        };
        get_tsk_result(tsk_fs_result).map(|inner| TskFs {
            inner,
            _marker: PhantomData,
        })
    }
}

impl Drop for TskImage {
    fn drop(&mut self) {
        unsafe { tsk_sys::tsk_img_close(self.inner.as_mut()) };
    }
}

pub struct TskFs<'a> {
    pub(crate) inner: NonNull<tsk_sys::TSK_FS_INFO>,
    _marker: PhantomData<&'a tsk_sys::TSK_FS_INFO>,
}

pub enum WalkDirCallbackResult {
    /// Continue walking.
    Continue,
    /// Stop walking.
    Stop,
}

impl TskFs<'_> {
    pub fn root_inum(&self) -> u64 {
        unsafe { self.inner.as_ref() }.root_inum
    }
    /// Returns the string name of a file system type id, e.g. "ntfs".
    pub fn get_fs_type(&self) -> TskResult<String> {
        let ty = unsafe { self.inner.as_ref().ftype };
        let name_ptr = unsafe { tsk_sys::tsk_fs_type_toname(ty) };
        get_tsk_result(name_ptr as _)
            .map(|non_null| unsafe { CStr::from_ptr(non_null.as_ptr()).to_bytes() })
            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
    }

    /// Opens a directory given its path.
    pub fn open_dir(&self, path: &Path) -> TskResult<TskFsDir> {
        let tsk_path = TskPath::from_path(path);
        let result = unsafe { tsk_fs_dir_open(self.inner.as_ptr(), tsk_path.as_ptr()) };
        get_tsk_result(result as _).map(TskFsDir::new)
    }

    /// Opens a file given its metadata address.
    pub fn open_dir_meta(&self, meta: u64) -> TskResult<TskFsDir> {
        let result = unsafe { tsk_fs_dir_open_meta(self.inner.as_ptr(), meta) };
        get_tsk_result(result as _).map(TskFsDir::new)
    }

    /// Opens a file given its path.
    pub fn open_file(&self, path: &Path) -> TskResult<TskFsFile> {
        let tsk_path = TskPath::from_path(path);
        let result =
            unsafe { tsk_fs_file_open(self.inner.as_ptr(), null_mut(), tsk_path.as_ptr()) };
        get_tsk_result(result as _).map(TskFsFile::new)
    }

    /// Recursively walks the directory with the given metadata address. Calls
    /// `callback` for each file and directory.
    pub fn walk_dir(
        &mut self,
        dir_addr: u64,
        mut callback: impl FnMut(TskFsFile, &[u8]) -> WalkDirCallbackResult,
    ) -> TskResult<()> {
        // References to trait objects are "fat" and cannot be passed as
        // raw pointers.
        #[allow(clippy::complexity)]
        let refcell: RefCell<&mut dyn FnMut(TskFsFile, &[u8]) -> WalkDirCallbackResult> =
            RefCell::new(&mut callback);

        unsafe extern "C" fn c_callback(
            file: *mut tsk_sys::TSK_FS_FILE,
            path: *const c_char,
            ptr: *mut c_void,
        ) -> tsk_sys::TSK_WALK_RET_ENUM {
            let file =
                TskFsFile::new(NonNull::new(file).expect("null file passed in walk_dir callback"));
            let path =
                NonNull::new(path as *mut _).expect("null path passed into walk_dir callback");
            let path: &[u8] = unsafe { CStr::from_ptr(path.as_ptr()).to_bytes() };
            let callback_ptr =
                ptr as *const RefCell<&mut dyn FnMut(TskFsFile, &[u8]) -> WalkDirCallbackResult>;
            let mut callback = unsafe { callback_ptr.as_ref() }
                .expect("null ptr passed to tsk_fs_dir_walk callback")
                .borrow_mut();
            match callback(file, path) {
                WalkDirCallbackResult::Continue => tsk_sys::TSK_WALK_RET_ENUM_TSK_WALK_CONT,
                WalkDirCallbackResult::Stop => tsk_sys::TSK_WALK_RET_ENUM_TSK_WALK_STOP,
            }
        }

        let flags = tsk_sys::TSK_FS_DIR_WALK_FLAG_ENUM_TSK_FS_DIR_WALK_FLAG_RECURSE
            | tsk_sys::TSK_FS_DIR_WALK_FLAG_ENUM_TSK_FS_DIR_WALK_FLAG_UNALLOC
            | tsk_sys::TSK_FS_DIR_WALK_FLAG_ENUM_TSK_FS_DIR_WALK_FLAG_ALLOC;
        // Returns 1 on error and 0 on success.
        let result = unsafe {
            tsk_sys::tsk_fs_dir_walk(
                self.inner.as_ptr(),
                dir_addr,
                flags,
                Some(c_callback),
                (&refcell) as *const _ as *mut c_void,
            )
        };
        (result == 0).then_some(()).ok_or_else(try_get_tsk_error)
    }
}

impl Drop for TskFs<'_> {
    fn drop(&mut self) {
        unsafe { tsk_sys::tsk_fs_close(self.inner.as_mut()) };
    }
}

pub struct TskFsDir<'a> {
    inner: NonNull<tsk_sys::TSK_FS_DIR>,
    _marker: PhantomData<&'a tsk_sys::TSK_FS_DIR>,
}

impl<'a> TskFsDir<'a> {
    fn new(inner: NonNull<tsk_sys::TSK_FS_DIR>) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
    pub fn addr(&self) -> u64 {
        unsafe { self.inner.as_ref() }.addr
    }
    pub fn get_file(&mut self) -> TskFsFile {
        let inner_ref = unsafe { self.inner.as_ref() };
        NonNull::new(inner_ref.fs_file)
            .map(TskFsFile::new)
            .expect("TSK_FS_DIR file is null")
    }
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        let inner_ref = unsafe { self.inner.as_ref() };
        unsafe { tsk_sys::tsk_fs_dir_getsize(inner_ref) }
    }
    pub fn iter_entries(&'a mut self) -> impl Iterator<Item = TskFsFile<'a>> + 'a {
        TskFsDirIterator::new(self)
    }
}

struct TskFsDirIterator<'a> {
    idx: usize,
    dir: &'a mut TskFsDir<'a>,
}

impl<'a> TskFsDirIterator<'a> {
    fn new(dir: &'a mut TskFsDir<'a>) -> Self {
        Self { idx: 0, dir }
    }
}

impl<'a> Iterator for TskFsDirIterator<'a> {
    type Item = TskFsFile<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let dir_ref = unsafe { self.dir.inner.as_ref() };
        let file_ptr = unsafe { tsk_sys::tsk_fs_dir_get(dir_ref, self.idx) };
        let file = NonNull::new(file_ptr).map(TskFsFile::new);
        if file.is_some() {
            self.idx += 1;
        }
        file
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.dir.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for TskFsDirIterator<'_> {}

pub struct TskFsFile<'a> {
    pub(crate) inner: NonNull<tsk_sys::TSK_FS_FILE>,
    _marker: PhantomData<&'a tsk_sys::TSK_FS_FILE>,
}

impl TskFsFile<'_> {
    fn new(inner: NonNull<tsk_sys::TSK_FS_FILE>) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
    /// Returns the name of the file, or None if the file was opened by
    /// metadata address.
    pub fn get_name(&self) -> Option<String> {
        let inner_ref = unsafe { self.inner.as_ref() };
        NonNull::new(inner_ref.name)
            .map(|name| unsafe { CStr::from_ptr(name.as_ref().name) })
            .map(|cstr| cstr.to_string_lossy().to_string())
    }

    /// Returns the metadata of the file, or None if the file was opened with an
    /// invalid metadata address.
    pub fn get_meta(&self) -> Option<TskFsMeta> {
        let inner_ref = unsafe { self.inner.as_ref() };
        NonNull::new(inner_ref.meta).map(|inner| TskFsMeta {
            inner,
            _marker: PhantomData,
        })
    }
}

/// Stores file names found within the file metadata. Note that this is
/// different from the file name stored in the directory heirarchy, and is
/// currently used for NTFS and FAT file systems only.
pub struct TskFsMetaName {
    /// Name of the file, not including the name of the parent directory.
    pub name: String,
    /// Inode address of parent directory (NTFS only).
    pub par_inode: u64,
    /// Sequence number of parent directory (NTFS only).
    pub par_seq: u32,
}

pub struct TskFsMeta<'a> {
    pub(crate) inner: NonNull<tsk_sys::TSK_FS_META>,
    _marker: PhantomData<&'a tsk_sys::TSK_FS_META>,
}

/// TSK data structure to store file and directory metadata.
impl TskFsMeta<'_> {
    /// Address of the metadata structure for this file.
    pub fn addr(&self) -> u64 {
        unsafe { self.inner.as_ref() }.addr
    }
    /// Last file content accessed time (stored in number of seconds since Jan 1, 1970 UTC).
    pub fn atime(&self) -> i64 {
        unsafe { self.inner.as_ref() }.atime
    }
    /// Nano-second resolution in addition to atime.
    pub fn atime_nano(&self) -> u32 {
        unsafe { self.inner.as_ref() }.atime_nano
    }
    /// Created time (stored in number of seconds since Jan 1, 1970 UTC).
    pub fn crtime(&self) -> i64 {
        unsafe { self.inner.as_ref() }.crtime
    }
    /// Nano-second resolution in addition to crtime.
    pub fn crtime_nano(&self) -> u32 {
        unsafe { self.inner.as_ref() }.crtime_nano
    }
    /// Last file / metadata status change time (stored in number of seconds since Jan 1, 1970 UTC).
    pub fn ctime(&self) -> i64 {
        unsafe { self.inner.as_ref() }.ctime
    }
    /// Nano-second resolution in addition to ctime.
    pub fn ctime_nano(&self) -> u32 {
        unsafe { self.inner.as_ref() }.ctime_nano
    }
    /// Group ID.
    pub fn gid(&self) -> u32 {
        unsafe { self.inner.as_ref() }.gid
    }
    /// Unix-style permissions.
    // mode is a C enum that may either be u32 or i32 (on MSVC)
    #[allow(clippy::unnecessary_cast)]
    pub fn mode(&self) -> u32 {
        unsafe { self.inner.as_ref() }.mode as u32
    }
    /// Last file content modification time (stored in number of seconds since Jan 1, 1970 UTC)
    pub fn mtime(&self) -> i64 {
        unsafe { self.inner.as_ref() }.mtime
    }
    /// Nano-second resolution in addition to m_time.
    pub fn mtime_nano(&self) -> u32 {
        unsafe { self.inner.as_ref() }.mtime_nano
    }
    /// Gets names stored in the metadata.
    pub fn get_meta_names(&self) -> Vec<TskFsMetaName> {
        let mut names = vec![];
        // SAFETY: inner pointer is checked for null.
        let mut name_list_ptr = unsafe { self.inner.as_ref() }.name2;
        // SAFETY: trusting TSK to not give us a garbage non-null pointer.
        while let Some(name_list) = unsafe { name_list_ptr.as_ref() } {
            let name: &[c_char; 512] = &name_list.name;
            if !name.contains(&('\0' as c_char)) {
                panic!("meta name missing null terminator");
            }
            // SAFETY: checked for null terminator.
            let name = unsafe { CStr::from_ptr(name_list.name.as_ptr()) }
                .to_string_lossy()
                .to_string();
            names.push(TskFsMetaName {
                name,
                par_inode: name_list.par_inode,
                par_seq: name_list.par_seq,
            });

            name_list_ptr = name_list.next;
        }
        names
    }
    /// File size (in bytes).
    pub fn size(&self) -> i64 {
        unsafe { self.inner.as_ref() }.size
    }
    /// Owner ID.
    pub fn uid(&self) -> u32 {
        unsafe { self.inner.as_ref() }.uid
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::{Read as _, Write as _};

    use tempfile::NamedTempFile;

    use super::*;
    #[test]
    fn test_get_tsk_version() {
        assert_eq!(get_tsk_version(), "4.13.0");
    }

    #[test]
    fn test_ntfs() {
        let source = "test_data/smol.ntfs.gz";
        let file = File::open(source).expect("Failed to load test data");
        let mut gz = flate2::read::GzDecoder::new(file);
        let mut ntfs_raw = Vec::new();
        gz.read_to_end(&mut ntfs_raw)
            .expect("Failed to read test data");
        let mut tempfile = NamedTempFile::new().expect("Failed to open tempfile");
        tempfile
            .write_all(&ntfs_raw)
            .expect("Failed to write tempfile");
        let image = TskImage::open(tempfile.path()).expect("Failed to open ntfs image");
        let fs = image.open_fs().expect("Failed to open NTFS FS");
        assert_eq!(fs.get_fs_type().unwrap(), "ntfs");
        let root_f = fs
            .open_file("/".as_ref())
            .expect("Failed to open root file");
        assert_eq!(root_f.get_meta().unwrap().addr(), 5);
        let root_name = root_f.get_name().expect("No root name");
        assert_eq!(root_name, "");
        let mut root_dir = fs.open_dir("/".as_ref()).expect("Failed to open root dir");
        let root_f2 = root_dir.get_file();
        assert_eq!(root_f2.get_meta().unwrap().addr(), 5);
        let mut root_dir_entries = root_dir.iter_entries().collect::<Vec<_>>();
        let names = root_dir_entries
            .iter_mut()
            .map(|e| e.get_name().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "$AttrDef",
                "$BadClus",
                "$Bitmap",
                "$Boot",
                "$Extend",
                "$LogFile",
                "$MFT",
                "$MFTMirr",
                "$Secure",
                "$UpCase",
                "$Volume",
                ".",
                "bar",
                "baz",
                "circular",
                "dir",
                "emptydir",
                "encoding",
                "foo",
                "hardlinks",
                ".fuse_hidden0000000700000001",
                "$OrphanFiles"
            ]
        );
        let bar_entry = &mut root_dir_entries[12];
        assert_eq!(bar_entry.get_name().unwrap(), "bar");
        let bar_meta = bar_entry.get_meta().unwrap();
        assert_eq!(bar_meta.atime(), 1710542035);
        assert_eq!(bar_meta.atime_nano(), 951596300);
        assert_eq!(bar_meta.addr(), 64);
    }

    #[test]
    fn test_walk() {
        let source = "test_data/smol.ntfs.gz";
        let file = File::open(source).expect("Failed to load test data");
        let mut gz = flate2::read::GzDecoder::new(file);
        let mut ntfs_raw = Vec::new();
        gz.read_to_end(&mut ntfs_raw)
            .expect("Failed to read test data");
        let mut tempfile = NamedTempFile::new().expect("Failed to open tempfile");
        tempfile
            .write_all(&ntfs_raw)
            .expect("Failed to write tempfile");
        let image = TskImage::open(tempfile.path()).expect("Failed to open ntfs image");
        let mut fs = image.open_fs().expect("Failed to open NTFS FS");
        let mut paths = std::collections::HashSet::new();
        fs.walk_dir(fs.root_inum(), |file, path| {
            let mut full_path = String::from_utf8_lossy(path).to_string();
            full_path.push_str(&file.get_name().unwrap());
            paths.insert(full_path);
            WalkDirCallbackResult::Continue
        })
        .unwrap();
        assert!(paths.contains("foo"));
        assert!(paths.contains("bar"));
        assert!(paths.contains("dir"));
        assert!(paths.contains("dir/foobar"));
        assert!(paths.contains("dir/subdir"));
        assert!(paths.contains("dir/subdir/deepfile"));
    }
}
