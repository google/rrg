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

/// Returns the version reported by the underlying sleuthkit library.
pub fn version() -> String {
    // SAFETY: TSK returns a pointer to a static string.
    let cstr = unsafe { CStr::from_ptr(tsk_sys::tsk_version_get_str()) };
    String::from_utf8_lossy(cstr.to_bytes()).into_owned()
}

#[derive(Debug)]
pub struct Error {
    message: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

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
        let mut path: Vec<u8> = path.to_string_lossy().as_bytes().to_vec();
        path.push(0);
        Self { path }
    }

    fn as_ptr(&self) -> *const c_char {
        self.path.as_ptr().cast()
    }
}

fn last_tsk_error() -> Error {
    // SAFETY: trusting TSK.
    let message_ptr = unsafe { tsk_sys::tsk_error_get() };
    if message_ptr.is_null() {
        return Error {
            message: String::from("unknown"),
        };
    }
    // SAFETY: pointer was null-checked, trusting TSK to give us a valid pointer.
    let message = unsafe { CStr::from_ptr(message_ptr) }
        .to_string_lossy()
        .to_string();
    Error { message }
}

fn handle_result<T>(result: *mut T) -> Result<NonNull<T>> {
    NonNull::new(result).ok_or_else(last_tsk_error)
}

pub struct Image {
    pub(crate) inner: NonNull<tsk_sys::TSK_IMG_INFO>,
}

impl Image {
    pub fn open(path: &Path) -> Result<Self> {
        // TSK takes in host paths as UTF-16 or UTF-8 depending on the platform.
        // See TSK_TCHAR in https://www.sleuthkit.org/sleuthkit/docs/api-docs/4.5/basepage.html
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
        // SAFETY: Passing TSK a valid pointer. Trusting TSK.
        let tsk_img_result = unsafe {
            tsk_sys::tsk_img_open_sing(
                path.as_ptr(),
                tsk_sys::TSK_IMG_TYPE_ENUM_TSK_IMG_TYPE_RAW_SING,
                0,
            )
        };
        handle_result(tsk_img_result).map(|inner| Self { inner })
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        // SAFETY: memory is not freed anywhere else. This is only called once.
        unsafe { tsk_sys::tsk_img_close(self.inner.as_mut()) };
    }
}

pub struct Filesystem<'a> {
    pub(crate) inner: NonNull<tsk_sys::TSK_FS_INFO>,
    marker: PhantomData<&'a tsk_sys::TSK_FS_INFO>,
}

pub enum WalkDirCallbackResult {
    /// Continue walking.
    Continue,
    /// Stop walking.
    Stop,
}

impl<'image> Filesystem<'image> {
    pub fn open(image: &'image Image) -> Result<Self> {
        // SAFETY: the image pointer was checked to be non-null. We trust TSK's C API to work.
        let tsk_fs_result = unsafe {
            tsk_sys::tsk_fs_open_img(image.inner.as_ptr(), 0, TSK_FS_TYPE_ENUM_TSK_FS_TYPE_DETECT)
        };
        handle_result(tsk_fs_result).map(|inner| Filesystem {
            inner,
            marker: PhantomData,
        })
    }

    fn as_raw(&self) -> &tsk_sys::TSK_FS_INFO {
        // SAFETY: This pointer was checked to be non-null, and it is not freed
        // until this struct is dropped.
        unsafe { self.inner.as_ref() }
    }

    pub fn root_inum(&self) -> u64 {
        self.as_raw().root_inum
    }
    /// Returns the string name of a file system type id, e.g. "ntfs".
    pub fn fs_type(&self) -> Result<String> {
        let ty = self.as_raw().ftype;
        // SAFETY: trusting TSK's C API.
        let name_ptr = unsafe { tsk_sys::tsk_fs_type_toname(ty) };
        handle_result(name_ptr as *mut c_char)
            // SAFETY: trusting TSK to return either a valid C string or NULL.
            .map(|non_null| unsafe { CStr::from_ptr(non_null.as_ptr()).to_bytes() })
            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
    }

    /// Opens a directory given its path.
    pub fn open_dir(&self, path: &Path) -> Result<Directory> {
        let tsk_path = TskPath::from_path(path);
        // SAFETY: passing checked non-null pointers into TSK's C API.
        let result = unsafe { tsk_fs_dir_open(self.inner.as_ptr(), tsk_path.as_ptr()) };
        handle_result(result).map(Directory::new)
    }

    /// Opens a file given its metadata address.
    pub fn open_dir_meta(&self, meta: u64) -> Result<Directory> {
        // SAFETY: passing checked non-null pointers into TSK's C API.
        let result = unsafe { tsk_fs_dir_open_meta(self.inner.as_ptr(), meta) };
        handle_result(result).map(Directory::new)
    }

    /// Opens a file given its path.
    pub fn open_file(&self, path: &Path) -> Result<File> {
        let tsk_path = TskPath::from_path(path);
        let result =
            // SAFETY: passing checked non-null pointers into TSK's C API.
            unsafe { tsk_fs_file_open(self.inner.as_ptr(), null_mut(), tsk_path.as_ptr()) };
        handle_result(result).map(File::new)
    }

    /// Recursively walks the directory with the given metadata address. Calls
    /// `callback` for each file and directory with two arguments: a reference
    /// to the file and the full path to the file.
    pub fn walk_dir(
        &self,
        dir: &Directory,
        mut callback: impl FnMut(File, &[u8]) -> WalkDirCallbackResult,
    ) -> Result<()> {
        // References to trait objects are "fat" and cannot be passed as
        // raw pointers.
        type CallbackRefCell<'a> = RefCell<&'a mut dyn FnMut(File, &[u8]) -> WalkDirCallbackResult>;
        let refcell: CallbackRefCell = RefCell::new(&mut callback);

        // See https://www.sleuthkit.org/sleuthkit/docs/api-docs/4.5/tsk__fs_8h.html#ad381d6cb96ae78351e88b7aa54d81008 for the type of this callback function.
        extern "C" fn c_callback(
            // Pointer to the current file in the directory.
            file: *mut tsk_sys::TSK_FS_FILE,
            // Path of the file.
            path: *const c_char,
            // Pointer that was originally passed by caller to tsk_fs_dir_walk.
            // This is a pointer to the refcell above.
            ptr: *mut c_void,
        ) -> tsk_sys::TSK_WALK_RET_ENUM {
            let file =
                File::new(NonNull::new(file).expect("null file passed in walk_dir callback"));
            let path =
                NonNull::new(path as *mut c_char).expect("null path passed into walk_dir callback");
            // SAFETY: path was checked for null. We trust TSK to pass us a null-terminated string.
            let path: &[u8] = unsafe { CStr::from_ptr(path.as_ptr()).to_bytes() };
            let callback_ptr =
                ptr as *const RefCell<&mut dyn FnMut(File, &[u8]) -> WalkDirCallbackResult>;
            // SAFETY: we trust TSK to pass in the same pointer we passed into tsk_fs_dir_walk.
            let mut callback = unsafe { callback_ptr.as_ref() }
                .expect("null ptr passed to tsk_fs_dir_walk callback")
                .borrow_mut();
            match callback(file, path) {
                WalkDirCallbackResult::Continue => tsk_sys::TSK_WALK_RET_ENUM_TSK_WALK_CONT,
                WalkDirCallbackResult::Stop => tsk_sys::TSK_WALK_RET_ENUM_TSK_WALK_STOP,
            }
        }

        let flags = tsk_sys::TSK_FS_DIR_WALK_FLAG_ENUM_TSK_FS_DIR_WALK_FLAG_RECURSE
            | tsk_sys::TSK_FS_DIR_WALK_FLAG_ENUM_TSK_FS_DIR_WALK_FLAG_ALLOC;
        // Returns 1 on error and 0 on success.
        // SAFETY: calling TSK's C API with checked non-null pointers, and the
        // pointer to refcell is valid for the scope of this function.
        let result = unsafe {
            tsk_sys::tsk_fs_dir_walk(
                self.inner.as_ptr(),
                dir.addr(),
                flags,
                Some(c_callback),
                (&refcell) as *const CallbackRefCell as *mut c_void,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(last_tsk_error())
        }
    }
}

impl Drop for Filesystem<'_> {
    fn drop(&mut self) {
        // SAFETY: calling TSK's C API to drop this pointer exactly once.
        unsafe { tsk_sys::tsk_fs_close(self.inner.as_mut()) };
    }
}

pub struct Directory<'a> {
    inner: NonNull<tsk_sys::TSK_FS_DIR>,
    marker: PhantomData<&'a tsk_sys::TSK_FS_DIR>,
}

impl<'a> Directory<'a> {
    fn new(inner: NonNull<tsk_sys::TSK_FS_DIR>) -> Self {
        Self {
            inner,
            marker: PhantomData,
        }
    }
    fn as_raw(&self) -> &tsk_sys::TSK_FS_DIR {
        // SAFETY: This pointer was checked to be non-null, and it is not freed
        // until this struct is dropped.
        unsafe { self.inner.as_ref() }
    }
    /// Returns the metadata address of this directory.
    pub fn addr(&self) -> u64 {
        self.as_raw().addr
    }
    /// Returns the file structure for the directory.
    pub fn file(&mut self) -> File {
        NonNull::new(self.as_raw().fs_file)
            .map(File::new)
            .expect("TSK_FS_DIR file is null")
    }
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        // SAFETY: This pointer was checked to be non-null, and we trust the TSK C API.
        unsafe { tsk_sys::tsk_fs_dir_getsize(self.inner.as_ptr()) }
    }
    /// Returns an iterator containing file entries for this directory.
    ///
    /// May return errors if the file entries fail to parse, e.g. if there is filesystem corruption.
    pub fn iter_entries(&'a mut self) -> impl Iterator<Item = Result<File<'a>>> + 'a {
        DirectoryIterator::new(self)
    }
}

struct DirectoryIterator<'a> {
    idx: usize,
    dir: &'a mut Directory<'a>,
}

impl<'a> DirectoryIterator<'a> {
    fn new(dir: &'a mut Directory<'a>) -> Self {
        Self { idx: 0, dir }
    }
}

impl<'a> Iterator for DirectoryIterator<'a> {
    type Item = Result<File<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.dir.len() >= self.idx {
            return None;
        }
        // SAFETY: trusting the TSK C API.
        let file_ptr = unsafe { tsk_sys::tsk_fs_dir_get(self.dir.as_raw(), self.idx) };
        let result = handle_result(file_ptr).map(File::new);
        self.idx += 1;
        Some(result)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.dir.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for DirectoryIterator<'_> {}

pub struct File<'a> {
    pub(crate) inner: NonNull<tsk_sys::TSK_FS_FILE>,
    _marker: PhantomData<&'a tsk_sys::TSK_FS_FILE>,
}

impl File<'_> {
    fn new(inner: NonNull<tsk_sys::TSK_FS_FILE>) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
    fn as_raw(&self) -> &tsk_sys::TSK_FS_FILE {
        // SAFETY: This pointer was checked to be non-null, and it is not freed
        // until this struct is dropped.
        unsafe { self.inner.as_ref() }
    }

    /// Returns the name of the file, or None if the file was opened by
    /// metadata address.
    pub fn name(&self) -> Option<String> {
        NonNull::new(self.as_raw().name)
            // SAFETY: trusting TSK to return a null-terminated c string.
            .map(|name| unsafe { CStr::from_ptr(name.as_ref().name) })
            .map(|cstr| cstr.to_string_lossy().to_string())
    }

    /// Returns the metadata of the file, or None if the file was opened with an
    /// invalid metadata address.
    pub fn meta(&self) -> Option<Metadata> {
        NonNull::new(self.as_raw().meta).map(|inner| Metadata {
            inner,
            _marker: PhantomData,
        })
    }
}

/// Stores file names found within the file metadata. Note that this is
/// different from the file name stored in the directory heirarchy, and is
/// currently used for NTFS and FAT file systems only.
pub struct MetaName {
    /// Name of the file, not including the name of the parent directory.
    pub name: String,
    /// Inode address of parent directory (NTFS only).
    pub par_inode: u64,
    /// Sequence number of parent directory (NTFS only).
    pub par_seq: u32,
}

pub struct Metadata<'a> {
    pub(crate) inner: NonNull<tsk_sys::TSK_FS_META>,
    _marker: PhantomData<&'a tsk_sys::TSK_FS_META>,
}

/// TSK data structure to store file and directory metadata.
impl Metadata<'_> {
    fn as_raw(&self) -> &tsk_sys::TSK_FS_META {
        // SAFETY: This pointer was checked to be non-null, and it is not freed
        // until this struct is dropped.
        unsafe { self.inner.as_ref() }
    }
    /// Address of the metadata structure for this file.
    pub fn addr(&self) -> u64 {
        self.as_raw().addr
    }
    /// Last file content accessed time (stored in number of seconds since Jan 1, 1970 UTC).
    pub fn atime(&self) -> i64 {
        self.as_raw().atime
    }
    /// Nano-second resolution in addition to atime.
    pub fn atime_nano(&self) -> u32 {
        self.as_raw().atime_nano
    }
    /// Created time (stored in number of seconds since Jan 1, 1970 UTC).
    pub fn crtime(&self) -> i64 {
        self.as_raw().crtime
    }
    /// Nano-second resolution in addition to crtime.
    pub fn crtime_nano(&self) -> u32 {
        self.as_raw().crtime_nano
    }
    /// Last file / metadata status change time (stored in number of seconds since Jan 1, 1970 UTC).
    pub fn ctime(&self) -> i64 {
        self.as_raw().ctime
    }
    /// Nano-second resolution in addition to ctime.
    pub fn ctime_nano(&self) -> u32 {
        self.as_raw().ctime_nano
    }
    /// Group ID.
    pub fn gid(&self) -> u32 {
        self.as_raw().gid
    }
    /// Unix-style permissions.
    // mode is a C enum that may either be u32 or i32 (on MSVC)
    #[allow(clippy::unnecessary_cast)]
    pub fn mode(&self) -> u32 {
        self.as_raw().mode as u32
    }
    /// Last file content modification time (stored in number of seconds since Jan 1, 1970 UTC)
    pub fn mtime(&self) -> i64 {
        self.as_raw().mtime
    }
    /// Nano-second resolution in addition to m_time.
    pub fn mtime_nano(&self) -> u32 {
        self.as_raw().mtime_nano
    }
    /// Gets names stored in the metadata.
    pub fn meta_names(&self) -> Vec<MetaName> {
        let mut names = vec![];
        // SAFETY: inner pointer is checked for null.
        let mut name_list_ptr = self.as_raw().name2;
        // SAFETY: trusting TSK to not give us a garbage non-null pointer.
        while let Some(name_list) = unsafe { name_list_ptr.as_ref() } {
            let name: &[c_char; 512] = &name_list.name;
            if !name.contains(&('\0' as c_char)) {
                panic!("meta name missing null terminator");
            }
            // SAFETY: checked for null terminator.
            let name = unsafe { CStr::from_ptr(name_list.name.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            names.push(MetaName {
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
        self.as_raw().size
    }
    /// Owner ID.
    pub fn uid(&self) -> u32 {
        self.as_raw().uid
    }
}

#[cfg(test)]
mod test {
    use std::io::{Read as _, Write as _};

    use tempfile::NamedTempFile;

    use super::*;

    const SMOL_NTFS_GZ: &[u8] = include_bytes!("../test_data/smol.ntfs.gz");
    #[test]
    fn test_version() {
        assert_eq!(version(), "4.13.0");
    }

    #[test]
    fn test_ntfs() {
        let mut gz = flate2::read::GzDecoder::new(SMOL_NTFS_GZ);
        let mut ntfs_raw = Vec::new();
        gz.read_to_end(&mut ntfs_raw)
            .expect("failed to read test data");
        let mut tempfile = NamedTempFile::new().expect("failed to open tempfile");
        tempfile
            .write_all(&ntfs_raw)
            .expect("failed to write tempfile");
        let image = Image::open(tempfile.path()).expect("failed to open ntfs image");
        let fs = Filesystem::open(&image).expect("failed to open NTFS FS");
        assert_eq!(fs.fs_type().unwrap(), "ntfs");
        let root_f = fs
            .open_file("/".as_ref())
            .expect("failed to open root file");
        assert_eq!(root_f.meta().unwrap().addr(), 5);
        let root_name = root_f.name().expect("no root name");
        assert_eq!(root_name, "");
        let mut root_dir = fs.open_dir("/".as_ref()).expect("failed to open root dir");
        let root_f2 = root_dir.file();
        assert_eq!(root_f2.meta().unwrap().addr(), 5);
        let mut root_dir_entries = root_dir
            .iter_entries()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        let names = root_dir_entries
            .iter_mut()
            .map(|e| e.name().unwrap())
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
        assert_eq!(bar_entry.name().unwrap(), "bar");
        let bar_meta = bar_entry.meta().unwrap();
        assert_eq!(bar_meta.atime(), 1710542035);
        assert_eq!(bar_meta.atime_nano(), 951596300);
        assert_eq!(bar_meta.addr(), 64);
    }

    #[test]
    fn test_walk() {
        let mut gz = flate2::read::GzDecoder::new(SMOL_NTFS_GZ);
        let mut ntfs_raw = Vec::new();
        gz.read_to_end(&mut ntfs_raw)
            .expect("failed to read test data");
        let mut tempfile = NamedTempFile::new().expect("failed to open tempfile");
        tempfile
            .write_all(&ntfs_raw)
            .expect("failed to write tempfile");
        let image = Image::open(tempfile.path()).expect("failed to open ntfs image");
        let mut fs = Filesystem::open(&image).expect("failed to open NTFS FS");
        let mut paths = std::collections::HashSet::new();
        fs.walk_dir(fs.root_inum(), |file, path| {
            let mut full_path = String::from_utf8_lossy(path).to_string();
            full_path.push_str(&file.name().unwrap());
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
