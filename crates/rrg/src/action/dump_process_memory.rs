// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::collections::VecDeque;
use std::path::PathBuf;

/// A memory mapping in a running process' virtual address space.
/// [`MappedRegionIterator`] allows you to iterate through a process' memory mappings.
#[derive(Default, Debug, Clone)]
pub struct MappedRegion {
    /// The offset in the process' virtual address space at which this mapping starts, in bytes.
    address_start: u64,
    /// The size of this mapping in bytes.
    size: u64,
    /// Permissions associated with this mapping.
    pub permissions: Permissions,
    /// If this mapping is backed by a file, this field will contain said file's inode.
    /// Only valid on Linux.
    pub inode: Option<u64>,
    /// If this mapping is backed by a file, this field will contain the path to said file.
    /// It can also contain a pseudo-path that indicates the type of mapping, otherwise.
    /// For example, [heap] or [stack]. Refer to `man 5 proc_pid_maps` for more information.
    pub path: Option<PathBuf>,
}

impl MappedRegion {
    /// Constructs a fake region of memory corresponding to the address range `\[start..end\]`.
    /// All other parameters than the region boundaries will be set according to [`MappedRegion::default`].
    /// Mainly useful for testing.
    pub fn from_bounds(start: u64, end: u64) -> Self {
        MappedRegion {
            address_start: start,
            size: (end - start),
            ..Default::default()
        }
    }

    /// Returns the offset in the process' virtual address space at which this mapping starts, in bytes.
    pub fn start_address(&self) -> u64 {
        self.address_start
    }

    /// Returns the offset in the process' virtual address space at which this mapping ends (exclusive), in bytes.
    pub fn end_address(&self) -> u64 {
        self.address_start + self.size
    }

    /// Returns the size of this mapping, in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }
}

// Represents a handle to read another process' memory.
pub trait MemoryReader {
    /// Reads a slice `\[offset..(offset+length)\]` of the opened process' memory
    /// and returns it as a [`Vec<u8>`]. `offset` is considered as an absolute offset
    /// in the process' address space. If the slice falls outside the memory's address space,
    /// the returned buffer will be truncated.
    fn read_chunk(&mut self, offset: u64, length: u64) -> std::io::Result<Vec<u8>>;
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs::File;
    use std::io::{BufRead, Read as _, Seek as _, SeekFrom};

    /// An error that occurred during parsing of a process' memory mappings file.
    #[derive(Debug)]
    pub struct ParseRegionError {
        field_name: &'static str,
        kind: ParseRegionErrorKind,
    }

    #[derive(Debug)]
    enum ParseRegionErrorKind {
        /// An expected field was not present.
        MissingField,
        /// A field had an invalid format.
        InvalidField(Box<dyn std::error::Error>),
    }

    impl std::fmt::Display for ParseRegionError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match &self.kind {
                ParseRegionErrorKind::MissingField => {
                    write!(f, "missing field \"{}\"", self.field_name)
                }
                ParseRegionErrorKind::InvalidField(error) => write!(
                    f,
                    "invalid format for field \"{}\": {}",
                    self.field_name, error
                ),
            }
        }
    }
    impl std::error::Error for ParseRegionError {
        fn cause(&self) -> Option<&dyn std::error::Error> {
            match &self.kind {
                ParseRegionErrorKind::InvalidField(error) => Some(error.as_ref()),
                _ => None,
            }
        }
    }

    impl ParseRegionError {
        fn missing_field(field_name: &'static str) -> Self {
            Self {
                field_name,
                kind: ParseRegionErrorKind::MissingField,
            }
        }

        fn invalid_field<E: std::error::Error + 'static>(
            field_name: &'static str,
            cause: E,
        ) -> Self {
            Self {
                field_name,
                kind: ParseRegionErrorKind::InvalidField(Box::new(cause)),
            }
        }
    }

    impl MappedRegion {
        /// Parses a single mapping from a line in a process' mappings file.
        fn parse(line: &str) -> Result<Self, ParseRegionError> {
            let mut parts = line.split_ascii_whitespace();
            let address = parts
                .next()
                .ok_or_else(|| ParseRegionError::missing_field("address_start"))?;
            let (address_start, address_end) = address
                .split_once('-')
                .ok_or_else(|| ParseRegionError::missing_field("address_end"))?;
            let address_start = u64::from_str_radix(address_start, 16)
                .map_err(|e| ParseRegionError::invalid_field("address_start", e))?;
            let address_end = u64::from_str_radix(address_end, 16)
                .map_err(|e| ParseRegionError::invalid_field("address_end", e))?;
            let size = address_end - address_start;

            let permissions = {
                let mut perms = parts
                    .next()
                    .ok_or_else(|| ParseRegionError::missing_field("permissions"))?
                    .chars();
                let read = perms.next().is_some_and(|x| x == 'r');
                let write = perms.next().is_some_and(|x| x == 'w');
                let execute = perms.next().is_some_and(|x| x == 'x');
                let sharing = perms.next();
                let shared = sharing.as_ref().is_some_and(|&x| x == 's');
                let private = sharing.as_ref().is_some_and(|&x| x == 'p');
                Permissions {
                    read,
                    write,
                    execute,
                    shared,
                    private,
                }
            };

            let offset = parts
                .next()
                .ok_or_else(|| ParseRegionError::missing_field("offset"))?;
            let _offset = u64::from_str_radix(offset, 16)
                .map_err(|e| ParseRegionError::invalid_field("offset", e))?;
            let _dev = parts
                .next()
                .ok_or_else(|| ParseRegionError::missing_field("dev"))?;

            let inode = parts
                .next()
                .ok_or_else(|| ParseRegionError::missing_field("inode"))?;
            let inode = inode
                .parse::<u64>()
                .map_err(|e| ParseRegionError::invalid_field("inode", e))?;
            let inode = if inode != 0 { Some(inode) } else { None };

            let path = parts.next().map(PathBuf::from);
            Ok(MappedRegion {
                address_start,
                size,
                permissions,
                inode,
                path,
            })
        }
    }

    /// Allows to read the contents of a running process' memory.
    pub struct ReadableProcessMemory {
        mem_file: File,
    }

    impl ReadableProcessMemory {
        /// Opens the contents of process `pid`'s memory for reading.
        pub fn open(pid: u32) -> std::io::Result<Self> {
            let mem_file = File::open(format!("/proc/{pid}/mem"))?;
            Ok(Self::from_file(mem_file))
        }

        pub fn from_file(mem_file: File) -> Self {
            Self { mem_file }
        }
    }

    impl MemoryReader for ReadableProcessMemory {
        fn read_chunk(&mut self, offset: u64, length: u64) -> std::io::Result<Vec<u8>> {
            self.mem_file.seek(SeekFrom::Start(offset))?;
            let mut buf = Vec::new();
            let mem_file = self.mem_file.by_ref();
            // Limit amount of bytes that can be read
            let mut mem_file_limited = mem_file.take(length);
            mem_file_limited.read_to_end(&mut buf)?;
            Ok(buf)
        }
    }

    /// Iterator over a running process' memory mappings.
    /// To avoid inconsistencies in observed mappings, the mappings are not updated lazily as the iterator advances,
    /// but are effectively a snapshot of a process' memory space at the time the iterator is created.
    pub struct MappedRegionIter {
        // We do not use a `BufReader<File>` here for two reasons:
        // 1. So that we have a consistent snapshot of the process memory maps,
        // taken at the moment the iterator is created.
        // 2. So we only have to propagate an io::Error on creation instead of for each line read.
        // I wish there was an owned version of std::str::Lines, but this workaround does the job
        // for now.
        lines: std::io::Lines<std::io::Cursor<String>>,
    }

    impl MappedRegionIter {
        /// Creates a new [`MappedRegionIterator`] of the process with id `pid`.
        pub fn from_pid(pid: u32) -> std::io::Result<Self> {
            let file = File::open(format!("/proc/{pid}/maps"))?;
            Self::from_map_file(file)
        }

        fn from_map_file(mut file: File) -> std::io::Result<Self> {
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            Ok(Self {
                lines: std::io::Cursor::new(contents).lines(),
            })
        }
    }

    impl Iterator for MappedRegionIter {
        type Item = Result<MappedRegion, ParseRegionError>;

        fn next(&mut self) -> Option<Self::Item> {
            self.lines.next().map(|line| {
                MappedRegion::parse(line.as_deref().expect("Cursor read should not panic"))
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn region_iter_detects_mmap() {
            // `mmap` a file and check that the mapping is detected among those returned by
            // `MappedRegionIter`.
            use std::io::Write as _;
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::io::AsRawFd;

            let mut file = tempfile::tempfile().unwrap();
            writeln!(file, "hello there").unwrap();

            let meta = file.metadata().unwrap();
            let length = meta.len() as usize;

            /// RAII wrapper around a `mmap`ed pointer that will `munmap` on drop.
            struct MappedPtr {
                ptr: *mut libc::c_void,
                length: usize,
            }

            impl Drop for MappedPtr {
                fn drop(&mut self) {
                    unsafe {
                        libc::munmap(self.ptr, self.length);
                    }
                }
            }

            let mapped_ptr = unsafe {
                let ptr = libc::mmap(
                    std::ptr::null_mut(),
                    length,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE,
                    file.as_raw_fd(),
                    0,
                );
                assert_ne!(ptr, libc::MAP_FAILED);
                MappedPtr { ptr, length }
            };

            let regions: Vec<MappedRegion> = MappedRegionIter::from_pid(std::process::id())
                .expect("could not read memory regions of current process")
                .collect::<Result<_, _>>()
                .expect("reading maps");

            drop(mapped_ptr);

            assert!(regions.into_iter().any(|r| r.inode == Some(meta.ino())
                && r.permissions.private
                && r.permissions.read));
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use core::ffi::c_void;
    use std::mem::MaybeUninit;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Memory::{MEM_FREE, MEMORY_BASIC_INFORMATION, VirtualQueryEx};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    struct ProcessHandle(HANDLE);

    impl ProcessHandle {
        fn open(pid: u32) -> std::io::Result<Self> {
            // SAFETY: the returned handle will be closed by the `drop` impl.
            let handle: HANDLE = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
            if handle.is_null() {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(Self(handle))
            }
        }
    }

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            // SAFETY: since this struct has no `Clone` or `Copy` impl,
            // this handle will not be used again after the struct is dropped.
            unsafe { CloseHandle(self.0) };
        }
    }

    pub struct MappedRegionIter {
        process: ProcessHandle,
        cur_addr: *mut c_void,
    }

    impl MappedRegionIter {
        /// Creates a new [`MappedRegionIterator`] of the process with id `pid`.
        pub fn from_pid(pid: u32) -> std::io::Result<Self> {
            let process = ProcessHandle::open(pid)?;
            Ok(Self {
                process,
                cur_addr: std::ptr::null_mut(),
            })
        }
    }

    fn parse_permissions(mem_info: &MEMORY_BASIC_INFORMATION) -> Permissions {
        use windows_sys::Win32::System::Memory::*;

        // Info obtained from https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
        // and https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information

        const EXECUTE_FLAGS: u32 =
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        const WRITE_FLAGS: u32 =
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_READWRITE | PAGE_WRITECOPY;

        // Use the protection information of the actual committed memory if available,
        // otherwise the flags with which the memory mapping was created.
        let flags = if mem_info.State == MEM_COMMIT {
            mem_info.Protect
        } else {
            mem_info.AllocationProtect
        };

        Permissions {
            // The only flag which disables read access is PAGE_NOACCESS
            read: flags & PAGE_NOACCESS == 0,
            write: flags & WRITE_FLAGS != 0,
            execute: flags & EXECUTE_FLAGS != 0,
            private: mem_info.Type == MEM_PRIVATE,
            shared: false,
        }
    }

    fn get_mapped_filename(addr: *const c_void, process: &ProcessHandle) -> Option<PathBuf> {
        use windows_sys::Win32::Foundation::MAX_PATH;
        use windows_sys::Win32::System::ProcessStatus::GetMappedFileNameW;

        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        let mut buf = [0u16; (MAX_PATH + 1) as usize];
        // SAFETY: `GetMappedFileNameW` will only write up to `nSize` (last argument)
        // characters in `buf` (null-terminator included). Therefore there can be no buffer overflow.
        let len = unsafe { GetMappedFileNameW(process.0, addr, buf.as_mut_ptr(), buf.len() as u32) }
            as usize;
        // A return value of 0 indicates an error, and nSize indicates that the path was
        // truncated. We treat both cases as errors and just return None.
        if len == 0 || len == buf.len() {
            return None;
        }
        Some(PathBuf::from(OsString::from_wide(&buf[..len])))
    }

    impl Iterator for MappedRegionIter {
        type Item = std::io::Result<MappedRegion>;
        fn next(&mut self) -> Option<Self::Item> {
            loop {
                let mem_info: MEMORY_BASIC_INFORMATION = {
                    let mut mem: std::mem::MaybeUninit<MEMORY_BASIC_INFORMATION> =
                        MaybeUninit::zeroed();
                    // SAFETY: `VirtualQueryEx` will only write up to `dwLength` (last argument)
                    // bytes in `mem`.
                    let status = unsafe {
                        VirtualQueryEx(
                            self.process.0,
                            self.cur_addr,
                            mem.as_mut_ptr(),
                            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                        )
                    };
                    if status == 0 {
                        let err = std::io::Error::last_os_error();
                        // InvalidInput is returned when the given address
                        // falls beyond the last page accessible by the process,
                        // so we know we are done iterating when we receive that.
                        if err.kind() == std::io::ErrorKind::InvalidInput {
                            return None;
                        }
                        break Some(Err(err));
                    }
                    // SAFETY: We just checked that the call to `VirtualQueryEx`
                    // has succeeded, so we can safely assume that `mem` was initialized.
                    unsafe { mem.assume_init() }
                };

                let address_start = mem_info.BaseAddress;
                let address_end = address_start.wrapping_byte_add(mem_info.RegionSize);
                self.cur_addr = address_end;

                if mem_info.State == MEM_FREE {
                    // Skip over chunks of free memory
                    continue;
                }

                break Some(Ok(MappedRegion {
                    address_start: address_start as u64,
                    size: mem_info.RegionSize as u64,
                    permissions: parse_permissions(&mem_info),
                    inode: None,
                    path: get_mapped_filename(address_start, &self.process),
                }));
            }
        }
    }

    /// Allows to read the contents of a running process' memory.
    pub struct ReadableProcessMemory {
        process: ProcessHandle,
    }

    impl ReadableProcessMemory {
        /// Opens the contents of process `pid`'s memory for reading.
        pub fn open(pid: u32) -> std::io::Result<Self> {
            Ok(Self {
                process: ProcessHandle::open(pid)?,
            })
        }
    }

    impl MemoryReader for ReadableProcessMemory {
        fn read_chunk(&mut self, offset: u64, length: u64) -> std::io::Result<Vec<u8>> {
            let mut buf = vec![0; length as usize];
            let mut bytes_read = 0;
            // SAFETY: `ReadProcessMemory` will write at most `nSize` (second to last argument) bytes
            // in `buf`, so the bounded length prevents a buffer overflow.
            let status = unsafe {
                ReadProcessMemory(
                    self.process.0,
                    std::ptr::without_provenance_mut(offset as usize),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    &mut bytes_read,
                )
            };
            if status == 0 {
                return Err(std::io::Error::last_os_error());
            }
            buf.truncate(bytes_read);
            Ok(buf)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn region_iter_detects_mmap() {
            // `mmap` a file and check that the mapping is detected among those returned by
            // `MappedRegionIter`.
            use std::io::Write as _;
            use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
            use windows_sys::Win32::System::Memory::{
                CreateFileMappingW, FILE_MAP_ALL_ACCESS, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
                PAGE_READWRITE, UnmapViewOfFile,
            };

            let mut file = tempfile::tempfile().unwrap();
            writeln!(file, "hello there").unwrap();

            let meta = file.metadata().unwrap();
            let length = meta.len() as usize;

            // SAFETY: the returned mapping will be dropped
            // by `OwnedHandle`'s `drop` impl.
            let mapping = unsafe {
                CreateFileMappingW(
                    file.as_raw_handle(),
                    std::ptr::null(), // default security
                    PAGE_READWRITE,   // read/write permission
                    0,                // size of mapping object, high
                    length as u32,    // size of mapping object, low
                    std::ptr::null(),
                )
            };

            if mapping.is_null() {
                panic!("could not create file mapping");
            }

            // SAFETY: we just cheched that the mapping was created succesfully.
            // The raw handle was also not copied to another variable in the meantime
            let mapping = unsafe { OwnedHandle::from_raw_handle(mapping) };

            /// RAII wrapper around a `mmap`ed pointer that will `munmap` on drop.
            struct MappedView {
                addr: MEMORY_MAPPED_VIEW_ADDRESS,
            }

            impl Drop for MappedView {
                fn drop(&mut self) {
                    // SAFETY: we only need `unsafe` to call the FFI function here.
                    unsafe {
                        UnmapViewOfFile(self.addr);
                    }
                }
            }

            // Map the view and test the results.

            let view = unsafe {
                // SAFETY: the returned mapping will be unmapped by `MappedView`'s `drop`
                // impl. We check right away if the returned handle is valid.
                let addr = MapViewOfFile(
                    mapping.as_raw_handle(), // handle to mapping object
                    FILE_MAP_ALL_ACCESS,     // read/write
                    0,                       // high-order 32 bits of file offset
                    0,                       // low-order 32 bits of file offset
                    length,
                );
                assert!(!addr.Value.is_null());
                MappedView { addr }
            };

            let regions: Vec<MappedRegion> = MappedRegionIter::from_pid(std::process::id())
                .expect("could not read memory regions of current process")
                .collect::<Result<_, _>>()
                .expect("reading maps");

            assert!(regions.into_iter().any(|r| {
                r.address_start == view.addr.Value as u64
                    && r.permissions.read
                    && r.permissions.write
                    && r.path.is_some()
            }));

            drop(view);
        }
    }
}

/// A set of permissions associated with a [`MappedRegion`].
#[derive(Debug, Default, Clone, Copy)]
pub struct Permissions {
    /// Whether the contents of this mapping can be read from.
    read: bool,
    /// Whether the contents of this mapping can be written to.
    write: bool,
    /// Whether the contents of this mapping can be executed.
    execute: bool,
    /// Whether this mapping was created as `shared`.
    /// Writes to a shared mapping (usually backed by a file)
    /// can be observed by other processes which map the same file.
    /// Currently only supported on Linux.
    shared: bool,
    /// Whether this mapping was created as 'private'.
    /// Writes to a private mapping (usually backed by a file)
    /// are private to a process and cannot be observed by other processes which map the same file.
    private: bool,
}

/// Converts a [`Permissions`] struct to its corresponding protobuf version.
impl From<Permissions> for rrg_proto::dump_process_memory::Permissions {
    fn from(val: Permissions) -> Self {
        let mut perms = Self::new();
        perms.set_read(val.read);
        perms.set_write(val.write);
        perms.set_execute(val.execute);
        perms.set_shared(val.shared);
        perms.set_private(val.private);
        perms
    }
}

/// Arguments of the `dump_process_memory` action.
#[derive(Default)]
pub struct Args {
    /// PIDs of the processs whose memory we are interested in.
    pids: Vec<u32>,

    // Maximum amount of process memory to dump. Applies across all processes in `pids`.
    // The first memory region that exceeds the limit will be dumped partially.
    total_size_limit: Option<u64>,

    // Memory offsets to prioritize when the process memory size is greater
    // than the limit specified in `total_size_limit`. First, memory pages containing the
    // offsets will be dumped up to `total_size_limit`.
    // If not reached, the remaining memory pages will be dumped up to `total_size_limit`.
    priority_offsets: Option<Vec<u64>>,

    // Set this flag to avoid dumping mapped files.
    skip_mapped_files: bool,
    // Set this flag to avoid dumping shared memory regions.
    skip_shared_regions: bool,
    // Set this flag to avoid dumping executable memory regions.
    skip_executable_regions: bool,
    // Set this flag to avoid dumping readonly memory regions.
    skip_readonly_regions: bool,
}

use crate::request::ParseArgsError;
impl crate::request::Args for Args {
    type Proto = rrg_proto::dump_process_memory::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Self, ParseArgsError> {
        if !proto.priority_offsets.is_empty() && proto.pids.len() > 1 {
            #[derive(Debug)]
            struct InvalidOffsetPriority;
            impl std::fmt::Display for InvalidOffsetPriority {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(
                        f,
                        "cannot specify 'priority_offsets' with more than one 'pid'"
                    )
                }
            }
            impl std::error::Error for InvalidOffsetPriority {}
            return Err(ParseArgsError::invalid_field(
                "priority_offsets",
                InvalidOffsetPriority,
            ));
        }

        let priority_offsets = proto.take_priority_offsets();
        let priority_offsets = if priority_offsets.is_empty() {
            None
        } else {
            Some(priority_offsets)
        };
        Ok(Self {
            pids: proto.take_pids(),
            total_size_limit: proto.total_size_limit,
            priority_offsets,
            skip_mapped_files: proto.skip_mapped_files,
            skip_shared_regions: proto.skip_shared_regions,
            skip_executable_regions: proto.skip_executable_regions,
            skip_readonly_regions: proto.skip_readonly_regions,
        })
    }
}

impl Args {
    /// Whether `region` should be dumped according to `self`'s filtering parameters.
    fn should_dump(&self, region: &MappedRegion) -> bool {
        if self.skip_shared_regions && region.permissions.shared {
            return false;
        }
        if self.skip_executable_regions && region.permissions.execute {
            return false;
        }
        if self.skip_mapped_files && region.inode.is_some() || region.path.is_some() {
            return false;
        }
        if self.skip_readonly_regions
            && region.permissions.read
            && !region.permissions.write
            && !region.permissions.execute
        {
            return false;
        }
        true
    }
}

const MAX_BLOB_SIZE: u64 = 2 * (1024 * 1024);

/// Succesful result of the `dump_process_memory` action.
/// Represents a single (potentially partially) dumped
/// region of memory.
struct OkItem {
    /// PID of the process whose memory was dumped.
    pid: u32,
    /// Memory mapping that the dumped region belongs to.
    region: MappedRegion,
    /// Offset within the mapping that this dumped region starts at.
    offset: u64,
    /// Size of the dumped memory region. Can be less than `region.size()`
    /// if the region's size exceeds [`MAX_BLOB_SIZE`].
    size: u64,
    /// Sha256 digest of the dumped bytes that were sent to the blob sink.
    blob_sha256: [u8; 32],
}

enum ErrorKind {
    /// Failed to open the process' memory for reading.
    OpenMemory,
    /// Failed to read a single memory region.
    ReadRegionMemory(MappedRegion),
}

/// Represents an error returned by the `dump_process_memory` action.
struct ErrorItem {
    /// The PID whose memory dumping encountered an error.
    pid: u32,
    /// IO Error that caused this error.
    cause: std::io::Error,
    /// Type of error that was encountered.
    kind: ErrorKind,
}

/// Result of the `dump_process_memory` action.
type Item = Result<OkItem, ErrorItem>;

impl crate::response::Item for Item {
    type Proto = rrg_proto::dump_process_memory::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = Self::Proto::new();
        match self {
            Err(ErrorItem { pid, cause, kind }) => {
                proto.set_pid(pid);
                if let ErrorKind::ReadRegionMemory(region) = kind {
                    proto.set_region_start(region.start_address());
                    proto.set_region_end(region.end_address());
                }
                proto.set_error(cause.to_string());
            }
            Ok(OkItem {
                pid,
                region,
                blob_sha256,
                offset,
                size,
            }) => {
                proto.set_pid(pid);
                proto.set_region_start(region.start_address());
                proto.set_region_end(region.end_address());
                proto.set_blob_sha256(blob_sha256.into());
                proto.set_offset(offset);
                proto.set_size(size);
                proto.set_permissions(region.permissions.into());
                if let Some(path) = region.path {
                    proto.set_file_path(path.into());
                }
            }
        }
        proto
    }
}

/// Orders the memory regions yielded by `regions` such that
/// memory regions containing addresses in `offsets`
/// will come before those that don't.
/// The algorithm uses a [`VecDeque`] internally, and it is returned as-is
/// to avoid an O(n) shift operation that occurs when converting it to a [`Vec`].
pub fn sort_by_priority(
    regions: impl Iterator<Item = MappedRegion>,
    mut offsets: Vec<u64>,
) -> VecDeque<MappedRegion> {
    let mut deque = VecDeque::new();

    offsets.sort_unstable();
    // regions are already sorted by increasing address
    // they are also disjoint
    let mut regions = regions.peekable();

    for offset in offsets {
        while let Some(reg) = regions.peek()
            && reg.end_address() <= offset
        {
            // Haven't reached offset yet
            deque.push_back(regions.next().unwrap());
        }
        let Some(reg) = regions.next() else { break };
        if reg.start_address() > offset {
            // No region contains the offset
            deque.push_back(reg);
        } else {
            // Region contains offset
            deque.push_front(reg);
        }
    }
    // Add all remaining regions in whatever order they came in
    deque.extend(regions);
    deque
}

/// Reads the contents of all of process `pid`'s memory mappings
/// and sends them to the session.
/// `regions` and `memory` are passed as arguments for testability.
pub fn dump_regions<S, Mem>(
    session: &mut S,
    regions: impl Iterator<Item = MappedRegion>,
    memory: &mut Mem,
    pid: u32,
    total_size_left: &mut u64,
) -> crate::session::Result<()>
where
    S: crate::session::Session,
    Mem: MemoryReader,
{
    use sha2::Digest as _;

    'outer: for region in regions {
        let mut offset = region.start_address();
        while offset < region.end_address() {
            let offset_in_region = offset - region.start_address();
            let size = region.end_address() - offset;
            let size = size.min(MAX_BLOB_SIZE).min(*total_size_left);
            match memory.read_chunk(offset, size) {
                Err(cause) => {
                    session.reply(Err(ErrorItem {
                        pid,
                        cause,
                        kind: ErrorKind::ReadRegionMemory(region),
                    }))?;
                    continue 'outer;
                }
                Ok(buf) => {
                    // `read_chunk` could have read fewer than `size` bytes
                    let size = buf.len() as u64;
                    offset += size;
                    *total_size_left -= size;

                    let blob = crate::blob::Blob::from(buf);
                    let blob_sha256 = sha2::Sha256::digest(blob.as_bytes()).into();

                    session.send(crate::Sink::Blob, blob)?;
                    session.reply(Ok(OkItem {
                        pid,
                        offset: offset_in_region,
                        region: region.clone(),
                        blob_sha256,
                        size,
                    }))?;
                }
            }
            if *total_size_left == 0 {
                // Limit exceeded, bail out early
                break 'outer;
            }
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn handle<S>(_session: &mut S, _args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use std::io::{Error, ErrorKind};
    Err(crate::session::Error::action(Error::from(
        ErrorKind::Unsupported,
    )))
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn handle<S>(session: &mut S, mut args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let mut total_size_left = args.total_size_limit.unwrap_or(u64::MAX);
    // Circumvent borrow checker complaint about partial moves with `take`
    let pids = std::mem::take(&mut args.pids);
    for pid in pids {
        let regions = match MappedRegionIter::from_pid(pid) {
            Ok(regions) => regions,
            Err(cause) => {
                session.reply(Err(ErrorItem {
                    pid,
                    cause,
                    kind: ErrorKind::OpenMemory,
                }))?;
                continue;
            }
        };
        let mut memory = match ReadableProcessMemory::open(pid) {
            Ok(memory) => memory,
            Err(cause) => {
                session.reply(Err(ErrorItem {
                    pid,
                    cause,
                    kind: ErrorKind::OpenMemory,
                }))?;
                continue;
            }
        };

        // ParseRegionErrors are internal errors, so wrap them in `Error::action`
        // and bail early if any error is encountered.
        let regions: Vec<MappedRegion> = regions
            .map(|reg| reg.map_err(crate::session::Error::action))
            .collect::<Result<_, _>>()?;

        // priority_offsets can only be used if `pid.len() == 1`,
        // so we enforce that by `take`ing it here.
        // This too is a workaround for partial moves.
        let offsets = args.priority_offsets.take();
        let regions = regions.into_iter().filter(|reg| args.should_dump(reg));

        let regions = if let Some(offsets) = offsets {
            sort_by_priority(regions, offsets)
        } else {
            regions.collect()
        };

        dump_regions(
            session,
            regions.into_iter(),
            &mut memory,
            pid,
            &mut total_size_left,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeProcessMemory {
        contents: Vec<u8>,
    }

    impl MemoryReader for FakeProcessMemory {
        fn read_chunk(&mut self, offset: u64, length: u64) -> std::io::Result<Vec<u8>> {
            let start = offset as usize;
            let end = (offset + length) as usize;
            Ok(self.contents[start..end].to_owned())
        }
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn iterate_this_process_regions() {
        let pid = std::process::id();
        let iterator = MappedRegionIter::from_pid(pid)
            .expect("could not read memory regions of current process");
        let result = iterator.collect::<Result<Vec<MappedRegion>, _>>().unwrap();
        assert!(!result.is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn can_read_this_process_memory() {
        let pid = std::process::id();
        let regions: Vec<MappedRegion> = MappedRegionIter::from_pid(pid)
            .expect("could not read memory regions of current process")
            .collect::<Result<_, _>>()
            .expect("reading maps");

        let mut memory = ReadableProcessMemory::open(pid).expect("could not open process memory");
        assert! {
            regions.iter().any(|region| memory.read_chunk(
                region.start_address(),
                region.size(),
            ).is_ok())
        }
    }

    #[test]
    fn offset_priority() {
        let regions = [
            MappedRegion::from_bounds(0, 1000),
            MappedRegion::from_bounds(1000, 1500),
            MappedRegion::from_bounds(2000, 3000),
            MappedRegion::from_bounds(4000, 5000),
        ];
        // No offsets in first or last region, last offset is not contained in any region.
        let offsets = vec![1000, 2225, 6000];
        let regions: Vec<MappedRegion> = sort_by_priority(regions.into_iter(), offsets).into();

        assert_eq!(regions.len(), 4);

        let (prio, no_prio) = regions.split_at(2);
        // First half contains offsets
        assert!(prio.iter().any(|reg| reg.start_address() == 1000));
        assert!(prio.iter().any(|reg| reg.start_address() == 2000));
        assert!(prio.iter().all(|reg| reg.start_address() != 0));
        assert!(prio.iter().all(|reg| reg.start_address() != 4000));

        // Second half does not
        assert!(no_prio.iter().all(|reg| reg.start_address() != 1000));
        assert!(no_prio.iter().all(|reg| reg.start_address() != 2000));
        assert!(no_prio.iter().any(|reg| reg.start_address() == 0));
        assert!(no_prio.iter().any(|reg| reg.start_address() == 4000));
    }

    #[test]
    fn offset_priority_multiple_offset_same_region() {
        let regions = [
            MappedRegion::from_bounds(0, 1000),
            MappedRegion::from_bounds(1000, 1500),
            MappedRegion::from_bounds(2000, 3000),
            MappedRegion::from_bounds(4000, 5000),
        ];
        // Three offsets falling in the same region
        let offsets = vec![1000, 1200, 1300];
        let regions: Vec<MappedRegion> = sort_by_priority(regions.into_iter(), offsets).into();

        assert_eq!(regions.len(), 4);

        let (prio, no_prio) = regions.split_first().unwrap();
        assert_eq!(prio.start_address(), 1000);
        assert_eq!(prio.end_address(), 1500);

        assert!(no_prio.iter().all(|reg| reg.start_address() != 1000));
        assert!(no_prio.iter().any(|reg| reg.start_address() == 0));
        assert!(no_prio.iter().any(|reg| reg.start_address() == 4000));
    }

    #[test]
    fn offset_priority_offset_before_regions() {
        let regions = [
            MappedRegion::from_bounds(1000, 1500),
            MappedRegion::from_bounds(2000, 3000),
            MappedRegion::from_bounds(4000, 5000),
        ];
        // One offset that is before any region
        let offsets = vec![0];
        let regions: Vec<MappedRegion> = sort_by_priority(regions.into_iter(), offsets).into();

        // No guarantee about order, just check the contents
        assert_eq!(regions.len(), 3);
        assert!(regions.iter().any(|reg| reg.start_address() == 1000));
        assert!(regions.iter().any(|reg| reg.start_address() == 2000));
        assert!(regions.iter().any(|reg| reg.start_address() == 4000));
    }

    #[test]
    fn dumps_regions() {
        let regions = vec![
            MappedRegion::from_bounds(0, 1000),
            MappedRegion::from_bounds(1000, 3000),
            MappedRegion::from_bounds(3000, 3500),
        ];

        // Write fake memory contents and check that they're read correctly
        let mut fake_mem = Vec::new();
        fake_mem.extend(std::iter::repeat_n(1, 1000));
        fake_mem.extend(std::iter::repeat_n(2, 2000));
        fake_mem.extend(std::iter::repeat_n(3, 500));

        let mut memory = FakeProcessMemory { contents: fake_mem };

        let mut session = crate::session::FakeSession::new();
        let mut limit = u64::MAX;
        dump_regions(
            &mut session,
            regions.into_iter(),
            &mut memory,
            42000,
            &mut limit,
        )
        .unwrap();

        assert_eq!(session.reply_count(), 3);
        assert_eq!(session.parcel_count(crate::Sink::Blob), 3);

        let mut parcels = session.parcels::<crate::blob::Blob>(crate::Sink::Blob);
        assert!(parcels.next().unwrap().as_bytes().iter().all(|x| *x == 1));
        assert!(parcels.next().unwrap().as_bytes().iter().all(|x| *x == 2));
        assert!(parcels.next().unwrap().as_bytes().iter().all(|x| *x == 3));
    }

    #[test]
    fn size_limit() {
        let regions = vec![
            MappedRegion::from_bounds(0, 1000),
            MappedRegion::from_bounds(1000, 3000),
            MappedRegion::from_bounds(3000, 3500),
        ];

        // Write fake memory contents and check that they're read correctly
        let mut fake_mem = Vec::new();
        fake_mem.extend(std::iter::repeat_n(1, 1000));
        fake_mem.extend(std::iter::repeat_n(2, 2000));
        fake_mem.extend(std::iter::repeat_n(3, 500));

        let mut memory = FakeProcessMemory { contents: fake_mem };

        let mut session = crate::session::FakeSession::new();
        // Should dump first region fully, second partially
        let mut limit = 1175;
        dump_regions(
            &mut session,
            regions.into_iter(),
            &mut memory,
            42000,
            &mut limit,
        )
        .unwrap();

        assert_eq!(session.reply_count(), 2);
        assert_eq!(session.parcel_count(crate::Sink::Blob), 2);

        let mut replies = session.replies::<Item>().filter_map(|x| x.as_ref().ok());
        let first_region = replies.next().unwrap();
        let second_region = replies.next().unwrap();
        assert_eq!(first_region.size, 1000);
        assert_eq!(first_region.offset, 0);
        assert_eq!(first_region.region.start_address(), 0);
        assert_eq!(first_region.region.end_address(), 1000);

        assert_eq!(second_region.size, 175);
        assert_eq!(second_region.offset, 0);
        assert_eq!(second_region.region.start_address(), 1000);
        assert_eq!(second_region.region.end_address(), 3000);
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn handle_dumps_current_process_regions() {
        let mut session = crate::session::FakeSession::new();
        let args = Args {
            pids: vec![std::process::id()],
            // Set limit to keep unit test time reasonable
            total_size_limit: Some(10000),
            ..Default::default()
        };

        handle(&mut session, args).unwrap();

        assert!(session.reply_count() > 0);
        assert!(session.parcel_count(crate::Sink::Blob) > 0);
        assert!(session.reply_count() >= session.parcel_count(crate::Sink::Blob));
        assert!(session.replies::<Item>().any(Result::is_ok));
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn filters_regions() {
        let mut session = crate::session::FakeSession::new();
        let args = Args {
            pids: vec![std::process::id()],
            // Set limit to keep unit test time reasonable
            total_size_limit: Some(10000),
            skip_executable_regions: true,
            skip_shared_regions: true,
            ..Default::default()
        };

        handle(&mut session, args).unwrap();

        let replies = session.replies::<Item>().filter_map(|x| x.as_ref().ok());
        for item in replies {
            assert!(!item.region.permissions.execute);
            assert!(!item.region.permissions.shared);
        }
    }
}
