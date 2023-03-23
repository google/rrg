// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Returns an iterator yielding identifiers of all processes on the system.
pub fn ids() -> std::io::Result<impl Iterator<Item = std::io::Result<u32>>> {
    Ids::new()
}

/// A Windows-specific implementation of the iterator over process identifiers.
struct Ids {
    /// An iterator over the process identifiers returned by `EnumProcesses`.
    iter: std::vec::IntoIter<u32>,
}

impl Ids {

    /// Creates a new iterator over system process identifiers.
    fn new() -> std::io::Result<Ids> {
        use windows_sys::Win32::Foundation::*;

        let mut buf_cap = DEFAULT_PID_BUF_CAP;

        loop {
            let mut buf = Vec::with_capacity(buf_cap);
            let mut buf_size = std::mem::MaybeUninit::uninit();

            // SAFETY: We allocate the buffer above and pass its size (capacity
            // multiplied by the size of individual element). In case the buffer
            // is too small, the function should return an appropriate error.
            let status = unsafe {
                windows_sys::Win32::System::ProcessStatus::K32EnumProcesses(
                    buf.as_mut_ptr(),
                    (buf_cap * std::mem::size_of::<u32>()) as u32,
                    buf_size.as_mut_ptr(),
                )
            };

            if status == FALSE {
                // SAFETY: We are on Windows and the function should be safe to
                // call in all context.
                let code = unsafe { GetLastError() };

                // If the provided buffer is not big enough, we try again we a
                // one that is twice as big until we reach the limit and bail
                // out (which is handled be the error handler below).
                if code == ERROR_INSUFFICIENT_BUFFER {
                    buf_cap *= 2;
                    if buf_cap <= MAX_PID_BUF_CAP {
                        continue;
                    }
                }

                return Err(std::io::Error::from_raw_os_error(code as i32));
            }

            // SAFETY: The call to `EnumProcesses` succeeded, so the `buf_size`
            // variable should contain the number of bytes filled in the buffer.
            let buf_size = unsafe { buf_size.assume_init() } as usize;

            if buf_size % std::mem::size_of::<u32>() != 0 {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            let buf_len = buf_size / std::mem::size_of::<u32>();

            // SAFETY: Since `buf_size` contains the amount of bytes filled in
            // the buffer we can now safely set the length of the buffer.
            unsafe {
                buf.set_len(buf_len);
            }

            return Ok(Ids {
                iter: buf.into_iter()
            });
        }
    }
}

impl Iterator for Ids {

    type Item = std::io::Result<u32>;

    fn next(&mut self) -> Option<std::io::Result<u32>> {
        self.iter.next().map(Ok)
    }
}

/// The default capacity of the process identifiers buffer.
const DEFAULT_PID_BUF_CAP: usize = 1024;

/// The maximum capacity of the process identifiers buffer.
const MAX_PID_BUF_CAP: usize = 16384;
