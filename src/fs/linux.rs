// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::path::Path;

pub fn flags<P>(path: P) -> std::io::Result<u32> where
    P: AsRef<Path>
{
    let file = std::fs::File::open(path)?;

    let mut flags = 0;
    let code = unsafe {
        use std::os::unix::io::AsRawFd as _;
        ioctls::fs_ioc_getflags(file.as_raw_fd(), &mut flags)
    };

    if code == 0 {
        Ok(flags as u32)
    } else {
        Err(std::io::Error::from_raw_os_error(code))
    }
}
