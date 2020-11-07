// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::io::{Read, Write, Result};

pub fn copy_until<R, W, P>(reader: &mut R, writer: &mut W, mut pred: P)
    -> Result<()>
where
    R: Read,
    W: Write,
    P: FnMut(&R, &W) -> bool,
{
    // TODO: Move the magic number to a constant.
    let mut buf = [0; 1024];
    loop {
        // TODO: Retry on interrupted errors (just like `std::io::copy` does).
        let size = reader.read(&mut buf[..])?;
        if size == 0 {
            break;
        }

        writer.write_all(&buf[..size])?;
        if pred(reader, writer) {
            break;
        }
    }

    Ok(())
}

// TODO: Write tests.
