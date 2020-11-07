// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::io::{Read, Write, Result};

// The same as in the Rust's standard library.
const DEFAULT_BUF_SIZE: usize = 8 * 1024;

pub fn copy_until<R, W, P>(reader: &mut R, writer: &mut W, mut pred: P)
    -> Result<()>
where
    R: Read,
    W: Write,
    P: FnMut(&R, &W) -> bool,
{
    let mut buf = [0; DEFAULT_BUF_SIZE];
    loop {
        use std::io::ErrorKind::*;
        let len = match reader.read(&mut buf[..]) {
            Ok(0) => break,
            Ok(len) => len,
            Err(ref error) if error.kind() == Interrupted => continue,
            Err(error) => return Err(error),
        };

        writer.write_all(&buf[..len])?;
        if pred(reader, writer) {
            break;
        }
    }

    Ok(())
}

// TODO: Write tests.
