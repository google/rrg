// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Extensions to the standard I/O utilities.
//!
//! This module essentially provides useful, RRG-specific utilities that are not
//! available in `std::io`, mostly operating on the standard `Read` and `Write`
//! traits.

use std::io::{Read, Write, Result};

// The same as in the Rust's standard library.
const DEFAULT_BUF_SIZE: usize = 8 * 1024;

/// Copies contents of one buffer into the other until a condition is met.
///
/// This function should behave similarly to the standard `std::io::copy` with
/// the difference that it can be given a condition when copying should stop.
///
/// Note that the predicate is not checked after each copied byte. Therefore,
/// there are no guarantees about when exactly and how often it will be called.
///
/// # Errors
///
/// The errors is reported immediately if there is an error when reading from
/// the input or writing to the output.
///
/// Like `std::io::copy`, this function will retry instances of `Interrupted`
/// errors.
///
/// # Examples
///
/// ```no_run
/// use std::fs::File;
///
/// let mut rand = File::open("/dev/random").unwrap();
/// let mut buf = vec!();
///
/// rrg::io::copy_until(&mut rand, &mut buf, |_, writer| writer.len() >= 1024);
///
/// println!("random bytes: {:?}", buf);
/// ```
pub fn copy_until<R, W, P>(reader: &mut R, writer: &mut W, mut pred: P)
    -> Result<()>
where
    R: Read,
    W: Write,
    P: FnMut(&R, &W) -> bool,
{
    let mut buf = [0; DEFAULT_BUF_SIZE];
    loop {
        if pred(reader, writer) {
            break;
        }

        use std::io::ErrorKind::*;
        let len = match reader.read(&mut buf[..]) {
            Ok(0) => break,
            Ok(len) => len,
            Err(ref error) if error.kind() == Interrupted => continue,
            Err(error) => return Err(error),
        };

        writer.write_all(&buf[..len])?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_copy_until_with_empty_buffer() {
        let mut reader: &[u8] = b"";
        let mut writer = vec!();

        assert!(copy_until(&mut reader, &mut writer, |_, _| false).is_ok());
        assert_eq!(writer, b"");
    }

    #[test]
    fn test_copy_until_begin() {
        let mut reader: &[u8] = b"foobar";
        let mut writer = vec!();

        assert!(copy_until(&mut reader, &mut writer, |_, _| true).is_ok());
        assert_eq!(writer, b"");
    }

    #[test]
    fn test_copy_until_end() {
        let mut reader: &[u8] = b"foobar";
        let mut writer = vec!();

        assert!(copy_until(&mut reader, &mut writer, |_, _| false).is_ok());
        assert_eq!(writer, b"foobar");
    }

    #[test]
    fn test_copy_until_specific_size() {
        let limit = 4 * 1024 * 1024;

        // An infinite stream of zeros (see explanation below).
        struct Null;

        impl std::io::Read for Null {

            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                // TODO: Rewriter with `slice::fill` once it stabilizes.
                for item in buf.iter_mut() {
                    *item = 0;
                }

                Ok(buf.len() as usize)
            }
        }

        let mut reader = Null;
        let mut writer = vec!();

        // This should verify that copying eventually stops after the condition
        // is met since the reader is inifite.
        assert! {
            copy_until(&mut reader, &mut writer, |_, writer| {
                writer.len() > limit
            }).is_ok()
        }

        assert!(writer.iter().all(|item| *item == 0));
        assert!(writer.len() > limit);
    }
}
