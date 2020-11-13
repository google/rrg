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
/// On success, the total number of bytes copied from `reader` to `writer` is
/// returned.
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
    -> Result<u64>
where
    R: Read,
    W: Write,
    P: FnMut(&R, &W) -> bool,
{
    let mut buf = [0; DEFAULT_BUF_SIZE];
    let mut written = 0;

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
        written += len as u64;
    }

    Ok(written)
}

/// An reader implementation for a stream of readers.
///
/// It turns a stream of `Read` instances into one `Read` instance where bytes
/// are pulled sequentially from underlying readers. Once the first reader ends,
/// the next one starts to be read and so on.
///
/// # Examples
///
/// ```
/// use std::io::Read as _;
///
/// let items: Vec<&[u8]> = vec!(b"foo", b"bar", b"baz");
/// let mut reader = rrg::io::IterReader::new(items.into_iter());
///
/// let mut buf = vec!();
/// reader.read_to_end(&mut buf).unwrap();
///
/// assert_eq!(buf, b"foobarbaz");
/// ```
pub struct IterReader<I, R> {
    /// Underlying iterator with pending readers.
    iter: I,
    /// Currently active reader.
    curr: Option<R>,
}

impl<I, R> IterReader<I, R>
where
    I: Iterator<Item=R>,
    R: Read,
{
    /// Constructs a new iterator reader.
    pub fn new(iter: I) -> IterReader<I, R> {
        IterReader {
            iter: iter,
            curr: None,
        }
    }
}

impl<I, R> Read for IterReader<I, R>
where
    I: Iterator<Item=R>,
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.curr.is_none() {
                self.curr = self.iter.next();
            }

            // If after executing the previous line there is still no current
            // buffer to read from, it means the underlying iterator is finished
            // and there is no more data.
            let curr = match self.curr {
                Some(ref mut buf) => buf,
                None => return Ok(0),
            };

            // If we read 0 bytes from the current buffer, it means it is empty
            // now. By setting it to `None`, we will try to pull a new one in
            // the next iteration.
            match curr.read(buf)? {
                0 => self.curr = None,
                len => return Ok(len),
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_copy_until_with_empty_buffer() {
        let mut reader: &[u8] = b"";
        let mut writer = vec!();

        let result = copy_until(&mut reader, &mut writer, |_, _| false);
        assert_eq!(result.unwrap(), 0);
        assert_eq!(writer, b"");
    }

    #[test]
    fn test_copy_until_begin() {
        let mut reader: &[u8] = b"foobar";
        let mut writer = vec!();

        let result = copy_until(&mut reader, &mut writer, |_, _| true);
        assert_eq!(result.unwrap(), 0);
        assert_eq!(writer, b"");
    }

    #[test]
    fn test_copy_until_end() {
        let mut reader: &[u8] = b"foobar";
        let mut writer = vec!();

        let result = copy_until(&mut reader, &mut writer, |_, _| false);
        assert_eq!(result.unwrap(), 6);
        assert_eq!(writer, b"foobar");
    }

    #[test]
    fn test_copy_until_specific_size() {
        let limit = 4 * 1024 * 1024;

        let mut reader = std::io::repeat(0x42);
        let mut writer = vec!();

        // This should verify that copying eventually stops after the condition
        // is met since the reader is infinite.
        assert! {
            copy_until(&mut reader, &mut writer, |_, writer| {
                writer.len() > limit
            }).is_ok()
        };

        assert!(writer.iter().all(|item| *item == 0x42));
        assert!(writer.len() > limit);
    }

    #[test]
    fn test_iter_reader_with_empty_iter() {
        let mut reader = IterReader::new(std::iter::empty::<&[u8]>());
        let mut buf = vec!();
        reader.read_to_end(&mut buf).unwrap();

        assert_eq!(buf, b"");
    }

    #[test]
    fn test_iter_reader_with_empty_iter_items() {
        let items: Vec<&[u8]> = vec!(b"", b"", b"");

        let mut reader = IterReader::new(items.into_iter());
        let mut buf = vec!();
        reader.read_to_end(&mut buf).unwrap();

        assert_eq!(buf, b"");
    }

    #[test]
    fn test_iter_reader_with_single_iter_item() {
        let items: Vec<&[u8]> = vec!(b"foo");

        let mut reader = IterReader::new(items.into_iter());
        let mut buf = vec!();
        reader.read_to_end(&mut buf).unwrap();

        assert_eq!(buf, b"foo");
    }

    #[test]
    fn test_iter_reader_with_multiple_iter_items() {
        let items: Vec<&[u8]> = vec!(b"foo", b"bar", b"baz");

        let mut reader = IterReader::new(items.into_iter());
        let mut buf = vec!();
        reader.read_to_end(&mut buf).unwrap();

        assert_eq!(buf, b"foobarbaz");
    }
}
