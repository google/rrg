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

/// Buffered reader for efficent line reading.
///
/// This object works similarly to [`std::io::BufReader`] but is tailored for
/// line reading capabilities.
pub struct LineReader<R: Read> {
    /// Content source to read from.
    inner: R,
    /// Buffer that we use for reading.
    buf: Box<[u8]>,
    /// Number of elements of `buf` that are actually available.
    buf_fill_len: usize,
}

impl<R: Read> LineReader<R> {

    /// Creates a new `LineReader` with default buffer capacity.
    ///
    /// See also [`std::io::BufReader::new`].
    pub fn new(inner: R) -> LineReader<R> {
        LineReader::with_capacity(DEFAULT_BUF_SIZE, inner)
    }

    /// Creates a new `LineReader` with the specified buffer capacity.
    ///
    /// See also [`std::io::BufReader::with_capacity`].
    pub fn with_capacity(capacity: usize, inner: R) -> LineReader<R> {
        LineReader {
            inner,
            buf: vec![0; capacity].into_boxed_slice(),
            buf_fill_len: 0,
        }
    }

    /// Reads all bytes until a newline (the `0xA` byte) is reached, and appends
    /// them to the provided `String` buffer.
    ///
    /// Unlike [`std::io::BufRead::read_line`], this method does not fail when
    /// an invalid UTF-8 sequence is encountered but instead uses [lossy UTF8
    /// conversion][1].which replaces such sequences with [`U+FFFD REPLACEMENT
    /// CHARACTER`][2].
    ///
    /// # Errors
    ///
    /// This function will fail if an I/O error is raised when reading data. In
    /// such cases `buf` may contain some new bytes that were read so far.
    ///
    /// [1]: std::string::String::from_utf8_lossy
    /// [2]: std::char::REPLACEMENT_CHARACTER
    pub fn read_line_lossy(&mut self, buf: &mut String) -> std::io::Result<usize> {
        let mut len = 0;

        loop {
            // We may have a line feed somewhere in our buffer already. In such
            // a case, we extend the result buffer with content up until that
            // point and advance the internal buffer accordingly.
            if let Some(pos) = self.buf[..self.buf_fill_len].iter().position(|byte| *byte == b'\n') {
                buf.push_str(&String::from_utf8_lossy(&self.buf[..pos + 1]));
                len += pos + 1;

                self.buf.rotate_left(pos + 1);
                self.buf_fill_len -= pos + 1;
                return Ok(len);
            }

            // There is no line feed in our buffer. Thus, we put everything we
            // have to the result string and fill it again with new content.
            buf.push_str(&String::from_utf8_lossy(&self.buf[..self.buf_fill_len]));
            len += self.buf_fill_len;

            self.buf_fill_len = 0;
            loop {
                match self.inner.read(&mut self.buf) {
                    Ok(0) => {
                        // We reached the end of the input without finding any
                        // line feed character.
                        return Ok(len);
                    }
                    Ok(len) => {
                        self.buf_fill_len = len;
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                        // We do what the standard library does in case reads to a
                        // buffer fail with interruption errors: we try again.
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }
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
    fn line_reader_empty() {
        let mut reader = LineReader::new("".as_bytes());
        let mut line = String::new();

        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 0);
        assert_eq!(line, "");
    }

    #[test]
    fn line_reader_one_line_without_line_feed() {
        let mut reader = LineReader::new("foo".as_bytes());
        let mut line = String::new();

        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 3);
        assert_eq!(line, "foo");
    }

    #[test]
    fn line_reader_one_line_with_line_feed() {
        let mut reader = LineReader::new("foo\n".as_bytes());
        let mut line = String::new();

        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 4);
        assert_eq!(line, "foo\n");
    }

    #[test]
    fn line_reader_many_lines() {
        let mut reader = LineReader::new("foo\nbar\nbaz".as_bytes());
        let mut line = String::new();

        line.clear();
        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 4);
        assert_eq!(line, "foo\n");

        line.clear();
        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 4);
        assert_eq!(line, "bar\n");

        line.clear();
        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 3);
        assert_eq!(line, "baz");
    }

    #[test]
    fn line_reader_small_capacity_one_line_without_line_feed() {
        let mut reader = LineReader::with_capacity(2, "quux".as_bytes());
        let mut line = String::new();

        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 4);
        assert_eq!(line, "quux");
    }

    #[test]
    fn line_reader_small_capacity_one_line_with_line_feed() {
        let mut reader = LineReader::with_capacity(2, "quux\n".as_bytes());
        let mut line = String::new();

        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 5);
        assert_eq!(line, "quux\n");
    }

    #[test]
    fn line_reader_small_capacity_many_lines() {
        let mut reader = LineReader::with_capacity(2, "foo\nbar\nbaz".as_bytes());
        let mut line = String::new();

        line.clear();
        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 4);
        assert_eq!(line, "foo\n");

        line.clear();
        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 4);
        assert_eq!(line, "bar\n");

        line.clear();
        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 3);
        assert_eq!(line, "baz");
    }

    #[test]
    fn line_reader_invalid_utf8_without_line_feed() {
        let mut reader = LineReader::new(&b"ba\xF0\x90\x80"[..]);
        let mut line = String::new();

        line.clear();
        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 5);
        assert_eq!(line, "ba�");
    }

    #[test]
    fn line_reader_invalid_utf8_with_line_feed() {
        let mut reader = LineReader::new(&b"ba\xF0\x90\x80\n"[..]);
        let mut line = String::new();

        line.clear();
        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 6);
        assert_eq!(line, "ba�\n");
    }

    #[test]
    fn line_reader_append() {
        let mut reader = LineReader::new("content".as_bytes());
        let mut line = String::from("prefix");

        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 7);
        assert_eq!(line, "prefixcontent");
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
