// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Extensions to the standard I/O utilities.
//!
//! This module essentially provides useful, RRG-specific utilities that are not
//! available in `std::io`, mostly operating on the standard `Read` and `Write`
//! traits.

use std::io::Read;

// The same as in the Rust's standard library.
const DEFAULT_BUF_SIZE: usize = 8 * 1024;

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
    /// Limit on the length of a single line that the reader can read.
    max_line_len: usize,
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
            max_line_len: usize::MAX,
        }
    }

    /// Sets the limit on the length of a single line that the reader can read.
    ///
    /// This is useful to avoid situation in which a large file without any line
    /// feed characters can cause the memory to be completely exhausted when
    /// trying to read the line.
    pub fn with_max_line_len(mut self, len: usize) -> LineReader<R> {
        self.max_line_len = len;
        self
    }

    /// Reads all bytes until a newline (the `0xA` byte) is reached, and appends
    /// them to the provided `String` buffer.
    ///
    /// Unlike [`std::io::BufRead::read_line`], this method does not fail when
    /// an invalid UTF-8 sequence is encountered but instead uses [lossy UTF-8
    /// conversion][1], which replaces such sequences with [`U+FFFD REPLACEMENT
    /// CHARACTER`][2].
    ///
    /// # Errors
    ///
    /// This function will fail if an I/O error is raised when reading data. In
    /// such cases `buf` may contain some new bytes that were read so far.
    ///
    /// This will also fail if the line length limit was specified and the line
    /// being read exceeds it.
    ///
    /// [1]: std::string::String::from_utf8_lossy
    /// [2]: std::char::REPLACEMENT_CHARACTER
    pub fn read_line_lossy(&mut self, buf: &mut String) -> std::io::Result<usize> {
        let mut len = 0;

        loop {
            // We may have a line feed somewhere in our buffer already. In such
            // a case, we extend the result buffer with content up until that
            // point (provided that the length limit is not exceeted) and
            // advance the internal buffer accordingly.
            if let Some(pos) = self.buf[..self.buf_fill_len].iter().position(|byte| *byte == b'\n') {
                if len + pos + 1 > self.max_line_len {
                    return Err(std::io::Error::other(MaxLineLenError(self.max_line_len)));
                }

                buf.push_str(&String::from_utf8_lossy(&self.buf[..pos + 1]));
                len += pos + 1;

                self.buf.rotate_left(pos + 1);
                self.buf_fill_len -= pos + 1;
                return Ok(len);
            }

            // There is no line feed in our buffer. Thus, we put everything we
            // have to the result string (provided that the length limit is not
            // exceeded) and fill it again with new content.

            if len + self.buf_fill_len > self.max_line_len {
                return Err(std::io::Error::other(MaxLineLenError(self.max_line_len)));
            }

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

#[derive(Debug)]
struct MaxLineLenError(usize);

impl std::fmt::Display for MaxLineLenError {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "maximum line length ({} bytes) exceeded", self.0)
    }
}

impl std::error::Error for MaxLineLenError {
}

#[cfg(test)]
mod tests {

    use super::*;

    use quickcheck::quickcheck;

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
    fn line_reader_small_max_line_len_one_line_without_line_feed() {
        let mut reader = LineReader::new("foo".as_bytes())
            .with_max_line_len(2);

        let error = reader.read_line_lossy(&mut String::new())
            .unwrap_err().into_inner().unwrap()
            .downcast::<MaxLineLenError>().unwrap();
        assert!(matches!(error.as_ref(), MaxLineLenError(2)));
    }

    #[test]
    fn line_reader_small_max_line_len_one_line_with_line_feed() {
        let mut reader = LineReader::new("foo\n".as_bytes())
            .with_max_line_len(3);

        let error = reader.read_line_lossy(&mut String::new())
            .unwrap_err().into_inner().unwrap()
            .downcast::<MaxLineLenError>().unwrap();
        assert!(matches!(error.as_ref(), MaxLineLenError(3)));
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
    fn line_reader_empty_lines() {
        let mut reader = LineReader::new("\n\nfoo\n\n".as_bytes());
        let mut line = String::new();

        line.clear();
        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 1);
        assert_eq!(line, "\n");

        line.clear();
        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 1);
        assert_eq!(line, "\n");

        line.clear();
        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 4);
        assert_eq!(line, "foo\n");

        line.clear();
        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 1);
        assert_eq!(line, "\n");

        line.clear();
        assert_eq!(reader.read_line_lossy(&mut line).unwrap(), 0);
        assert_eq!(line, "");
    }

    quickcheck! {

        fn line_reader_joined_lines(strings: Vec<String>) -> quickcheck::TestResult {
            // This property holds only for strings without line feed chars as
            // otherwise an input string can get an extra split when reading.
            if strings.iter().any(|string| string.contains('\n')) {
                return quickcheck::TestResult::discard();
            }

            let mut content = strings.join("\n");
            content.push('\n');

            let mut reader = LineReader::new(content.as_bytes());
            let mut line = String::new();

            for string in &strings {
                line.clear();
                if reader.read_line_lossy(&mut line).unwrap() != string.len() + 1 {
                    return quickcheck::TestResult::failed();
                }
                if line != format!("{string}\n") {
                    return quickcheck::TestResult::failed();
                }
            }

            quickcheck::TestResult::passed()
        }
    }
}
