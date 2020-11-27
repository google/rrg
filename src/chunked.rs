// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Utilities for working with the chunked format.
//!
//! The chunked file format is extremely simple serialization procedure where
//! each chunk of raw bytes is prepended with the size of the chunk (as 64-bit
//! unsigned big-endian integer).
//!
//! Its primary application is streaming encoding and decoding of blobs of data
//! in formats that do not support or are inefficient for these purposes (such
//! as serialized Protocol Buffer messages).

use std::io::Cursor;

use byteorder::BigEndian;

/// Encodes a given iterator over binary blobs into the chunked format.
///
/// This is a streaming encoder and performs the encoding in a lazy way. It
/// should compose well with other streaming encoders (e.g. these offered by
/// the [`flate2`] crate).
///
/// [`flate2`]: https://crates.io/crates/flate2
///
/// # Examples
///
/// ```no_run
/// use std::fs::File;
///
/// let data = [b"foo", b"bar", b"baz"];
///
/// let mut stream = rrg::chunked::encode(data.iter().map(|blob| &blob[..]));
/// let mut file = File::create("output.chunked").unwrap();
/// std::io::copy(&mut stream, &mut file).unwrap();
/// ```
pub fn encode<I, M>(iter: I) -> Encode<I>
where
    I: Iterator<Item = M>,
    M: prost::Message,
{
    Encode {
        iter: iter,
        cur: Cursor::new(vec!()),
    }
}

/// Decodes a buffer in the chunked format into binary blobs.
///
/// This is a streaming decoder and performs the decoding in a lazy way. It
/// should compose well with other streaming decoders (e.g. these offered by the
/// [`flate2`] crate).
///
/// [`flate2`]: https://crates.io/crates/flate2
///
/// # Examples
///
/// ```no_run
/// use std::fs::File;
///
/// let file = File::open("input.chunked").unwrap();
/// for (idx, blob) in rrg::chunked::decode(file).enumerate() {
///     println!("blob #{}: {:?}", idx, blob.unwrap());
/// }
/// ```
pub fn decode<R, M>(buf: R) -> Decode<R, M>
where
    R: std::io::Read,
    M: prost::Message,
{
    Decode {
        reader: buf,
        buf: vec!(),
        marker: std::marker::PhantomData,
    }
}

/// Streaming encoder for the chunked format.
///
/// It implements the `Read` trait, lazily polling the underlying chunk iterator
/// as more bytes is needed.
///
/// Instances of this type can be constructed using the [`encode`] function.
///
/// [`encode`]: fn.encode.html
pub struct Encode<I> {
    iter: I,
    cur: Cursor<Vec<u8>>,
}

impl<I, M> Encode<I>
where
    I: Iterator<Item = M>,
    M: prost::Message,
{
    /// Checks whether all the data from the underlying cursor has been read.
    fn is_empty(&self) -> bool {
        self.cur.position() == self.cur.get_ref().len() as u64
    }

    /// Pulls another blob of data from the underlying iterator.
    fn pull(&mut self) -> std::io::Result<()> {
        use byteorder::WriteBytesExt as _;

        let msg = match self.iter.next() {
            Some(msg) => msg,
            None => return Ok(()),
        };

        self.cur.get_mut().clear();
        self.cur.set_position(0);

        self.cur.write_u64::<BigEndian>(msg.encoded_len() as u64)?;
        msg.encode(&mut self.cur.get_mut())?;
        self.cur.set_position(0);

        Ok(())
    }
}

impl<I, M> std::io::Read for Encode<I>
where
    I: Iterator<Item = M>,
    M: prost::Message,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.is_empty() {
            self.pull()?;
        }

        self.cur.read(buf)
    }
}

/// Streaming decoder for the chunked format.
///
/// It implements the `Iterator` trait yielding chunks of decoded blobs, lazily
/// decoding data from the underlying buffer.
///
/// Instances of this type can be constructed using the [`decode`] function.
///
/// [`decode`]: fn.decode.html
pub struct Decode<R, M> {
    reader: R,
    buf: Vec<u8>,
    marker: std::marker::PhantomData<M>,
}

impl<R: std::io::Read, M> Decode<R, M> {

    /// Reads a size tag from the underlying buffer.
    ///
    /// It will return `None` if the is no more data in the buffer.
    fn read_len(&mut self) -> std::io::Result<Option<usize>> {
        use byteorder::ReadBytesExt as _;

        let mut buf = [0; 8];
        match self.reader.read(&mut buf[..])? {
            8 => (),
            0 => return Ok(None),
            _ => return Err(SizeTagError.into()),
        }

        let len = (&buf[..]).read_u64::<BigEndian>()? as usize;
        Ok(Some(len))
    }
}

impl<R, M> Iterator for Decode<R, M>
where
    R: std::io::Read,
    M: prost::Message + Default,
{
    type Item = std::io::Result<M>;

    fn next(&mut self) -> Option<std::io::Result<M>> {
        let len = match self.read_len() {
            Ok(Some(len)) => len,
            Ok(None) => return None,
            Err(error) => return Some(Err(error)),
        };

        self.buf.resize(len, u8::default());
        match self.reader.read_exact(&mut self.buf[..]) {
            Ok(()) => (),
            Err(error) => return Some(Err(error)),
        }

        let msg = match M::decode(&self.buf[..]) {
            Ok(msg) => msg,
            Err(error) => return Some(Err(error.into())),
        };

        Some(Ok(msg))
    }
}

/// An error type for errors encountered when reading the size tag.
#[derive(Debug)]
struct SizeTagError;

impl std::fmt::Display for SizeTagError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "incorrect length of the size tag")
    }
}

impl std::error::Error for SizeTagError {
}

impl From<SizeTagError> for std::io::Error {

    fn from(error: SizeTagError) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, error)
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    pub fn test_encode_empty_iter() {
        use std::io::Read as _;

        let mut stream = encode(std::iter::empty::<()>());

        let mut output = vec!();
        stream.read_to_end(&mut output).unwrap();

        assert!(output.is_empty());
    }

    #[test]
    pub fn test_decode_empty_buf() {
        let buf: &[u8] = b"";
        let mut iter = decode::<_, ()>(buf);

        assert!(iter.next().is_none());
    }

    #[test]
    pub fn test_decode_incorrect_size_tag() {
        let buf: &[u8] = b"\x12\x34\x56";
        let mut iter = decode::<_, ()>(buf);

        let error = iter.next().unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    pub fn test_decode_short_input() {
        let buf: &[u8] = b"\x00\x00\x00\x00\x00\x00\x00\x42foo";
        let mut iter = decode::<_, ()>(buf);

        let error = iter.next().unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    pub fn test_encode_and_decode_single_message() {
        let mut iter = decode(encode(vec!(String::from("foo")).into_iter()))
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(String::from("foo")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    pub fn test_encode_and_decode_single_unit_message() {
        let mut iter = decode(encode(vec!(()).into_iter()))
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    pub fn test_encode_and_decode_multiple_messages() {
        let msgs = vec! {
            b"foo".to_vec(),
            b"bar".to_vec(),
            b"baz".to_vec(),
        };

        let mut iter = decode(encode(msgs.into_iter()))
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(b"foo".to_vec()));
        assert_eq!(iter.next(), Some(b"bar".to_vec()));
        assert_eq!(iter.next(), Some(b"baz".to_vec()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    pub fn test_encode_and_decode_multiple_unit_messages() {
        let msgs = vec!((), (), ());

        let mut iter = decode(encode(msgs.into_iter()))
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(()));
        assert_eq!(iter.next(), Some(()));
        assert_eq!(iter.next(), Some(()));
        assert_eq!(iter.next(), None);
    }
}
