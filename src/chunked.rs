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

use byteorder::BigEndian;

/// Encodes a given iterator over protobuf messages into the chunked format.
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
/// let data = vec! {
///     String::from("foo"),
///     String::from("bar"),
///     String::from("baz")
/// };
///
/// let mut stream = rrg::chunked::encode(data.into_iter());
/// let mut file = File::create("output.chunked").unwrap();
/// std::io::copy(&mut stream, &mut file).unwrap();
/// ```
pub fn encode<I>(iter: I) -> Encode<I>
where
    I: Iterator,
    I::Item: prost::Message,
{
    Encode {
        iter: iter,
        cur: std::io::Cursor::new(vec!()),
    }
}

/// Decodes a buffer in the chunked format into a stream of protobuf messages.
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
/// for (idx, msg) in rrg::chunked::decode(file).enumerate() {
///     let msg: String = msg.unwrap();
///     println!("message #{}: {:?}", idx, msg);
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
/// It implements the `Read` trait, lazily polling the underlying iterator over
/// Protocol Buffers messages as needed.
///
/// Instances of this type can be constructed using the [`encode`] function.
///
/// [`encode`]: fn.encode.html
pub struct Encode<I> {
    iter: I,
    cur: std::io::Cursor<Vec<u8>>,
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

    /// Pulls another message from the underlying iterator.
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
/// It implements the `Iterator` trait yielding Protocol Buffers messages,
/// lazily decoding data from the underlying buffer.
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

        // `read` might not always read all 8 bytes. On the other hand, we also
        // cannot use just `read_exact` because the stream might have ended
        // already. Hence, we combine the two. First we attempt to read some
        // bytes with `read`: it should either return 0 (indicating end of the
        // stream), 8 (indicating that we have filled the whole buffer fully)
        // or something in between. In the last case, we use `read_exact to get
        // the remaining bytes (which should be non-zero now).
        let mut buf = [0; 8];
        match self.reader.read(&mut buf[..])? {
            8 => (),
            0 => return Ok(None),
            len => self.reader.read_exact(&mut buf[len..])?,
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
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    pub fn test_decode_zero_size_tag() {
        let buf: &[u8] = b"\x00\x00\x00\x00\x00\x00\x00\x00";

        let mut iter = decode(buf).map(Result::unwrap);

        assert_eq!(iter.next(), Some(()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    pub fn test_decode_partial_size_tag() {

        // A simple reader that yields a 0-valued size tag byte by byte.
        struct Reader(u8);

        impl std::io::Read for Reader {

            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0 == 8 {
                    Ok(0)
                } else {
                    buf[0] = 0;
                    self.0 += 1;
                    Ok(1)
                }
            }
        }

        let mut iter = decode(Reader(0)).map(Result::unwrap);

        assert_eq!(iter.next(), Some(()));
        assert_eq!(iter.next(), None);
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
        let mut iter = decode(encode(std::iter::once(String::from("foo"))))
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(String::from("foo")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    pub fn test_encode_and_decode_single_unit_message() {
        let mut iter = decode(encode(std::iter::once(())))
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
