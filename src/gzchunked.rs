// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Utilities for working with streams in the gzchunked format.
//!
//! gzchunked is a simple file format used for storing large sequences of
//! Protocol Buffers messages. A gzchunked file consists of multiple parts where
//! each part is a gzipped fragment of a stream encoded in the [chunked] format.
//!
//! A high-level pseudocode for encoding and decoding procedures of the
//! gzchunked format can be described using the following formulae:
//!
//!   * _encode(protos) = map(gzip, partition(chunk(protos)))_
//!   * _decode(parts) = unchunk(join(map(ungzip, parts)))_
//!
//! This pseudocode uses the following subroutines:
//!
//!   * _chunk_ encodes a sequence of proto messages into the chunked format.
//!   * _unchunk_ decodes a chunked stream into a sequence of messages.
//!   * _partition_ divides a stream of bytes into multiple parts.
//!   * _join_ sequentially combines multiple byte streams into one.
//!   * _gzip_ encodes a byte stream into the gzip format.
//!   * _ungzip_ decodes a byte stream from the gzip format.
//!
//! [chunked]: crate::chunked

/// Encodes the given iterator over protobuf messages into the gzchunked format.
///
/// This is a streaming encoder that lazily encodes the data and can be used to
/// effectively process megabytes of data. The function returns an iterator that
/// yields parts of the gzchunked file.
///
/// This variant uses default encoding settings. To customize them, one can use
/// the [`encode_with_opts`] function.
///
/// [`encode_with_opts`]: fn.encode_with_opts.html
///
/// # Examples
///
/// ```no_run
/// use std::fs::File;
/// use std::io::Write as _;
///
/// let items = vec! {
///     String::from("foo"),
///     String::from("bar"),
///     String::from("baz"),
/// };
///
/// let chunks = rrg::gzchunked::encode(items.into_iter());
/// for (idx, chunk) in chunks.enumerate() {
///     let mut file = File::open(format!("output.gzc.{}", idx)).unwrap();
///     file.write_all(chunk.unwrap().as_slice());
/// }
/// ```
pub fn encode<I>(iter: I) -> Encode<I>
where
    I: Iterator,
    I::Item: prost::Message,
{
    encode_with_opts(iter, EncodeOpts::default())
}

/// Encodes the given iterator over protobuf messages into the gzchunked format.
///
/// This is a variant of the [`encode`] function that allows customization of
/// encoding parameters. Refer to its documentation for more details.
///
/// [`encode`]: fn.encode.html
pub fn encode_with_opts<I>(iter: I, opts: EncodeOpts) -> Encode<I>
where
    I: Iterator,
    I::Item: prost::Message,
{
    Encode::with_opts(iter, opts)
}

/// Decodes an iterator over gzchunked file parts into a stream of messages.
///
/// This is a streaming decoder that performs the decoding in a lazy way and can
/// be used to effectively process megabytes of data.
///
/// # Examples
///
/// ```no_run
/// use std::fs::File;
///
/// let paths = ["foo.gzc.1", "foo.gzc.2", "foo.gzc.3"];
/// let files = paths.iter().map(|path| File::open(path).unwrap());
///
/// for (idx, msg) in rrg::gzchunked::decode(files).enumerate() {
///     let msg: String = msg.unwrap();
///     println!("item #{}: {:?}", idx, msg);
/// }
/// ```
pub fn decode<I, M>(iter: I) -> impl Iterator<Item=std::io::Result<M>>
where
    I: Iterator,
    I::Item: std::io::Read,
    M: prost::Message + Default,
{
    let parts = iter.map(flate2::read::GzDecoder::new);
    crate::chunked::decode(crate::io::IterReader::new(parts))
}

/// A type describing compression level of a gzchunked output stream.
#[derive(Clone, Copy, Debug)]
pub struct Compression(flate2::Compression);

impl Compression {

    /// Creates a new compression descriptor at the specified level.
    ///
    /// The lower the number the worse the compression (with 0 meaning no
    /// compression at all).
    pub fn new(level: u32) -> Compression {
        Compression(flate2::Compression::new(level))
    }

    /// Creates a new compression descriptor with disabled compression.
    pub fn none() -> Compression {
        Compression(flate2::Compression::none())
    }

    /// Creates a new compression descriptor with highest compression.
    pub fn best() -> Compression {
        Compression(flate2::Compression::best())
    }
}

impl Default for Compression {

    fn default() -> Compression {
        Compression(flate2::Compression::new(5))
    }
}

/// Options and flags that configure encoding into the gzchuned format.
#[derive(Clone, Copy, Debug)]
pub struct EncodeOpts {
    /// Compression level used for the gzip encoding.
    pub compression: Compression,
    /// A rough file size limit for parts of the output file.
    pub part_size: u64,
}

impl Default for EncodeOpts {

    fn default() -> EncodeOpts {
        EncodeOpts {
            compression: Compression::default(),
            part_size: 1 * 1024 * 1024, // 1 MiB.
        }
    }
}

/// Streaming encoder for the gzchunked format.
///
/// It implements the `Iterator` trait, lazily polling the underlying iterator
/// over Protocol Buffers messages as more parts are needed.
///
/// Instances of this type can be constructed using the [`encode_with_opts`] or
/// [`encode`] function.
///
/// [`encode`]: fn.encode.html
/// [`encode_with_opts`]: fn.encode_with_opts.html
pub struct Encode<I> {
    chunked: crate::chunked::Encode<I>,
    opts: EncodeOpts,
}

impl<I> Encode<I>
where
    I: Iterator,
    I::Item: prost::Message,
{
    /// Creates a new encoder instance with the specified options.
    fn with_opts(iter: I, opts: EncodeOpts) -> Encode<I> {
        Encode {
            chunked: crate::chunked::encode(iter),
            opts: opts,
        }
    }

    /// Obtains the next part of the output file (if available).
    fn next_part(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        use crate::io::copy_until;

        let compression = self.opts.compression.0;
        let part_size = self.opts.part_size;

        let mut encoder = flate2::write::GzEncoder::new(vec!(), compression);
        let len = copy_until(&mut self.chunked, &mut encoder, |_, encoder| {
            encoder.get_ref().len() as u64 >= part_size
        })?;

        if len == 0 {
            Ok(None)
        } else {
            Ok(Some(encoder.finish()?))
        }
    }
}

impl<I> Iterator for Encode<I>
where
    I: Iterator,
    I::Item: prost::Message,
{
    type Item = std::io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<std::io::Result<Vec<u8>>> {
        self.next_part().transpose()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_encode_with_empty_iter() {
        let mut iter = encode(std::iter::empty::<()>())
            .map(Result::unwrap);

        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_decode_with_empty_iter() {
        let mut iter = decode::<_, ()>(std::iter::empty::<&[u8]>())
            .map(Result::unwrap);

        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_encode_and_decode_with_single_item_iter() {
        let chunks = encode(std::iter::once(String::from("foo")))
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        let mut iter = decode(chunks.iter().map(Vec::as_slice))
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(String::from("foo")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_encode_and_decode_with_multiple_items_iter() {
        let data = vec! {
            String::from("foo"),
            String::from("bar"),
            String::from("baz"),
        };

        let chunks = encode(data.into_iter())
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        let mut iter = decode(chunks.iter().map(Vec::as_slice))
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(String::from("foo")));
        assert_eq!(iter.next(), Some(String::from("bar")));
        assert_eq!(iter.next(), Some(String::from("baz")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_encode_and_decode_with_empty_items_iter() {
        let data = vec!((), (), ());

        let chunks = encode(data.into_iter())
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        let mut iter = decode(chunks.iter().map(Vec::as_slice))
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(b"".to_vec()));
        assert_eq!(iter.next(), Some(b"".to_vec()));
        assert_eq!(iter.next(), Some(b"".to_vec()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_encode_and_decode_with_many_items_iter() {
        let sample = rand::random::<[u8; 32]>().to_vec();
        let items = std::iter::repeat(sample.clone()).take(32 * 1024);

        let opts = EncodeOpts {
            compression: Compression::default(),
            part_size: 4 * 1024,
        };

        let chunks = encode_with_opts(items, opts)
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        let mut iter = decode::<_, Vec<u8>>(chunks.iter().map(Vec::as_slice))
            .map(Result::unwrap);

        assert!(iter.all(|item| item == sample));
    }

    #[test]
    fn test_encode_and_decode_with_no_compression() {
        let sample = rand::random::<[u8; 32]>().to_vec();
        let items = std::iter::repeat(sample.clone()).take(32 * 1024);

        let opts = EncodeOpts {
            compression: Compression::none(),
            part_size: 4 * 1024,
        };

        let chunks = encode_with_opts(items, opts)
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        let mut iter = decode::<_, Vec<u8>>(chunks.iter().map(Vec::as_slice))
            .map(Result::unwrap);

        assert!(iter.all(|item| item == sample));
    }

    #[test]
    fn test_encode_and_decode_with_best_compression() {
        let sample = rand::random::<[u8; 32]>().to_vec();
        let items = std::iter::repeat(sample.clone()).take(32 * 1024);

        let opts = EncodeOpts {
            compression: Compression::best(),
            part_size: 4 * 1024,
        };

        let chunks = encode_with_opts(items, opts)
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        let mut iter = decode::<_, Vec<u8>>(chunks.iter().map(Vec::as_slice))
            .map(Result::unwrap);

        assert!(iter.all(|item| item == sample));
    }
}
