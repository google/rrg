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
/// fn string<S>(value: S) -> protobuf::well_known_types::wrappers::StringValue
/// where
///     S: Into<String>,
/// {
///     let mut proto = protobuf::well_known_types::wrappers::StringValue::new();
///     proto.value = value.into();
///
///     proto
/// }
///
/// let items = vec! {
///     string("foo"),
///     string("bar"),
///     string("baz"),
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
    I::Item: protobuf::Message,
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
    I::Item: protobuf::Message,
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
///     let msg: protobuf::well_known_types::wrappers::StringValue = msg.unwrap();
///     println!("item #{}: {:?}", idx, msg.value);
/// }
/// ```
pub fn decode<I, M>(iter: I) -> impl Iterator<Item=std::io::Result<M>>
where
    I: Iterator,
    I::Item: std::io::Read,
    M: protobuf::Message + Default,
{
    Decode {
        chunks: iter,
        buf: Vec::new(),
        decoder: None,
        marker: std::marker::PhantomData,
    }
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
    pub part_size: usize,
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
    iter: I,
    opts: EncodeOpts,
}

impl<I> Encode<I>
where
    I: Iterator,
    I::Item: protobuf::Message,
{
    /// Creates a new encoder instance with the specified options.
    fn with_opts(iter: I, opts: EncodeOpts) -> Encode<I> {
        Encode {
            iter,
            opts: opts,
        }
    }

    /// Obtains the next part of the output file (if available).
    fn next_part(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let mut encoder = flate2::write::GzEncoder::new(
            vec!(),
            self.opts.compression.0,
        );

        let mut msg_count = 0;
        for msg in &mut self.iter {
            msg_count += 1;

            use std::io::Write as _;
            use protobuf::Message as _;

            encoder.write_all(&(msg.compute_size() as u64).to_be_bytes())?;
            msg.write_to_writer(&mut encoder)?;

            if encoder.get_ref().len() > self.opts.part_size {
                return encoder.finish().map(Some);
            }
        }

        if msg_count > 0 {
            encoder.finish().map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<I> Iterator for Encode<I>
where
    I: Iterator,
    I::Item: protobuf::Message,
{
    type Item = std::io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<std::io::Result<Vec<u8>>> {
        self.next_part().transpose()
    }
}

/// Streaming decoder for the gzchunked format.
///
/// It implements the `Iterator` trait, lazily polling the underlying iterator
/// over chunks with gzipped messages as needed and yields Protocol Buffer
/// messages of the `M` type.
///
/// Instances of this type can be constructed using the [`decode`] function.
struct Decode<I, M>
where
    I: Iterator,
    I::Item: std::io::Read,
    M: protobuf::Message,
{
    /// Iterator over gzipped chunks.
    ///
    /// Each chunk is a sequence of interleaved message lengths and serialized
    /// Protocol Buffer messages of such length.
    chunks: I,
    /// gzip decoder with actively decompressed chunk.
    ///
    /// `None` indicates that there is no active chunk (e.g. because the last
    /// one was depleted) and the iterator should be polled for the next one.
    decoder: Option<flate2::read::GzDecoder<I::Item>>,
    /// Temporary buffer for reading messages into.
    ///
    /// It is used to avoid repeated allocations across `next` calls on the
    /// iterator.
    buf: Vec<u8>,
    /// Marker that binds the decoder to a particular message type.
    ///
    /// This is needed because we cannot implement the `Iterator` trait for a
    /// decoder that yields results of arbitrary type.
    marker: std::marker::PhantomData<M>,
}

impl<I, M> Decode<I, M>
where
    I: Iterator,
    I::Item: std::io::Read,
    M: protobuf::Message,
{
    fn next_msg(&mut self) -> std::io::Result<Option<M>> {
        loop {
            let decoder = match self.decoder {
                Some(ref mut decoder) => decoder,
                None => match self.chunks.next() {
                    Some(chunk) => {
                        self.decoder.insert(flate2::read::GzDecoder::new(chunk))
                    }
                    None => break Ok(None),
                },
            };

            use std::io::Read as _;

            let mut len_buf = [0; std::mem::size_of::<u64>()];
            match decoder.read(&mut len_buf[..])? {
                0 => {
                    self.decoder = None;
                    continue;
                },
                len if len == std::mem::size_of::<u64>() => (),
                len => decoder.read_exact(&mut len_buf[len..])?,
            }
            let len = u64::from_be_bytes(len_buf);
            let len = usize::try_from(len).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error)
            })?;

            self.buf.resize(len, u8::default());
            decoder.read_exact(&mut self.buf[..])?;

            break Ok(Some(protobuf::Message::parse_from_bytes(&self.buf[..])?));
        }
    }
}

impl<I, M> Iterator for Decode<I, M>
where
    I: Iterator,
    I::Item: std::io::Read,
    M: protobuf::Message,
{
    type Item = std::io::Result<M>;

    fn next(&mut self) -> Option<std::io::Result<M>> {
        self.next_msg().transpose()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use protobuf::well_known_types::{
        empty::Empty,
        wrappers::{BytesValue, StringValue},
    };

    fn string<S: Into<String>>(value: S) -> StringValue {
        let mut proto = StringValue::new();
        proto.value = value.into();

        proto
    }

    fn bytes<B: Into<Vec<u8>>>(value: B) -> BytesValue {
        let mut proto = BytesValue::new();
        proto.value = value.into();

        proto
    }

    #[test]
    fn test_encode_with_empty_iter() {
        let mut iter = encode(std::iter::empty::<Empty>())
            .map(Result::unwrap);

        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_decode_with_empty_iter() {
        let mut iter = decode::<_, Empty>(std::iter::empty::<&[u8]>())
            .map(Result::unwrap);

        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_encode_and_decode_with_single_item_iter() {
        let chunks = encode(std::iter::once(string("foo")))
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        let mut iter = decode(chunks.iter().map(Vec::as_slice))
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(string("foo")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_encode_and_decode_with_multiple_items_iter() {
        let data = vec! {
            string("foo"),
            string("bar"),
            string("baz"),
        };

        let chunks = encode(data.into_iter())
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        let mut iter = decode(chunks.iter().map(Vec::as_slice))
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(string("foo")));
        assert_eq!(iter.next(), Some(string("bar")));
        assert_eq!(iter.next(), Some(string("baz")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_encode_and_decode_with_empty_items_iter() {
        let data = vec!(Empty::new(), Empty::new(), Empty::new());

        let chunks = encode(data.into_iter())
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        let mut iter = decode(chunks.iter().map(Vec::as_slice))
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(Empty::new()));
        assert_eq!(iter.next(), Some(Empty::new()));
        assert_eq!(iter.next(), Some(Empty::new()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_encode_and_decode_with_many_items_iter() {
        let sample = bytes(rand::random::<[u8; 32]>());
        let items = std::iter::repeat(sample.clone()).take(32 * 1024);

        let opts = EncodeOpts {
            compression: Compression::default(),
            part_size: 4 * 1024,
        };

        let chunks = encode_with_opts(items, opts)
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        let mut iter = decode::<_, BytesValue>(chunks.iter().map(Vec::as_slice))
            .map(Result::unwrap);

        assert!(iter.all(|item| item == sample));
    }

    #[test]
    fn test_encode_and_decode_with_no_compression() {
        let sample = bytes(rand::random::<[u8; 32]>());
        let items = std::iter::repeat(sample.clone()).take(32 * 1024);

        let opts = EncodeOpts {
            compression: Compression::none(),
            part_size: 4 * 1024,
        };

        let chunks = encode_with_opts(items, opts)
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        let mut iter = decode::<_, BytesValue>(chunks.iter().map(Vec::as_slice))
            .map(Result::unwrap);

        assert!(iter.all(|item| item == sample));
    }

    #[test]
    fn test_encode_and_decode_with_best_compression() {
        let sample = bytes(rand::random::<[u8; 32]>());
        let items = std::iter::repeat(sample.clone()).take(32 * 1024);

        let opts = EncodeOpts {
            compression: Compression::best(),
            part_size: 4 * 1024,
        };

        let chunks = encode_with_opts(items, opts)
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        let mut iter = decode::<_, BytesValue>(chunks.iter().map(Vec::as_slice))
            .map(Result::unwrap);

        assert!(iter.all(|item| item == sample));
    }
}
