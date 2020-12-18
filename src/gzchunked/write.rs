// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// A wrapper type for gzip compression level.
#[derive(Clone, Copy, Debug)]
pub struct Compression(flate2::Compression);

/// A type for defining gzip compression level for gzchunked.
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
pub fn encode<I, M>(iter: I) -> Encode<I>
where
    I: Iterator<Item=M>,
    M: prost::Message,
{
    encode_with_opts(iter, EncodeOpts::default())
}

/// Encodes the given iterator over protobuf messages into the gzchunked format.
///
/// This is a variant of the [`encode`] function that allows customization of
/// encoding parameters. Refer to its documentation for more details.
///
/// [`encode`]: fn.encode.html
pub fn encode_with_opts<I, M>(iter: I, opts: EncodeOpts) -> Encode<I>
where
    I: Iterator<Item=M>,
    M: prost::Message,
{
    Encode::with_opts(iter, opts)
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
