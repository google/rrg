// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

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
pub fn decode<I, R, M>(iter: I) -> impl Iterator<Item=std::io::Result<M>>
where
    I: Iterator<Item=R>,
    R: std::io::Read,
    M: prost::Message + Default,
{
    let parts = iter.map(flate2::read::GzDecoder::new);
    crate::chunked::decode(crate::io::IterReader::new(parts))
}
