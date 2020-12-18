// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Utils for forming gzchunked streams.

mod read;
mod write;

pub use write::{encode, encode_with_opts, Encode, EncodeOpts, Compression};
pub use read::{decode};

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
        let mut iter = decode::<_, _, ()>(std::iter::empty::<&[u8]>())
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

        let mut iter = decode::<_, _, Vec<u8>>(chunks.iter().map(Vec::as_slice))
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

        let mut iter = decode::<_, _, Vec<u8>>(chunks.iter().map(Vec::as_slice))
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

        let mut iter = decode::<_, _, Vec<u8>>(chunks.iter().map(Vec::as_slice))
            .map(Result::unwrap);

        assert!(iter.all(|item| item == sample));
    }
}
