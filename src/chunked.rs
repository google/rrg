use std::io::Cursor;

use byteorder::BigEndian;

pub fn encode<'a, I>(iter: I) -> Encode<I>
where
    I: Iterator<Item = &'a [u8]>,
{
    Encode {
        iter: iter,
        cur: Cursor::new(vec!()),
    }
}

pub fn decode<R>(buf: R) -> Decode<R>
where
    R: std::io::Read,
{
    Decode {
        buf: buf,
    }
}

pub struct Encode<I> {
    iter: I,
    cur: Cursor<Vec<u8>>,
}

impl<'a, I> Encode<I>
where
    I: Iterator<Item = &'a [u8]>,
{
    fn is_empty(&self) -> bool {
        self.cur.position() == self.cur.get_ref().len() as u64
    }

    fn pull(&mut self) -> std::io::Result<()> {
        use std::io::Write as _;
        use byteorder::WriteBytesExt as _;

        let data = match self.iter.next() {
            Some(data) => data,
            None => return Ok(()),
        };

        self.cur.get_mut().clear();
        self.cur.set_position(0);

        self.cur.write_u64::<BigEndian>(data.len() as u64)?;
        self.cur.write_all(data)?;
        self.cur.set_position(0);

        Ok(())
    }
}

impl<'a, I> std::io::Read for Encode<I>
where
    I: Iterator<Item = &'a [u8]>,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.is_empty() {
            self.pull()?;
        }

        self.cur.read(buf)
    }
}

pub struct Decode<R> {
    buf: R,
}

impl<R: std::io::Read> Decode<R> {

    fn read_len(&mut self) -> std::io::Result<Option<usize>> {
        use byteorder::ReadBytesExt as _;

        let mut buf = [0; 8];
        match self.buf.read(&mut buf[..])? {
            8 => (),
            0 => return Ok(None),
            _ => return Err(SizeTagError.into()),
        }

        let len = (&buf[..]).read_u64::<BigEndian>()? as usize;
        Ok(Some(len))
    }
}

impl<R: std::io::Read> Iterator for Decode<R> {

    type Item = std::io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<std::io::Result<Vec<u8>>> {
        let len = match self.read_len() {
            Ok(Some(len)) => len,
            Ok(None) => return None,
            Err(error) => return Some(Err(error)),
        };

        let mut buf = vec!(0; len);
        match self.buf.read_exact(&mut buf[..]) {
            Ok(()) => (),
            Err(error) => return Some(Err(error)),
        }

        Some(Ok(buf))
    }
}

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

    use std::io::Read as _;

    use super::*;

    #[test]
    pub fn test_encode_empty() {
        let mut stream = encode(std::iter::empty());

        let mut output = vec!();
        stream.read_to_end(&mut output).unwrap();

        assert!(output.is_empty());
    }

    #[test]
    pub fn test_encode_single_chunk() {
        let mut stream = encode(vec!(&b"foo"[..]).into_iter());

        let mut output = vec!();
        stream.read_to_end(&mut output).unwrap();

        assert_eq!(output, b"\x00\x00\x00\x00\x00\x00\x00\x03foo");
    }

    #[test]
    pub fn test_encode_single_empty_chunk() {
        let mut stream = encode(vec!(&b""[..]).into_iter());

        let mut output = vec!();
        stream.read_to_end(&mut output).unwrap();

        assert_eq!(output, b"\x00\x00\x00\x00\x00\x00\x00\x00");
    }

    #[test]
    pub fn test_encode_multiple_empty_chunks() {
        let mut stream = encode(vec!(&b""[..], &b""[..]).into_iter());

        let mut output = vec!();
        stream.read_to_end(&mut output).unwrap();

        assert_eq!(&output[..8], b"\x00\x00\x00\x00\x00\x00\x00\x00");
        assert_eq!(&output[8..], b"\x00\x00\x00\x00\x00\x00\x00\x00");
    }

    #[test]
    pub fn test_decode_empty() {
        let mut iter = decode(&b""[..]);
        assert!(iter.next().is_none());
    }

    #[test]
    pub fn test_decode_single_chunk() {
        let mut iter = decode(&b"\x00\x00\x00\x00\x00\x00\x00\x03foo"[..])
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(b"foo".to_vec()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    pub fn test_decode_empty_chunk() {
        let mut iter = decode(&b"\x00\x00\x00\x00\x00\x00\x00\x00"[..])
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(b"".to_vec()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    pub fn test_decode_incorrect_size_tag() {
        let mut iter = decode(&b"\x12\x34\x56"[..]);

        let error = iter.next().unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    pub fn test_decode_short_input() {
        let mut iter = decode(&b"\x00\x00\x00\x00\x00\x00\x00\x42foo"[..]);

        let error = iter.next().unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    pub fn test_encode_and_decode_multiple_chunks() {
        let chunks = vec! {
            &b"foo"[..],
            &b"bar"[..],
            &b"baz"[..],
        };

        let mut iter = decode(encode(chunks.into_iter()))
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(b"foo".to_vec()));
        assert_eq!(iter.next(), Some(b"bar".to_vec()));
        assert_eq!(iter.next(), Some(b"baz".to_vec()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    pub fn test_encode_and_decode_multiple_empty_chunks() {
        let chunks = vec!(&b""[..], &b""[..], &b""[..]);

        let mut iter = decode(encode(chunks.into_iter()))
            .map(Result::unwrap);

        assert_eq!(iter.next(), Some(b"".to_vec()));
        assert_eq!(iter.next(), Some(b"".to_vec()));
        assert_eq!(iter.next(), Some(b"".to_vec()));
        assert_eq!(iter.next(), None);
    }
}
