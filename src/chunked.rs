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
