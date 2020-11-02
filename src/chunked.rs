use std::io::Cursor;

use byteorder::LittleEndian;

struct Encode<I> {
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

        self.cur.write_u64::<LittleEndian>(data.len() as u64)?;
        self.cur.write_all(data)?;

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
