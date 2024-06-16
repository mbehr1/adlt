use std::{
    cmp::min,
    io::{Read, Seek, SeekFrom},
};

use super::cloneable_seekable_reader::HasLength;

/// A chain of readers that can be seeked.
///
/// At ::new the length is determined by the result from Seek::End(0).
pub struct SeekableChain<RS: Read + Seek> {
    chain: Vec<(u64, RS)>,
    max_pos: u64,
    abs_pos: u64,
    cur_idx: usize,
    rel_pos: u64, // pos within the current reader
}

impl<RS: Read + Seek> HasLength for &mut SeekableChain<RS> {
    fn len(&self) -> u64 {
        self.max_pos
    }
}

impl<RS: Read + Seek> HasLength for SeekableChain<RS> {
    fn len(&self) -> u64 {
        self.max_pos
    }
}

impl<RS: Read + Seek> SeekableChain<RS> {
    pub fn new(chain: Vec<RS>) -> Self {
        let chain: Vec<(u64, RS)> = chain
            .into_iter()
            .map(|mut r| {
                let size = r.seek(SeekFrom::End(0)).unwrap(); // todo ignore readers with errors?
                r.seek(SeekFrom::Start(0)).unwrap();
                (size, r)
            })
            .collect();
        let max_pos = chain.iter().map(|(size, _)| size).sum(); // todo saturizing...
        SeekableChain {
            max_pos,
            abs_pos: 0,
            cur_idx: 0,
            rel_pos: 0,
            chain,
            // todo skip ones with have size 0
        }
    }

    fn seek_abs(&mut self, pos: u64) -> std::io::Result<u64> {
        if self.abs_pos == pos {
            return Ok(pos);
        }
        if pos >= self.max_pos {
            self.abs_pos = self.max_pos;
            self.cur_idx = self.chain.len() + 1;
            self.rel_pos = 0;
            return Ok(self.max_pos);
        }
        // todo optimize for relative... seek within rel_pos...
        self.abs_pos = 0;
        self.cur_idx = 0;
        self.rel_pos = 0;
        let mut pos = pos;
        for (size, reader) in &mut self.chain {
            if pos < *size {
                reader.seek(SeekFrom::Start(pos))?;
                self.rel_pos = pos;
                self.abs_pos += pos;
                break;
            } else {
                self.abs_pos += *size;
                pos -= *size;
                self.cur_idx += 1;
            }
        }
        /*println!(
            "seek_abs: {}: cur_idx={} rel_pos={}",
            self.abs_pos, self.cur_idx, self.rel_pos
        );*/
        Ok(self.abs_pos)
    }
}

impl<RS: Read + Seek> Read for SeekableChain<RS> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.cur_idx >= self.chain.len() {
            Ok(0)
        } else {
            // cur_idx is valid
            // read from current reader:
            let (max_pos, reader) = &mut self.chain[self.cur_idx];
            if self.rel_pos == 0 {
                reader.seek(SeekFrom::Start(0))?; // todo optimize (only seek if needed)
            }
            let max_read = min(max_pos.saturating_sub(self.rel_pos) as usize, buf.len());
            let read = reader.read(&mut buf[..max_read])?;
            self.rel_pos += read as u64;
            self.abs_pos += read as u64;
            // check if we need to switch to the next reader
            if self.rel_pos >= *max_pos {
                self.cur_idx += 1;
                self.rel_pos = 0;
                // seek new reader to 0? reader.seek(SeekFrom::Start(pos))?; for now do it at the beginning of read
            }
            // todo check whether optimizing to fill full buffer is faster
            Ok(read)
        }
    }
}

impl<RS: Read + Seek> Seek for SeekableChain<RS> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        // println!("seek: {:?}", pos);
        match pos {
            SeekFrom::Start(offset) => self.seek_abs(offset),
            SeekFrom::Current(offset) => {
                let new_pos = if offset < 0 {
                    self.abs_pos.saturating_sub(-offset as u64)
                } else {
                    self.abs_pos.saturating_add(offset as u64)
                };
                self.seek_abs(new_pos)
            }
            SeekFrom::End(offset) => {
                if offset <= 0 {
                    self.seek_abs(self.max_pos.saturating_sub(-offset as u64))
                } else {
                    Ok(self.max_pos)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_seekable_chain() {
        let data = vec![
            Cursor::new(b"hello".to_vec()),
            Cursor::new(b"world".to_vec()),
            Cursor::new(b"!".to_vec()),
        ];
        let mut chain = SeekableChain::new(data);
        let mut buf = [0; 5];
        assert_eq!(5, chain.read(&mut buf).unwrap());
        assert_eq!(&buf, b"hello");
        assert_eq!(5, chain.read(&mut buf).unwrap());
        assert_eq!(&buf, b"world");
        chain.seek(SeekFrom::Current(-4)).unwrap();
        assert_eq!(chain.read(&mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], b"orld");
        chain.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(5, chain.read(&mut buf).unwrap());
        assert_eq!(&buf, b"hello");
        chain.seek(SeekFrom::End(-1)).unwrap();
        assert_eq!(1, chain.read(&mut buf).unwrap());
        assert_eq!(&buf[..1], b"!");

        chain.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = Vec::new();
        chain.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, b"helloworld!");

        chain.seek(SeekFrom::Current(-2)).unwrap();
        let mut buf = Vec::new();
        chain.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, b"d!");

        chain.seek(SeekFrom::End(-2)).unwrap();
        let mut buf = Vec::new();
        chain.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, b"d!");

        chain.seek(SeekFrom::Start(2)).unwrap();
        let mut buf = Vec::new();
        chain.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, b"lloworld!");
    }
}
