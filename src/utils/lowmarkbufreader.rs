use std::io::{BufRead, Read, Seek};

/// The `LowMarkBufReader<R>` struct adds buffering to any reader.
///
/// It reads data in chunks from the reader only if the amount of data buffered drops
/// below the low water mark. It performs then a single large read trying to fill the
/// full buffer.
pub struct LowMarkBufReader<R> {
    inner: R,
    buf: Box<[u8]>,
    pos: usize,
    abs_pos: usize, // abs. pos from initial read for start of buf content (used for Seek)
    cap: usize,
    low_mark: usize,
    empty_last_read: bool,
}

impl<R: std::fmt::Debug> std::fmt::Debug for LowMarkBufReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LowMarkBufReader")
            //.field("inner", &self.inner)
            .field("buf.len", &self.buf.len())
            .field("pos", &self.pos)
            .field("abs_pos", &self.abs_pos)
            .field("cap", &self.cap)
            .field("low_mark", &self.low_mark)
            .field("empty_last_read", &self.empty_last_read)
            .finish()
    }
}

const CACHE_LINE_SIZE: usize = 4096;

impl<R: Read> LowMarkBufReader<R> {
    pub fn new(inner: R, capacity: usize, low_mark: usize) -> LowMarkBufReader<R> {
        assert!(low_mark + CACHE_LINE_SIZE <= capacity);
        assert!(low_mark > 0);

        let buf = vec![0u8; capacity].into_boxed_slice();
        LowMarkBufReader {
            inner,
            buf,
            pos: 0,
            abs_pos: 0,
            cap: 0,
            low_mark,
            empty_last_read: false,
        }
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buf[self.pos..self.cap]
    }

    pub fn capacity(&self) -> usize {
        self.buf.len()
    }
}

impl<R: Read> Read for LowMarkBufReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let nread = {
            let mut rem = self.fill_buf()?;
            // false positive https://github.com/rust-lang/rust-clippy/issues/12519 in 1.77
            // #[allow(clippy::unused_io_amount)] doesn't seem to disable it?
            let nread = rem.read(buf)?;
            #[allow(clippy::let_and_return)]
            nread
        };
        self.consume(nread);
        Ok(nread)
    }
}

impl<R: Read> BufRead for LowMarkBufReader<R> {
    /// fill the buffer but only if currently less than low_mark bytes are in the buffer.
    /// It tries to fill until at leat low_mark is reached or the reader returns no more data.
    /// It handles read returning often less than wanted.
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        // if we have less than low_mark in the buf read more:
        if !self.empty_last_read {
            // read might return less than we requested so loop
            loop {
                let in_buf = self.cap - self.pos;
                if in_buf < self.low_mark {
                    // move remaining data to the front so that the new end
                    // is CACHE_LINE_SIZE aligned.
                    if self.pos >= CACHE_LINE_SIZE {
                        let new_cap = self.cap - self.pos;
                        let mut offset = CACHE_LINE_SIZE - (new_cap % CACHE_LINE_SIZE);
                        if offset == CACHE_LINE_SIZE {
                            offset = 0;
                        }
                        let new_cap = new_cap + offset;
                        //assert!(new_cap % CACHE_LINE_SIZE == 0);
                        //println!("moving {} bytes", in_buf);
                        self.buf.copy_within(self.pos..self.cap, offset);
                        self.cap = new_cap;
                        self.abs_pos += self.pos - offset;
                        self.pos = offset;
                    }
                    // and add more from inner:
                    let read = self.inner.read(&mut self.buf[self.cap..])?;
                    if read == 0 {
                        self.empty_last_read = true;
                        break;
                    } else {
                        //println!(" read {} bytes", read);
                        let max_read = self.buf.len() - self.cap;
                        self.cap += read;
                        if read == max_read {
                            break;
                        } // else check again if either we're below low mark or read is last/empty/eof
                    }
                } else {
                    break;
                }
            }
        }
        Ok(&self.buf[self.pos..self.cap])
    }

    fn consume(&mut self, amt: usize) {
        self.pos = std::cmp::min(self.pos + amt, self.cap)
    }
}

impl<R: Read> Seek for LowMarkBufReader<R> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match pos {
            std::io::SeekFrom::Start(n) => {
                if self.cap == 0 {
                    self.fill_buf()?;
                }
                if n < self.abs_pos as u64 {
                    println!(
                        "LowMarkBufReader nok seek to {:?} < abs_pos {}",
                        pos, self.abs_pos
                    );
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "LowMarkBufReader unsupported Seek {:?} < abs_pos {}",
                            pos, self.abs_pos
                        ),
                    ))
                } else if n > (self.abs_pos + self.cap) as u64 {
                    println!(
                        "LowMarkBufReader nok seek to {:?} >= abs_pos {} + cap",
                        pos, self.abs_pos
                    );
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "LowMarkBufReader unsupported Seek {:?} >= abs_pos {} +cap {}",
                            pos, self.abs_pos, self.cap
                        ),
                    ))
                } else {
                    /*println!(
                        "LowMarkBufReader.seek to {:?} at pos {} / abs_pos {}",
                        pos, self.pos, self.abs_pos
                    );*/
                    self.pos = n as usize - self.abs_pos;
                    Ok(n)
                }
            }
            std::io::SeekFrom::Current(r) => {
                let new_pos = (self.abs_pos + self.pos).saturating_add_signed(r as isize);
                self.seek(std::io::SeekFrom::Start(new_pos as u64))
            }
            _ => {
                println!(
                    "LowMarkBufReader unsupported Seek {:?} at abs_pos {}",
                    pos, self.abs_pos
                );
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "LowMarkBufReader unsupported Seek {:?} at abs_pos {}",
                        pos, self.abs_pos
                    ),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, SeekFrom};

    #[test]
    fn test_lowmarkbufreader() {
        let data = (0..=(2 * CACHE_LINE_SIZE + 10))
            .map(|x| x as u8)
            .collect::<Vec<u8>>();
        let mut reader =
            LowMarkBufReader::new(Cursor::new(data), 2 * CACHE_LINE_SIZE, CACHE_LINE_SIZE);
        // we can debug print:
        println!("reader={:?}", reader);
        let mut buf = [0u8; 5];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, &[0, 1, 2, 3, 4]);
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, &[5, 6, 7, 8, 9]);
        assert_eq!(reader.abs_pos, 0);
        // we consumed 10, now consume till low_mark:
        reader.consume(CACHE_LINE_SIZE - 10);
        println!("reader={:?}", reader);
        assert_eq!(reader.abs_pos, 0);
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, &[0, 1, 2, 3, 4]);
        println!("reader={:?}", reader);
        // first read started with a >=low_mark buffer:
        assert_eq!(reader.abs_pos, 0);
        // next read will refill buffer:
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, &[5, 6, 7, 8, 9]);
        println!("reader={:?}", reader);
        assert_eq!(reader.abs_pos, 4096);
    }

    #[test]
    fn test_lowmarkbufreader_seek() {
        let data = (0..=(2 * CACHE_LINE_SIZE + 10))
            .map(|x| x as u8)
            .collect::<Vec<u8>>();
        let mut reader =
            LowMarkBufReader::new(Cursor::new(data), 2 * CACHE_LINE_SIZE, CACHE_LINE_SIZE);
        // we can seek within the cached part (even before any read/fill_buf) (cap=0):
        let n = reader
            .seek(SeekFrom::Start(CACHE_LINE_SIZE as u64))
            .unwrap();
        assert_eq!(n, CACHE_LINE_SIZE as u64);
        assert_eq!(reader.abs_pos, 0);
        // we can seek beyond low_mark
        assert_eq!(
            reader
                .seek(SeekFrom::Start(CACHE_LINE_SIZE as u64 + 1))
                .unwrap(),
            CACHE_LINE_SIZE as u64 + 1
        );
        assert_eq!(
            reader
                .seek(SeekFrom::Start(2 * CACHE_LINE_SIZE as u64))
                .unwrap(),
            2 * CACHE_LINE_SIZE as u64
        );
        // we cannot seek beyond capacity:
        assert!(reader
            .seek(SeekFrom::Start((2 * CACHE_LINE_SIZE as u64) + 1))
            .is_err());

        // we can seek back to start:
        assert_eq!(reader.seek(SeekFrom::Start(0)).unwrap(), 0);

        // trigger refill:
        println!("reader={:?}", reader);
        reader.consume(CACHE_LINE_SIZE + 1);
        reader.fill_buf().unwrap();
        println!("reader={:?}", reader);
        assert_eq!(reader.abs_pos, 4096);
        // now we cannot seek back to 0:
        assert!(reader.seek(SeekFrom::Start(0)).is_err());
        assert_eq!(
            reader.stream_position().unwrap(),
            CACHE_LINE_SIZE as u64 + 1
        );
        assert_eq!(
            reader.seek(SeekFrom::Current(-1)).unwrap(),
            CACHE_LINE_SIZE as u64
        );
    }
}
