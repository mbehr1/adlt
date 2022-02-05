use std::io::{BufRead, Read};

/// The `LowMarkBufReader<R>` struct adds buffering to any reader.
///
/// It reads data in chunks from the reader only if the amount of data buffered drops
/// below the low water mark. It performs then a single large read trying to fill the
/// full buffer.
pub struct LowMarkBufReader<R> {
    inner: R,
    buf: Box<[u8]>,
    pos: usize,
    cap: usize,
    low_mark: usize,
    empty_last_read: bool,
}

impl<R: Read> LowMarkBufReader<R> {
    pub fn new(inner: R, capacity: usize, low_mark: usize) -> LowMarkBufReader<R> {
        assert!(low_mark < capacity);
        assert!(low_mark > 0);

        let buf = vec![0u8; capacity].into_boxed_slice();
        LowMarkBufReader {
            inner,
            buf,
            pos: 0,
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
            rem.read(buf)?
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
        loop {
            // read might return less than we requested:
            let in_buf = self.cap - self.pos;
            if in_buf < self.low_mark {
                // move remaining data to the front:
                if self.pos > 0 && !self.empty_last_read {
                    //println!("moving {} bytes", in_buf);
                    self.buf.copy_within(self.pos..self.cap, 0);
                    self.cap -= self.pos;
                    self.pos = 0;
                }
                // and add more from inner:
                let read = self.inner.read(&mut self.buf[self.cap..])?;
                if read == 0 {
                    if !self.empty_last_read {
                        self.empty_last_read = true;
                        //println!(" read 0 bytes -> empty_last_read={}", self.empty_last_read);
                    }
                    break;
                } else {
                    //println!(" read {} bytes", read);
                    let max_read = self.buf.len() - self.cap;
                    self.cap += read;
                    self.empty_last_read = false;
                    if read == max_read {
                        break;
                    } // else check again if either we're below low mark or read is last/empty/eof
                }
            } else {
                break;
            }
        }
        Ok(&self.buf[self.pos..self.cap])
    }

    fn consume(&mut self, amt: usize) {
        self.pos = std::cmp::min(self.pos + amt, self.cap)
    }
}
