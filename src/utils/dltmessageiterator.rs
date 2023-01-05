use crate::dlt::{
    parse_dlt_with_serial_header, parse_dlt_with_storage_header, DltMessage, DltMessageIndexType,
};
use slog::debug;
use std::io::BufRead;

pub struct DltMessageIterator<'a, R> {
    reader: R,
    pub index: DltMessageIndexType,
    pub bytes_processed: usize,
    pub bytes_skipped: usize,
    pub detected_storage_header: bool,
    pub detected_serial_header: bool,
    pub log: Option<&'a slog::Logger>,
    pub log_skipped: Option<(DltMessageIndexType, usize, String)>, // index, bytes_processed (aka offset) where the skipping started and reason
}

impl<'a, R> DltMessageIterator<'a, R> {
    pub fn new(start_index: DltMessageIndexType, reader: R) -> DltMessageIterator<'a, R> {
        DltMessageIterator {
            reader,
            index: start_index,
            bytes_processed: 0,
            bytes_skipped: 0,
            detected_storage_header: false,
            detected_serial_header: false,
            log: None,
            log_skipped: None,
        }
    }
}

impl<'a, R> Iterator for DltMessageIterator<'a, R>
where
    R: BufRead,
{
    type Item = DltMessage;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // default search with storage header
            if !self.detected_serial_header {
            match parse_dlt_with_storage_header(self.index, self.reader.fill_buf().unwrap()) {
                Ok((res, msg)) => {
                    self.reader.consume(res);
                    self.bytes_processed += res;
                    self.index += 1;
                        self.detected_storage_header = true;
                        return Some(msg);
                    }
                    Err(error) => match error.kind() {
                        crate::dlt::ErrorKind::InvalidData(_str) => {
                            if self.detected_storage_header {
                                self.bytes_processed += 1;
                                self.bytes_skipped += 1;
                                self.reader.consume(1);
                                if let Some(log) = self.log {
                                    debug!(log, "skipped 1 byte at {}", self.bytes_processed - 1);
                                }
                            } // else we'll try serial first
                              // we loop here again
                        }
                        _ => {
                            break;
                        }
                    },
                }
            }
            if !self.detected_storage_header {
                match parse_dlt_with_serial_header(self.index, self.reader.fill_buf().unwrap()) {
                    Ok((res, msg)) => {
                        if let Some((l_index, l_bytes_processed, reason)) = &self.log_skipped {
                            if let Some(log)=self.log {
                                debug!(log, "skipped {} bytes at 0x{:x} (={}) index of next log #{} due to '{}'", self.bytes_processed - l_bytes_processed, l_bytes_processed, l_bytes_processed, l_index, reason);
                            }
                            self.log_skipped = None;
                        }
                        self.reader.consume(res);
                        self.bytes_processed += res;
                        self.index += 1;
                        self.detected_serial_header = true;
                    return Some(msg);
                }
                Err(error) => match error.kind() {
                    crate::dlt::ErrorKind::InvalidData(reason) => {
                        self.bytes_processed += 1;
                        self.bytes_skipped += 1;
                        self.reader.consume(1);
                        if self.log.is_some() {
                            if self.log_skipped.is_none() {
                                self.log_skipped = Some((self.index, self.bytes_processed-1, reason.to_owned()));
                            }
                            //debug!(log, "skipped 1 byte at {}", self.bytes_processed - 1);
                        }
                        // we loop here again
                    }
                    _ => {
                        break;
                    }
                },
                }
            }
        }
        if let Some((l_index, l_bytes_processed, reason)) = &self.log_skipped {
            if let Some(log)=self.log {
                debug!(log, "skipped {} bytes at 0x{:x} (={}) index of next log #{} due to '{}'", self.bytes_processed - l_bytes_processed, l_bytes_processed, l_bytes_processed, l_index, reason);
            }
            self.log_skipped = None;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlt::{DltChar4, DltStandardHeader, DltStorageHeader, DLT_MAX_STORAGE_MSG_SIZE};
    use crate::utils::{LowMarkBufReader, US_PER_SEC};
    use std::fs::File;
    use std::io::prelude::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_iterator() {
        // create a test file with 1M DLT messages:
        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        let persisted_msgs: DltMessageIndexType = 10;
        let ecus = [
            DltChar4::from_buf(b"ECU1"),
            DltChar4::from_buf(b"ECU2"),
            DltChar4::from_buf(b"ECU3"),
        ];
        for i in 0..persisted_msgs {
            let sh = DltStorageHeader {
                secs: (1640995200000000 / US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu: ecus[i as usize % ecus.len()],
            };
            let standard_header = DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
            m.to_write(&mut file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();
        let file_size = std::fs::metadata(&file_path).unwrap().len();

        let fi = File::open(&file_path).unwrap();
        let start_index = 1000;
        let mut it = DltMessageIterator::new(
            start_index,
            LowMarkBufReader::new(fi, 512 * 1024, DLT_MAX_STORAGE_MSG_SIZE),
        );
        let mut iterated_msgs = 0;
        for m in &mut it {
            assert_eq!(m.index, start_index + iterated_msgs);
            iterated_msgs += 1;
        }
        assert_eq!(persisted_msgs, iterated_msgs);
        assert_eq!(it.bytes_skipped, 0);
        assert_eq!(it.bytes_processed, file_size as usize);
        assert_eq!(it.index, start_index + iterated_msgs);
    }
}
