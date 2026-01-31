use crate::dlt::{
    parse_dlt_with_serial_header, parse_dlt_with_storage_header, DltChar4, DltMessage,
    DltMessageIndexType,
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

impl<R> Iterator for DltMessageIterator<'_, R>
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
                match parse_dlt_with_serial_header(
                    self.index,
                    self.reader.fill_buf().unwrap(),
                    DltChar4::from_buf(b"DLS\0"),
                    false,
                ) {
                    Ok((res, msg)) => {
                        if let Some((l_index, l_bytes_processed, reason)) = &self.log_skipped {
                            if let Some(log) = self.log {
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
                            if self.log.is_some() && self.log_skipped.is_none() {
                                self.log_skipped =
                                    Some((self.index, self.bytes_processed - 1, reason.to_owned()));
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
            if let Some(log) = self.log {
                debug!(
                    log,
                    "skipped {} bytes at 0x{:x} (={}) index of next log #{} due to '{}'",
                    self.bytes_processed - l_bytes_processed,
                    l_bytes_processed,
                    l_bytes_processed,
                    l_index,
                    reason
                );
            }
            self.log_skipped = None;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlt::{
        DltChar4, DltStandardHeader, DltStorageHeader, DLT_MAX_STORAGE_MSG_SIZE,
        DLT_SERIAL_HEADER_PATTERN,
    };
    use crate::utils::{LowMarkBufReader, US_PER_SEC};
    use slog::{o, Drain, Logger};
    use std::fs::File;
    use std::io::prelude::*;
    use tempfile::NamedTempFile;

    fn new_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, o!())
    }

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

    #[test]
    fn test_dls_iterator() {
        let logger = new_logger();
        // create a test file with 1000 DLT messages:
        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        let persisted_msgs: DltMessageIndexType = 1000;
        let mut garbage_bytes = 0;
        for i in 0..persisted_msgs {
            let standard_header = DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let payload = vec![];
            let dls_pat = DLT_SERIAL_HEADER_PATTERN.to_le_bytes();

            // insert some garbage:
            let garbage = &dls_pat.as_slice()[0..(i as usize % 5)];
            file.write_all(garbage).unwrap();
            garbage_bytes += garbage.len();

            // DLS format = serial header patter, standard header, [ext header], payload
            file.write_all(&dls_pat).unwrap();
            //file.write_all(&b1).unwrap();

            DltStandardHeader::to_write(
                file.as_file_mut(),
                &standard_header,
                &None,
                None, // ecu already in storageheader
                None, // session_id = None, todo
                if standard_header.has_timestamp() {
                    Some(i)
                } else {
                    None
                },
                &payload,
            )
            .unwrap();
        }
        file.flush().unwrap();
        let file_size = std::fs::metadata(&file_path).unwrap().len();

        let fi = File::open(&file_path).unwrap();
        let start_index = 1000;
        let mut it = DltMessageIterator::new(
            start_index,
            LowMarkBufReader::new(fi, 512 * 1024, DLT_MAX_STORAGE_MSG_SIZE),
        );
        it.log = Some(&logger);
        let mut iterated_msgs = 0;
        for m in &mut it {
            assert_eq!(m.index, start_index + iterated_msgs);
            iterated_msgs += 1;
        }
        assert_eq!(persisted_msgs, iterated_msgs);
        assert_eq!(it.bytes_skipped, garbage_bytes);
        assert_eq!(it.bytes_processed, file_size as usize);
        assert_eq!(it.index, start_index + iterated_msgs);
    }
}
