use serde::ser::{Serialize, Serializer};
use std::fmt;
use std::io::BufRead; // SerializeStruct

#[derive(Clone, PartialEq, Eq, Copy, Hash)] // Debug, Hash, Eq, Copy?
pub struct DltChar4 {
    char4: [u8; 4], // String, // todo u8,4 array?
}

impl DltChar4 {
    pub fn from_buf(buf: &[u8]) -> DltChar4 {
        DltChar4 {
            char4: [buf[0], buf[1], buf[2], buf[3]],
        }
    }
    pub fn from_str(astr: &str) -> Option<DltChar4> {
        // we do only support ascii strings
        // add some defaults? or return None
        if !astr.is_ascii() {
            return None;
        }
        let bytes = astr.as_bytes();
        let mut chars: [u8; 4] = [0, 0, 0, 0];
        for n in 0..std::cmp::min(bytes.len(), 4) {
            chars[n] = bytes[n];
        }

        Some(DltChar4 { char4: chars })
    }
}

impl Serialize for DltChar4 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl fmt::Debug for DltChar4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.char4))
    }
}

impl fmt::Display for DltChar4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a_str: &str = if self.char4[0] > 0 {
            if self.char4[1] > 0 {
                if self.char4[2] > 0 {
                    if self.char4[3] > 0 {
                        std::str::from_utf8(&self.char4).unwrap()
                    } else {
                        std::str::from_utf8(&self.char4[0..3]).unwrap()
                    }
                } else {
                    std::str::from_utf8(&self.char4[0..2]).unwrap()
                }
            } else {
                std::str::from_utf8(&self.char4[0..1]).unwrap()
            }
        } else {
            ""
        };

        f.pad(a_str) // handles width, fill/align and precision
    }
}

#[derive(Debug)]
pub struct DltStorageHeader {
    // we dont store the pattern pub pattern: u32,
    pub secs: u32,
    pub micros: u32,
    pub ecu: DltChar4,
}

pub const DLT_STORAGE_HEADER_PATTERN: u32 = 0x01544c44; // DLT\01
const DLT_STORAGE_HEADER_SIZE: usize = 16;
const DLT_MIN_STD_HEADER_SIZE: usize = 4;
const MIN_DLT_MSG_SIZE: usize = DLT_STORAGE_HEADER_SIZE + DLT_MIN_STD_HEADER_SIZE;
const DLT_EXT_HEADER_SIZE: usize = 10;

impl DltStorageHeader {
    fn from_buf(buf: &[u8]) -> Option<DltStorageHeader> {
        if buf.len() < 16 {
            return None;
        }
        let pat = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if pat != DLT_STORAGE_HEADER_PATTERN {
            return None;
        }
        let sh = DltStorageHeader {
            // pattern: pat,
            secs: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            micros: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            ecu: DltChar4::from_buf(&buf[12..16]),
        };
        Some(sh)
    }

    fn reception_time_us(&self) -> u64 {
        (self.secs as u64 * 1000_000) + self.micros as u64
    }
    #[allow(dead_code)]
    fn reception_time_ms(&self) -> u64 {
        (self.secs as u64 * 1000) + (self.micros / 1000) as u64
    }
}

// dlt standard header htyp bitfield:
const DLT_STD_HDR_HAS_EXT_HDR: u8 = 1;
const DLT_STD_HDR_BIG_ENDIAN: u8 = 1 << 1;
const DLT_STD_HDR_HAS_ECU_ID: u8 = 1 << 2;
const DLT_STD_HDR_HAS_SESSION_ID: u8 = 1 << 3;
const DLT_STD_HDR_HAS_TIMESTAMP: u8 = 1 << 4;

#[derive(Debug)]
pub struct DltStandardHeader {
    pub htyp: u8,
    pub mcnt: u8,
    pub len: u16,
}

impl DltStandardHeader {
    fn from_buf(buf: &[u8]) -> Option<DltStandardHeader> {
        if buf.len() < 4 {
            return None;
        }
        let htyp = buf[0];
        let sh = DltStandardHeader {
            htyp,
            mcnt: buf[1],
            len: u16::from_be_bytes([buf[2], buf[3]]), // all big endian
        };
        if sh.is_big_endian() {
            eprintln!("DltStandardHeader with big endian!");
        }
        Some(sh)
    }
    fn std_ext_header_size(&self) -> u16 {
        let mut length = DLT_MIN_STD_HEADER_SIZE as u16;
        if self.has_ecu_id() {
            length += 4;
        }
        if self.has_session_id() {
            length += 4;
        }
        if self.has_timestamp() {
            length += 4;
        }

        if self.has_ext_hdr() {
            length += DLT_EXT_HEADER_SIZE as u16;
        }
        length
    }

    fn has_ext_hdr(&self) -> bool {
        (self.htyp & DLT_STD_HDR_HAS_EXT_HDR) > 0
    }

    fn is_big_endian(&self) -> bool {
        (self.htyp & DLT_STD_HDR_BIG_ENDIAN) > 0
    }

    fn has_ecu_id(&self) -> bool {
        (self.htyp & DLT_STD_HDR_HAS_ECU_ID) > 0
    }
    fn has_session_id(&self) -> bool {
        (self.htyp & DLT_STD_HDR_HAS_SESSION_ID) > 0
    }
    fn has_timestamp(&self) -> bool {
        (self.htyp & DLT_STD_HDR_HAS_TIMESTAMP) > 0
    }

    fn ecu(&self, add_header_buf: &[u8]) -> Option<DltChar4> {
        if self.has_ecu_id() {
            Some(DltChar4::from_buf(&add_header_buf[0..4]))
        } else {
            None
        }
    }
    fn timestamp_dms(&self, add_header_buf: &[u8]) -> u32 {
        if self.has_timestamp() {
            let mut offset = if self.has_ecu_id() { 4 } else { 0 };
            if self.has_session_id() {
                offset += 4;
            }
            u32::from_be_bytes([
                add_header_buf[offset],
                add_header_buf[offset + 1],
                add_header_buf[offset + 2],
                add_header_buf[offset + 3],
            ])
        } else {
            0
        }
    }
}

#[derive(Debug)]
pub struct DltExtendedHeader {
    pub(super) verb_mstp_mtin: u8,
    pub(super) noar: u8,
    pub(super) apid: DltChar4,
    pub(super) ctid: DltChar4,
}
impl DltExtendedHeader {
    fn from_buf(buf: &[u8]) -> Option<DltExtendedHeader> {
        if buf.len() < DLT_EXT_HEADER_SIZE {
            return None;
        }
        let eh = DltExtendedHeader {
            verb_mstp_mtin: buf[0],
            noar: buf[1],
            apid: DltChar4::from_buf(&buf[2..6]),
            ctid: DltChar4::from_buf(&buf[6..10]),
        };
        Some(eh)
    }
}

/// Index type for DltMessage. 32bit seem somewhat limited. but we save 4bytes in ram per msg. which alone make 16gb saved for a huge dlt file with 4mrd msgs...
/// anyhow prepare a type so that it can be easily changed later.
pub type DltMessageIndexType = u32;

#[derive(Debug)]
pub struct DltMessage {
    pub index: DltMessageIndexType,
    pub(super) reception_time_us: u64, // from storage header, ms would be sufficent but needs same 64 bit
    pub ecu: DltChar4,
    // sessionId: u32 todo
    pub timestamp_dms: u32, // orig in 0.1ms (deci-ms)
    pub(super) standard_header: DltStandardHeader,
    pub(super) extended_header: Option<DltExtendedHeader>, // todo optimize ecu, apid, ctid into one map<u32>
    pub(super) payload: Vec<u8>,
    pub lifecycle: u32, // 0 = none, otherwise the id of an lifecycle
}

#[cfg(test)]
static NEXT_TEST_TIMESTAMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl DltMessage {
    pub fn timestamp_us(&self) -> u64 {
        return self.timestamp_dms as u64 * 100;
    }

    pub fn reception_time(&self) -> chrono::NaiveDateTime {
        chrono::NaiveDateTime::from_timestamp_opt( // todo get rid of all those mult/%... 
            (self.reception_time_us / 1_000_000) as i64,
            1000u32 * (self.reception_time_us % 1_000_000) as u32,
        )
        .unwrap_or_else(|| chrono::NaiveDateTime::from_timestamp(0, 0))
    }

    pub fn mcnt(&self) -> u8 {
        self.standard_header.mcnt
    }

    fn from(
        index: DltMessageIndexType,
        storage_header: DltStorageHeader,
        standard_header: DltStandardHeader,
        add_header_buf: &[u8],
        payload: Vec<u8>,
    ) -> DltMessage {
        let ecu = standard_header
            .ecu(add_header_buf)
            .unwrap_or_else(|| storage_header.ecu.clone());

        let timestamp_dms = standard_header.timestamp_dms(add_header_buf);

        let extended_header = if standard_header.has_ext_hdr() {
            DltExtendedHeader::from_buf(
                &add_header_buf[add_header_buf.len() - DLT_EXT_HEADER_SIZE..],
            )
        } else {
            None
        };

        DltMessage {
            index,
            reception_time_us: storage_header.reception_time_us(),
            ecu: ecu,
            timestamp_dms,
            standard_header,
            extended_header,
            payload,
            lifecycle: 0,
        }
    }

    #[cfg(test)]
    pub fn for_test() -> DltMessage {
        let timestamp_us =
            100 * NEXT_TEST_TIMESTAMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        DltMessage {
            index: 0,
            reception_time_us: 100_000 + timestamp_us,
            ecu: DltChar4::from_buf(b"TEST"),
            timestamp_dms: (timestamp_us / 100) as u32,
            standard_header: DltStandardHeader {
                htyp: 1,
                len: 0,
                mcnt: 0,
            },
            extended_header: None,
            payload: [].to_vec(),
            lifecycle: 0,
        }
    }

    pub fn is_big_endian(&self) -> bool {
        self.standard_header.is_big_endian()
    }

    pub fn apid(&self) -> Option<&DltChar4> {
        match &self.extended_header {
            None => None,
            Some(e) => Some(&e.apid),
        }
    }

    pub fn ctid(&self) -> Option<&DltChar4> {
        match &self.extended_header {
            None => None,
            Some(e) => Some(&e.ctid),
        }
    }
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub fn new(kind: ErrorKind) -> Error {
        Error { kind }
    }

    pub fn kind(&self) -> &ErrorKind {
        return &self.kind;
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            ErrorKind::NotEnoughData(amount) => {
                write!(f, "not enough data - missing at least {}", amount)
            }
            ErrorKind::InvalidData(ref desc) => {
                write!(f, "invalid data - {}", desc)
            }
            ErrorKind::OtherFatal(ref desc) => {
                write!(f, "other fatal error! - {}", desc)
            }
        }
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    InvalidData(String),
    NotEnoughData(usize),
    OtherFatal(String),
}

pub fn parse_dlt_with_storage_header(
    index: DltMessageIndexType,
    data: &mut impl BufRead,
) -> Result<(usize, DltMessage), Error> {
    let peek_buf = data.fill_buf().unwrap(); // todo err handling
                                             // eprintln!(
                                             //     "parse_dlt_with_storage_header peekBuf.len()={} data={:?}",
                                             //     peek_buf.len(),
                                             //     &peek_buf[0..16]
                                             // );
    let mut remaining = peek_buf.len();

    if remaining >= MIN_DLT_MSG_SIZE {
        match DltStorageHeader::from_buf(peek_buf) {
            Some(sh) => {
                remaining -= DLT_STORAGE_HEADER_SIZE;
                let stdh = DltStandardHeader::from_buf(&peek_buf[DLT_STORAGE_HEADER_SIZE..])
                    .expect("no valid stdheader!");
                let std_ext_header_size = stdh.std_ext_header_size();
                if stdh.len >= std_ext_header_size {
                    // do we have the remaining data?
                    if remaining >= stdh.len as usize {
                        remaining -= std_ext_header_size as usize;
                        let payload_offset = DLT_STORAGE_HEADER_SIZE + std_ext_header_size as usize;
                        let payload_size = stdh.len - std_ext_header_size as u16;
                        remaining -= payload_size as usize;
                        let to_consume = peek_buf.len() - remaining;
                        let payload = Vec::from(
                            &peek_buf[payload_offset..payload_offset + payload_size as usize],
                        );
                        let msg = DltMessage::from(
                            index,
                            sh,
                            stdh,
                            &peek_buf
                                [DLT_STORAGE_HEADER_SIZE + DLT_MIN_STD_HEADER_SIZE..payload_offset],
                            payload,
                        );
                        data.consume(to_consume);
                        Ok((to_consume, msg))
                    } else {
                        Err(Error::new(ErrorKind::NotEnoughData(
                            stdh.len as usize - remaining,
                        )))
                    }
                } else {
                    Err(Error::new(ErrorKind::InvalidData(String::from(
                        "stdh.len too small",
                    ))))
                }
            }
            None => Err(Error::new(ErrorKind::InvalidData(String::from(
                "no storageheader",
            )))),
        }
    } else {
        Err(Error::new(ErrorKind::NotEnoughData(
            MIN_DLT_MSG_SIZE - remaining,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod dlt_storage_header {
        use super::*;
        #[test]
        fn from_buf_invalid() {
            // wrong pattern
            let buf: Vec<u8> = vec![
                0x41, 0x4c, 0x54, 0x01, 224, 181, 124, 94, 0, 0, 0, 0, 0x45, 0x43, 0x55, 0x31,
            ];
            let shdr = DltStorageHeader::from_buf(&buf);
            assert_eq!(shdr.is_none(), true);
            // too short
            let buf: Vec<u8> = vec![
                0x41, 0x4c, 0x54, 0x01, 224, 181, 124, 94, 0, 0, 0, 0, 0x45, 0x43, 0x55,
            ];
            let shdr = DltStorageHeader::from_buf(&buf);
            assert_eq!(shdr.is_none(), true);
        }
        #[test]
        fn from_buf_valid1() {
            let buf: Vec<u8> = vec![
                0x44, 0x4c, 0x54, 0x01, 224, 181, 124, 94, 0, 0, 0, 0, 0x45, 0x43, 0x55, 0x31,
            ];
            let shdr =
                DltStorageHeader::from_buf(&buf).expect("failed to parse valid storage header");
            assert_eq!(shdr.secs, 1585231328); // 26.3.2020 14:02:08 gmt
            assert_eq!(shdr.micros, 0);
            assert_eq!(&shdr.ecu.char4, b"ECU1");
            assert_eq!(
                shdr.reception_time_ms() as u64 * 1000,
                shdr.reception_time_us()
            );
        }

        #[test]
        fn dltchar4_format() {
            assert_eq!(format!("{}", DltChar4::from_str("----").unwrap()), "----");
            // just 3 bytes
            assert_eq!(format!("{}", DltChar4::from_str("ECU").unwrap()), "ECU");
            // just 2 bytes
            assert_eq!(format!("{}", DltChar4::from_str("EC").unwrap()), "EC");
            // just 1 byte
            assert_eq!(format!("{}", DltChar4::from_str("E").unwrap()), "E");

            // just 1 byte but width 4
            assert_eq!(format!("{:4}", DltChar4::from_str("E").unwrap()), "E   ");

            // just 1 byte but pad left bound with - with interims to_string
            assert_eq!(format!("{:-<4}", DltChar4::from_str("E").unwrap().to_string()), "E---");

            // just 1 byte but pad left bound with - without to_string
            assert_eq!(format!("{:-<4}", DltChar4::from_str("E").unwrap()), "E---");
        }
    }
}
