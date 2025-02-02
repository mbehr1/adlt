pub mod control_msgs;
use chrono::{Local, TimeZone};
use encoding_rs::WINDOWS_1252;
use lazy_static::lazy_static;
use nohash_hasher::BuildNoHashHasher;
use serde::ser::{Serialize, Serializer};
use std::{
    borrow::Cow,
    collections::HashMap,
    convert::TryInto,
    fmt::{self, Write},
    str::FromStr,
    sync::LazyLock,
};

use crate::utils::{is_non_printable_char_wo_rnt, US_PER_SEC};
use control_msgs::{
    parse_ctrl_connection_info_payload, parse_ctrl_log_info_payload, parse_ctrl_sw_version_payload,
    parse_ctrl_timezone_payload, parse_ctrl_unregister_context_payload,
};

/// todo use perfo ideas from https://lise-henry.github.io/articles/optimising_strings.html
/// todo use crate ryu for float to str conversations (numtoa seems outdated)

// MARK: DltChar4
#[derive(Clone, Eq, Copy)] // Debug, Hash, Eq, Copy?
pub struct DltChar4 {
    char4: [u8; 4], // String, // todo u8,4 array?
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseNonAsciiError;

impl DltChar4 {
    /**
    convert from buffer to DltChar4
    It's assumed only printable ascii.

    Anyhow no conversions are done at construction on wrong/invalid data!

    [ ] todo decide whether the following should be done here already but then the orig data will be lost on export!

    chars < 0x20 are represented as '-'
    chars > 0x7e as '?'
    */
    pub fn from_buf(buf: &[u8]) -> DltChar4 {
        assert_eq!(
            4,
            buf.len(),
            "DltChar::from_buf with invalid buf len {} called",
            buf.len()
        );
        DltChar4 {
            char4: [buf[0], buf[1], buf[2], buf[3]],
        }
    }

    pub fn as_buf(&self) -> &[u8; 4] {
        &self.char4
    }

    /// hack to return the DltChar4 as a little endianess u32
    /// this is mainly for an efficient serialization as long as
    /// bincode-typescript doesn't support [u8;4]
    pub fn as_u32le(&self) -> u32 {
        u32::from_le_bytes(self.char4)
    }
}

impl std::hash::Hash for DltChar4 {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        hasher.write_u32(u32::from_ne_bytes(self.char4))
    }
}
impl nohash_hasher::IsEnabled for DltChar4 {}

impl PartialEq for DltChar4 {
    #[inline]
    fn eq(&self, other: &DltChar4) -> bool {
        u32::from_ne_bytes(self.char4).eq(&u32::from_ne_bytes(other.char4))
    }
}

impl FromStr for DltChar4 {
    type Err = ParseNonAsciiError;
    fn from_str(astr: &str) -> Result<Self, Self::Err> {
        // we do only support ascii strings
        // add some defaults? or return None
        if !astr.is_ascii() {
            return Err(ParseNonAsciiError);
        }
        let bytes = astr.as_bytes();
        let mut chars: [u8; 4] = [0, 0, 0, 0]; // [Dlt308]
        let avail_chars = std::cmp::min(bytes.len(), 4);
        chars[..avail_chars].clone_from_slice(&bytes[..avail_chars]);
        /*for n in 0..avail_chars {chars[n] = bytes[n];}*/

        Ok(DltChar4 { char4: chars })
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
    /**
        format the DltChar4 as a readable/printable ascii.

        The following conversions are done:
        - chars < 0x20 are represented as '-'
        - chars > 0x7e as '?'
    */
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut printable_chars: [u8; 4] = [0; 4];
        let mut printable_len = 0;
        for (i, printable_char) in printable_chars.iter_mut().enumerate() {
            let c = self.char4[i];
            if c > 0 {
                printable_len += 1;
                *printable_char = if c < 0x20 {
                    b'-'
                } else if c > 0x7e {
                    b'?'
                } else {
                    c
                };
            } else {
                break;
            }
        }
        let a_str: &str = if printable_len > 0 {
            unsafe {
                // we are really sure its valid utf8
                std::str::from_utf8_unchecked(&printable_chars[0..printable_len])
            }
        } else {
            ""
        };

        f.pad(a_str) // handles width, fill/align and precision
    }
}

// MARK: DltStorageHeader
#[derive(Debug)]
pub struct DltStorageHeader {
    // we dont store the pattern pub pattern: u32,
    pub secs: u32,
    pub micros: u32,
    pub ecu: DltChar4,
}

pub const DLT_STORAGE_HEADER_PATTERN: u32 = 0x01544c44; // DLT\01
pub const DLT_STORAGE_HEADER_SIZE: usize = 16; // DLT\0x1 + secs, micros, ecu

pub const DLT_SERIAL_HEADER_PATTERN: u32 = 0x01534c44; // DLS\01
pub const DLT_SERIAL_HEADER_SIZE: usize = 4; // just the pattern

/// maximum size of a DLT message with a storage header:
pub const DLT_MAX_STORAGE_MSG_SIZE: usize = DLT_STORAGE_HEADER_SIZE + u16::MAX as usize;

pub const DLT_MIN_STD_HEADER_SIZE: usize = 4;
pub const MIN_DLT_MSG_SIZE: usize = DLT_STORAGE_HEADER_SIZE + DLT_MIN_STD_HEADER_SIZE;
pub const DLT_EXT_HEADER_SIZE: usize = 10;

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

    fn from_msg(msg: &DltMessage) -> DltStorageHeader {
        DltStorageHeader {
            secs: (msg.reception_time_us / crate::utils::US_PER_SEC) as u32,
            micros: (msg.reception_time_us % crate::utils::US_PER_SEC) as u32,
            ecu: msg.ecu,
        }
    }

    /// serialize to a writer in DLT byte format
    fn to_write(&self, writer: &mut impl std::io::Write) -> Result<usize, std::io::Error> {
        let pat = DLT_STORAGE_HEADER_PATTERN;

        let b1 = &u32::to_le_bytes(pat);
        let b2 = &u32::to_le_bytes(self.secs);
        let b3 = &u32::to_le_bytes(self.micros);
        writer.write_all(b1)?;
        writer.write_all(b2)?;
        writer.write_all(b3)?;
        writer.write_all(&self.ecu.char4)?;
        Ok(DLT_STORAGE_HEADER_SIZE)
    }

    fn reception_time_us(&self) -> u64 {
        (self.secs as u64 * US_PER_SEC) + self.micros as u64
    }
    #[allow(dead_code)]
    fn reception_time_ms(&self) -> u64 {
        (self.secs as u64 * 1000) + (self.micros / 1000) as u64
    }
}

// dlt standard header htyp bitfield:
pub(crate) const DLT_STD_HDR_HAS_EXT_HDR: u8 = 1;
pub(crate) const DLT_STD_HDR_BIG_ENDIAN: u8 = 1 << 1;
pub(crate) const DLT_STD_HDR_HAS_ECU_ID: u8 = 1 << 2;
pub(crate) const DLT_STD_HDR_HAS_SESSION_ID: u8 = 1 << 3;
pub(crate) const DLT_STD_HDR_HAS_TIMESTAMP: u8 = 1 << 4;

pub(crate) const DLT_STD_HDR_VERSION: u8 = 0x1 << 5; // 3 bits (5,6,7) max.  [Dlt299]

// MARK: DltStandardHeader
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DltStandardHeader {
    pub htyp: u8,
    pub mcnt: u8,
    pub len: u16,
}

impl DltStandardHeader {
    pub fn from_buf(buf: &[u8]) -> Option<DltStandardHeader> {
        if buf.len() < 4 {
            return None;
        }
        let htyp = buf[0];
        let sh = DltStandardHeader {
            htyp,
            mcnt: buf[1],
            len: u16::from_be_bytes([buf[2], buf[3]]), // all big endian includes std.header, ext header and the payload
        };
        // [Dlt104] check the version number. We expect 0x1 currently
        /* let dlt_vers = sh.dlt_vers();
        match dlt_vers {
            1 => (),
            _ => {
                // eprintln!("DltStandardHeader with unsupported version {}!", dlt_vers);
                // todo return None? / set len to 0, exthdr,... to false
            }
        } */

        Some(sh)
    }

    /// write a full DLT message starting with a standard header
    /// changes the standard header (ignores) htyp to reflect
    /// whether ecu, session_id, timestamp is available!
    // todo example
    pub fn to_write(
        writer: &mut impl std::io::Write,
        std_hdr: &DltStandardHeader,
        ext_hdr: &Option<DltExtendedHeader>,
        ecu: Option<DltChar4>,
        session_id: Option<u32>,
        timestamp: Option<u32>,
        payload: &[u8],
    ) -> Result<(), std::io::Error> {
        let mut htyp: u8 = if std_hdr.is_big_endian() {
            DLT_STD_HDR_VERSION | DLT_STD_HDR_BIG_ENDIAN
        } else {
            DLT_STD_HDR_VERSION
        };
        let mut len: u16 = DLT_MIN_STD_HEADER_SIZE as u16;
        if ecu.is_some() {
            htyp |= DLT_STD_HDR_HAS_ECU_ID;
            len += 4;
        }
        if session_id.is_some() {
            htyp |= DLT_STD_HDR_HAS_SESSION_ID;
            len += 4;
        }
        if timestamp.is_some() {
            htyp |= DLT_STD_HDR_HAS_TIMESTAMP;
            len += 4;
        }
        if ext_hdr.is_some() {
            htyp |= DLT_STD_HDR_HAS_EXT_HDR;
            len += DLT_EXT_HEADER_SIZE as u16;
        }
        len += payload.len() as u16; // todo check for max len...

        let b2 = &u16::to_be_bytes(len);
        let b1 = &[htyp, std_hdr.mcnt, b2[0], b2[1]];
        writer.write_all(b1)?;
        if let Some(e) = ecu {
            writer.write_all(&e.char4)?;
        }
        if let Some(s) = session_id {
            writer.write_all(&u32::to_be_bytes(s))?;
        }
        if let Some(t) = timestamp {
            writer.write_all(&u32::to_be_bytes(t))?;
        }
        if let Some(e) = ext_hdr {
            e.to_write(writer)?;
        }
        if !payload.is_empty() {
            writer.write_all(payload)?;
        }

        Ok(())
    }

    /// return the size of this standard header and the expected extensions
    /// like ecu, session_id, timestamp and extended header.
    pub fn std_ext_header_size(&self) -> u16 {
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

    #[inline(always)]
    /// returns the dlt version from header. Currently only 0x1 should be supported.
    pub fn dlt_vers(&self) -> u8 {
        (self.htyp >> 5) & 0x07
    }

    #[inline(always)]
    pub fn has_ext_hdr(&self) -> bool {
        (self.htyp & DLT_STD_HDR_HAS_EXT_HDR) > 0
    }

    #[inline(always)]
    pub fn is_big_endian(&self) -> bool {
        (self.htyp & DLT_STD_HDR_BIG_ENDIAN) > 0
    }

    #[inline(always)]
    pub fn has_ecu_id(&self) -> bool {
        (self.htyp & DLT_STD_HDR_HAS_ECU_ID) > 0
    }

    #[inline(always)]
    pub fn has_session_id(&self) -> bool {
        (self.htyp & DLT_STD_HDR_HAS_SESSION_ID) > 0
    }

    #[inline(always)]
    pub fn has_timestamp(&self) -> bool {
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

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DltMessageLogType {
    Fatal = 1,
    Error,
    Warn,
    Info,
    Debug,
    Verbose,
}

impl DltMessageLogType {
    fn from(mtin: u8) -> DltMessageLogType {
        match mtin {
            2 => DltMessageLogType::Error,
            3 => DltMessageLogType::Warn,
            4 => DltMessageLogType::Info,
            5 => DltMessageLogType::Debug,
            6 => DltMessageLogType::Verbose,
            1 => DltMessageLogType::Fatal,
            _ => DltMessageLogType::Fatal,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DltMessageTraceType {
    Variable = 1,
    FunctionIn,
    FunctionOut,
    State,
    Vfb,
}

impl DltMessageTraceType {
    fn from(mtin: u8) -> DltMessageTraceType {
        match mtin {
            2 => DltMessageTraceType::FunctionIn,
            3 => DltMessageTraceType::FunctionOut,
            4 => DltMessageTraceType::State,
            5 => DltMessageTraceType::Vfb,
            1 => DltMessageTraceType::Variable,
            _ => DltMessageTraceType::Variable,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DltMessageNwType {
    Ipc = 1,
    Can,
    Flexray,
    Most,
    Ethernet,
    SomeIp,
}

impl DltMessageNwType {
    fn from(mtin: u8) -> DltMessageNwType {
        match mtin {
            2 => DltMessageNwType::Can,
            3 => DltMessageNwType::Flexray,
            4 => DltMessageNwType::Most,
            5 => DltMessageNwType::Ethernet,
            6 => DltMessageNwType::SomeIp,
            1 => DltMessageNwType::Ipc,
            _ => DltMessageNwType::Ipc,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DltMessageControlType {
    Request = 1,
    Response,
    Time,
}

impl DltMessageControlType {
    fn from(mtin: u8) -> DltMessageControlType {
        match mtin {
            2 => DltMessageControlType::Response,
            3 => DltMessageControlType::Time,
            1 => DltMessageControlType::Request,
            _ => DltMessageControlType::Request,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DltMessageType {
    Log(DltMessageLogType),
    AppTrace(DltMessageTraceType),
    NwTrace(DltMessageNwType),
    Control(DltMessageControlType),
}

// MARK: DltExtendedHeader
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DltExtendedHeader {
    pub verb_mstp_mtin: u8,
    pub noar: u8,
    pub apid: DltChar4,
    pub ctid: DltChar4,
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

    /// is verbose message?
    pub fn is_verbose(&self) -> bool {
        self.verb_mstp_mtin & 0x01 == 0x01
    }

    /// return message type info
    /// combined mstp/mtin info is returned
    /// for now invalid values lead to Log()
    pub fn mstp(&self) -> DltMessageType {
        let mstp = (self.verb_mstp_mtin >> 1) & 0x7;
        let mtin = (self.verb_mstp_mtin >> 4) & 0xf;
        match mstp {
            1 => DltMessageType::AppTrace(DltMessageTraceType::from(mtin)),
            2 => DltMessageType::NwTrace(DltMessageNwType::from(mtin)),
            3 => DltMessageType::Control(DltMessageControlType::from(mtin)),
            0 => DltMessageType::Log(DltMessageLogType::from(mtin)),
            _ => DltMessageType::Log(DltMessageLogType::from(mtin)),
        }
    }

    /// serialize to a writer in DLT byte format
    pub(crate) fn to_write(
        &self,
        writer: &mut impl std::io::Write,
    ) -> Result<usize, std::io::Error> {
        let b1 = &[self.verb_mstp_mtin, self.noar];
        writer.write_all(b1)?;
        writer.write_all(&self.apid.char4)?;
        writer.write_all(&self.ctid.char4)?;
        Ok(DLT_EXT_HEADER_SIZE)
    }
}

/// Index type for DltMessage. 32bit seem somewhat limited. but we save 4bytes in ram per msg. which alone make 16gb saved for a huge dlt file with 4mrd msgs...
/// anyhow prepare a type so that it can be easily changed later.
pub type DltMessageIndexType = u32;

// MARK: DltMessage
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DltMessage {
    pub index: DltMessageIndexType,
    pub reception_time_us: u64, // from storage header, ms would be sufficent but needs same 64 bit
    pub ecu: DltChar4,
    // sessionId: u32 todo
    pub timestamp_dms: u32, // orig in 0.1ms (deci-ms)
    pub standard_header: DltStandardHeader,
    pub extended_header: Option<DltExtendedHeader>, // todo optimize ecu, apid, ctid into one map<u32>
    pub payload: Vec<u8>,
    pub payload_text: Option<String>,
    pub lifecycle: crate::lifecycle::LifecycleId, // 0 = none, otherwise the id of an lifecycle
}

#[cfg(test)]
static NEXT_TEST_TIMESTAMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

static DEFAULT_APID_CTID: DltChar4 = DltChar4 {
    char4: [b'-', b'-', b'-', b'-'],
};

static LOG_LEVEL_STRS: [&str; 7] = ["", "fatal", "error", "warn", "info", "debug", "verbose"];
static TRACE_TYPE_STRS: [&str; 6] = ["", "variable", "func_in", "func_out", "state", "vfb"];
static NW_TYPE_STRS: [&str; 7] = ["", "ipc", "can", "flexray", "most", "ethernet", "someip"];
static CONTROL_TYPE_STRS: [&str; 4] = ["", "request", "response", "time"];

pub const SERVICE_ID_GET_LOG_INFO: u32 = 3;
pub const SERVICE_ID_GET_SOFTWARE_VERSION: u32 = 19;

// user services as from dlt-daemon:
pub const SERVICE_ID_UNREGISTER_CONTEXT: u32 = 0xF01;
pub const SERVICE_ID_CONNECTION_INFO: u32 = 0xF02;
pub const SERVICE_ID_TIMEZONE: u32 = 0xF03;
pub const SERVICE_ID_MARKER: u32 = 0xF04;
pub const SERVICE_ID_OFFLINE_LOGSTORAGE: u32 = 0xF05;
pub const SERVICE_ID_PASSIVE_NODE_CONNECT: u32 = 0xF06;
pub const SERVICE_ID_PASSIVE_NODE_CONNECTION_STATUS: u32 = 0xF07;
pub const SERVICE_ID_SET_ALL_LOG_LEVEL: u32 = 0xF08;
pub const SERVICE_ID_SET_ALL_TRACE_STATUS: u32 = 0xF09;
pub const SERVICE_ID_RESERVED_B: u32 = 0xF0B;
pub const SERVICE_ID_RESERVED_C: u32 = 0xF0C;
pub const SERVICE_ID_RESERVED_D: u32 = 0xF0D;
pub const SERVICE_ID_RESERVED_E: u32 = 0xF0E;

type HashMapNoHash<K, V> = HashMap<K, V, BuildNoHashHasher<K>>;
static SERVICE_ID_NAMES: LazyLock<HashMapNoHash<u32, &'static str>> = LazyLock::new(|| {
    let mut map = HashMapNoHash::default();
    map.extend([
        (1, "set_log_level"),
        (2, "set_trace_status"),
        (SERVICE_ID_GET_LOG_INFO, "get_log_info"),
        (4, "get_default_log_level"),
        (5, "store_config"),
        (6, "reset_to_factory_default"),
        (7, "set_com_interface_status"),
        (8, "set_com_interface_max_bandwidth"),
        (9, "set_verbose_mode"),
        (10, "set_message_filtering"),
        (11, "set_timing_packets"),
        (12, "get_local_time"),
        (13, "use_ecu_id"),
        (14, "use_session_id"),
        (15, "use_timestamp"),
        (16, "use_extended_header"),
        (17, "set_default_log_level"),
        (18, "set_default_trace_status"),
        (SERVICE_ID_GET_SOFTWARE_VERSION, "get_software_version"),
        (20, "message_buffer_overflow"),
        // user services as from dlt-daemon:
        (SERVICE_ID_UNREGISTER_CONTEXT, "unregister_context"),
        (SERVICE_ID_CONNECTION_INFO, "connection_info"),
        (SERVICE_ID_TIMEZONE, "timezone"),
        (SERVICE_ID_MARKER, "MARKER"),
        (SERVICE_ID_OFFLINE_LOGSTORAGE, "offline_logstorage"),
        (SERVICE_ID_PASSIVE_NODE_CONNECT, "passive_node_connect"),
        (
            SERVICE_ID_PASSIVE_NODE_CONNECTION_STATUS,
            "passive_node_connection_status",
        ),
        (SERVICE_ID_SET_ALL_LOG_LEVEL, "set_all_log_level"),
        (SERVICE_ID_SET_ALL_TRACE_STATUS, "set_all_trace_status"),
        (0xF0A, "undefined"),
        (SERVICE_ID_RESERVED_B, "reserved_b"),
        (SERVICE_ID_RESERVED_C, "reserved_c"),
        (SERVICE_ID_RESERVED_D, "reserved_d"),
        (SERVICE_ID_RESERVED_E, "reserved_e"),
    ]);
    map
});

static CTRL_RESPONSE_STRS: [&str; 9] = [
    "ok",
    "not_supported",
    "error",
    "perm_denied",
    "warning",
    "",
    "",
    "",
    "no_matching_context_id",
];

lazy_static! {
    pub(crate) static ref RE_NEW_LINE: regex::Regex = regex::Regex::new(r"[\r\n\t]").unwrap();
}

impl DltMessage {
    pub fn timestamp_us(&self) -> u64 {
        self.timestamp_dms as u64 * 100
    }

    pub fn reception_time(&self) -> chrono::NaiveDateTime {
        crate::utils::utc_time_from_us(self.reception_time_us)
    }

    pub fn mcnt(&self) -> u8 {
        self.standard_header.mcnt
    }

    /// return the message type based on the extended header info.
    /// If the message has no extended header Log/Fatal is used as default.
    pub fn mstp(&self) -> DltMessageType {
        match &self.extended_header {
            Some(e) => e.mstp(),
            None => DltMessageType::Log(DltMessageLogType::Fatal), // using this as default
        }
    }

    /// return whether the message is a CONTROL_REQUEST message
    #[inline(always)]
    pub fn is_ctrl_request(&self) -> bool {
        match &self.extended_header {
            Some(e) => {
                // could return e.mstp() == DltMessageType::Control(DltMessageControlType::Request)
                (e.verb_mstp_mtin >> 1) & 0x07 ==  3 && // TYPE_CONTROL
            (e.verb_mstp_mtin>>4 & 0x0f) == 1
                // mtin == MTIN_CTRL.CONTROL_REQUEST
            }
            None => false,
        }
    }

    /// return whether the message is a CONTROL_RESPONSE message
    #[inline(always)]
    pub fn is_ctrl_response(&self) -> bool {
        match &self.extended_header {
            Some(e) => {
                // could return e.mstp() == DltMessageType::Control(DltMessageControlType::Response)
                (e.verb_mstp_mtin >> 1) & 0x07 ==  3 && // TYPE_CONTROL
                (e.verb_mstp_mtin>>4 & 0x0f) == 2
                // mtin == MTIN_CTRL.CONTROL_RESPONSE
            }
            None => false,
        }
    }

    /// return number of args from extended header. Returns 0 if no ext header is avail.
    pub fn noar(&self) -> u8 {
        match &self.extended_header {
            Some(e) => e.noar,
            None => 0,
        }
    }

    /// return whether message has verbose mode (from ext header). false if no ext header.
    #[inline(always)]
    pub fn is_verbose(&self) -> bool {
        match &self.extended_header {
            Some(e) => e.is_verbose(),
            None => false, // [Dlt096]
        }
    }

    /// return verb_mstp_mtin field from ext header. None if no ext header
    pub fn verb_mstp_mtin(&self) -> Option<u8> {
        self.extended_header.as_ref().map(|e| e.verb_mstp_mtin)
    }

    pub fn from_headers(
        index: DltMessageIndexType,
        storage_header: DltStorageHeader,
        standard_header: DltStandardHeader,
        add_header_buf: &[u8],
        payload: Vec<u8>,
    ) -> DltMessage {
        let ecu = standard_header
            .ecu(add_header_buf)
            .unwrap_or(storage_header.ecu);

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
            ecu,
            timestamp_dms,
            standard_header,
            extended_header,
            payload,
            payload_text: None,
            lifecycle: 0,
        }
    }

    /// write the msg to a writer as a DLT file byte stream
    /// - storage header
    /// - standard header
    /// - extended header
    /// - payload
    ///
    /// Doesn't try to do "atomic" writes, might fail on io errors with partial writes.
    ///
    /// session_id not supported yet.
    ///
    /// Payload endian format is taken from the msg.
    pub fn to_write(&self, writer: &mut impl std::io::Write) -> Result<(), std::io::Error> {
        let storage_header = DltStorageHeader::from_msg(self);
        storage_header.to_write(writer)?;
        DltStandardHeader::to_write(
            writer,
            &self.standard_header,
            &self.extended_header,
            None, // ecu already in storageheader
            None, // session_id = None, todo
            if self.standard_header.has_timestamp() {
                Some(self.timestamp_dms)
            } else {
                None
            },
            &self.payload,
        )?;
        Ok(())
    }

    pub fn header_as_text_to_write<T: std::io::Write>(
        &self,
        writer: &mut T,
    ) -> Result<(), std::io::Error> {
        write!(
            writer,
            "{index} {reception_time} {timestamp_dms:10} {mcnt:03} {ecu:-<4} {apid:-<4} {ctid:-<4} ",
            index = self.index,
            reception_time = Local
                .from_utc_datetime(&self.reception_time())
                .format("%Y/%m/%d %H:%M:%S%.6f"),
            timestamp_dms = self.timestamp_dms,
            mcnt = self.mcnt(),
            ecu = self.ecu,
            apid = self.apid().unwrap_or(&DEFAULT_APID_CTID),
            ctid = self.ctid().unwrap_or(&DEFAULT_APID_CTID),
        )?;
        if self.extended_header.is_some() {
            match self.mstp() {
                DltMessageType::Control(ct) => {
                    write!(writer, "control {}", CONTROL_TYPE_STRS[ct as usize])?;
                    // todo
                }
                DltMessageType::AppTrace(tt) => {
                    write!(writer, "app_trace {}", TRACE_TYPE_STRS[tt as usize])?;
                    // todo
                }
                DltMessageType::NwTrace(nt) => {
                    write!(writer, "nw_trace {}", NW_TYPE_STRS[nt as usize])?;
                    // todo
                }
                DltMessageType::Log(lt) => {
                    write!(writer, "log {}", LOG_LEVEL_STRS[lt as usize])?;
                }
            }
            if self.is_verbose() {
                writer.write_all(b" V")?;
            } else {
                writer.write_all(b" N")?;
            }
        } else {
            writer.write_all(b"--- --- N -")?;
        }

        write!(writer, " {}", self.noar())?;

        Ok(())
    }

    /// overwrite the payload text
    ///
    /// this is intended to be used by e.g. plugins to modify the payload text
    /// for now we use a 2nd variable but we could as well simply modify the payload
    /// todo think about better ways (pros/cons)
    pub fn set_payload_text(&mut self, text: String) {
        self.payload_text = Some(text);
    }

    /// process the iterator adding text to the provided string.
    /// The text is modified and should only be used if no error is returned
    pub(crate) fn process_msg_arg_iter<'a, I>(
        args: I,
        text: &mut String,
    ) -> Result<(), std::fmt::Error>
    where
        I: Iterator<Item = DltArg<'a>>,
    {
        let mut itoa_buf = itoa::Buffer::new(); // even though cheap, we do reuse
        for (nr_arg, arg) in args.enumerate() {
            if nr_arg > 0 {
                text.push(' ');
            }
            // let _tyle = arg.type_info & 0x0f;
            let is_bool = arg.type_info & DLT_TYPE_INFO_BOOL > 0;
            let is_sint = arg.type_info & DLT_TYPE_INFO_SINT > 0;
            let is_uint = arg.type_info & DLT_TYPE_INFO_UINT > 0;
            let is_floa = arg.type_info & DLT_TYPE_INFO_FLOA > 0;
            let _is_aray = arg.type_info & DLT_TYPE_INFO_ARAY > 0;
            let is_strg = arg.type_info & DLT_TYPE_INFO_STRG > 0;
            let is_rawd = arg.type_info & DLT_TYPE_INFO_RAWD > 0;

            if is_bool {
                let val = arg.payload_raw[0];
                if val > 0 {
                    text.push_str("true");
                } else {
                    text.push_str("false");
                }
            } else if is_uint {
                match arg.payload_raw.len() {
                    1 => {
                        let val: u8 = arg.payload_raw[0];
                        text.push_str(itoa_buf.format(val));
                        // itoa_buf is faster than write!(text, "{}", val)?; // is surpringly faster than text.write_str(&val.to_string())?;
                    }
                    2 => {
                        let val: u16 = if arg.is_big_endian {
                            u16::from_be_bytes(arg.payload_raw.try_into().unwrap())
                        } else {
                            u16::from_le_bytes(arg.payload_raw.try_into().unwrap())
                        };
                        text.push_str(itoa_buf.format(val));
                    }
                    4 => {
                        let val: u32 = if arg.is_big_endian {
                            u32::from_be_bytes(arg.payload_raw.try_into().unwrap())
                        } else {
                            u32::from_le_bytes(arg.payload_raw.try_into().unwrap())
                        };
                        text.push_str(itoa_buf.format(val));
                    }
                    8 => {
                        let val: u64 = if arg.is_big_endian {
                            u64::from_be_bytes(arg.payload_raw.try_into().unwrap())
                        } else {
                            u64::from_le_bytes(arg.payload_raw.try_into().unwrap())
                        };
                        text.push_str(itoa_buf.format(val));
                    }
                    16 => {
                        let val: u128 = if arg.is_big_endian {
                            u128::from_be_bytes(arg.payload_raw.try_into().unwrap())
                        } else {
                            u128::from_le_bytes(arg.payload_raw.try_into().unwrap())
                        };
                        text.push_str(itoa_buf.format(val));
                    }
                    _ => (),
                };
            } else if is_sint {
                match arg.payload_raw.len() {
                    1 => {
                        let val: i8 = arg.payload_raw[0] as i8;
                        text.push_str(itoa_buf.format(val));
                    }
                    2 => {
                        let val: i16 = if arg.is_big_endian {
                            i16::from_be_bytes(arg.payload_raw.try_into().unwrap())
                        } else {
                            i16::from_le_bytes(arg.payload_raw.try_into().unwrap())
                        };
                        text.push_str(itoa_buf.format(val));
                    }
                    4 => {
                        let val: i32 = if arg.is_big_endian {
                            i32::from_be_bytes(arg.payload_raw.try_into().unwrap())
                        } else {
                            i32::from_le_bytes(arg.payload_raw.try_into().unwrap())
                        };
                        text.push_str(itoa_buf.format(val));
                    }
                    8 => {
                        let val: i64 = if arg.is_big_endian {
                            i64::from_be_bytes(arg.payload_raw.try_into().unwrap())
                        } else {
                            i64::from_le_bytes(arg.payload_raw.try_into().unwrap())
                        };
                        text.push_str(itoa_buf.format(val));
                    }
                    16 => {
                        let val: i128 = if arg.is_big_endian {
                            i128::from_be_bytes(arg.payload_raw.try_into().unwrap())
                        } else {
                            i128::from_le_bytes(arg.payload_raw.try_into().unwrap())
                        };
                        text.push_str(itoa_buf.format(val));
                    }
                    _ => (),
                };
            } else if is_floa {
                match arg.payload_raw.len() {
                    4 => {
                        let val: f32 = if arg.is_big_endian {
                            f32::from_be_bytes(arg.payload_raw.try_into().unwrap())
                        } else {
                            f32::from_le_bytes(arg.payload_raw.try_into().unwrap())
                        };
                        write!(text, "{}", val)?;
                        // ryu seems not to be faster (at least in our bench dlt_payload_verb)
                        //text.push_str(ryu::Buffer::new().format(val));
                    }
                    8 => {
                        let val: f64 = if arg.is_big_endian {
                            f64::from_be_bytes(arg.payload_raw.try_into().unwrap())
                        } else {
                            f64::from_le_bytes(arg.payload_raw.try_into().unwrap())
                        };
                        write!(text, "{}", val)?;
                        //text.push_str(ryu::Buffer::new().format(val));
                    }
                    // f16 and f128 dont exist. todo could use create half::f16 and f128::f128 but dlt-viewer doesn't support it either
                    _ => {
                        write!(
                            text,
                            "?<floa with len={} raw={:?}>",
                            arg.payload_raw.len(),
                            arg.payload_raw
                        )?;
                    }
                }
            } else if is_rawd {
                if !arg.payload_raw.is_empty() {
                    for (i, &c) in arg.payload_raw[0..arg.payload_raw.len()].iter().enumerate() {
                        if i > 0 {
                            write!(text, " {:02x}", c)?;
                        } else {
                            write!(text, "{:02x}", c)?;
                        }
                    }
                }
            } else if is_strg {
                let scod = arg.type_info & DLT_TYPE_INFO_MASK_SCOD;
                match scod {
                    DLT_SCOD_UTF8 => {
                        // according to PRS_Dlt_00156 and PRS_Dlt_00373 the strings should *not* be zero terminated.
                        // but it seems that some client libs (e.g. genivi/covesa dlt-client) to zero terminate
                        // so we do autodetect here whether a zero is the last payload_raw byte and if so ignore it.

                        if !arg.payload_raw.is_empty() {
                            // is the last payload byte a zero term?
                            let is_zero_term = arg.payload_raw[arg.payload_raw.len() - 1] == 0u8;

                            // use copy-on-write strings that alloc only if modification is needed
                            let s = String::from_utf8_lossy(
                                &arg.payload_raw
                                    [0..arg.payload_raw.len() - if is_zero_term { 1 } else { 0 }],
                            );
                            /* todo or ? let s = match s {
                                std::borrow::Cow::Borrowed(s) => RE.replace_all(s, " "),
                                std::borrow::Cow::Owned(s) => std::borrow::Cow::Owned(
                                    RE.replace_all(&s, " ").into_owned(),
                                ),
                            };*/
                            let s = RE_NEW_LINE.replace_all(&s, " ");
                            text.push_str(&s);
                        }
                    }
                    DLT_SCOD_ASCII => {
                        // dlt doesn't seem to define the ASCII codepage.
                        // we could use ISO-8859-1 or WINDOWS_1252 "Latin 1"
                        // or we reduce the printable ones to 0x20 (' ') .. 0x7e ('~')
                        // for now we start with WINDOWS_1252 and \n\r\t -> ' '
                        // zero terminated: (see above, not expected but done by some famous libs)
                        if !arg.payload_raw.is_empty() {
                            // is the last payload byte a zero term?
                            let is_zero_term = arg.payload_raw[arg.payload_raw.len() - 1] == 0u8;
                            // use copy-on-write strings that alloc only if modification is needed
                            let (s, _) = WINDOWS_1252.decode_without_bom_handling(
                                &arg.payload_raw
                                    [0..arg.payload_raw.len() - if is_zero_term { 1 } else { 0 }],
                            );
                            let s = RE_NEW_LINE.replace_all(&s, " ");
                            text.push_str(&s);
                        }
                    }

                    DLT_SCOD_HEX => {
                        write!(text, "<scod hex nyi! todo>")?;
                    }
                    DLT_SCOD_BIN => {
                        write!(text, "<scod bin nyi! todo>")?;
                    }
                    _ => {
                        write!(text, "<scod unknown {}>", scod)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn payload_as_text(&self) -> Result<Cow<str>, std::fmt::Error> {
        if let Some(text) = &self.payload_text {
            return Ok(Cow::Borrowed(text));
        }
        let mut args = self.into_iter();
        if self.is_verbose() {
            let mut text = String::with_capacity(256); // String::new(); // can we guess the capacity upfront better? (e.g. payload len *3?)
            DltMessage::process_msg_arg_iter(args, &mut text)?;
            Ok(Cow::Owned(text))
        } else {
            // non-verbose
            let message_id_arg = args.next();
            let message_id = match message_id_arg {
                Some(a) => {
                    if a.is_big_endian {
                        // todo this fails if first arg is not a uint32! add check
                        u32::from_be_bytes(a.payload_raw.get(0..4).unwrap().try_into().unwrap())
                    } else {
                        u32::from_le_bytes(a.payload_raw.get(0..4).unwrap().try_into().unwrap())
                    }
                }
                None => {
                    return Ok("[<args missing>]".into()); // stop here
                }
            };
            let payload_arg = args.next();
            let (payload, is_big_endian) = match payload_arg {
                Some(a) => (a.payload_raw, a.is_big_endian),
                None => (&[] as &[u8], false),
            };

            match self.mstp() {
                DltMessageType::Control(ct) => {
                    let mut text = String::with_capacity(256); // String::new(); // can we guess the capacity upfront better? (e.g. payload len *3?)
                    if let Some(service_name) = SERVICE_ID_NAMES.get(&message_id) {
                        write!(&mut text, "[{}", service_name)?;
                    } else if ct != DltMessageControlType::Time {
                        write!(&mut text, "[service({})", message_id)?;
                    }
                    let mut needs_closing_bracket = true;
                    match ct {
                        DltMessageControlType::Response => {
                            // todo dump first byte as response result
                            if !payload.is_empty() {
                                let retval = payload.first().unwrap();
                                if *retval < 5u8 || *retval == 8u8 {
                                    write!(
                                        &mut text,
                                        " {}]",
                                        CTRL_RESPONSE_STRS[*retval as usize]
                                    )?;
                                } else {
                                    write!(&mut text, " {:02x}]", *retval)?;
                                }
                                needs_closing_bracket = false;
                                let payload = &payload[1..];
                                match message_id {
                                    SERVICE_ID_GET_SOFTWARE_VERSION => {
                                        let res =
                                            parse_ctrl_sw_version_payload(is_big_endian, payload);
                                        if let Some(res) = res {
                                            write!(&mut text, " ")?;
                                            text.write_str(&res)?;
                                        }
                                    }
                                    SERVICE_ID_GET_LOG_INFO => {
                                        let apids = parse_ctrl_log_info_payload(
                                            *retval,
                                            is_big_endian,
                                            payload,
                                        );
                                        // output as json parseable array
                                        let apids_json = serde_json::to_string(&apids);
                                        match &apids_json {
                                            Ok(apid_str) => write!(&mut text, " {}", apid_str)?,
                                            Err(err) => write!(&mut text, " got err={:?}", err)?,
                                        }
                                    }
                                    SERVICE_ID_UNREGISTER_CONTEXT => {
                                        if let Some((apid, ctid, comid)) =
                                            parse_ctrl_unregister_context_payload(payload)
                                        {
                                            let val = serde_json::json!({
                                                "apid": apid,
                                                "ctid": ctid,
                                                "comid": comid
                                            });
                                            write!(&mut text, " {}", val)?;
                                        } else {
                                            write!(&mut text, " ")?;
                                            crate::utils::buf_as_hex_to_write(&mut text, payload)?;
                                        }
                                    }
                                    SERVICE_ID_CONNECTION_INFO => {
                                        if let Some((state, comid)) =
                                            parse_ctrl_connection_info_payload(payload)
                                        {
                                            let val = serde_json::json!({
                                                "state": match state {
                                                    1 => "disconnected",
                                                    2 => "connected",
                                                    _ => "unknown",
                                                },
                                                "comid": comid
                                            });
                                            write!(&mut text, " {}", val)?;
                                        } else {
                                            write!(&mut text, " ")?;
                                            crate::utils::buf_as_hex_to_write(&mut text, payload)?;
                                        }
                                    }
                                    SERVICE_ID_TIMEZONE => {
                                        if let Some((gmt_off, is_dst)) =
                                            parse_ctrl_timezone_payload(is_big_endian, payload)
                                        {
                                            write!(
                                                &mut text,
                                                " {{\"gmt_off_secs\":{},\"is_dst\":{}}}",
                                                gmt_off,
                                                if is_dst { "true" } else { "false" }
                                            )?;
                                        } else {
                                            write!(&mut text, " ")?;
                                            crate::utils::buf_as_hex_to_write(&mut text, payload)?;
                                        }
                                    }
                                    _ => {
                                        write!(&mut text, " ")?;
                                        crate::utils::buf_as_hex_to_write(&mut text, payload)?;
                                    } // todo add SERVICE_ID_OFFLINE_LOGSTORAGE, SERVICE_ID_PASSIVE_NODE_CONNECT, SERVICE_ID_PASSIVE_NODE_CONNECTION_STATUS, SERVICE_ID_SET_ALL_LOG_LEVEL, SERVICE_ID_SET_ALL_TRACE_STATUS
                                }
                            }
                        }
                        _ => {
                            write!(&mut text, "] ")?;
                            needs_closing_bracket = false;
                            crate::utils::buf_as_hex_to_write(&mut text, payload)?;
                            // todo
                        }
                    }
                    if needs_closing_bracket {
                        write!(&mut text, "]")?;
                    }
                    Ok(Cow::Owned(text))
                }
                _ => {
                    // write in dlt-viewer format [<msg id>] ascii chars| hex dump e.g. [4711] CID|43 49 44
                    const MAX_U32_LEN: usize = "4294967295".len(); // format!("{}", u32::MAX).len();
                    let est_len_ascii = 3 + 1 + MAX_U32_LEN + payload.len();
                    // if the string is too long the time for the search removes the benefit of a smaller allocation
                    // so we assume >128 bytes that we will replace the ascii chars with a hex dump
                    let will_be_replaced =
                        est_len_ascii > 128 || payload.iter().any(is_non_printable_char_wo_rnt);
                    let est_len_full = if will_be_replaced {
                        est_len_ascii + (payload.len() * 3) - if payload.is_empty() { 0 } else { 1 }
                    } else {
                        est_len_ascii
                    };
                    let mut text = String::with_capacity(est_len_full.next_power_of_two());
                    write!(&mut text, "[{}] ", message_id)?;
                    let times_replaced =
                        crate::utils::buf_as_printable_ascii_to_write(&mut text, payload, '-')?;
                    text.push('|');
                    if times_replaced > 0 {
                        crate::utils::buf_as_hex_to_write(&mut text, payload)?;
                    }
                    Ok(Cow::Owned(text))
                }
            }
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
                htyp: DLT_STD_HDR_HAS_TIMESTAMP,
                len: 0,
                mcnt: 0,
            },
            extended_header: None,
            payload: [].to_vec(),
            payload_text: None,
            lifecycle: 0,
        }
    }

    #[cfg(test)]
    pub fn for_test_rcv_tms_ms(reception_time_ms: u64, timestamp_ms: u32) -> DltMessage {
        DltMessage {
            index: 0,
            reception_time_us: 1640995200000000 /* 1.1.22, 00:00:00 as GMT */ + (reception_time_ms * 1_000),
            ecu: DltChar4::from_buf(b"TEST"),
            timestamp_dms: (timestamp_ms * 10),
            standard_header: DltStandardHeader {
                htyp: DLT_STD_HDR_HAS_TIMESTAMP,
                len: 0,
                mcnt: 0,
            },
            extended_header: None,
            payload: [].to_vec(),
            payload_text: None,
            lifecycle: 0,
        }
    }

    #[cfg(test)]
    /// return a control message
    pub fn get_testmsg_control(big_endian: bool, noar: u8, payload_buf: &[u8]) -> DltMessage {
        let sh = DltStorageHeader {
            secs: 0,
            micros: 0,
            ecu: DltChar4::from_str("ECU1").unwrap(),
        };
        let exth = DltExtendedHeader {
            verb_mstp_mtin: 0x3 << 1 | (0x02 << 4),
            noar,
            apid: DltChar4::from_buf(b"DA1\0"),
            ctid: DltChar4::from_buf(b"DC1\0"),
        };
        let stdh = DltStandardHeader {
            htyp: 0x21
                | (if big_endian {
                    DLT_STD_HDR_BIG_ENDIAN
                } else {
                    0
                }),
            mcnt: 0,
            len: (DLT_MIN_STD_HEADER_SIZE + DLT_EXT_HEADER_SIZE + payload_buf.len()) as u16,
        };
        let mut add_header_buf = Vec::new();
        exth.to_write(&mut add_header_buf).unwrap();

        DltMessage::from_headers(1, sh, stdh, &add_header_buf, payload_buf.to_vec())
    }

    /// return a verbose dltmessage with the noar and payload
    ///
    /// should only be used for testing
    ///
    /// ECU1/APID/CTID is used
    pub fn get_testmsg_with_payload(big_endian: bool, noar: u8, payload_buf: &[u8]) -> DltMessage {
        let sh = DltStorageHeader {
            secs: 0,
            micros: 0,
            ecu: DltChar4::from_str("ECU1").unwrap(),
        };
        let exth = DltExtendedHeader {
            verb_mstp_mtin: 0x41,
            noar,
            apid: DltChar4::from_buf(b"APID"),
            ctid: DltChar4::from_buf(b"CTID"),
        };
        let stdh = DltStandardHeader {
            htyp: 0x21
                | (if big_endian {
                    DLT_STD_HDR_BIG_ENDIAN
                } else {
                    0
                }),
            mcnt: 0,
            len: (DLT_MIN_STD_HEADER_SIZE + DLT_EXT_HEADER_SIZE + payload_buf.len()) as u16,
        };
        let mut add_header_buf = Vec::new();
        exth.to_write(&mut add_header_buf).unwrap();

        DltMessage::from_headers(1, sh, stdh, &add_header_buf, payload_buf.to_vec())
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

// MARK: DltMessageArgIterator
pub struct DltMessageArgIterator<'a> {
    msg: &'a DltMessage,
    is_verbose: bool,
    is_big_endian: bool,
    index: usize,
}

/// DLT argument encoding mask for type lengths DLT_TYLE_*
const DLT_TYPE_INFO_MASK_TYLE: u32 = 0x0000000f;

pub const DLT_TYPE_INFO_BOOL: u32 = 0x00000010;
pub const DLT_TYPE_INFO_SINT: u32 = 0x00000020;
pub const DLT_TYPE_INFO_UINT: u32 = 0x00000040;
pub const DLT_TYPE_INFO_FLOA: u32 = 0x00000080;
/// DLT argument encoding for array of standard types
const DLT_TYPE_INFO_ARAY: u32 = 0x00000100;

pub const DLT_TYPE_INFO_STRG: u32 = 0x00000200;
pub const DLT_TYPE_INFO_RAWD: u32 = 0x00000400;
/// DLT argument encoding for additional information to a variable (name and unit)
const DLT_TYPE_INFO_VARI: u32 = 0x00000800;
/// DLT argument encoding for FIXP encoding with quantization and offset
const DLT_TYPE_INFO_FIXP: u32 = 0x00001000;
/// DLT argument encoding for additional trace information
const DLT_TYPE_INFO_TRAI: u32 = 0x00002000;
/// DLT argument encoding for structs
const DLT_TYPE_INFO_STRU: u32 = 0x00004000;
/// DLT argument encoding mask for the string types DLT_SCOD_*
const DLT_TYPE_INFO_MASK_SCOD: u32 = 0x00038000;

pub const DLT_TYLE_8BIT: u8 = 1;
pub const DLT_TYLE_16BIT: u8 = 2;
pub const DLT_TYLE_32BIT: u8 = 3;
pub const DLT_TYLE_64BIT: u8 = 4;
const DLT_TYLE_128BIT: u8 = 5;

pub const DLT_SCOD_ASCII: u32 = 0x00000000;
pub const DLT_SCOD_UTF8: u32 = 0x00008000;
pub const DLT_SCOD_HEX: u32 = 0x00010000;
pub const DLT_SCOD_BIN: u32 = 0x00018000;

// MARK: DltArg
#[derive(Debug, PartialEq, Eq)]
pub struct DltArg<'a> {
    pub type_info: u32,        // in host endianess already
    pub is_big_endian: bool,   // for the payload raw
    pub payload_raw: &'a [u8], // data within is
}

impl DltArg<'_> {
    pub fn is_string(&self) -> bool {
        self.type_info & DLT_TYPE_INFO_STRG > 0
    }
    pub fn is_raw(&self) -> bool {
        self.type_info & DLT_TYPE_INFO_RAWD > 0
    }

    /// return the scod encoding bits (DLT_SCOD_...)
    pub fn scod(&self) -> u32 {
        self.type_info & DLT_TYPE_INFO_MASK_SCOD
    }
}

impl<'a> IntoIterator for &'a DltMessage {
    type Item = DltArg<'a>; // &'a [u8];
    type IntoIter = DltMessageArgIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        DltMessageArgIterator {
            msg: self,
            is_verbose: self.is_verbose(),
            is_big_endian: self.is_big_endian(),
            index: 0,
        }
    }
}

impl<'a> Iterator for DltMessageArgIterator<'a> {
    type Item = DltArg<'a>; // &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.is_verbose {
            // we need at least the typeinfo (4 byte) [Dlt459]
            // todo [Dlt421] only for MSTP Log or AppTrace!
            if self.msg.payload.len() >= self.index + 4 {
                let type_info = if self.is_big_endian {
                    u32::from_be_bytes(
                        self.msg.payload[self.index..self.index + 4]
                            .try_into()
                            .unwrap(),
                    )
                } else {
                    u32::from_le_bytes(
                        self.msg.payload[self.index..self.index + 4]
                            .try_into()
                            .unwrap(),
                    )
                };
                self.index += 4;

                // determine length
                let tyle: u8 = (type_info & DLT_TYPE_INFO_MASK_TYLE) as u8; // [Dlt354] 1 = 8, 2 = 16, 3 = 32, 4 = 64, 5 = 128bit
                let mut len: usize = match tyle {
                    DLT_TYLE_8BIT => 1,
                    DLT_TYLE_16BIT => 2,
                    DLT_TYLE_32BIT => 4,
                    DLT_TYLE_64BIT => 8,
                    DLT_TYLE_128BIT => 16,
                    _ => 0,
                };

                // vari info? (for STRG it's after the str len...)
                if type_info & DLT_TYPE_INFO_VARI != 0 {
                    // todo e.g. [Dlt369] unsigned 16-bit int. following as first payload, then the name, then the bool!
                    //panic!("type_info VARI not supported yet!");
                    return None;
                }
                // fixp set?
                if type_info & DLT_TYPE_INFO_FIXP != 0 {
                    // todo e.g. [Dlt386] 32-bit float, then tyle signed int as offset.
                    // panic!("type_info FIXP not supported yet!");
                    return None;
                }

                if type_info & DLT_TYPE_INFO_BOOL != 0 {
                    if len != 1 {
                        // dlt-viewer persists bool with len 0
                        // see https://github.com/COVESA/dlt-viewer/issues/242
                        if len != 0 {
                            return None; // [Dlt139] with exception for dlt-viewer bug 242
                        }
                        len = 1;
                    }
                } else if type_info & (DLT_TYPE_INFO_SINT | DLT_TYPE_INFO_UINT) != 0 {
                    if len < 1 {
                        //  see [Dlt356]
                        return None;
                    }
                } else if type_info & (DLT_TYPE_INFO_FLOA) != 0 {
                    if len < 2 {
                        // see [Dlt145]
                        // floats are only defined for 2,4,8,16 byte
                        return None;
                    }
                } else if type_info & (DLT_TYPE_INFO_STRG | DLT_TYPE_INFO_RAWD) != 0 {
                    // STRG bit9, rawd bit10, aray bit8, floa bit7, uint bit6, sint bit5, bool bit4, trai bit 13, stru bit 14
                    // bit 15-17 string coding (scod), 0 = ascii, 1 = utf-8, 2-7 reserved
                    // 16 bit uint with length of string + term. char first
                    // for VARI only here...
                    // then the payload
                    if self.msg.payload.len() < self.index + 2 {
                        return None;
                    }
                    len = if self.is_big_endian {
                        u16::from_be_bytes(
                            self.msg.payload[self.index..self.index + 2]
                                .try_into()
                                .unwrap(),
                        ) as usize
                    } else {
                        u16::from_le_bytes(
                            self.msg.payload[self.index..self.index + 2]
                                .try_into()
                                .unwrap(),
                        ) as usize
                    };
                    self.index += 2;

                    // now the payload
                    let to_ret = if self.msg.payload.len() >= self.index + len {
                        // len 0 is weird but valid
                        Some(DltArg {
                            type_info,
                            is_big_endian: self.is_big_endian,
                            payload_raw: &self.msg.payload[self.index..self.index + len],
                        })
                    } else {
                        None // todo we could output the partial/received payload here e.g. with an error bit set in type_info
                             /* panic!(
                                 "#{} at index {}: not enough payload for the string. type_info={:x} expected len={} got={} payload={:?}",
                                 self.msg.index, self.index, type_info, len,
                                 self.msg.payload.len() - self.index, self.msg.payload
                             );*/
                    };
                    self.index += len; // we incr. in any case
                    return to_ret;
                } else {
                    let _ = DLT_TYPE_INFO_ARAY | DLT_TYPE_INFO_TRAI | DLT_TYPE_INFO_STRU;
                    /*
                    panic!(
                        "type_info=0x{:x} unhandled! is_big_endian={}, index={}, msg={:?}",
                        type_info, self.is_big_endian, self.index, self.msg
                    );*/
                    return None; // todo
                }
                let to_ret = if len > 0 && self.msg.payload.len() >= self.index + len {
                    Some(DltArg {
                        type_info,
                        is_big_endian: self.is_big_endian,
                        payload_raw: &self.msg.payload[self.index..self.index + len],
                    })
                } else {
                    None
                };
                self.index += len; // we incr. in any case
                return to_ret;
            } else if self.msg.payload.len() > self.index {
                return None; // todo could add an error alike DltArg with payload_raw
            }
        } else {
            // non-verbose:
            // we return max 2 args if the payload is big enough
            // a 4 byte message id and the non-static data [Dlt460]
            return match self.index {
                0 => {
                    if self.msg.payload.len() >= 4 {
                        self.index += 4;
                        Some(DltArg {
                            type_info: 0,
                            is_big_endian: self.is_big_endian,
                            payload_raw: &self.msg.payload[0..4],
                        })
                    } else {
                        None
                    }
                }
                4 => {
                    if self.msg.payload.len() > 4 {
                        self.index = self.msg.payload.len();
                        Some(DltArg {
                            type_info: 0,
                            is_big_endian: self.is_big_endian,
                            payload_raw: &self.msg.payload[4..],
                        })
                    } else {
                        None
                    }
                }
                _ => None,
            };
        }

        None
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
        &self.kind
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            ErrorKind::NotEnoughData(amount) => {
                write!(f, "not enough data - missing at least {} bytes", amount)
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

#[inline]
/// return whether the start of the buffer contains the DLT storage header pattern
/// DLT\x1
///
/// returns false if buffer is too small (<4 bytes)
pub fn is_storage_header_pattern(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }

    let pat = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    pat == DLT_STORAGE_HEADER_PATTERN
    // that's significantly slower: buf[0] == b'D' && buf[1] == b'L' && buf[2] == b'T' && buf[3] == 0x1u8
}

#[inline]
/// return whether the start of the buffer contains the DLT serial header pattern
/// DLS\x1
///
/// returns false if buffer is too small (<4 bytes)
pub fn is_serial_header_pattern(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }

    let pat = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    pat == DLT_SERIAL_HEADER_PATTERN
}

#[derive(Debug)]
pub enum ErrorKind {
    InvalidData(String),
    NotEnoughData(usize),
    OtherFatal(String),
}

pub fn parse_dlt_with_storage_header(
    index: DltMessageIndexType,
    data: &[u8],
) -> Result<(usize, DltMessage), Error> {
    let mut remaining = data.len();

    if remaining >= MIN_DLT_MSG_SIZE {
        match DltStorageHeader::from_buf(data) {
            Some(sh) => {
                remaining -= DLT_STORAGE_HEADER_SIZE;
                let stdh = DltStandardHeader::from_buf(&data[DLT_STORAGE_HEADER_SIZE..])
                    .expect("no valid stdheader!");
                let std_ext_header_size = stdh.std_ext_header_size();
                if stdh.len >= std_ext_header_size {
                    // do we have the remaining data?
                    if remaining >= stdh.len as usize {
                        remaining -= std_ext_header_size as usize;
                        let payload_offset = DLT_STORAGE_HEADER_SIZE + std_ext_header_size as usize;
                        let payload_size = stdh.len - std_ext_header_size;
                        remaining -= payload_size as usize;
                        // sanity check for corrupt msgs (sadly dlt has no crc or end of msg tag)
                        // we check whether the next data starts with proper storage header.
                        // if so -> we assume this one is correct.
                        // If not
                        //  - no more data remaining -> treat as ok
                        //  - check whether there is a 2nd storage header
                        //    - if so -> skip to the new one
                        //    - if not -> use the current msg
                        let to_consume = data.len() - remaining;

                        if remaining >= 4 && !is_storage_header_pattern(&data[to_consume..]) {
                            // the new msg would be from [0..to_consume]
                            // is a 2nd storage header within data[5]..data[to_consume+3]?
                            for i in 5..to_consume {
                                if is_storage_header_pattern(&data[i..]) {
                                    // yes, lets use that.
                                    // we simply return an error here and let the usual skip logic apply
                                    return Err(Error::new(ErrorKind::InvalidData(
                                                String::from("skipped probably corrupt msg due to storage header pattern heuristic"),
                                            )));
                                }
                            }
                        }

                        let payload = Vec::from(
                            &data[payload_offset..payload_offset + payload_size as usize],
                        );
                        let msg = DltMessage::from_headers(
                            index,
                            sh,
                            stdh,
                            &data
                                [DLT_STORAGE_HEADER_SIZE + DLT_MIN_STD_HEADER_SIZE..payload_offset],
                            payload,
                        );
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

pub fn parse_dlt_with_serial_header(
    index: DltMessageIndexType,
    data: &[u8],
) -> Result<(usize, DltMessage), Error> {
    let mut remaining = data.len();

    if remaining >= DLT_SERIAL_HEADER_SIZE + DLT_MIN_STD_HEADER_SIZE {
        if is_serial_header_pattern(data) {
            remaining -= DLT_SERIAL_HEADER_SIZE;
            let stdh = DltStandardHeader::from_buf(&data[DLT_SERIAL_HEADER_SIZE..])
                .expect("no valid stdheader!");
            let std_ext_header_size = stdh.std_ext_header_size();
            if stdh.len >= std_ext_header_size {
                // do we have the remaining data?
                if remaining >= stdh.len as usize {
                    remaining -= std_ext_header_size as usize;
                    let payload_offset = DLT_SERIAL_HEADER_SIZE + std_ext_header_size as usize;
                    let payload_size = stdh.len - std_ext_header_size;
                    remaining -= payload_size as usize;
                    // sanity check for corrupt msgs (sadly dlt has no crc or end of msg tag)
                    // we check whether the next data starts with proper storage header.
                    // if so -> we assume this one is correct.
                    // If not
                    //  - no more data remaining -> treat as ok
                    //  - check whether there is a 2nd storage header
                    //    - if so -> skip to the new one
                    //    - if not -> use the current msg
                    let to_consume = data.len() - remaining;

                    if remaining >= 4 && !is_serial_header_pattern(&data[to_consume..]) {
                        // the new msg would be from [0..to_consume]
                        // is a 2nd storage header within data[5]..data[to_consume+3]?
                        for i in 5..to_consume {
                            if is_serial_header_pattern(&data[i..]) {
                                // yes, lets use that.
                                // we simply return an error here and let the usual skip logic apply
                                return Err(Error::new(ErrorKind::InvalidData(
                                                format!("skipped probably corrupt msg due to serial header pattern heuristic. serial pattern at {} vs expected {}", i, to_consume),
                                            )));
                            }
                        }
                    }

                    let payload =
                        Vec::from(&data[payload_offset..payload_offset + payload_size as usize]);
                    let sh = DltStorageHeader {
                        // todo... use start time? and header via config/parameter?
                        secs: (2023 - 1970) * 365 * 24 * 60 * 60,
                        micros: 0,
                        ecu: DltChar4 {
                            char4: [b'D', b'L', b'S', 0],
                        },
                    };
                    let msg = DltMessage::from_headers(
                        index,
                        sh,
                        stdh,
                        &data[DLT_SERIAL_HEADER_SIZE + DLT_MIN_STD_HEADER_SIZE..payload_offset],
                        payload,
                    );
                    Ok((to_consume, msg))
                } else {
                    // we do return invalid data here as the stdh.len might be corrupt.
                    // and we better search in the remaining data for a new serial header
                    // than skipping the full range
                    // todo consider this for DLT storage header as well?
                    Err(Error::new(ErrorKind::InvalidData(String::from(
                        "not enough data",
                    ))))
                }
            } else {
                Err(Error::new(ErrorKind::InvalidData(String::from(
                    "stdh.len too small",
                ))))
            }
        } else {
            Err(Error::new(ErrorKind::InvalidData(String::from(
                "no serialheader",
            ))))
        }
    } else {
        Err(Error::new(ErrorKind::NotEnoughData(
            MIN_DLT_MSG_SIZE - remaining,
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::{to_endian_vec, utils::*};

    mod dlt_char4 {
        use super::*;

        #[test]
        fn dltchar4_from_invalid() {
            assert_eq!(format!("{}", DltChar4::from_str("ABCDE").unwrap()), "ABCD");
            assert!(DltChar4::from_str("AB\u{2122}").is_err());
            assert_eq!(DltChar4::from_str("AB\u{2122}"), Err(ParseNonAsciiError));
        }
        #[test]
        #[should_panic]
        fn dltchar4_from_invalid2() {
            assert_eq!(format!("{}", DltChar4::from_buf(b"ab")), "ab"); // is invalid as too short so for now panic as we treat this a logical and not a data error!
        }

        #[test]
        fn dltchar4_from_invalid_printable_ascii() {
            assert_eq!(
                format!("{}", DltChar4::from_buf(&[67, 9, 92, 140])),
                "C-\\?"
            ); // is invalid printable ascii
               // we want <0x20 as - and >0x7e as ?
        }
        #[test]
        fn dltchar4_from_valid2() {
            assert_eq!(format!("{}", DltChar4::from_str("").unwrap()), "");
            assert_eq!(
                format!("{}", DltChar4::from_buf(&[0u8, b'b', b'c', b'd'])),
                "" // and not bcd! todo think about this. Another option "-bcd" (see _invalid_utf8)
            );
            assert!(DltChar4::from_str("AB\u{2122}").is_err());
            assert_eq!(DltChar4::from_str("AB\u{2122}"), Err(ParseNonAsciiError));
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
            assert_eq!(
                format!("{:-<4}", DltChar4::from_str("E").unwrap().to_string()),
                "E---"
            );

            // just 1 byte but pad left bound with - without to_string
            assert_eq!(format!("{:-<4}", DltChar4::from_str("E").unwrap()), "E---");
        }
    }

    mod dlt_storage_header {
        use super::*;
        #[test]
        fn from_buf_invalid() {
            // wrong pattern
            let buf: Vec<u8> = vec![
                0x41, 0x4c, 0x54, 0x01, 224, 181, 124, 94, 0, 0, 0, 0, 0x45, 0x43, 0x55, 0x31,
            ];
            let shdr = DltStorageHeader::from_buf(&buf);
            assert!(shdr.is_none());
            // too short
            let buf: Vec<u8> = vec![
                0x41, 0x4c, 0x54, 0x01, 224, 181, 124, 94, 0, 0, 0, 0, 0x45, 0x43, 0x55,
            ];
            let shdr = DltStorageHeader::from_buf(&buf);
            assert!(shdr.is_none());
        }
        #[test]
        fn from_buf_valid1() {
            let buf: Vec<u8> = vec![
                0x44, 0x4c, 0x54, 0x01, 224, 181, 124, 94, 0xe8, 3, 0, 0, 0x45, 0x43, 0x55, 0x31,
            ];
            let shdr =
                DltStorageHeader::from_buf(&buf).expect("failed to parse valid storage header");
            assert_eq!(shdr.secs, 1585231328); // 26.3.2020 14:02:08 gmt
            assert_eq!(shdr.micros, 1000);
            assert_eq!(&shdr.ecu.char4, b"ECU1");
            assert_eq!(shdr.reception_time_ms() * 1000, shdr.reception_time_us());
            assert!(!format!("{:?}", shdr).is_empty()); // we can debug print a storage header
        }

        #[test]
        fn from_msg1() {
            let mut m = DltMessage::for_test_rcv_tms_ms(0, 0);
            m.reception_time_us = (1585231328 * US_PER_SEC) + 1_000;
            m.ecu = DltChar4::from_buf(b"ECU1");
            let shdr = DltStorageHeader::from_msg(&m);
            assert_eq!(shdr.secs, 1585231328); // 26.3.2020 14:02:08 gmt
            assert_eq!(shdr.micros, 1000);
            assert_eq!(&shdr.ecu.char4, b"ECU1");
        }

        #[test]
        fn to_write1() {
            let shdr = DltStorageHeader {
                secs: 1585231328,
                micros: 1000,
                ecu: DltChar4::from_buf(b"ECU1"),
            };

            let mut file = Vec::<u8>::new();
            let res = shdr.to_write(&mut file);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), 16);
            assert_eq!(
                file,
                vec![
                    0x44, 0x4c, 0x54, 0x01, 224, 181, 124, 94, 0xe8, 3, 0, 0, 0x45, 0x43, 0x55,
                    0x31,
                ]
            );
        }
    }

    mod dlt_standard_header {
        use super::*;

        #[test]
        fn from_buf_invalid1() {
            let buf: Vec<u8> = vec![0x44, 0x4c];
            let stdh = DltStandardHeader::from_buf(&buf);
            assert!(stdh.is_none());

            let buf: Vec<u8> = vec![0, 0, 0, 0]; // invalid version 0, valid is only 1.
                                                 // but we parse it anyhow... todo change...
            let stdh = DltStandardHeader::from_buf(&buf).unwrap();
            assert_eq!(stdh.dlt_vers(), 0);
            assert!(!format!("{:?}", stdh).is_empty()); // we can debug print a standard header
        }

        #[test]
        fn from_buf_valid1() {
            let buf: Vec<u8> = vec![0x3f, 0x42, 0xf1, 0x23];
            let shdr = DltStandardHeader::from_buf(&buf).unwrap();
            assert_eq!(shdr.htyp, 0x3f);
            assert_eq!(shdr.mcnt, 0x42);
            assert_eq!(shdr.len, 0xf123);
            assert_eq!(shdr.dlt_vers(), 1);
            assert!(shdr.has_ext_hdr());
            assert!(shdr.is_big_endian());
            assert!(shdr.has_ecu_id());
            assert!(shdr.has_session_id());
            assert!(shdr.has_timestamp());
            assert_eq!(
                shdr.std_ext_header_size(),
                (DLT_MIN_STD_HEADER_SIZE + DLT_EXT_HEADER_SIZE + 4 + 4 + 4) as u16
            );

            let buf: Vec<u8> = vec![0x22, 0x42, 0, 4];
            let shdr = DltStandardHeader::from_buf(&buf).unwrap();
            assert_eq!(shdr.len as usize, DLT_MIN_STD_HEADER_SIZE);
            assert_eq!(shdr.dlt_vers(), 1);
            assert!(!shdr.has_ext_hdr());
            assert!(shdr.is_big_endian());
            assert!(!shdr.has_ecu_id());
            assert!(!shdr.has_session_id());
            assert!(!shdr.has_timestamp());
            assert_eq!(shdr.std_ext_header_size(), DLT_MIN_STD_HEADER_SIZE as u16);
            assert!(shdr.ecu(&buf).is_none());
        }

        #[test]
        fn from_buf_valid2() {
            // minimal with ecu id
            let buf: Vec<u8> = vec![0x26, 0x42, 0xf1, 0x23, b'a', b'B', b'c', b'D'];
            let shdr = DltStandardHeader::from_buf(&buf).unwrap();
            assert_eq!(shdr.mcnt, 0x42);
            assert_eq!(shdr.len, 0xf123);
            assert_eq!(shdr.dlt_vers(), 1);
            assert!(!shdr.has_ext_hdr());
            assert!(shdr.is_big_endian());
            assert!(shdr.has_ecu_id());
            assert!(!shdr.has_session_id());
            assert!(!shdr.has_timestamp());
            assert_eq!(
                shdr.std_ext_header_size(),
                (DLT_MIN_STD_HEADER_SIZE + 4) as u16
            );
            assert_eq!(shdr.ecu(&buf[4..]), DltChar4::from_str("aBcD").ok());
            assert_eq!(shdr.timestamp_dms(&buf[4..]), 0);
        }

        #[test]
        fn from_buf_valid3() {
            // minimal with timestamp
            let buf: Vec<u8> = vec![0x32, 0x42, 0xf1, 0x23, 0xf2, 0x34, 0x56, 0x78];
            let shdr = DltStandardHeader::from_buf(&buf).unwrap();
            assert_eq!(shdr.mcnt, 0x42);
            assert_eq!(shdr.len, 0xf123);
            assert_eq!(shdr.dlt_vers(), 1);
            assert!(!shdr.has_ext_hdr());
            assert!(shdr.is_big_endian());
            assert!(!shdr.has_ecu_id());
            assert!(!shdr.has_session_id());
            assert!(shdr.has_timestamp());
            assert_eq!(
                shdr.std_ext_header_size(),
                (DLT_MIN_STD_HEADER_SIZE + 4) as u16
            );
            assert_eq!(shdr.timestamp_dms(&buf[4..]), 0xf2345678);
        }

        #[test]
        fn from_buf_valid4() {
            // minimal with timestamp and ecu id and session id
            let buf: Vec<u8> = vec![
                0x3e, 0x42, 0xf1, 0x23, 0, 0, 0, 0, 1, 1, 1, 2, 0xf2, 0x34, 0x56, 0x78,
            ];
            let shdr = DltStandardHeader::from_buf(&buf).unwrap();
            assert_eq!(shdr.mcnt, 0x42);
            assert_eq!(shdr.len, 0xf123);
            assert_eq!(shdr.dlt_vers(), 1);
            assert!(!shdr.has_ext_hdr());
            assert!(shdr.is_big_endian());
            assert!(shdr.has_ecu_id());
            assert!(shdr.has_session_id());
            assert!(shdr.has_timestamp());
            assert_eq!(
                shdr.std_ext_header_size(),
                (DLT_MIN_STD_HEADER_SIZE + 4 + 4 + 4) as u16
            );
            assert_eq!(shdr.timestamp_dms(&buf[4..]), 0xf2345678);
        }

        #[test]
        fn to_write1() {
            // write a minimal standard header
            let shdr = DltStandardHeader {
                htyp: 0x3f,
                mcnt: 0x42,
                len: 4,
            };

            let mut file = Vec::<u8>::new();
            let res = DltStandardHeader::to_write(&mut file, &shdr, &None, None, None, None, &[]);
            assert!(res.is_ok());
            assert_eq!(file, vec![0x22, 0x42, 0, 4,]);
        }

        #[test]
        fn to_write2() {
            // write a full standard header
            let shdr = DltStandardHeader {
                htyp: 0x2, // set only endianess
                mcnt: 0x42,
                len: 4,
            };

            let mut file = Vec::<u8>::new();

            let ehdr = Some(DltExtendedHeader {
                verb_mstp_mtin: 0,
                noar: 1,
                apid: DltChar4::from_buf(b"APID"),
                ctid: DltChar4::from_buf(b"CTID"),
            });
            let ecu = Some(DltChar4::from_buf(b"ECU1"));
            let res = DltStandardHeader::to_write(
                &mut file,
                &shdr,
                &ehdr,
                ecu,
                Some(0xdeadbeef),
                Some(0x11223344),
                &[42u8],
            );
            assert!(res.is_ok());
            let len = (DLT_MIN_STD_HEADER_SIZE + DLT_EXT_HEADER_SIZE + 4 + 4 + 4 + 1) as u8;
            assert_eq!(
                file,
                vec![
                    0x3f_u8, 0x42, 0, len, b'E', b'C', b'U', b'1', 0xde, 0xad, 0xbe, 0xef, 0x11,
                    0x22, 0x33, 0x44, 0x0, 0x1, b'A', b'P', b'I', b'D', b'C', b'T', b'I', b'D', 42
                ]
            );
        }
    }

    mod dlt_extended_header {
        use super::*;

        #[test]
        fn invalid() {
            // too short -> invalid / None
            let eh = DltExtendedHeader::from_buf(&[0, 0, 1, 2, 3, 4, 5, 6, 7]);
            assert!(eh.is_none());
            // too much data -> dont care
        }

        #[test]
        fn verbose() {
            let eh = DltExtendedHeader::from_buf(&[0, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert!(!eh.is_verbose());
            let eh = DltExtendedHeader::from_buf(&[1, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert!(eh.is_verbose());
            let eh = DltExtendedHeader::from_buf(&[0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert!(eh.is_verbose());
            let eh = DltExtendedHeader::from_buf(&[0xfe, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert!(!eh.is_verbose());
            assert!(!format!("{:?}", eh).is_empty()); // can debug print
        }
        #[test]
        fn mstp() {
            let eh = DltExtendedHeader::from_buf(&[0, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert_eq!(eh.mstp(), DltMessageType::Log(DltMessageLogType::Fatal)); // default used
            let eh = DltExtendedHeader::from_buf(&[1u8 << 4, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert_eq!(eh.mstp(), DltMessageType::Log(DltMessageLogType::Fatal)); // default still

            let eh =
                DltExtendedHeader::from_buf(&[(3 << 4) | 1, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert_eq!(eh.mstp(), DltMessageType::Log(DltMessageLogType::Warn));

            let eh =
                DltExtendedHeader::from_buf(&[(2 << 4) | 1, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert_eq!(eh.mstp(), DltMessageType::Log(DltMessageLogType::Error));
            let eh =
                DltExtendedHeader::from_buf(&[(5 << 4) | 1, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert_eq!(eh.mstp(), DltMessageType::Log(DltMessageLogType::Debug));
            let eh = // mstp 0 -> default to Log as well (unspecified)
                DltExtendedHeader::from_buf(&[(6 << 4), 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert_eq!(eh.mstp(), DltMessageType::Log(DltMessageLogType::Verbose));

            let eh =
                DltExtendedHeader::from_buf(&[(6 << 4) | 4, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert_eq!(eh.mstp(), DltMessageType::NwTrace(DltMessageNwType::SomeIp));
            let eh =
                DltExtendedHeader::from_buf(&[(5 << 4) | 4, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert_eq!(
                eh.mstp(),
                DltMessageType::NwTrace(DltMessageNwType::Ethernet)
            );
            let eh =
                DltExtendedHeader::from_buf(&[(2 << 4) | 4, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert_eq!(eh.mstp(), DltMessageType::NwTrace(DltMessageNwType::Can));
            let eh =
                DltExtendedHeader::from_buf(&[(1 << 4) | 4, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert_eq!(eh.mstp(), DltMessageType::NwTrace(DltMessageNwType::Ipc));
            let eh =
                DltExtendedHeader::from_buf(&[(3 << 4) | 4, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert_eq!(
                eh.mstp(),
                DltMessageType::NwTrace(DltMessageNwType::Flexray)
            );
            assert!(!format!("{:?}", eh).is_empty()); // can debug print

            let eh =
                DltExtendedHeader::from_buf(&[(4 << 4) | 2, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert_eq!(
                eh.mstp(),
                DltMessageType::AppTrace(DltMessageTraceType::State)
            );
            assert!(!format!("{:?}", eh).is_empty()); // can debug print
            let eh =
                DltExtendedHeader::from_buf(&[(2 << 4) | 2, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert_eq!(
                eh.mstp(),
                DltMessageType::AppTrace(DltMessageTraceType::FunctionIn)
            );
            let eh =
                DltExtendedHeader::from_buf(&[(3 << 4) | 2, 0, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            assert_eq!(
                eh.mstp(),
                DltMessageType::AppTrace(DltMessageTraceType::FunctionOut)
            );

            let eh = DltExtendedHeader::from_buf(&[(1 << 1) | (1 << 4), 0, 1, 2, 3, 4, 5, 6, 7, 8])
                .unwrap();
            assert_eq!(
                eh.mstp(),
                DltMessageType::AppTrace(DltMessageTraceType::Variable)
            );
            let eh = DltExtendedHeader::from_buf(&[(3 << 1) | (2 << 4), 0, 1, 2, 3, 4, 5, 6, 7, 8])
                .unwrap();
            assert_eq!(
                eh.mstp(),
                DltMessageType::Control(DltMessageControlType::Response)
            );
        }
    }

    mod dlt_message {
        use super::*;

        #[test]
        fn basic_info() {
            let m = DltMessage::for_test_rcv_tms_ms(0, 1);
            let rt = m.reception_time();
            // all those tests are a bit useless...
            assert_eq!(rt.timestamp_millis(), 1640995200000);
            assert_eq!(m.mcnt(), m.standard_header.mcnt);
            assert_eq!(m.mstp(), DltMessageType::Log(DltMessageLogType::Fatal));
            assert!(!m.is_ctrl_request());
            assert_eq!(m.noar(), 0); // no ext header at all
        }

        #[test]
        fn from_headers() {
            let shdr = DltStorageHeader {
                secs: 1,
                micros: 2,
                ecu: DltChar4::from_str("ECU1").unwrap(),
            };
            let stdh = DltStandardHeader {
                htyp: 0x22,
                mcnt: 42,
                len: 4,
            };
            let m = DltMessage::from_headers(2, shdr, stdh, &[], [].to_vec());
            assert_eq!(m.mcnt(), 42);
            assert_eq!(m.ecu, DltChar4::from_str("ECU1").unwrap()); // from storage header as no ext header
            assert_eq!(m.reception_time_us, US_PER_SEC + 2);
            assert_eq!(m.timestamp_us(), 0);

            let mut file = Vec::<u8>::new();
            assert!(m.header_as_text_to_write(&mut file).is_ok());
            assert_eq!(
                String::from_utf8_lossy(&file),
                format!(
                    "2 {}          0 042 ECU1 ---- ---- --- --- N - 0",
                    Local
                        .from_utc_datetime(&m.reception_time())
                        .format("%Y/%m/%d %H:%M:%S%.6f")
                )
            ); // todo is printed in local timezone... consider proper TZ support for output
        }

        #[test]
        fn arg_iter() {
            let m = DltMessage::for_test();
            assert!(!m.is_verbose());
            let args_iter = m.into_iter();

            assert_eq!(args_iter.count(), 0);

            // now non-verbose, with enough payload:
            let m = DltMessage {
                index: 0,
                reception_time_us: 0,
                ecu: DltChar4::from_buf(b"ECU1"),
                timestamp_dms: 0,
                standard_header: DltStandardHeader {
                    htyp: 1,
                    len: 100,
                    mcnt: 0,
                },
                extended_header: Some(DltExtendedHeader {
                    verb_mstp_mtin: 0, // non-verbose
                    noar: 2,
                    apid: DltChar4::from_buf(b"APID"),
                    ctid: DltChar4::from_buf(b"CTID"),
                }),
                lifecycle: 0,
                payload: vec![1, 2, 3, 4, 5],
                payload_text: None,
            };
            let args_iter = m.into_iter();
            assert_eq!(args_iter.count(), 2);
            // verify payload:
            let mut args_iter = m.into_iter();
            assert_eq!(args_iter.next().unwrap().payload_raw, vec!(1, 2, 3, 4));
            assert_eq!(args_iter.next().unwrap().payload_raw, vec!(5));
            assert!(args_iter.next().is_none());

            // now non-verbose, with only the id as payload:
            let m = DltMessage {
                index: 0,
                reception_time_us: 0,
                ecu: DltChar4::from_buf(b"ECU1"),
                timestamp_dms: 0,
                standard_header: DltStandardHeader {
                    htyp: 1,
                    len: 100,
                    mcnt: 0,
                },
                extended_header: Some(DltExtendedHeader {
                    verb_mstp_mtin: 0, // non-verbose
                    noar: 2,
                    apid: DltChar4::from_buf(b"APID"),
                    ctid: DltChar4::from_buf(b"CTID"),
                }),
                lifecycle: 0,
                payload: vec![1, 2, 3, 4],
                payload_text: None,
            };
            let args_iter = m.into_iter();
            assert_eq!(args_iter.count(), 1);

            let mut args_iter = m.into_iter();
            assert!(!format!("{:?}", args_iter.next().unwrap()).is_empty()); // can debug print

            // now verbose, with two booleans:
            let m = DltMessage {
                index: 0,
                reception_time_us: 0,
                ecu: DltChar4::from_buf(b"ECU1"),
                timestamp_dms: 0,
                standard_header: DltStandardHeader {
                    htyp: 0, // little end.
                    len: 100,
                    mcnt: 0,
                },
                extended_header: Some(DltExtendedHeader {
                    verb_mstp_mtin: 1, // verbose
                    noar: 2,
                    apid: DltChar4::from_buf(b"APID"),
                    ctid: DltChar4::from_buf(b"CTID"),
                }),
                lifecycle: 0,
                payload: vec![0x11, 0, 0, 0, 1, 0x11, 0, 0, 0, 0], // two bools
                payload_text: None,
            };
            assert_eq!(u32::from_be_bytes([0, 0, 0, 0x10]), 0x10);
            assert_eq!(u32::from_le_bytes([0x10, 0, 0, 0]), 0x10); // least sign. byte first

            let args_iter = m.into_iter();
            assert_eq!(args_iter.count(), 2);
            // verify payload:
            let mut args_iter = m.into_iter();
            assert_eq!(args_iter.next().unwrap().payload_raw, vec!(1));
            assert_eq!(args_iter.next().unwrap().payload_raw, vec!(0));
        }
    }

    #[test]
    fn real_ex1() {
        // wireshark dlt dissector problem? Shows Buffer too short with 6th arg (type info 0x10 = bool with undefined tyle 0 -> we default to 1 byte for that case )
        let v = hex_to_bytes("3d 0a 00 af 4d 4d 4d 41 00 00 03 48 00 75 7d 16 41 08 4c 52 4d 46 55 44 53 00 00 82 00 00 1c 00 46 69 6e 61 6c 20 61 6e 73 77 65 72 20 61 72 72 69 76 65 64 20 61 66 74 65 72 20 00 23 00 00 00 93 01 00 00 00 82 00 00 21 00 75 73 20 66 72 6f 6d 20 74 68 65 20 6a 6f 62 20 68 61 6e 64 6c 65 72 20 5b 73 74 61 74 65 3a 20 00 00 82 00 00 0a 00 41 6e 73 77 65 72 69 6e 67 00 00 82 00 00 0b 00 2c 20 61 6e 73 77 65 72 3a 20 00 10 00 00 00 01 00 82 00 00 10 00 5d 20 66 6f 72 20 72 65 71 75 65 73 74 20 23 00 43 00 00 00 dc 05 00 00").unwrap();
        assert_eq!(175, v.len());
        let sh = DltStorageHeader {
            secs: 0,
            micros: 0,
            ecu: DltChar4::from_str("ECU1").unwrap(),
        };
        let stdh = DltStandardHeader::from_buf(&v).unwrap();
        let payload_offset = stdh.std_ext_header_size() as usize;
        let m = DltMessage::from_headers(
            1423084,
            sh,
            stdh,
            &v[DLT_MIN_STD_HEADER_SIZE..payload_offset],
            v[payload_offset..].to_vec(),
        );
        assert_eq!(m.mcnt(), 10);
        assert!(m.extended_header.is_some());
        assert!(!m.is_big_endian());
        assert!(!m.is_ctrl_request());
        assert_eq!(m.mstp(), DltMessageType::Log(DltMessageLogType::Info));
        assert!(m.is_verbose());
        assert_eq!(m.ecu, DltChar4::from_str("MMMA").unwrap());
        assert_eq!(m.apid().unwrap(), &DltChar4::from_str("LRMF").unwrap());
        assert_eq!(m.ctid().unwrap(), &DltChar4::from_str("UDS").unwrap());
        assert_eq!(m.noar(), 8);
        let args: Vec<DltArg> = m.into_iter().collect();
        for a in &args {
            println!("{:?}", a);
        }
        assert_eq!(args.len(), 8);
        assert!(args.iter().all(|a| !a.is_big_endian));

        let mut file = Vec::new();
        assert!(m.header_as_text_to_write(&mut file).is_ok());
        assert_eq!(
            String::from_utf8_lossy(&file),
            format!(
                "1423084 {}    7699734 010 MMMA LRMF UDS- log info V 8",
                Local
                    .from_utc_datetime(&m.reception_time())
                    .format("%Y/%m/%d %H:%M:%S%.6f")
            )
        );
        assert_eq!(m.payload_as_text().unwrap(), "Final answer arrived after  403 us from the job handler [state:  Answering , answer:  true ] for request # 1500");

        let a = &args[0];
        assert!(!a.is_big_endian);

        println!("{:?}", m);
    }

    #[test]
    fn real_ex1b() {
        let v = hex_to_bytes("3d 0a 00 af 4d 4d 4d 41 00 00 03 48 00 75 7d 16 41 08 4c 52 4d 46 55 44 53 00 00 82 00 00 1c 00 46 69 6e 61 6c 20 61 6e 73 77 65 72 20 61 72 72 69 76 65 64 20 61 66 74 65 72 20 00 23 00 00 00 93 01 00 00 00 82 00 00 21 00 75 73 20 66 72 6f 6d 20 74 68 65 20 6a 6f 62 20 68 61 6e 64 6c 65 72 20 5b 73 74 61 74 65 3a 20 00 00 82 00 00 0a 00 41 6e 73 77 65 72 69 6e 67 00 00 82 00 00 0b 00 2c 20 61 6e 73 77 65 72 3a 20 00 10 00 00 00 01 00 82 00 00 10 00 5d 20 66 6f 72 20 72 65 71 75 65 73 74 20 23 00 43 00 00 00 dc 05 00 00").unwrap();
        assert_eq!(175, v.len());
        let sh = DltStorageHeader {
            secs: 0,
            micros: 0,
            ecu: DltChar4::from_str("ECU1").unwrap(),
        };
        let stdh = DltStandardHeader::from_buf(&v).unwrap();
        let payload_offset = stdh.std_ext_header_size() as usize;
        let m = DltMessage::from_headers(
            1423084,
            sh,
            stdh,
            &v[DLT_MIN_STD_HEADER_SIZE..payload_offset],
            v[payload_offset..].to_vec(),
        );
        let mut file = Vec::new();
        // persist to "file"/buf:
        assert!(m.to_write(&mut file).is_ok());
        // and parse that again
        let sh2 = DltStorageHeader::from_buf(&file).unwrap();
        let stdh2 = DltStandardHeader::from_buf(&file[DLT_STORAGE_HEADER_SIZE..]).unwrap();
        let payload_offset = stdh2.std_ext_header_size() as usize;
        assert_eq!(0, sh2.secs);
        assert_eq!(0, sh2.micros);
        assert_eq!(m.ecu, sh2.ecu);
        // checks on std header (currently we don't persist the ecu again and the session_id. needs adaption once changed)
        assert_eq!(stdh2.mcnt, m.mcnt());
        assert_eq!(DLT_STORAGE_HEADER_SIZE + stdh2.len as usize, file.len());

        assert!(!stdh2.has_session_id()); // see above
        assert_eq!(m.is_big_endian(), stdh2.is_big_endian());

        let m2 = DltMessage::from_headers(
            1423084,
            sh2,
            stdh2,
            &file[DLT_STORAGE_HEADER_SIZE..DLT_STORAGE_HEADER_SIZE + payload_offset],
            file[DLT_STORAGE_HEADER_SIZE + payload_offset..].to_vec(),
        );
        assert_eq!(m.ecu, m2.ecu);
        assert_eq!(m.is_ctrl_request(), m2.is_ctrl_request());
        assert_eq!(m.mstp(), m2.mstp());
        assert_eq!(m.apid(), m2.apid());
        assert_eq!(m.ctid(), m2.ctid());
        assert_eq!(m.noar(), m2.noar());
        let m_args: Vec<DltArg> = m.into_iter().collect();
        let m2_args: Vec<DltArg> = m2.into_iter().collect();
        assert_eq!(m_args.len(), m2_args.len());
        for i in 0..m_args.len() {
            assert_eq!(m_args[i], m2_args[i]);
        }
    }

    fn get_testmsg_with_payload(big_endian: bool, noar: u8, payload_buf: &[u8]) -> DltMessage {
        DltMessage::get_testmsg_with_payload(big_endian, noar, payload_buf)
    }

    #[test]
    fn payload_bool() {
        let m = get_testmsg_with_payload(
            true,
            5,
            &[
                0, 0, 0, 0x11, 0, 0, 0, 0, 0x11, 1, 0, 0, 0, 0x11, 2, 0, 0, 0, 0x10, 1, 0, 0, 0,
                0x10, 0,
            ],
        ); // tyle=1, 0x10(bool) with 0 (false), 1(true), 2 (undefined according to Dlt423, we default to !=0 -> true), tyle=0 (not fitting to Dlt139 but seems used)
        let a: Vec<DltArg> = m.into_iter().collect();
        assert_eq!(a.len(), 5);
        assert_eq!(
            a[0],
            DltArg {
                type_info: 0x11,
                is_big_endian: true,
                payload_raw: &[0]
            }
        );
        assert_eq!(
            a[4],
            DltArg {
                type_info: 0x10,
                is_big_endian: true,
                payload_raw: &[0]
            }
        );
        assert_eq!(m.payload_as_text().unwrap(), "false true true true false");
    }

    #[test]
    fn payload_sint() {
        let m = get_testmsg_with_payload(
            true,
            4,
            &[
                0, 0, 0, 0x21, 42, 0, 0, 0, 0x22, 0xab, 0xcd, 0, 0, 0, 0x23, 0x12, 0x23, 0x34,
                0x45, 0, 0, 0, 0x24, 0xf0, 2, 3, 4, 5, 6, 7, 8,
            ],
        ); // tyle=1, 0x10(bool) with 0 (false), 1(true), 2 (undefined according to Dlt423, we default to !=0 -> true), tyle=0 (not fitting to Dlt139 but seems used)
        let a: Vec<DltArg> = m.into_iter().collect();
        assert_eq!(a.len(), 4);
        assert_eq!(
            a[0],
            DltArg {
                type_info: 0x21,
                is_big_endian: true,
                payload_raw: &[42]
            }
        );
        assert_eq!(
            a[3],
            DltArg {
                type_info: 0x24,
                is_big_endian: true,
                payload_raw: &[0xf0, 2, 3, 4, 5, 6, 7, 8]
            }
        );
        assert_eq!(
            m.payload_as_text().unwrap(),
            "42 -21555 304297029 -1152355238854392056"
        );
        let m = get_testmsg_with_payload(
            false,
            4,
            &[
                0x21, 0, 0, 0, 42, 0x22, 0, 0, 0, 0xcd, 0xab, 0x23, 0, 0, 0, 0x45, 0x34, 0x23,
                0x12, 0x24, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 0xf0,
            ],
        ); // tyle=1, 0x10(bool) with 0 (false), 1(true), 2 (undefined according to Dlt423, we default to !=0 -> true), tyle=0 (not fitting to Dlt139 but seems used)
        let a: Vec<DltArg> = m.into_iter().collect();
        assert_eq!(a.len(), 4);
        assert_eq!(
            a[0],
            DltArg {
                type_info: 0x21,
                is_big_endian: false,
                payload_raw: &[42]
            }
        );
        assert_eq!(
            a[3],
            DltArg {
                type_info: 0x24,
                is_big_endian: false,
                payload_raw: &[8, 7, 6, 5, 4, 3, 2, 0xf0]
            }
        );
        assert_eq!(
            m.payload_as_text().unwrap(),
            "42 -21555 304297029 -1152355238854392056"
        );
    }

    #[test]
    fn payload_int_float() {
        for big_endian in [false, true] {
            let testsdata = [
                (
                    DLT_TYPE_INFO_FLOA | DLT_TYLE_32BIT as u32,
                    to_endian_vec!(1.0f32, big_endian),
                    "1",
                ),
                (
                    DLT_TYPE_INFO_FLOA | DLT_TYLE_32BIT as u32,
                    to_endian_vec!(0.0f32, big_endian),
                    "0",
                ),
                (
                    DLT_TYPE_INFO_FLOA | DLT_TYLE_32BIT as u32,
                    to_endian_vec!(-1.1f32, big_endian),
                    "-1.1",
                ),
                (
                    DLT_TYPE_INFO_FLOA | DLT_TYLE_64BIT as u32,
                    to_endian_vec!(1.0f64, big_endian),
                    "1",
                ),
                (
                    DLT_TYPE_INFO_FLOA | DLT_TYLE_64BIT as u32,
                    to_endian_vec!(f64::MIN, big_endian),
                    &format!("{}", f64::MIN),
                ),
                (
                    DLT_TYPE_INFO_FLOA | DLT_TYLE_64BIT as u32,
                    to_endian_vec!(f64::MAX, big_endian),
                    &format!("{}", f64::MAX),
                ),
                (
                    DLT_TYPE_INFO_FLOA | DLT_TYLE_16BIT as u32,
                    vec![0, 0],
                    "?<floa with len=2 raw=[0, 0]>",
                ),
                (
                    DLT_TYPE_INFO_FLOA | DLT_TYLE_128BIT as u32,
                    vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    "?<floa with len=16 raw=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]>",
                ),
                (0x41u32, vec![0xffu8], "255"),
                (0x21u32, vec![0xffu8], "-1"),
                (0x21u32, to_endian_vec!(-128i8, big_endian), "-128"),
                (0x21u32, to_endian_vec!(127i8, big_endian), "127"),
                (0x41u32, vec![0], "0"),
                (0x21u32, vec![0], "0"),
                (0x42, to_endian_vec!(4711u16, big_endian), "4711"),
                (0x22, to_endian_vec!(4711i16, big_endian), "4711"),
                (0x22, to_endian_vec!(-4711i16, big_endian), "-4711"),
                (0x43, to_endian_vec!(12345678u32, big_endian), "12345678"),
                (0x23, to_endian_vec!(12345678i32, big_endian), "12345678"),
                (0x23, to_endian_vec!(-12345678i32, big_endian), "-12345678"),
                (
                    0x44,
                    to_endian_vec!(1234567890123u64, big_endian),
                    "1234567890123",
                ),
                (
                    0x24,
                    to_endian_vec!(-1234567890123i64, big_endian),
                    "-1234567890123",
                ),
                (
                    0x45,
                    to_endian_vec!(1234567890123456789u128, big_endian),
                    "1234567890123456789",
                ),
                (
                    0x45,
                    to_endian_vec!(u128::MAX, big_endian),
                    &format!("{}", u128::MAX),
                ),
                (
                    0x25,
                    to_endian_vec!(i128::MIN, big_endian),
                    &format!("{}", i128::MIN),
                ),
                (
                    0x25,
                    to_endian_vec!(i128::MAX, big_endian),
                    &format!("{}", i128::MAX),
                ),
            ];
            let noar = testsdata.len();
            let string_expected = testsdata
                .iter()
                .map(|e| e.2)
                .collect::<Vec<&str>>()
                .join(" ");
            let mut payload: Vec<u8> = Vec::new();
            for t in &testsdata {
                // push the type
                let mut type_buf = to_endian_vec!(t.0, big_endian);
                payload.append(&mut type_buf);
                for b in &t.1 {
                    payload.push(*b);
                }
            }

            let m = get_testmsg_with_payload(big_endian, noar as u8, &payload);
            let args: Vec<DltArg> = m.into_iter().collect();
            assert_eq!(m.noar() as usize, noar);
            assert_eq!(args.len(), noar);
            for (i, arg) in args.iter().enumerate() {
                assert_eq!(arg.type_info, testsdata[i].0);
            }
            assert_eq!(m.payload_as_text().unwrap(), string_expected);
        }
    }

    #[test]
    fn payload_single_strg_rawd_floa() {
        for big_endian in [false, true] {
            let testsdata = [
                (DLT_TYPE_INFO_BOOL | DLT_TYLE_16BIT as u32, vec![], None), // only 1 or 0 TYLE accepted
                (DLT_TYPE_INFO_SINT, vec![], None),                         // no len
                (DLT_TYPE_INFO_FLOA, vec![], None),                         // no len
                (DLT_TYPE_INFO_FLOA | DLT_TYLE_8BIT as u32, vec![], None),  // len 1 not defined
                (
                    // valid but empty
                    DLT_TYPE_INFO_STRG,
                    vec![to_endian_vec!(0u16, big_endian)],
                    Some(""),
                ),
                (
                    DLT_TYPE_INFO_RAWD,
                    vec![to_endian_vec!(0u16, big_endian)],
                    Some(""),
                ),
                (
                    DLT_TYPE_INFO_RAWD,
                    vec![to_endian_vec!(1u16, big_endian), vec![0xfe]],
                    Some("fe"),
                ),
                (
                    DLT_TYPE_INFO_RAWD,
                    vec![to_endian_vec!(2u16, big_endian), vec![0x0f, 0x00]],
                    Some("0f 00"),
                ),
                (
                    DLT_TYPE_INFO_RAWD,
                    vec![to_endian_vec!(3u16, big_endian), vec![0x00, 0x01, 0xff]],
                    Some("00 01 ff"),
                ),
                (DLT_TYPE_INFO_STRG, vec![], None), // no len
                (DLT_TYPE_INFO_STRG, vec![vec![42u8]], None), // only 1 byte from len
                (
                    DLT_TYPE_INFO_STRG,
                    // len but no payload
                    vec![to_endian_vec!(1u16, big_endian)],
                    None,
                ),
                (
                    DLT_TYPE_INFO_STRG,
                    // len but no payload
                    vec![to_endian_vec!(0xffffu16, big_endian)],
                    None,
                ),
                (
                    DLT_TYPE_INFO_STRG,
                    // len but partial payload
                    vec![to_endian_vec!(0xffffu16, big_endian), vec![0x0]],
                    None,
                ),
                (
                    DLT_TYPE_INFO_STRG | DLT_SCOD_UTF8,
                    // w.o. zero term
                    vec![to_endian_vec!(1u16, big_endian), vec![b'a']],
                    Some("a"),
                ),
                (
                    DLT_TYPE_INFO_STRG | DLT_SCOD_UTF8,
                    // zero term only
                    vec![to_endian_vec!(1u16, big_endian), vec![0x0]],
                    Some(""),
                ),
                (
                    DLT_TYPE_INFO_STRG | DLT_SCOD_UTF8,
                    // with zero term works as well
                    vec![to_endian_vec!(2u16, big_endian), vec![b'a', 0]],
                    Some("a"),
                ),
                (
                    DLT_TYPE_INFO_STRG | DLT_SCOD_UTF8,
                    // zero term missing
                    vec![to_endian_vec!(2u16, big_endian), vec![b'a', b'b']],
                    Some("ab"),
                ),
                (
                    DLT_TYPE_INFO_STRG | DLT_SCOD_UTF8,
                    // ascii non printable, todo add full <0x20,... range
                    // \r \n should be replace by a ' ' each
                    // \t as well
                    // dlt doesn't seem to define the ASCII codepage.
                    // we could use ISO-8859-1
                    // or we reduce the printable ones to 0x20 (' ') .. 0x7e ('~')
                    vec![
                        to_endian_vec!(4u16, big_endian),
                        vec![b'\n', b'\r', b'\t', 0],
                    ],
                    Some("   "),
                ),
                (
                    DLT_TYPE_INFO_STRG | DLT_SCOD_UTF8,
                    // utf8 with  non utf8
                    vec![to_endian_vec!(2u16, big_endian), vec![0x80, 0]],
                    Some("\u{FFFD}"),
                ),
                (
                    DLT_TYPE_INFO_STRG | DLT_SCOD_ASCII,
                    // zero term missing
                    vec![to_endian_vec!(1u16, big_endian), vec![b'a']],
                    Some("a"),
                ),
                (
                    DLT_TYPE_INFO_STRG | DLT_SCOD_ASCII,
                    // zero term only
                    vec![to_endian_vec!(1u16, big_endian), vec![0]],
                    Some(""),
                ),
                (
                    DLT_TYPE_INFO_STRG | DLT_SCOD_ASCII,
                    // zero term included works as well
                    vec![to_endian_vec!(2u16, big_endian), vec![b'a', 0]],
                    Some("a"),
                ),
                (
                    DLT_TYPE_INFO_STRG | DLT_SCOD_ASCII,
                    // zero term missing (as by spec)
                    vec![to_endian_vec!(2u16, big_endian), vec![b'a', b'b']],
                    Some("ab"),
                ),
                (
                    DLT_TYPE_INFO_STRG | DLT_SCOD_ASCII,
                    // ascii non printable, todo add full <0x20,... range
                    // \r \n should be replace by a ' ' each
                    // \t as well
                    // dlt doesn't seem to define the ASCII codepage.
                    // we could use ISO-8859-1
                    // or we reduce the printable ones to 0x20 (' ') .. 0x7e ('~')
                    // todo dlt-viewer seems to replace only \n (and not \r, \t)
                    //  dlt-console converts \n and \r but not \t
                    vec![
                        to_endian_vec!(4u16, big_endian),
                        vec![b'\n', b'\r', b'\t', 0],
                    ],
                    Some("   "),
                ),
                /* we do print all of those with WINDOWS_1252 encoding (
                    DLT_TYPE_INFO_STRG | DLT_SCOD_ASCII,
                    // acsii with non printable ascii
                    vec![to_endian_vec!(3u16, big_endian), vec![0x19, 0x80, 0]],
                    Some("\u{FFFD}\u{FFFD}"),
                ),*/
            ];
            // we test them alone to be able to test for parser errors
            for (i, testdata) in testsdata.iter().enumerate() {
                let noar = 1;
                let string_expected = testdata.2;
                let mut payload: Vec<u8> = Vec::new();
                // push the type

                let mut type_buf = to_endian_vec!(testdata.0, big_endian);
                payload.append(&mut type_buf);
                for b in &testdata.1 {
                    for c in b {
                        payload.push(*c);
                    }
                }

                let m = get_testmsg_with_payload(big_endian, noar as u8, &payload);
                let args: Vec<DltArg> = m.into_iter().collect();
                assert_eq!(m.noar() as usize, noar);
                if let Some(string_expected) = string_expected {
                    assert_eq!(
                        args.len(),
                        noar,
                        "testcase #{} args mismatch; args.len()={}, noar={}, payload={:?}",
                        i,
                        args.len(),
                        noar,
                        payload,
                    );
                    assert_eq!(args[0].type_info, testdata.0);
                    assert_eq!(m.payload_as_text().unwrap(), string_expected);
                } else {
                    assert_eq!(args.len(), 0);
                }
            }
        }
    }

    // todo add smaller test cases for all FLOAT, VARI, FIXP, STRING encodings,...
    // todo test invalid/missing payload for SINT, UINT, and think about proper error handling
    // todo add SCOD_BIN and SCOD_HEX for uints see e.g. https://github.com/COVESA/dlt-viewer/blob/03baa67d3bb059458cb5b8e0ed940ea6f607f575/qdlt/qdltargument.cpp#L444

    #[test]
    fn control_msgs_sw_version() {
        let m = DltMessage::get_testmsg_control(
            false,
            1,
            &[19, 0, 0, 0, 0, 4, 0, 0, 0, b'S', b'W', b' ', b'1'],
        );
        assert!(m.is_ctrl_response());

        assert_eq!(
            m.payload_as_text().unwrap(),
            "[get_software_version ok] SW 1"
        );

        let m = DltMessage::get_testmsg_control(
            true,
            1,
            &[0, 0, 0, 19, 0, 0, 0, 0, 4, b'S', b'W', b' ', b'2'],
        );
        assert_eq!(
            m.payload_as_text().unwrap(),
            "[get_software_version ok] SW 2"
        );

        // len wrong!
        let m = DltMessage::get_testmsg_control(
            true,
            1,
            &[0, 0, 0, 19, 0, 0, 0, 0, 5, b'S', b'W', b' ', b'2'],
        );
        assert_eq!(m.payload_as_text().unwrap(), "[get_software_version ok]");

        // len too short is ok, rest ignored
        let m = DltMessage::get_testmsg_control(
            true,
            1,
            &[0, 0, 0, 19, 0, 0, 0, 0, 3, b'S', b'W', b' ', b'2'],
        );
        assert_eq!(
            m.payload_as_text().unwrap(),
            "[get_software_version ok] SW "
        );

        // far too short
        let m = DltMessage::get_testmsg_control(true, 1, &[0, 0, 0, 19, 0]);
        assert_eq!(m.payload_as_text().unwrap(), "[get_software_version ok]");
        let m = DltMessage::get_testmsg_control(true, 1, &[0, 0, 0, 19, 0, 1]);
        assert_eq!(m.payload_as_text().unwrap(), "[get_software_version ok]");
        let m = DltMessage::get_testmsg_control(true, 1, &[0, 0, 0]);
        assert_eq!(m.payload_as_text().unwrap(), "[<args missing>]");
    }

    #[test]
    fn control_msgs_unregister_context() {
        let m = DltMessage::get_testmsg_control(
            false,
            1,
            &[
                0x01, 0x0f, 0, 0, 0, b'A', b'"', b'I', b'"', b'C', b'T', b'I', b'D', b'C', b'O',
                b'M', b'I',
            ],
        );
        assert!(m.is_ctrl_response());

        assert_eq!(
            m.payload_as_text().unwrap(),
            r##"[unregister_context ok] {"apid":"A\"I\"","comid":"COMI","ctid":"CTID"}"##
        );

        // wrong len -> dump only bytes:
        let m = DltMessage::get_testmsg_control(
            false,
            1,
            &[
                0x01, 0x0f, 0, 0, 0, b'A', b'P', b'I', b'D', b'C', b'T', b'I', b'D', b'C', b'O',
            ],
        );
        assert!(m.is_ctrl_response());

        assert_eq!(
            m.payload_as_text().unwrap(),
            r##"[unregister_context ok] 41 50 49 44 43 54 49 44 43 4f"##
        );
    }

    #[test]
    fn control_msgs_connection_info() {
        let m = DltMessage::get_testmsg_control(
            false,
            1,
            &[0x02, 0x0f, 0, 0, 0, 2, b'A', b'"', b'\\', b'"'],
        );
        assert!(m.is_ctrl_response());

        assert_eq!(
            m.payload_as_text().unwrap(),
            r##"[connection_info ok] {"comid":"A\"\\\"","state":"connected"}"##
        );

        // wrong len -> dump only bytes:
        let m = DltMessage::get_testmsg_control(false, 1, &[0x02, 0x0f, 0, 0, 0, 1]);
        assert!(m.is_ctrl_response());

        assert_eq!(m.payload_as_text().unwrap(), "[connection_info ok] 01");
    }

    #[test]
    fn control_msgs_timezone() {
        let m = DltMessage::get_testmsg_control(
            false,
            1,
            &[0x03, 0x0f, 0, 0, 0, 0xf0, 0xff, 0xff, 0xff, 0],
        );

        assert_eq!(
            m.payload_as_text().unwrap(),
            r##"[timezone ok] {"gmt_off_secs":-16,"is_dst":false}"##
        );

        // wrong len -> dump only bytes:
        let m = DltMessage::get_testmsg_control(false, 1, &[0x03, 0x0f, 0, 0, 0, 1]);
        assert!(m.is_ctrl_response());

        assert_eq!(m.payload_as_text().unwrap(), "[timezone ok] 01");
    }

    #[test]
    fn parse_storage() {
        let m = get_testmsg_with_payload(
            true,
            5,
            &[
                0, 0, 0, 0x11, 0, 0, 0, 0, 0x11, 1, 0, 0, 0, 0x11, 2, 0, 0, 0, 0x10, 1, 0, 0, 0,
                0x10, 0,
            ],
        );
        let mut file = Vec::new();
        m.to_write(&mut file).unwrap();
        let file_len = file.len();
        let (parsed, m2) = parse_dlt_with_storage_header(1, &file).unwrap();
        assert_eq!(parsed, file_len);
        assert!(!m2.is_ctrl_response());
        assert_eq!(m.ecu, m2.ecu);
        assert_eq!(m, m2);
        assert_eq!(m.extended_header, m2.extended_header);
        assert_eq!(m.payload, m2.payload);

        // incomplete (no storage header)
        let mut file = Vec::new();
        m.to_write(&mut file).unwrap();
        assert!(parse_dlt_with_storage_header(1, &file[1..]).is_err());

        // incomplete (1 byte missing at end)
        let mut file = Vec::new();
        m.to_write(&mut file).unwrap();
        assert!(parse_dlt_with_storage_header(1, &file[0..file.len() - 1]).is_err());

        // incomplete (only storage, std but not full ext header)
        let mut file = Vec::new();
        m.to_write(&mut file).unwrap();
        assert!(parse_dlt_with_storage_header(
            1,
            &file[0..DLT_STORAGE_HEADER_SIZE + DLT_MIN_STD_HEADER_SIZE + DLT_EXT_HEADER_SIZE - 1]
        )
        .is_err());
    }
    #[test]
    fn skip_corrupt_msgs() {
        let mut m = get_testmsg_with_payload(
            true,
            5,
            &[
                0, 0, 0, 0x11, 0, 0, 0, 0, 0x11, 1, 0, 0, 0, 0x11, 2, 0, 0, 0, 0x10, 1, 0, 0, 0,
                0x10, 0,
            ],
        );
        let mut file = Vec::new();
        m.to_write(&mut file).unwrap();

        // incomplete (1 byte missing at end) then a proper msg
        let mut file = Vec::new();
        m.to_write(&mut file).unwrap();
        file.pop(); // remove 1 byte (so this one is corrupt)
        let correct_msg_offset = file.len();
        m.standard_header.mcnt += 1;
        m.to_write(&mut file).unwrap();

        let r = parse_dlt_with_storage_header(1, &file[0..]);
        assert!(matches!(r.err().unwrap().kind(), ErrorKind::InvalidData(_)));
        let (_res, m2) = parse_dlt_with_storage_header(1, &file[correct_msg_offset..]).unwrap();
        assert_eq!(m2.mcnt(), m.mcnt());
    }

    fn get_serial_msg_payload(mcnt: u8) -> Vec<u8> {
        let mut file = Vec::new();

        let standard_header = DltStandardHeader {
            htyp: 1 << 5, // vers 1
            mcnt,
            len: 4,
        };

        let payload = vec![0x01u8];
        let dls_pat = DLT_SERIAL_HEADER_PATTERN.to_le_bytes();

        // DLS format = serial header patter, standard header, [ext header], payload
        file.write_all(&dls_pat).unwrap();
        //file.write_all(&b1).unwrap();

        DltStandardHeader::to_write(
            &mut file,
            &standard_header,
            &None,
            None, // ecu already in storageheader
            None, // session_id = None, todo
            if standard_header.has_timestamp() {
                Some(1000 + mcnt as u32)
            } else {
                None
            },
            &payload,
        )
        .unwrap();
        file
    }

    #[test]
    fn parse_serial() {
        let vec_m1 = get_serial_msg_payload(1);
        let vec_m2 = get_serial_msg_payload(2);

        let file: Vec<_> = vec![vec_m1.clone(), vec_m2.clone()]
            .into_iter()
            .flatten()
            .collect();

        let (parsed, m1) = parse_dlt_with_serial_header(1, &file).unwrap();
        assert_eq!(parsed, vec_m1.len());
        assert_eq!(m1.mcnt(), 1);
        let (parsed, m2) = parse_dlt_with_serial_header(1, &file[parsed..]).unwrap();
        assert_eq!(parsed, vec_m2.len());
        assert_eq!(m2.mcnt(), 2);
    }

    #[test]
    fn parse_serial_corrupt() {
        let vec_m1 = get_serial_msg_payload(1);
        let vec_m2 = get_serial_msg_payload(2);

        let mut file = Vec::new();
        // first message has 1 byte lost
        file.write_all(&vec_m1.as_slice()[0..vec_m1.len() - 1])
            .unwrap();
        // 2nd message is ok
        file.write_all(&vec_m2).unwrap();

        // we expect an error on the first message:
        assert!(parse_dlt_with_serial_header(1, &file).is_err());
        // so we do expect the 2nd message:
        let (parsed, m2) = parse_dlt_with_serial_header(1, &file[vec_m1.len() - 1..]).unwrap();
        assert_eq!(parsed, vec_m2.len());
        assert_eq!(m2.mcnt(), 2);
    }
}
