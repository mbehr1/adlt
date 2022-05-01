/// todos
/// [] check timezone/time shift
/// [] check extended frames
/// [] add support to someip plugin (or a new CAN plugin)
use crate::{
    dlt::{
        DltChar4, DltExtendedHeader, DltMessage, DltMessageIndexType, DltStandardHeader,
        DLT_EXT_HEADER_SIZE, DLT_MIN_STD_HEADER_SIZE, DLT_STD_HDR_BIG_ENDIAN,
        DLT_STD_HDR_HAS_ECU_ID, DLT_STD_HDR_HAS_EXT_HDR, DLT_STD_HDR_HAS_TIMESTAMP,
        DLT_STD_HDR_VERSION, SERVICE_ID_GET_LOG_INFO,
    },
    utils::hex_to_bytes,
};
use chrono::NaiveDateTime;
use lazy_static::lazy_static;
use regex::{CaptureLocations, Regex};
use slog::{debug, error, warn};
use std::{
    collections::HashMap,
    io::{BufRead, Lines},
    str::FromStr,
};

/// an iterator that creates/iterates over dlt messages created from an .asc CAN file.
///
/// The CAN messages get encoded as
///  - reception time is the time from .asc date lines plus the timestamp
///  - timestamp_dms is the timestamp truncated/rounded down to 0.1ms
///  - non verbose DLT msgs
///  - noar:2
///  - payload consists of
///    - a u32 with the frame_id
///    - the data bytes received from CAN
///
/// - ECU, APID, CTID: tbd (use CAN ID)
/// - session_id not set
/// - endianess used: host endianess
///
/// Example line that gets parsed:
///
/// **0.985210** *1* **36f** Rx d *5* **f2 f7 fe ff 14** Length = 0 BitCount = 0 ID = 879
///
pub struct Asc2DltMsgIterator<'a, R> {
    lines: Lines<R>, // todo could optimize with e.g. stream_iterator for &str instead of string copies!
    pub index: DltMessageIndexType,
    pub lines_processed: usize,
    pub lines_skipped: usize,
    pub log: Option<&'a slog::Logger>,

    date_us: u64, // will be parsed from first asc line "date ..."
    capture_locations: CaptureLocations,
    htyp: u8, // std hdr htyp
    len_wo_payload: u16,
    can_id_ecu_map: HashMap<u8, DltChar4>,
    apid: DltChar4,
    ctid: DltChar4,
}

impl<'a, R: BufRead> Asc2DltMsgIterator<'a, R> {
    pub fn new(
        start_index: DltMessageIndexType,
        reader: R,
        log: Option<&'a slog::Logger>,
    ) -> Asc2DltMsgIterator<'a, R> {
        let htyp = DLT_STD_HDR_VERSION
            | DLT_STD_HDR_HAS_ECU_ID
            | DLT_STD_HDR_HAS_TIMESTAMP
            | DLT_STD_HDR_HAS_EXT_HDR
            | if 1u32.to_be() == 1u32 {
                DLT_STD_HDR_BIG_ENDIAN
            } else {
                0u8
            };

        let len_wo_payload = (DLT_MIN_STD_HEADER_SIZE + 4 + 4 + DLT_EXT_HEADER_SIZE) as u16;

        Asc2DltMsgIterator {
            lines: reader.lines(),
            index: start_index,
            lines_processed: 0,
            lines_skipped: 0,
            log,
            date_us: 0,
            capture_locations: RE_MSG.capture_locations(),
            htyp,
            len_wo_payload,
            can_id_ecu_map: HashMap::new(),
            apid: DltChar4::from_buf(b"CAN\0"),
            ctid: DltChar4::from_buf(b"TC\0\0"),
        }
    }

    fn get_ecu(&mut self, can_id: u8) -> &DltChar4 {
        self.can_id_ecu_map.entry(can_id).or_insert_with(|| {
            if can_id < 10 {
                DltChar4::from_str(format!("CAN{}", can_id).as_str()).unwrap()
            } else if can_id < 100 {
                DltChar4::from_str(format!("CA{}", can_id).as_str()).unwrap()
            } else {
                DltChar4::from_str(format!("C{}", can_id).as_str()).unwrap()
            }
        })
    }
}

lazy_static! {
    pub(crate) static ref RE_COMMENT: Regex = Regex::new(r"^//").unwrap();
    pub(crate) static ref RE_DATE: Regex = Regex::new(r"^date (.*)$").unwrap();
    pub(crate) static ref RE_MSG: Regex =
        Regex::new(r"^(\d+\.\d{6}) (\d+) ([0-9a-fx]+) (Rx|Tx) d (\d+)").unwrap();
}

impl<'a, R> Iterator for Asc2DltMsgIterator<'a, R>
where
    R: BufRead,
{
    type Item = DltMessage;
    fn next(&mut self) -> Option<Self::Item> {
        for line in self.lines.by_ref() {
            self.lines_processed += 1;
            match &line {
                Ok(line) => {
                    // expect "base hex timestamps absolute"
                    // matches can msg regex?
                    if let Some(captures) = RE_MSG.captures_read(&mut self.capture_locations, line)
                    {
                        let cap_str = captures.as_str();
                        let loc_timestamp = self.capture_locations.get(1).unwrap();
                        let timestamp = &cap_str[loc_timestamp.0..loc_timestamp.1];
                        let dot_idx = timestamp.find('.').unwrap_or_default();
                        let timestamp_us: u64 =
                            (timestamp[0..dot_idx].parse::<u64>().unwrap_or_default() * 1_000_000)
                                + timestamp[dot_idx + 1..].parse::<u64>().unwrap_or_default();
                        let loc_can_id = self.capture_locations.get(2).unwrap();
                        // we map the can_id to the ECU to be used:
                        let can_id = &cap_str[loc_can_id.0..loc_can_id.1]
                            .parse::<u8>()
                            .unwrap_or_default();
                        let ecu = self.can_id_ecu_map.entry(*can_id).or_insert_with(|| {
                            if *can_id < 10 {
                                DltChar4::from_str(format!("CAN{}", can_id).as_str()).unwrap()
                            } else if *can_id < 100 {
                                DltChar4::from_str(format!("CA{}", can_id).as_str()).unwrap()
                            } else {
                                DltChar4::from_str(format!("C{}", can_id).as_str()).unwrap()
                            }
                        });
                        let loc_id = self.capture_locations.get(3).unwrap();
                        let id = &cap_str[loc_id.0..loc_id.1];
                        let frame_id = if let Some(stripped) = id.strip_suffix('x') {
                            let frame_id = u32::from_str_radix(stripped, 16).unwrap_or_default();
                            if let Some(log) = self.log {
                                debug!(
                                            log,
                                            "Asc2DltMsgIterator.next got msg with extended id={} {} at line #{}",
                                            id,
                                            frame_id,
                                            self.lines_processed
                                        );
                            }
                            frame_id
                        } else {
                            u32::from_str_radix(id, 16).unwrap_or_default()
                        };

                        //let loc_rxtx = self.capture_locations.get(4).unwrap();
                        //let rxtx = &cap_str[loc_rxtx.0..loc_rxtx.1];
                        let loc_d = self.capture_locations.get(5).unwrap();
                        let data_len =
                            &cap_str[loc_d.0..loc_d.1].parse::<u16>().unwrap_or_default();
                        // now the data itself:
                        let loc_d_start = loc_d.1 + 1;
                        let loc_d_end = loc_d_start + (3 * (*data_len as usize)) - 1;
                        let data = if *data_len > 0 && loc_d_end < line.len() {
                            hex_to_bytes(&line.as_str()[loc_d_start..loc_d_end])
                        } else {
                            None
                        };

                        let mut payload: Vec<u8> =
                            Vec::with_capacity((u32::BITS / 8) as usize + (*data_len as usize));
                        payload.extend(frame_id.to_ne_bytes());
                        if let Some(mut data) = data {
                            payload.append(&mut data);
                        }

                        /*if let Some(log) = self.log {
                            debug!(
                                        log,
                                        "Asc2DltMsgIterator.next got msg frame_id={} timestamp_us={} can_id={} id={} rxtx={} d={} payload={:?} at line #{}",
                                        frame_id,
                                        timestamp_us,
                                        can_id,
                                        id,
                                        rxtx,
                                        data_len,
                                        payload,
                                        self.lines_processed
                                    );
                        }*/
                        // return a DltMessage
                        let index = self.index;
                        self.index += 1;
                        return Some(DltMessage {
                            index,
                            reception_time_us: self.date_us + timestamp_us,
                            ecu: ecu.to_owned(),
                            timestamp_dms: (timestamp_us / 100) as u32, // rounding? or prefer round down to not move into the future? (could do w.o. timestamp_dms as well)
                            standard_header: DltStandardHeader {
                                htyp: self.htyp,
                                mcnt: (index & 0xff) as u8,
                                len: self.len_wo_payload + (payload.len() as u16),
                            },
                            extended_header: Some(DltExtendedHeader {
                                verb_mstp_mtin: (2u8 << 1) | (2u8 << 4), // NwTrace CAN, non verb.
                                noar: 2,
                                apid: self.apid.to_owned(),
                                ctid: self.ctid.to_owned(),
                            }),
                            payload,
                            payload_text: None,
                            lifecycle: 0,
                        });
                    } else if let Some(captures) = RE_DATE.captures(line) {
                        if let Some(date) = captures.get(1) {
                            let nt = NaiveDateTime::parse_from_str(
                                date.as_str(),
                                "%a %b %d %H:%M:%S %p %Y",
                            );
                            if let Ok(nt) = nt {
                                self.date_us = (nt.timestamp_nanos() / 1000) as u64;
                            }
                            if let Some(log) = self.log {
                                debug!(
                                    log,
                                    "Asc2DltMsgIterator.next got date {} as {:?} at line #{}",
                                    date.as_str(),
                                    nt,
                                    self.lines_processed
                                );
                            }
                        }
                    } else if RE_COMMENT.is_match(line) {
                        let comment = &line[2..].trim();
                        if comment.starts_with("BusMapping: CAN ") {
                            // use BusMapping: CAN x = <name> and send the name as ECU name?
                            if let Some((id, name)) = comment[15..].split_once('=') {
                                if let Ok(id) = id.trim().parse::<u8>() {
                                    let name = name.trim();
                                    if let Some(log) = self.log {
                                        debug!(
                                        log,
                                        "Asc2DltMsgIterator.next got BusMapping {} = {} at line #{}",
                                        id,
                                        name,
                                        self.lines_processed
                                    );
                                    }
                                    let apid = self.apid.to_owned(); // or special ones DA1 DA1?
                                    let ctid = self.ctid.to_owned(); // CAN plugin checks for that apid as well!
                                    let mut payload: Vec<u8> =
                                        SERVICE_ID_GET_LOG_INFO.to_ne_bytes().into();
                                    let apid_buf = apid.as_buf();
                                    payload.extend(
                                        [7u8]
                                            .into_iter()
                                            .chain(1u16.to_ne_bytes().into_iter()) // 1 app id, CAN plugin expects == 1
                                            .chain(apid_buf.iter().copied())
                                            .chain(0u16.to_ne_bytes().into_iter()) // 0 ctx ids
                                            .chain((name.len() as u16).to_ne_bytes().into_iter()) // len of apid desc
                                            .chain(name.as_bytes().iter().copied()),
                                    );
                                    // return a DltMessage with the LOG INFO APID incl. the BusMapping name
                                    let index = self.index;
                                    self.index += 1;
                                    return Some(DltMessage {
                                        index,
                                        reception_time_us: self.date_us,
                                        ecu: self.get_ecu(id).to_owned(),
                                        timestamp_dms: 0u32,
                                        standard_header: DltStandardHeader {
                                            htyp: self.htyp,
                                            mcnt: (index & 0xff) as u8,
                                            len: self.len_wo_payload + (payload.len() as u16),
                                        },
                                        extended_header: Some(DltExtendedHeader {
                                            verb_mstp_mtin: (3u8 << 1) | (2u8 << 4), // Control Resp., non verb
                                            noar: 2,
                                            apid,
                                            ctid,
                                        }),
                                        payload,
                                        payload_text: None,
                                        lifecycle: 0,
                                    });
                                }
                            }
                        }
                    } else if !line.is_empty() {
                        self.lines_skipped += 1;
                        if let Some(log) = self.log {
                            warn!(
                                log,
                                "Asc2DltMsgIterator.next unknown line {} at line #{}",
                                line,
                                self.lines_processed
                            );
                        }
                    }
                }
                Err(e) => {
                    if let Some(log) = self.log {
                        error!(
                            log,
                            "Asc2DltMsgIterator.next got err {} at line #{}",
                            e,
                            self.lines_processed
                        );
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::Asc2DltMsgIterator;
    use crate::{
        dlt::{DltMessageControlType, DltMessageNwType, DltMessageType, DLT_MAX_STORAGE_MSG_SIZE},
        utils::LowMarkBufReader,
    };
    use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
    use slog::{o, Drain, Logger};
    use std::fs::File;

    fn new_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, o!())
    }

    #[test]
    fn asc_basic1() {
        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        test_dir.push("can_example1.asc");
        let fi = File::open(&test_dir).unwrap();
        let start_index = 1000;
        let log = new_logger();
        let mut it = Asc2DltMsgIterator::new(
            start_index,
            LowMarkBufReader::new(fi, 512 * 1024, DLT_MAX_STORAGE_MSG_SIZE),
            Some(&log),
        );
        let mut iterated_msgs = 0;
        for m in &mut it {
            assert_eq!(m.index, start_index + iterated_msgs);
            assert!(!m.is_verbose());
            assert_eq!(m.mcnt(), (m.index & 0xff) as u8);
            match m.index {
                1000 => assert_eq!(
                    m.mstp(),
                    DltMessageType::Control(DltMessageControlType::Response)
                ),
                _ => assert_eq!(
                    m.mstp(),
                    DltMessageType::NwTrace(DltMessageNwType::Can),
                    "m.index={}",
                    m.index
                ),
            }
            iterated_msgs += 1;
            if m.index == start_index + 1 {
                // check some static data from example:
                assert_eq!(
                    m.reception_time(),
                    NaiveDateTime::new(
                        NaiveDate::from_ymd(2022, 4, 12),
                        NaiveTime::from_hms_micro(8, 55, 37, 985210)
                    )
                );
                assert_eq!(m.timestamp_dms, 9852);
                assert_eq!(m.noar(), 2);
                let exp_payload: Vec<u8> = 0x36fu32
                    .to_ne_bytes()
                    .into_iter()
                    .chain(vec![0xf2, 0xf7, 0xfe, 0xff, 0x14].into_iter())
                    .collect::<Vec<u8>>();
                assert_eq!(
                    m.payload,
                    exp_payload //vec![111u8, 3, 0, 0, 0xf2, 0xf7, 0xfe, 0xff, 0x14] // will fail on different endian (as the frame_id as u32 has different enc. there)
                );
            }
        }
        assert_eq!(iterated_msgs, 101);
    }
}
