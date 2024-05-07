/// todos
/// [] check timezone/time shift
/// [] check extended frames
/// [] CANFD frame_name (or brs) support
use crate::{
    dlt::{
        DltChar4, DltExtendedHeader, DltMessage, DltMessageIndexType, DltStandardHeader,
        DLT_EXT_HEADER_SIZE, DLT_MIN_STD_HEADER_SIZE, DLT_STD_HDR_BIG_ENDIAN,
        DLT_STD_HDR_HAS_ECU_ID, DLT_STD_HDR_HAS_EXT_HDR, DLT_STD_HDR_HAS_TIMESTAMP,
        DLT_STD_HDR_VERSION, SERVICE_ID_GET_LOG_INFO,
    },
    utils::{hex_to_bytes, US_PER_SEC},
};
use chrono::NaiveDateTime;
use lazy_static::lazy_static;
use regex::{CaptureLocations, Regex};
use slog::{debug, error, trace};
use std::{
    collections::HashMap,
    io::{BufRead, Lines},
    str::FromStr,
    sync::RwLock,
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
/// ### Note
/// ASC can format timestamps can be negative. This is usually used to have the timestamp 0
/// at a trigger time and have messages before the trigger as well.
/// As DLT doesn't support negative timestamps they are converted:
///   - the recording time is adjusted backwards and the first neg. message gets the timestamp 0.
///   - the following neg. timestamps get the difference to the prev. msg
pub struct Asc2DltMsgIterator<'a, R> {
    lines: Lines<R>, // todo could optimize with e.g. stream_iterator for &str instead of string copies!
    pub index: DltMessageIndexType,
    namespace: u32,
    timestamp_reference_time_us: Option<u64>,
    pub lines_processed: usize,
    pub lines_skipped: usize,
    pub log: Option<&'a slog::Logger>,

    date_us: u64,                // will be parsed from first asc line "date ..."
    timestamp_offset_dms: u32, // offset to be added to timestamps. Used if timestamp_reference_time is provided.
    first_neg_timestamp_us: i64, // first neg. timestamp after date line
    capture_locations_can: CaptureLocations,
    capture_locations_canfd: CaptureLocations,
    capture_locations_canfd_errorframe: CaptureLocations,
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
        namespace: u32,
        timestamp_reference_time_us: Option<u64>,
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
            namespace,
            timestamp_reference_time_us,
            lines_processed: 0,
            lines_skipped: 0,
            log,
            date_us: (chrono::Utc::now().naive_utc().timestamp_micros()) as u64, // init to avoid underrun if only neg timestamps are provided
            timestamp_offset_dms: 0,
            first_neg_timestamp_us: 0,
            capture_locations_can: RE_MSG.capture_locations(),
            capture_locations_canfd: RE_MSG_CANFD.capture_locations(),
            capture_locations_canfd_errorframe: RE_MSG_CANFD_ERRORFRAME.capture_locations(),
            htyp,
            len_wo_payload,
            can_id_ecu_map: HashMap::new(),
            apid: DltChar4::from_buf(b"CAN\0"),
            ctid: DltChar4::from_buf(b"TC\0\0"),
        }
    }

    fn get_ecu(&mut self, can_id: u8, name: &Option<&str>) -> DltChar4 {
        self.can_id_ecu_map
            .entry(can_id)
            .or_insert_with(|| get_ecuid_for_namespace(self.namespace, name))
            .to_owned()
    }

    fn timestamp_dms_from(&self, timestamp_us: i64) -> u32 {
        if timestamp_us >= 0 {
            self.timestamp_offset_dms + ((timestamp_us / 100) as u32)
        } else if self.timestamp_offset_dms > 0 {
            self.timestamp_offset_dms
                .saturating_sub((-timestamp_us / 100) as u32)
        } else {
            // for neg timestamps the reception time is correct but the timestamp needs to be corrected
            // to always be monotonicaly increasing so we convert e.g. -100...-0.,0.1... to 0..100,0.1...
            // i.e. timestamp - first_neg_timestamp... (so neg --(=+) first_neg_timestamp)
            // we do this only if we have no timestamp_offset_dms set (so no reference time to use)
            (timestamp_us.saturating_sub(self.first_neg_timestamp_us) / 100) as u32
        } // rounding? or prefer round down to not move into the future? (could do w.o. timestamp_dms as well)
    }
}

lazy_static! {
    pub(crate) static ref RE_COMMENT: Regex = Regex::new(r"^//").unwrap();
    pub(crate) static ref RE_DATE: Regex = Regex::new(r"^date (.*)$").unwrap();
    pub(crate) static ref RE_MSG: Regex =
    // timestamp channel_id can/frame_id Rx|Tx data_len
        Regex::new(r"^(-?\d+\.\d{6}) (\d+) ([0-9a-fx]+) (Rx|Tx) d (\d+)").unwrap();
    pub(crate) static ref RE_MSG_CANFD: Regex =
    // timestamp CANFD channel_id Rx|Tx can_id(hex) frame_name&brs_or_brs (todo!) esi dlc(hex) data_length(dec) data (rest ignored)
        Regex::new(r"^(-?\d+\.\d{6}) CANFD (\d+) (Rx|Tx) ([0-9a-fx]+)\s+(\d+) (\d+) ([0-9a-fx]+) (\d+)").unwrap();

    pub(crate) static ref RE_MSG_CANFD_ERRORFRAME: Regex =
        // timestamp CANFD channel_id Rx|Tx ErrorFrame (rest ignored)
        Regex::new(r"^(-?\d+\.\d{6}) CANFD (\d+) (Rx|Tx) ErrorFrame").unwrap();

    // map by namespace to a map for name to ecu-id:
    static ref CAN_GLOBAL_ECU_MAP: RwLock<HashMap<u32, HashMap<String, DltChar4>>> = RwLock::new(HashMap::new());
}

fn get_ecuid_for_namespace(namespace: u32, name: &Option<&str>) -> DltChar4 {
    let mut namespace_map = CAN_GLOBAL_ECU_MAP.write().unwrap();
    let map = namespace_map.entry(namespace).or_default();
    let next_id = map.len() + 1;
    map.entry(name.map_or_else(|| format!("AUTO_CAN_ID_{}", next_id), |f| f.to_string()))
        .or_insert_with(|| {
            if next_id < 10 {
                DltChar4::from_str(format!("CAN{}", next_id).as_str()).unwrap()
            } else if next_id < 100 {
                DltChar4::from_str(format!("CA{}", next_id).as_str()).unwrap()
            } else {
                DltChar4::from_str(format!("C{}", next_id).as_str()).unwrap()
            }
        })
        .to_owned()
}

/* todo for now we do never clear the namespaces map. could use some ref counted...
fn remove_namespace_global_ecu_map(namespace: u32) -> Option<HashMap<String, DltChar4>> {
    let mut map = CAN_GLOBAL_ECU_MAP.write().unwrap();
    map.remove(&namespace)
} */

pub fn asc_parse_date(date_str: &str) -> Result<NaiveDateTime, chrono::ParseError> {
    // we expect them in the following format:
    NaiveDateTime::parse_from_str(date_str, "%a %b %d %I:%M:%S%.f %p %Y")
}

/// Parse a timestamp in can asc format to a time in us.
///
/// Timestamps in asc can be negative thus a i64 is returned.
/// Expected format is (-)x.yyyyyy (x any number, y exactly 6 digits)
///
/// In case of any parsing errors 0 is returned.
/// ### Note
/// The function is slow if the the fraction is not 6 digits!
fn parse_signed_time_str(timestamp: &str) -> i64 {
    let timestamp_is_neg = timestamp.starts_with('-');
    let offset_timestamp = if timestamp_is_neg { 1_usize } else { 0 };
    let dot_idx = timestamp.find('.').unwrap_or(timestamp.len());

    let timestamp_secs_us: i64 = timestamp[offset_timestamp..dot_idx]
        .parse::<i64>()
        .unwrap_or_default()
        * (US_PER_SEC as i64);
    let timestamp_fraction_us = if dot_idx < timestamp.len() {
        let timestamp_fraction_str = &timestamp[dot_idx + 1..];
        let mut len_fraction = timestamp_fraction_str.len();
        let mut timestamp_fraction_us =
            timestamp_fraction_str.parse::<u64>().unwrap_or_default() as i64;
        if len_fraction != 6 {
            while len_fraction < 6 {
                timestamp_fraction_us *= 10; // todo optimize by pow10...
                len_fraction += 1;
            }
            while len_fraction > 6 {
                timestamp_fraction_us /= 10;
                len_fraction -= 1;
            }
        }
        timestamp_fraction_us
    } else {
        0
    };
    let timestamp_us = timestamp_secs_us + timestamp_fraction_us;
    if timestamp_is_neg {
        -timestamp_us
    } else {
        timestamp_us
    }
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
                    if let Some(captures) =
                        RE_MSG.captures_read(&mut self.capture_locations_can, line)
                    {
                        let cap_str = captures.as_str();
                        let loc_timestamp = self.capture_locations_can.get(1).unwrap();
                        let timestamp = &cap_str[loc_timestamp.0..loc_timestamp.1];
                        let timestamp_us = parse_signed_time_str(timestamp);
                        if timestamp_us.is_negative() && self.first_neg_timestamp_us == 0 {
                            self.first_neg_timestamp_us = timestamp_us;
                        }
                        let loc_can_id = self.capture_locations_can.get(2).unwrap();
                        // we map the can_id to the ECU to be used:
                        let can_id = &cap_str[loc_can_id.0..loc_can_id.1]
                            .parse::<u8>()
                            .unwrap_or_default();
                        let loc_id = self.capture_locations_can.get(3).unwrap();
                        let id = &cap_str[loc_id.0..loc_id.1];
                        let frame_id = if let Some(stripped) = id.strip_suffix('x') {
                            let frame_id = u32::from_str_radix(stripped, 16).unwrap_or_default();
                            if let Some(log) = self.log {
                                trace!(
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
                        let loc_d = self.capture_locations_can.get(5).unwrap();
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

                        let index = self.index;
                        self.index += 1;
                        let ecu = self.get_ecu(*can_id, &None);

                        return Some(DltMessage {
                            index,
                            reception_time_us: self.date_us.saturating_add_signed(timestamp_us),
                            ecu,
                            timestamp_dms: self.timestamp_dms_from(timestamp_us),
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
                    } else if let Some(captures) =
                        RE_MSG_CANFD.captures_read(&mut self.capture_locations_canfd, line)
                    {
                        // capture groups:
                        // 1 = timestamp
                        // 2 = channel_id
                        // 3 = dir
                        // 4 = frame_id
                        // 5 = brs
                        // 6 = esi
                        // 7 = dlc
                        // 8 = data_length

                        let cap_str = captures.as_str();
                        let loc_timestamp = self.capture_locations_canfd.get(1).unwrap();
                        let timestamp = &cap_str[loc_timestamp.0..loc_timestamp.1];
                        let timestamp_us = parse_signed_time_str(timestamp);
                        if timestamp_us.is_negative() && self.first_neg_timestamp_us == 0 {
                            self.first_neg_timestamp_us = timestamp_us;
                        }
                        let loc_can_id = self.capture_locations_canfd.get(2).unwrap();
                        // we map the can_id to the ECU to be used:
                        let can_id = &cap_str[loc_can_id.0..loc_can_id.1]
                            .parse::<u8>()
                            .unwrap_or_default();
                        let loc_id = self.capture_locations_canfd.get(4).unwrap();
                        let id = &cap_str[loc_id.0..loc_id.1];
                        let frame_id = if let Some(stripped) = id.strip_suffix('x') {
                            let frame_id = u32::from_str_radix(stripped, 16).unwrap_or_default();
                            if let Some(log) = self.log {
                                trace!(
                                        log,
                                        "Asc2DltMsgIterator.next got canfd msg with extended id={} {} at line #{}",
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
                        let loc_d = self.capture_locations_canfd.get(8).unwrap();
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
                        // return a DltMessage
                        let index = self.index;
                        self.index += 1;

                        let ecu = self.get_ecu(*can_id, &None);

                        return Some(DltMessage {
                            index,
                            reception_time_us: self.date_us.saturating_add_signed(timestamp_us),
                            ecu,
                            timestamp_dms: self.timestamp_dms_from(timestamp_us),
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
                    } else if let Some(captures) = RE_MSG_CANFD_ERRORFRAME
                        .captures_read(&mut self.capture_locations_canfd_errorframe, line)
                    {
                        // capture groups:
                        // 1 = timestamp
                        // 2 = channel_id
                        // 3 = dir

                        let cap_str = captures.as_str();
                        let loc_timestamp = self.capture_locations_canfd_errorframe.get(1).unwrap();
                        let timestamp = &cap_str[loc_timestamp.0..loc_timestamp.1];
                        let timestamp_us = parse_signed_time_str(timestamp);
                        if timestamp_us.is_negative() && self.first_neg_timestamp_us == 0 {
                            self.first_neg_timestamp_us = timestamp_us;
                        }
                        let loc_can_id = self.capture_locations_canfd_errorframe.get(2).unwrap();
                        // we map the can_id to the ECU to be used:
                        let can_id = &cap_str[loc_can_id.0..loc_can_id.1]
                            .parse::<u8>()
                            .unwrap_or_default();

                        let payload = vec![];

                        // return a DltMessage
                        let index = self.index;
                        self.index += 1;

                        let ecu = self.get_ecu(*can_id, &None);

                        return Some(DltMessage {
                            index,
                            reception_time_us: self.date_us.saturating_add_signed(timestamp_us),
                            ecu,
                            timestamp_dms: self.timestamp_dms_from(timestamp_us),
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
                            payload_text: Some("Error Frame".to_owned()),
                            lifecycle: 0,
                        });
                    } else if let Some(captures) = RE_DATE.captures(line) {
                        if let Some(date) = captures.get(1) {
                            let nt = asc_parse_date(date.as_str());
                            if let Ok(nt) = nt {
                                let nt_us = nt.timestamp_micros() as u64;
                                self.date_us = nt_us;
                                self.first_neg_timestamp_us = 0; // reset here if mult. files get concatenated
                                if let Some(timestamp_reference_time_us) =
                                    self.timestamp_reference_time_us
                                {
                                    if timestamp_reference_time_us < nt_us {
                                        self.timestamp_offset_dms =
                                            ((nt_us - timestamp_reference_time_us) / 100) as u32;
                                    }
                                }
                            }
                            if let Some(log) = self.log {
                                trace!(
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
                        if comment.starts_with("BusMapping: CAN") {
                            // use BusMapping: CAN x = <name> and send the name as ECU name?
                            // or CANFD x = <name>
                            let id_idx = 14 + comment[14..].find(' ').unwrap_or(1);
                            if let Some((id, name)) = comment[id_idx..].split_once('=') {
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
                                        ecu: self.get_ecu(id, &Some(name)),
                                        timestamp_dms: self.timestamp_offset_dms,
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
                            debug!(
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
    use super::{asc_parse_date, parse_signed_time_str, Asc2DltMsgIterator};
    use crate::{
        dlt::{
            DltChar4, DltMessageControlType, DltMessageNwType, DltMessageType,
            DLT_MAX_STORAGE_MSG_SIZE,
        },
        utils::{get_new_namespace, LowMarkBufReader},
    };
    use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
    use slog::{o, Drain, Logger};
    use std::{fs::File, str::FromStr};

    fn new_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, o!())
    }

    #[test]
    fn date1() {
        assert_eq!(
            Ok(NaiveDateTime::new(
                NaiveDate::from_ymd_opt(2022, 4, 12).unwrap(),
                NaiveTime::from_hms_micro_opt(8, 55, 37, 0).unwrap()
            )),
            asc_parse_date("Tue Apr 12 08:55:37 AM 2022")
        );

        let nt = NaiveDateTime::new(
            NaiveDate::from_ymd_opt(2022, 5, 25).unwrap(),
            NaiveTime::from_hms_micro_opt(15, 7, 31, 0).unwrap(),
        );
        // println!("nt formatted = '{}'", nt.format("%a %b %d %I:%M:%S %p %Y"));
        assert_eq!(Ok(nt), asc_parse_date("Wed May 25 03:07:31 PM 2022"));

        // with ms:
        assert_eq!(
            Ok(NaiveDateTime::new(
                NaiveDate::from_ymd_opt(2024, 4, 26).unwrap(),
                NaiveTime::from_hms_micro_opt(18, 52, 12, 825000).unwrap()
            )),
            asc_parse_date("Fri Apr 26 06:52:12.825 pm 2024")
        );
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
            get_new_namespace(),
            None,
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
                        NaiveDate::from_ymd_opt(2022, 4, 12).unwrap(),
                        NaiveTime::from_hms_micro_opt(8, 55, 37, 985210).unwrap()
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

    #[test]
    fn asc_canfd1() {
        let reader = r##"
//BusMapping: CAN 1 = ECU_CAN_FD
-0.169843 CANFD 1 Rx 135   1 0 8 8 f0 1a 7d 00 a6 ff ff ff 0 0 3000 0 0 0 0 0
-0.159843 CANFD 1 Rx 135   1 0 8 8 f1 1a 7d 00 a6 ff ff ff 0 0 3000 0 0 0 0 0
0.169843 CANFD 1 Rx 135   1 0 8 8 f2 1a 7d 00 a6 ff ff ff 0 0 3000 0 0 0 0 0"##
            .as_bytes();
        let mut it = Asc2DltMsgIterator::new(0, reader, get_new_namespace(), None, None);
        let mut iterated_msgs: u32 = 0;
        for m in &mut it {
            iterated_msgs += 1;
            // todo verify payload println!("m={:?}", m);
            match iterated_msgs {
                2 => assert_eq!(m.timestamp_dms, 0_u32), // the first neg. gets a 0 timestamp
                3 => assert_eq!(m.timestamp_dms, 100_u32), // the 10ms = 100dms apart
                4 => assert_eq!(m.timestamp_dms, 1698_u32),
                _ => {}
            }
        }
        assert_eq!(iterated_msgs, 4); // one ctrl and three canfd msgs
    }

    #[test]
    fn asc_canfd_errorframe() {
        let reader = r##"
//BusMapping: CANFD 1 = ECU_CAN_FD 559
-0.017230 CANFD 1 Rx ErrorFrame                                                 0 0 0 Data 0 0 0 0 0 0 0 11 0 0 0 0 0
0.017230 CANFD 1 Rx ErrorFrame                                                 0 0 0 Data 0 0 0 0 0 0 0 11 0 0 0 0 0"##
            .as_bytes();
        let mut it = Asc2DltMsgIterator::new(0, reader, get_new_namespace(), None, None);
        let mut iterated_msgs: u32 = 0;
        for _m in &mut it {
            iterated_msgs += 1;
            // todo verify payload println!("m={:?}", m);
        }
        assert_eq!(iterated_msgs, 3); // one ctrl and two canfd msgs
    }

    #[test]
    fn asc_can1() {
        let reader = r##"
//BusMapping: CAN 1 = ECU_CAN 431
-0.985210 1 36f Rx d 5 f2 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879
-0.000100 1 36f Rx d 5 f2 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879
0.000000 1 36f Rx d 5 f3 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879
0.000100 1 36f Rx d 5 f4 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879"##
            .as_bytes();
        let mut it = Asc2DltMsgIterator::new(0, reader, get_new_namespace(), None, None);
        let mut iterated_msgs: u32 = 0;
        for m in &mut it {
            iterated_msgs += 1;
            // todo verify payload println!("m={:?}", m);
            match iterated_msgs {
                2 => assert_eq!(m.timestamp_dms, 0_u32), // the first neg. gets a 0 timestamp
                3 => assert_eq!(m.timestamp_dms, 9851_u32), // 9851dms after the first one
                4 => assert_eq!(m.timestamp_dms, 0_u32),
                5 => assert_eq!(m.timestamp_dms, 1_u32),
                _ => {}
            }
        }
        assert_eq!(iterated_msgs, 5); // one ctrl and four can msgs
    }

    #[test]
    fn asc_can1_reference_time() {
        let reader = r##"
date Thu Apr 20 10:26:43 AM 2023
//BusMapping: CAN 1 = ECU_CAN 431
-0.985210 1 36f Rx d 5 f2 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879
-0.000100 1 36f Rx d 5 f2 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879
0.000000 1 36f Rx d 5 f3 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879
0.000100 1 36f Rx d 5 f4 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879"##
            .as_bytes();
        let timestamp_reference_time = asc_parse_date("Thu Apr 20 10:25:26 AM 2023")
            .ok()
            .map(|a| a.timestamp_micros() as u64);

        let mut it = Asc2DltMsgIterator::new(
            0,
            reader,
            get_new_namespace(),
            timestamp_reference_time,
            None,
        );
        let mut iterated_msgs: u32 = 0;
        for m in &mut it {
            iterated_msgs += 1;
            // todo verify payload println!("m={:?}", m);
            match iterated_msgs {
                2 => assert_eq!(m.timestamp_dms, 770000_u32 - 9852), // the first neg. gets the timestamp fitting to reference time
                3 => assert_eq!(m.timestamp_dms, 770000_u32 - 9852 + 9851_u32), // 9851dms after the first one
                4 => assert_eq!(m.timestamp_dms, 770000_u32),
                5 => assert_eq!(m.timestamp_dms, 770001_u32),
                _ => {}
            }
        }
        assert_eq!(iterated_msgs, 5); // one ctrl and four can msgs
    }

    #[test]
    fn parse_signed_time_str_1() {
        assert_eq!(parse_signed_time_str("-0.123456"), -123456_i64);
        assert_eq!(parse_signed_time_str("0.123456"), 123456_i64);
        assert_eq!(parse_signed_time_str("0.12345"), 123450_i64); // even though one digit missing!
        assert_eq!(parse_signed_time_str("-42.1"), -42100000_i64);
        assert_eq!(parse_signed_time_str("4242.123456"), 4242123456_i64);
        assert_eq!(parse_signed_time_str("42"), 42000000_i64);
        assert_eq!(parse_signed_time_str(""), 0_i64);
        assert_eq!(parse_signed_time_str("-"), 0_i64);
        assert_eq!(parse_signed_time_str(".1"), 100000_i64);
        assert_eq!(parse_signed_time_str("-.1"), -100000_i64);
    }

    // test multiple files support:
    // we expect:
    // msgs get ECU CAN., CA.., C... fitting to BusMapping infos
    #[test]
    fn asc_multiple_files_diff_can_id() {
        let reader1 = r##"
//BusMapping: CAN 1 = ECU_CAN 431
0.000100 1 36f Rx d 5 f4 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879"##
            .as_bytes();
        let namespace = get_new_namespace();
        let mut it = Asc2DltMsgIterator::new(0, reader1, namespace, None, None);
        let mut iterated_msgs: u32 = 0;
        for m in &mut it {
            iterated_msgs += 1;
            if iterated_msgs == 2 {
                assert_eq!(m.ecu, DltChar4::from_str("CAN1").ok().unwrap());
            }
        }
        assert_eq!(iterated_msgs, 2); // one ctrl and 1 can msgs

        // 2nd CAN should get a new number even though CAN id in the file is 1...
        // as the BusMapping: can name is different!
        let reader2 = r##"
//BusMapping: CAN 1 = ECU2_CAN 432
0.000101 1 36f Rx d 5 f4 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879"##
            .as_bytes();
        let mut it = Asc2DltMsgIterator::new(0, reader2, namespace, None, None);
        let mut iterated_msgs: u32 = 0;
        for m in &mut it {
            iterated_msgs += 1;
            if iterated_msgs == 2 {
                assert_eq!(m.ecu, DltChar4::from_str("CAN2").ok().unwrap());
            }
        }
        assert_eq!(iterated_msgs, 2); // one ctrl and 1 can msgs

        // 3rd CAN should get the same number as CAN 2  as Busmapping is the same
        let reader2 = r##"
//BusMapping: CAN 1 = ECU2_CAN 432
0.000102 1 36f Rx d 5 f4 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879"##
            .as_bytes();
        let mut it = Asc2DltMsgIterator::new(0, reader2, namespace, None, None);
        let mut iterated_msgs: u32 = 0;
        for m in &mut it {
            iterated_msgs += 1;
            if iterated_msgs == 2 {
                assert_eq!(m.ecu, DltChar4::from_str("CAN2").ok().unwrap());
            }
        }
        assert_eq!(iterated_msgs, 2); // one ctrl and 1 can msgs

        // 4th CAN should get the same number as CAN 2  as Busmapping maps to same name
        let reader2 = r##"
//BusMapping: CAN 5 = ECU2_CAN 432
0.000102 5 36f Rx d 5 f4 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879"##
            .as_bytes();
        let mut it = Asc2DltMsgIterator::new(0, reader2, namespace, None, None);
        let mut iterated_msgs: u32 = 0;
        for m in &mut it {
            iterated_msgs += 1;
            if iterated_msgs == 2 {
                assert_eq!(m.ecu, DltChar4::from_str("CAN2").ok().unwrap());
            }
        }
        assert_eq!(iterated_msgs, 2); // one ctrl and 1 can msgs
    }

    #[test]
    fn asc_multiple_files_no_busmapping() {
        let reader1 = r##"
0.000100 1 36f Rx d 5 f4 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879"##
            .as_bytes();
        let namespace = get_new_namespace();
        let mut it = Asc2DltMsgIterator::new(0, reader1, namespace, None, None);
        let mut iterated_msgs: u32 = 0;
        for m in &mut it {
            iterated_msgs += 1;
            if iterated_msgs == 1 {
                assert_eq!(m.ecu, DltChar4::from_str("CAN1").ok().unwrap());
            }
        }
        assert_eq!(iterated_msgs, 1);

        // 2nd CAN file should get a different ecu id even though the channel is the same but as we dont have a busmapping
        let reader2 = r##"
0.000101 1 36f Rx d 5 f4 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879"##
            .as_bytes();
        let mut it = Asc2DltMsgIterator::new(0, reader2, namespace, None, None);
        let mut iterated_msgs: u32 = 0;
        for m in &mut it {
            iterated_msgs += 1;
            if iterated_msgs == 1 {
                assert_eq!(m.ecu, DltChar4::from_str("CAN2").ok().unwrap());
            }
        }
        assert_eq!(iterated_msgs, 1);

        // 3rd CAN should get the a different ecu name as the id is different
        let reader2 = r##"
0.000102 42 36f Rx d 5 f4 f7 fe ff 14 Length = 0 BitCount = 0 ID = 879"##
            .as_bytes();
        let mut it = Asc2DltMsgIterator::new(0, reader2, namespace, None, None);
        let mut iterated_msgs: u32 = 0;
        for m in &mut it {
            iterated_msgs += 1;
            if iterated_msgs == 1 {
                assert_eq!(m.ecu, DltChar4::from_str("CAN3").ok().unwrap());
            }
        }
        assert_eq!(iterated_msgs, 1);
    }
}
