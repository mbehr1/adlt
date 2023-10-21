use chrono::{NaiveDate, NaiveDateTime};
use lazy_static::lazy_static;
use regex::{CaptureLocations, Regex};
use slog::{debug, error, info};
/// todos
/// [] think about a better way to handle multiple files opened. currently they might be wrongly sorted as the timestamp is added as offset
///    we'd want the last log from a file to have the recorded time = calculated time
/// [] support other formats than monotonic timestamp and threadtime
use std::{
    borrow::Cow,
    collections::{HashMap, VecDeque},
    io::{BufRead, Lines},
    str::FromStr,
    sync::RwLock,
};

use crate::{
    dlt::{
        DltChar4, DltExtendedHeader, DltMessage, DltMessageIndexType, DltMessageLogType,
        DltStandardHeader, DLT_EXT_HEADER_SIZE, DLT_MIN_STD_HEADER_SIZE, DLT_STD_HDR_BIG_ENDIAN,
        DLT_STD_HDR_HAS_ECU_ID, DLT_STD_HDR_HAS_EXT_HDR, DLT_STD_HDR_HAS_TIMESTAMP,
        DLT_STD_HDR_VERSION, SERVICE_ID_GET_LOG_INFO,
    },
    utils::utc_time_from_us,
};

use super::US_PER_SEC;

pub struct LogCat2DltMsgIterator<'a, R> {
    lines: Lines<R>, // todo could optimize with e.g. stream_iterator for &str instead of string copies!
    pub index: DltMessageIndexType,
    namespace: u32,
    recorded_start_time_us: u64,
    pub lines_processed: usize,
    pub lines_skipped: usize,
    pub log: Option<&'a slog::Logger>,

    ref_date: NaiveDate, // reference date used to determine year from mm-dd
    max_threadtime_treat_as_timestamp: NaiveDateTime, // points to e.g. 1.1.2023 12:00:00
    max_threadtime_treat_as_timestamp_start: NaiveDateTime, // points to e.g. 1.1.2023 0:00:00
    threadtime_timestamp_reference: Option<u64>, // first time is used as reference for initial monotonic timestamp value
    threadtime_last_monotonic_timestamp: u64,

    capture_locations_monotonic: CaptureLocations,
    capture_locations_threadtime: CaptureLocations,
    htyp: u8, // std hdr htyp
    len_wo_payload: u16,
    tag_apid_map: HashMap<String, DltChar4>,
    ecu: DltChar4,
    ctid: DltChar4,
    msgs_deque: VecDeque<DltMessage>,
}

impl<'a, R: BufRead> LogCat2DltMsgIterator<'a, R> {
    pub fn new(
        start_index: DltMessageIndexType,
        reader: R,
        namespace: u32,
        _timestamp_reference_time_us: Option<u64>,
        file_modified_time_us: Option<u64>,
        log: Option<&'a slog::Logger>,
    ) -> LogCat2DltMsgIterator<'a, R> {
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
        if let Some(log) = log {
            info!(
                log,
                "LogCat2DltMsgIterator: file_modified_time_us {:?}",
                file_modified_time_us.map(utc_time_from_us)
            )
        }

        let recorded_start_time_us = file_modified_time_us
            .unwrap_or_else(|| (chrono::Utc::now().naive_utc().timestamp_micros()) as u64);

        let ref_date =
            NaiveDateTime::from_timestamp_opt(1 + (recorded_start_time_us / US_PER_SEC) as i64, 0)
                .unwrap_or_default()
                .date();

        let max_threadtime_treat_as_timestamp_start =
            NaiveDate::from_ymd_opt(chrono::Datelike::year(&ref_date), 1, 1).unwrap_or_default();

        LogCat2DltMsgIterator {
            lines: reader.lines(),
            index: start_index,
            namespace,
            recorded_start_time_us,
            lines_processed: 0,
            lines_skipped: 0,
            log,
            ref_date,
            threadtime_last_monotonic_timestamp: 10_000 * US_PER_SEC,
            max_threadtime_treat_as_timestamp_start: max_threadtime_treat_as_timestamp_start
                .and_hms_opt(0, 0, 0)
                .unwrap_or_default(),
            max_threadtime_treat_as_timestamp: max_threadtime_treat_as_timestamp_start
                .and_hms_opt(12, 0, 0)
                .unwrap_or_default(),
            threadtime_timestamp_reference: None,
            capture_locations_monotonic: RE_MONOTONIC.capture_locations(),
            capture_locations_threadtime: RE_THREADTIME.capture_locations(),
            htyp,
            len_wo_payload,
            tag_apid_map: HashMap::new(),
            ecu: DltChar4::from_str(format!("LC{:02}", namespace % 100).as_str()).unwrap(),
            ctid: DltChar4::from_str("LogC").unwrap(),
            msgs_deque: VecDeque::with_capacity(1),
        }
    }

    /// return an apid for the tag
    ///
    /// returns a pair of bool/DltChar4 where the bool indicates whether this tag created a new apid
    fn get_apid(&mut self, tag: &str) -> (bool, DltChar4) {
        let e = self.tag_apid_map.get(tag);
        match e {
            Some(e) => (false, e.to_owned()),
            None => {
                let apid = get_apid_for_tag(self.namespace, tag);
                self.tag_apid_map.insert(tag.to_owned(), apid.to_owned());
                (true, apid)
            }
        }
    }

    fn timestamp_dms_from(&self, timestamp_us: u64) -> u32 {
        (timestamp_us / 100) as u32
    }

    /// return a DLT control response msg GET_LOG_INFO with the apid and tag as description
    fn get_apid_info_msg(
        &mut self,
        apid: &DltChar4,
        tag: &str,
        reception_time_us: u64,
        timestamp_us: u64,
    ) -> Option<DltMessage> {
        if tag.is_empty() {
            return None;
        }

        let mut payload: Vec<u8> = SERVICE_ID_GET_LOG_INFO.to_ne_bytes().into();
        let apid_buf = apid.as_buf();
        payload.extend(
            [7u8]
                .into_iter()
                .chain(1u16.to_ne_bytes()) // 1 app id, CAN plugin expects == 1
                .chain(apid_buf.iter().copied())
                .chain(0u16.to_ne_bytes()) // 0 ctx ids
                .chain((tag.len() as u16).to_ne_bytes()) // len of apid desc
                .chain(tag.as_bytes().iter().copied()),
        );
        // return a DltMessage with the LOG INFO APID incl. the BusMapping name
        let index = self.index;
        self.index += 1;
        Some(DltMessage {
            index,
            reception_time_us,
            ecu: self.ecu.to_owned(),
            timestamp_dms: self.timestamp_dms_from(timestamp_us),
            standard_header: DltStandardHeader {
                htyp: self.htyp,
                mcnt: (index & 0xff) as u8,
                len: self.len_wo_payload + (payload.len() as u16),
            },
            extended_header: Some(DltExtendedHeader {
                verb_mstp_mtin: (3u8 << 1) | (2u8 << 4), // Control Resp., non verb
                noar: 2,
                apid: apid.to_owned(),
                ctid: self.ctid.to_owned(),
            }),
            payload,
            payload_text: None,
            lifecycle: 0,
        })
    }
}

fn get_4digit_str(a_str: &str, iteration: u16) -> Cow<'_, str> {
    match iteration {
        0 => Cow::from(a_str),
        _ => {
            let len_str = a_str.len();
            let number_str = iteration.to_string();
            let len_number = number_str.len();
            let needed_str = if len_number > 3 { 0 } else { 4 - len_number };
            if needed_str > len_str {
                Cow::Owned(format!("{}{:0len$}", a_str, iteration, len = 4 - len_str))
            } else {
                Cow::Owned(format!("{}{}", &a_str[0..needed_str], iteration))
            }
        }
    }
}

fn get_apid_for_tag(namespace: u32, tag: &str) -> DltChar4 {
    let mut namespace_map = GLOBAL_TAG_APID_MAP.write().unwrap();
    let map = namespace_map.entry(namespace).or_default();
    match map.get(tag) {
        Some(e) => e.to_owned(),
        None => {
            let trimmed_tag = tag.trim();
            // try to find a good apid as tag abbrevation
            //
            let mut iteration = 0u16;
            loop {
                let apid = match trimmed_tag.len() {
                    0 => DltChar4::from_str(" ").unwrap(),
                    1..=4 => DltChar4::from_str(&get_4digit_str(trimmed_tag, iteration))
                        .unwrap_or(DltChar4::from_str(&get_4digit_str("NoAs", iteration)).unwrap()),
                    _ => {
                        let has_underscores = trimmed_tag.contains('_');
                        if has_underscores {
                            // assume snake case
                            let nr_underscore = trimmed_tag.chars().fold(0u32, |acc, c| {
                                if c == '_' {
                                    acc + 1
                                } else {
                                    acc
                                }
                            });
                            let mut needed_other = if nr_underscore < 3 {
                                3 - nr_underscore
                            } else {
                                0
                            };
                            let mut abbrev = String::with_capacity(4);
                            let mut take_next = true;
                            for c in trimmed_tag.chars() {
                                if c == '_' {
                                    take_next = true;
                                } else if c.is_ascii() {
                                    if take_next || needed_other > 0 {
                                        abbrev.push(c);
                                        if !take_next {
                                            needed_other -= 1;
                                        }
                                    }
                                    take_next = false;
                                }
                                if abbrev.len() >= 4 {
                                    break;
                                }
                            }

                            DltChar4::from_str(&get_4digit_str(&abbrev, iteration))
                        } else {
                            // assume camel case
                            let nr_capital = trimmed_tag.chars().fold(0u32, |acc, c| {
                                if c.is_ascii_uppercase() {
                                    acc + 1
                                } else {
                                    acc
                                }
                            });
                            let mut needed_lowercase =
                                if nr_capital < 4 { 4 - nr_capital } else { 0 };
                            let mut abbrev = String::with_capacity(4);
                            for c in trimmed_tag.chars() {
                                if c.is_ascii_uppercase() {
                                    abbrev.push(c);
                                } else if needed_lowercase > 0 && c.is_ascii() {
                                    abbrev.push(c);
                                    needed_lowercase -= 1;
                                }
                                if abbrev.len() >= 4 {
                                    break;
                                }
                            }

                            DltChar4::from_str(&get_4digit_str(&abbrev, iteration))
                        }
                    }
                    .unwrap_or(DltChar4::from_str(&get_4digit_str("NoAs", iteration)).unwrap()),
                };

                // does apid exist already?
                if let Some((_k, _v)) = map.iter().find(|(_k, v)| v == &&apid) {
                    /* println!(
                        "get_apid_for_tag iteration {} apid {} for tag {} exists already for tag {}",
                        iteration, apid, tag, k
                    ); */
                    iteration += 1;
                } else {
                    map.insert(tag.to_owned(), apid.to_owned());
                    return apid;
                }
            } // todo abort after >100 iterations with a default?
        }
    }
}

/// Parse a timestamp in logcat monotonic format to a time in us.
///
/// Expected format is x.y (x any number, y any number but expected 3 digits)
///
/// In case of any parsing errors 0 is returned.
/// ### Note
/// The function is slow if the the fraction is not 3 digits!
fn parse_time_str(timestamp: &str) -> u64 {
    let dot_idx = timestamp.find('.').unwrap_or(timestamp.len());

    let timestamp_secs_us: u64 =
        timestamp[0..dot_idx].parse::<u64>().unwrap_or_default() * US_PER_SEC;

    let timestamp_fraction_us = if dot_idx < timestamp.len() {
        let timestamp_fraction_str = &timestamp[dot_idx + 1..];
        let mut len_fraction = timestamp_fraction_str.len();
        let mut timestamp_fraction_us = timestamp_fraction_str.parse::<u64>().unwrap_or_default();
        if len_fraction == 3 {
            // expected len
            timestamp_fraction_us *= 1000;
        } else if len_fraction != 6 {
            while len_fraction < 6 {
                timestamp_fraction_us *= 10;
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
    timestamp_secs_us + timestamp_fraction_us
}

/// parse a mmdd string into a NaiveDate:
///
/// mmdd: string in format mm-dd
///
/// As the year is not specified the following logic is used
/// Year from refDate except if the date is later than the refDate. Then the prev year is used.
/// 29th of Feb might be an exception (if current or prev year) is not valid...
///
fn parse_mmdd_str(mmdd: &str, ref_date: &NaiveDate) -> Option<NaiveDate> {
    if mmdd.len() != 5 {
        return None;
    }
    let mm: u32 = mmdd[0..2].parse::<u32>().unwrap_or_default();
    let dd: u32 = mmdd[3..].parse::<u32>().unwrap_or_default();
    if (1..=12).contains(&mm) && (1..=31).contains(&dd) {
        let year = chrono::Datelike::year(ref_date);
        let nd = NaiveDate::from_ymd_opt(year, mm, dd);
        if let Some(nd) = nd {
            if nd > *ref_date {
                let nd_prev =
                    NaiveDate::from_ymd_opt(if year > 1970 { year - 1 } else { year }, mm, dd);
                if nd_prev.is_some() {
                    return nd_prev;
                }
            }
        } else {
            // the date with cur year is not valid. try with prev year
            let nd_prev =
                NaiveDate::from_ymd_opt(if year > 1970 { year - 1 } else { year }, mm, dd);
            return nd_prev;
        }
        nd // this should fit to the 29.2. and nd>ref_date case
    } else {
        None
    }
}

/// parse a string in logcat threadtime format:
/// mm-dd hh:mm:ss.mss
fn parse_threadtime_str(timestamp: &str, ref_date: &NaiveDate) -> Option<NaiveDateTime> {
    if timestamp.len() != 18 {
        None
    } else {
        let date = parse_mmdd_str(&timestamp[0..5], ref_date).unwrap_or(*ref_date);
        let hour: u32 = timestamp[6..8].parse::<u32>().unwrap_or_default();
        let min: u32 = timestamp[9..11].parse::<u32>().unwrap_or_default();
        let sec: u32 = timestamp[12..14].parse::<u32>().unwrap_or_default();
        let milli: u32 = timestamp[15..18].parse::<u32>().unwrap_or_default();
        date.and_hms_milli_opt(hour, min, sec, milli)
    }
}

fn parse_log_level(level_str: &str) -> DltMessageLogType {
    match &level_str.as_bytes()[0] {
        b'I' => DltMessageLogType::Info,
        b'W' => DltMessageLogType::Warn,
        b'E' => DltMessageLogType::Error,
        b'V' => DltMessageLogType::Verbose,
        b'F' | b'S' => DltMessageLogType::Fatal,
        _ => DltMessageLogType::Debug,
    }
}

lazy_static! {
    pub(crate) static ref RE_MONOTONIC: Regex =
        Regex::new(r"^\s*(\d+\.\d+)\s+(\d+)\s+(\d+) ([A-Za-z]) (.*?)\s*: (.*)$").unwrap();
        // captures: monotonic_timestamp pid tid level tag msg
    pub(crate) static ref RE_THREADTIME: Regex =
        Regex::new(r"^(\d\d\-\d\d \d\d:\d\d:\d\d\.\d+)\s+(\d+)\s+(\d+) ([A-Za-z]) (.*?)\s*: (.*)$").unwrap();
        // captures: threadtime pid tid level tag msg

    // map by namespace to a map for tag to apid:
    static ref GLOBAL_TAG_APID_MAP: RwLock<HashMap<u32, HashMap<String, DltChar4>>> = RwLock::new(HashMap::new());
}

impl<'a, R> Iterator for LogCat2DltMsgIterator<'a, R>
where
    R: BufRead,
{
    type Item = DltMessage;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(msg) = self.msgs_deque.pop_front() {
            return Some(msg);
        }

        for line in self.lines.by_ref() {
            self.lines_processed += 1;
            match &line {
                Ok(line) => {
                    if let Some(captures) =
                        RE_MONOTONIC.captures_read(&mut self.capture_locations_monotonic, line)
                    {
                        let cap_str = captures.as_str();
                        let loc_timestamp = self.capture_locations_monotonic.get(1).unwrap();
                        let timestamp_us =
                            parse_time_str(&cap_str[loc_timestamp.0..loc_timestamp.1]);

                        let loc_level = self.capture_locations_monotonic.get(4).unwrap();
                        let log_level = parse_log_level(&cap_str[loc_level.0..loc_level.1]);

                        // let loc_pid = self.capture_locations_monotonic.get(2).unwrap();

                        let loc_tag = self.capture_locations_monotonic.get(5).unwrap();
                        let tag = &cap_str[loc_tag.0..loc_tag.1];

                        let (new_apid, apid) = self.get_apid(tag);

                        let apid_info_msg = if new_apid {
                            self.get_apid_info_msg(
                                &apid,
                                tag,
                                self.recorded_start_time_us + timestamp_us,
                                timestamp_us,
                            )
                        } else {
                            None
                        };

                        let index = self.index;
                        self.index += 1;
                        let payload = vec![];

                        let mtin: u8 = log_level as u8;
                        let log_msg = DltMessage {
                            index,
                            reception_time_us: self.recorded_start_time_us + timestamp_us, // should be from last... (but we'd need to scan all)
                            ecu: self.ecu.to_owned(),
                            timestamp_dms: self.timestamp_dms_from(timestamp_us),
                            standard_header: DltStandardHeader {
                                htyp: self.htyp,
                                mcnt: (index & 0xff) as u8,
                                len: self.len_wo_payload + (payload.len() as u16),
                            },
                            extended_header: Some(DltExtendedHeader {
                                verb_mstp_mtin: (1u8 << 0) /* | (0u8 << 1)*/ | (mtin << 4), // verb, log,
                                noar: 0,
                                apid,
                                ctid: self.ctid.to_owned(),
                            }),
                            payload,
                            payload_text: Some(cap_str[loc_timestamp.1 + 1..].to_owned()),
                            lifecycle: 0,
                        };

                        return if apid_info_msg.is_some() {
                            // return a GET_LOG_INFO message for the new apid and put the log_msg in queue for next iteration
                            self.msgs_deque.push_back(log_msg);
                            apid_info_msg
                        } else {
                            Some(log_msg)
                        };
                    } else if let Some(captures) =
                        RE_THREADTIME.captures_read(&mut self.capture_locations_threadtime, line)
                    {
                        let cap_str = captures.as_str();
                        let loc_timestamp = self.capture_locations_threadtime.get(1).unwrap();
                        let threadtime = parse_threadtime_str(
                            &cap_str[loc_timestamp.0..loc_timestamp.1],
                            &self.ref_date,
                        );

                        if let Some(threadtime) = threadtime {
                            // we determine the monotonic_timestamp by two ways:
                            // a) if the threadtime was < 1.1. 12:00:00 (so assuming 1.1.70, not true at start of each year!)
                            //    we do use as monotonic timestamp the time since 1.1.1970
                            // b) otherwise we do use for the first message 10_000s and use the distance from first message to cur message as timestamp
                            let (timestamp_us, reception_time_us) = if threadtime
                                < self.max_threadtime_treat_as_timestamp
                            {
                                // case a
                                // as reception time we use the recorded_start_time_us +timestamp
                                let timestamp_us = threadtime
                                    .signed_duration_since(
                                        self.max_threadtime_treat_as_timestamp_start,
                                    )
                                    .num_microseconds()
                                    .unwrap_or_default()
                                    as u64;
                                self.threadtime_last_monotonic_timestamp = timestamp_us;
                                (timestamp_us, self.recorded_start_time_us + timestamp_us)
                            } else {
                                // here we'd need to use the max timestamp_us from the case a) as first timestamp
                                let recorded_time_us = threadtime.timestamp_micros() as u64;
                                let timestamp_us = if let Some(timestamp_reference) =
                                    self.threadtime_timestamp_reference
                                {
                                    recorded_time_us.saturating_sub(timestamp_reference)
                                } else {
                                    let timestamp_reference =
                                        recorded_time_us - self.threadtime_last_monotonic_timestamp;
                                    self.threadtime_timestamp_reference = Some(timestamp_reference);
                                    self.threadtime_last_monotonic_timestamp
                                };

                                (timestamp_us, recorded_time_us)
                            };

                            let loc_level = self.capture_locations_threadtime.get(4).unwrap();
                            let log_level = parse_log_level(&cap_str[loc_level.0..loc_level.1]);

                            // let loc_pid = self.capture_locations_monotonic.get(2).unwrap();

                            let loc_tag = self.capture_locations_threadtime.get(5).unwrap();
                            let tag = &cap_str[loc_tag.0..loc_tag.1];

                            let (new_apid, apid) = self.get_apid(tag);

                            let apid_info_msg = if new_apid {
                                self.get_apid_info_msg(&apid, tag, reception_time_us, timestamp_us)
                            } else {
                                None
                            };

                            let index = self.index;
                            self.index += 1;
                            let payload = vec![];

                            let mtin: u8 = log_level as u8;
                            let log_msg = DltMessage {
                                index,
                                reception_time_us,
                                ecu: self.ecu.to_owned(),
                                timestamp_dms: self.timestamp_dms_from(timestamp_us),
                                standard_header: DltStandardHeader {
                                    htyp: self.htyp,
                                    mcnt: (index & 0xff) as u8,
                                    len: self.len_wo_payload + (payload.len() as u16),
                                },
                                extended_header: Some(DltExtendedHeader {
                                    verb_mstp_mtin: (1u8 << 0) /* | (0u8 << 1)*/ | (mtin << 4), // verb, log,
                                    noar: 0,
                                    apid,
                                    ctid: self.ctid.to_owned(),
                                }),
                                payload,
                                payload_text: Some(cap_str[loc_timestamp.1 + 1..].to_owned()),
                                lifecycle: 0,
                            };

                            return if apid_info_msg.is_some() {
                                // return a GET_LOG_INFO message for the new apid and put the log_msg in queue for next iteration
                                self.msgs_deque.push_back(log_msg);
                                apid_info_msg
                            } else {
                                Some(log_msg)
                            };
                        } else {
                            self.lines_skipped += 1;
                            if let Some(log) = self.log {
                                debug!(
                                log,
                                "LogCat2DltMsgIterator.next ignored line {} at line #{} due to wrong threadtime",
                                line,
                                self.lines_processed
                            );
                            }
                        }
                    } else if !line.is_empty() {
                        self.lines_skipped += 1;
                        if let Some(log) = self.log {
                            debug!(
                                log,
                                "LogCat2DltMsgIterator.next unknown line '{}' at line #{}",
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
                            "LogCat2DltMsgIterator.next got err {} at line #{}",
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
    use std::fs::File;

    use slog::{o, Drain, Logger};

    use crate::{
        dlt::{
            DltChar4, DltMessageControlType, DltMessageLogType, DltMessageType,
            DLT_MAX_STORAGE_MSG_SIZE,
        },
        utils::{get_new_namespace, LogCat2DltMsgIterator, LowMarkBufReader, US_PER_SEC},
    };

    use super::{
        get_4digit_str, get_apid_for_tag, parse_mmdd_str, parse_threadtime_str, parse_time_str,
    };

    const MS_PER_SEC: u64 = 1000;

    #[test]
    fn parse_time_str_1() {
        assert_eq!(parse_time_str("19.002"), 19 * US_PER_SEC + 2 * MS_PER_SEC);
        assert_eq!(parse_time_str("0.999"), 999 * MS_PER_SEC);
    }

    #[test]
    fn parse_mmdd_str_1() {
        let ref_date = &chrono::NaiveDate::default();
        assert_eq!(parse_mmdd_str("", ref_date), None);
        assert_eq!(parse_mmdd_str("00-01", ref_date), None);
        assert_eq!(parse_mmdd_str("ab-cd", ref_date), None);
        assert_eq!(parse_mmdd_str("01-01", ref_date), Some(*ref_date));
    }

    #[test]
    fn parse_threadtime_str_1() {
        let ref_date = &chrono::NaiveDate::from_ymd_opt(2023, 2, 1).unwrap(); // &chrono::NaiveDate::default();
        assert_eq!(
            parse_threadtime_str("01-01 00:00:16.626", ref_date),
            chrono::NaiveDate::from_ymd_opt(2023, 1, 1)
                .unwrap()
                .and_hms_milli_opt(0, 0, 16, 626)
        );
        assert_eq!(
            parse_threadtime_str("12-31 00:00:07.007", ref_date),
            chrono::NaiveDate::from_ymd_opt(2022, 12, 31) // > ref_date so prev year
                .unwrap()
                .and_hms_milli_opt(0, 0, 7, 7)
        );

        let ref_date = &chrono::NaiveDate::from_ymd_opt(2021, 2, 1).unwrap(); // &chrono::NaiveDate::default();
        assert_eq!(
            parse_threadtime_str("02-29 23:59:57.999", ref_date),
            chrono::NaiveDate::from_ymd_opt(2020, 2, 29) // > ref_date so prev year but 29.2. and valid in 2020
                .unwrap()
                .and_hms_milli_opt(23, 59, 57, 999)
        );
        let ref_date = &chrono::NaiveDate::from_ymd_opt(2020, 2, 1).unwrap(); // &chrono::NaiveDate::default();
        assert_eq!(
            parse_threadtime_str("02-29 23:59:57.999", ref_date),
            chrono::NaiveDate::from_ymd_opt(2020, 2, 29) // > ref_date so prev year but 29.2. not valid in 2019 -> stays at 2020
                .unwrap()
                .and_hms_milli_opt(23, 59, 57, 999)
        );
        let ref_date = &chrono::NaiveDate::from_ymd_opt(2023, 2, 1).unwrap(); // &chrono::NaiveDate::default();
        assert_eq!(
            parse_threadtime_str("02-29 23:59:57.999", ref_date),
            ref_date.and_hms_milli_opt(23, 59, 57, 999) // > ref_date so prev year but 29.2. not valid in 2022, nor in 2023 -> ref_date
        );
    }

    #[test]
    fn get_4digit_str_1() {
        assert_eq!(get_4digit_str("", 0), "");
        assert_eq!(get_4digit_str("", 1), "0001");
        assert_eq!(get_4digit_str("a", 0), "a");
        assert_eq!(get_4digit_str("a", 1), "a001");
        assert_eq!(get_4digit_str("a", 99), "a099");
        assert_eq!(get_4digit_str("a", 1000), "1000");
        assert_eq!(get_4digit_str("abc", 9), "abc9");
        assert_eq!(get_4digit_str("abc", 99), "ab99");
        assert_eq!(get_4digit_str("abcd", 0), "abcd");
        assert_eq!(get_4digit_str("abcd", 1), "abc1");
        assert_eq!(get_4digit_str("abcd", 9), "abc9");
        assert_eq!(get_4digit_str("abcd", 10), "ab10");
        assert_eq!(get_4digit_str("abcd", 99), "ab99");
        assert_eq!(get_4digit_str("abcd", 100), "a100");
        assert_eq!(get_4digit_str("abcd", 999), "a999");
        assert_eq!(get_4digit_str("abcd", 1000), "1000");
    }

    #[test]
    fn get_apid_for_tag_1() {
        assert_eq!(
            get_apid_for_tag(0, "snake_case"),
            DltChar4::from_buf(b"snac")
        );
        assert_eq!(
            get_apid_for_tag(0, "snake_case2"),
            DltChar4::from_buf(b"sna1") // snac -> exists -> add numbers...
        );
        assert_eq!(
            get_apid_for_tag(1, "snake_case3"),
            DltChar4::from_buf(b"snac") // different namespace
        );

        assert_eq!(
            get_apid_for_tag(0, "CamelBaseAllGood"),
            DltChar4::from_buf(b"CBAG")
        );
        assert_eq!(
            get_apid_for_tag(0, "CamelBaseAll"),
            DltChar4::from_buf(b"CaBA")
        );
    }

    fn new_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, o!())
    }

    #[test]
    fn logcat_basic1() {
        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        test_dir.push("logcat_example1.txt");
        let fi = File::open(&test_dir).unwrap();
        let start_index = 1000;
        let log = new_logger();
        let mut it = LogCat2DltMsgIterator::new(
            start_index,
            LowMarkBufReader::new(fi, 512 * 1024, DLT_MAX_STORAGE_MSG_SIZE),
            get_new_namespace(),
            None,
            Some(1_000_000_000),
            Some(&log),
        );
        let mut iterated_msgs = 0;
        for m in &mut it {
            assert_eq!(m.index, start_index + iterated_msgs);
            assert_eq!(m.mcnt(), (m.index & 0xff) as u8);
            match m.index {
                1000 => assert_eq!(
                    m.mstp(),
                    DltMessageType::Control(DltMessageControlType::Response)
                ),
                1001 => assert_eq!(
                    m.mstp(),
                    DltMessageType::Log(DltMessageLogType::Info),
                    "m.index={}",
                    m.index
                ),
                _ => {}
            }
            iterated_msgs += 1;
            if m.index == start_index + 1 {
                // check some static data from example:
                assert_eq!(m.timestamp_dms, 180620);
                assert_eq!(m.noar(), 0);
            }
        }
        assert_eq!(iterated_msgs, 398);
    }

    #[test]
    fn logcat_timestamps() {
        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        test_dir.push("logcat_example2.txt");
        let fi = File::open(&test_dir).unwrap();
        let start_index = 0;
        let log = new_logger();
        let mut it = LogCat2DltMsgIterator::new(
            start_index,
            LowMarkBufReader::new(fi, 512 * 1024, DLT_MAX_STORAGE_MSG_SIZE),
            get_new_namespace(),
            None,
            Some(1_000_000_000_000_000),
            Some(&log),
        );
        let mut iterated_msgs = 0;
        for m in &mut it {
            assert_eq!(m.index, start_index + iterated_msgs);
            assert_eq!(m.mcnt(), (m.index & 0xff) as u8);
            iterated_msgs += 1;
            match m.index {
                1 => {
                    assert_eq!(m.timestamp_dms, 201300); // timestamps as in file

                    // recorded time is currently the file_modified_time_us (timestamp) + timestamp_us!
                    assert_eq!(m.reception_time_us, 1_000_000_000_000_000 + 20130000);
                }
                2 => {
                    assert_eq!(m.timestamp_dms, 49170);
                    // this is weird as the recorded time is now smaller than before even though the line was
                    // later in the log!
                    assert_eq!(m.reception_time_us, 1_000_000_000_000_000 + 4917000);
                }
                _ => {}
            }
        }
        assert_eq!(iterated_msgs, 3); // 2 + 1 apid log info
    }

    const FILE_MODIFIED_TIME: u64 = 1_000 * 137487600000; // some time in 1974

    #[test]
    fn logcat_threadtime_1() {
        // example for parsing threadtime format
        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        test_dir.push("logcat_example3.txt");
        let fi = File::open(&test_dir).unwrap();
        let start_index = 1000;
        let log = new_logger();
        let mut it = LogCat2DltMsgIterator::new(
            start_index,
            LowMarkBufReader::new(fi, 512 * 1024, DLT_MAX_STORAGE_MSG_SIZE),
            get_new_namespace(),
            None,
            Some(FILE_MODIFIED_TIME),
            Some(&log),
        );
        let mut iterated_msgs = 0;
        for m in &mut it {
            assert_eq!(m.index, start_index + iterated_msgs);
            assert_eq!(m.mcnt(), (m.index & 0xff) as u8);
            match m.index {
                1000 => assert_eq!(
                    m.mstp(),
                    DltMessageType::Control(DltMessageControlType::Response)
                ),
                1001 => assert_eq!(
                    m.mstp(),
                    DltMessageType::Log(DltMessageLogType::Warn),
                    "m.index={}",
                    m.index
                ),
                _ => {}
            }
            iterated_msgs += 1;
            if m.index == start_index + 1 {
                // check some static data from example:
                assert_eq!(m.timestamp_dms, 166260); // special case for 1.1.70 -> we use the time as timestamp as well
                assert_eq!(m.noar(), 0);
            } else if m.index == start_index + 8 + 5 {
                // last msg has non 1.1.1970 timestamp
                assert_eq!(m.timestamp_dms, 165750); // should have the prev. msg timestamp in that case

                // todo the reception timestamp of the prev msgs should be adjusted as well
                // this is only possible with checking upfront whether this case (jump to abs recorded time)
                // does exist...
                // to avoid:
                // 12 2023/09/02 16:09:54.578404     165750 012 LC00 chat LogC log info V 0 [    0     0 I chatty  : uid=0(root) logd identical 3 lines]
                // 13 2023/01/02 01:04:05.123000     165750 013 LC00 chat LogC log info V 0 [    0     0 I chatty  : now a jump to non 1.1.1970 timestamps]
            }
        }
        assert_eq!(iterated_msgs, 9 + 5 /*for the apid infos */);
    }

    #[test]
    fn logcat_threadtime_2() {
        // example for parsing threadtime format with timestamps that should be detected as non 1.1.1970
        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        test_dir.push("logcat_example4.txt");
        let fi = File::open(&test_dir).unwrap();
        let start_index = 1000;
        let log = new_logger();
        let mut it = LogCat2DltMsgIterator::new(
            start_index,
            LowMarkBufReader::new(fi, 512 * 1024, DLT_MAX_STORAGE_MSG_SIZE),
            get_new_namespace(),
            None,
            Some(FILE_MODIFIED_TIME),
            Some(&log),
        );
        let mut iterated_msgs = 0;
        for m in &mut it {
            assert_eq!(m.index, start_index + iterated_msgs);
            assert_eq!(m.mcnt(), (m.index & 0xff) as u8);
            match m.index {
                1000 => assert_eq!(
                    m.mstp(),
                    DltMessageType::Control(DltMessageControlType::Response)
                ),
                1001 => assert_eq!(
                    m.mstp(),
                    DltMessageType::Log(DltMessageLogType::Warn),
                    "m.index={}",
                    m.index
                ),
                _ => {}
            }
            iterated_msgs += 1;
            if m.index == start_index + 1 {
                // check some static data from example:
                assert_eq!(m.timestamp_dms, 10_000 * 10000); // first timestamp as 10'000secs
                assert_eq!(m.noar(), 0);
            } else if m.index == start_index + 2 {
                assert_eq!(m.timestamp_dms, (10_000 * 10000) + 10); // next relative +1ms
            }
        }
        assert_eq!(iterated_msgs, 8 + 5 /*for the apid infos */);
    }
}
