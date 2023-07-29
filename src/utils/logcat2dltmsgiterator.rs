use lazy_static::lazy_static;
use regex::{CaptureLocations, Regex};
use slog::{debug, error, warn};
/// todos
/// [] insert apid descriptions with full tag
/// [] think about a better way to handle multiple files opened. currently they might be wrongly sorted as the timestamp is added as offset
///    we'd want the last log from a file to have the recorded time = calculated time
/// [] support other formats than monotonic timestamp
use std::{
    borrow::Cow,
    collections::HashMap,
    io::{BufRead, Lines},
    str::FromStr,
    sync::RwLock,
};

use crate::{
    dlt::{
        DltChar4, DltExtendedHeader, DltMessage, DltMessageIndexType, DltMessageLogType,
        DltStandardHeader, DLT_EXT_HEADER_SIZE, DLT_MIN_STD_HEADER_SIZE, DLT_STD_HDR_BIG_ENDIAN,
        DLT_STD_HDR_HAS_ECU_ID, DLT_STD_HDR_HAS_EXT_HDR, DLT_STD_HDR_HAS_TIMESTAMP,
        DLT_STD_HDR_VERSION,
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

    capture_locations_monotonic: CaptureLocations,
    htyp: u8, // std hdr htyp
    len_wo_payload: u16,
    tag_apid_map: HashMap<String, DltChar4>,
    ecu: DltChar4,
    ctid: DltChar4,
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
        println!(
            "LogCat2DltMsgIterator: file_modified_time_us {:?}",
            file_modified_time_us.map(utc_time_from_us)
        );
        if let Some(log) = log {
            warn!(
                log,
                "LogCat2DltMsgIterator: file_modified_time_us {:?}",
                file_modified_time_us.map(utc_time_from_us)
            )
        }

        LogCat2DltMsgIterator {
            lines: reader.lines(),
            index: start_index,
            namespace,
            recorded_start_time_us: file_modified_time_us
                .unwrap_or_else(|| (chrono::Utc::now().naive_utc().timestamp_micros()) as u64),
            lines_processed: 0,
            lines_skipped: 0,
            log,
            capture_locations_monotonic: RE_MONOTONIC.capture_locations(),
            htyp,
            len_wo_payload,
            tag_apid_map: HashMap::new(),
            ecu: DltChar4::from_str(format!("LC{:02}", namespace % 100).as_str()).unwrap(),
            ctid: DltChar4::from_str("LogC").unwrap(),
        }
    }

    fn get_apid(&mut self, tag: &str) -> DltChar4 {
        let e = self.tag_apid_map.get(tag);
        match e {
            Some(e) => e.to_owned(),
            None => {
                let apid = get_apid_for_tag(self.namespace, tag);
                self.tag_apid_map.insert(tag.to_owned(), apid.to_owned());
                apid
            }
        }
    }

    fn timestamp_dms_from(&self, timestamp_us: u64) -> u32 {
        (timestamp_us / 100) as u32
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
    let map = namespace_map.entry(namespace).or_insert_with(HashMap::new);
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
                    1 | 2 | 3 | 4 => DltChar4::from_str(&get_4digit_str(trimmed_tag, iteration))
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

lazy_static! {
    pub(crate) static ref RE_MONOTONIC: Regex =
        Regex::new(r"^\s*(\d+\.\d+)\s+(\d+)\s+(\d+) ([A-Za-z]) (.*?)\s*: (.*)$").unwrap();
        // captures: monotonic_timestamp pid tid level tag msg

    // map by namespace to a map for tag to apid:
    static ref GLOBAL_TAG_APID_MAP: RwLock<HashMap<u32, HashMap<String, DltChar4>>> = RwLock::new(HashMap::new());

}

impl<'a, R> Iterator for LogCat2DltMsgIterator<'a, R>
where
    R: BufRead,
{
    type Item = DltMessage;
    fn next(&mut self) -> Option<Self::Item> {
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
                        let log_level = match &cap_str[loc_level.0..loc_level.1].as_bytes()[0] {
                            b'I' => DltMessageLogType::Info,
                            b'W' => DltMessageLogType::Warn,
                            b'E' => DltMessageLogType::Error,
                            b'V' => DltMessageLogType::Verbose,
                            b'F' | b'S' => DltMessageLogType::Fatal,
                            _ => DltMessageLogType::Debug,
                        };

                        // let loc_pid = self.capture_locations_monotonic.get(2).unwrap();

                        let loc_tag = self.capture_locations_monotonic.get(5).unwrap();
                        let tag = &cap_str[loc_tag.0..loc_tag.1];

                        let index = self.index;
                        self.index += 1;
                        let payload = vec![];

                        let apid = self.get_apid(tag);
                        let mtin: u8 = log_level as u8;
                        return Some(DltMessage {
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
                        });
                    } else if !line.is_empty() {
                        self.lines_skipped += 1;
                        if let Some(log) = self.log {
                            debug!(
                                log,
                                "LogCat2DltMsgIterator.next unknown line {} at line #{}",
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
    use crate::{dlt::DltChar4, utils::US_PER_SEC};

    use super::{get_4digit_str, get_apid_for_tag, parse_time_str};

    const MS_PER_SEC: u64 = 1000;

    #[test]
    fn parse_time_str_1() {
        assert_eq!(parse_time_str("19.002"), 19 * US_PER_SEC + 2 * MS_PER_SEC);
        assert_eq!(parse_time_str("0.999"), 999 * MS_PER_SEC);
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
}
