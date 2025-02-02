use crate::{
    dlt::{
        DltChar4, DltExtendedHeader, DltMessage, DltMessageIndexType, DltMessageLogType,
        DltStandardHeader, DLT_EXT_HEADER_SIZE, DLT_MIN_STD_HEADER_SIZE, DLT_STD_HDR_BIG_ENDIAN,
        DLT_STD_HDR_HAS_ECU_ID, DLT_STD_HDR_HAS_EXT_HDR, DLT_STD_HDR_HAS_TIMESTAMP,
        DLT_STD_HDR_VERSION, SERVICE_ID_GET_LOG_INFO,
    },
    utils::get_apid_for_tag,
};
use chrono::NaiveDateTime;
use regex::{CaptureLocations, Regex};
use slog::{error, Logger};
use std::{
    collections::{HashMap, VecDeque},
    io::{BufRead, Lines},
    str::FromStr,
};
/// a reader/parser for generic (text) log files to DLT msgs
///
/// Needed: an absolute timestamp, a log level, a tag and a log message
pub struct GenLog2DltMsgIterator<'a, R> {
    lines: Lines<R>,
    pub index: DltMessageIndexType,
    namespace: u32,
    pub log: Option<&'a Logger>,

    // todo move these is a config array and support multiple of them (might incl. ecu and ctid)
    line_regex: Regex,
    line_capture_locations: CaptureLocations,
    line_capture_idx_date_time: usize,
    line_capture_idx_level: usize,
    line_capture_idx_tag: usize, // used for apid generation
    line_capture_idx_msg: usize,

    ecu: DltChar4,
    ctid: DltChar4,
    htyp: u8, // std hdr htyp
    len_wo_payload: u16,

    pub lines_processed: usize,
    pub lines_skipped: usize,
    tag_apid_map: HashMap<String, DltChar4>,
    msgs_deque: VecDeque<DltMessage>,

    first_reception_time_us: Option<u64>,
}

impl<'a, R: BufRead> GenLog2DltMsgIterator<'a, R> {
    pub fn new(
        start_index: DltMessageIndexType,
        reader: R,
        namespace: u32,
        _timestamp_reference_time_us: Option<u64>,
        _file_modified_time_us: Option<u64>,
        log: Option<&'a slog::Logger>,
    ) -> GenLog2DltMsgIterator<'a, R> {
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
        let line_regex = Regex::new(
            r#"^\[(?<dateTime>2\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\] \[(?<level>.{3})] \[(?<tag>.*?)\] (?<msg>.*)$"#,
        )
        .unwrap();
        let line_capture_locations = line_regex.capture_locations();
        let line_capture_names = line_regex.capture_names();

        // determine position of timestamp, log level, log message
        let mut line_capture_idx_date_time: Option<usize> = None;
        let mut line_capture_idx_level: Option<usize> = None;
        let mut line_capture_idx_tag: Option<usize> = None;
        let mut line_capture_idx_msg: Option<usize> = None;
        for (cap_idx, cap_name) in line_capture_names.enumerate() {
            match cap_name {
                Some("dateTime") => line_capture_idx_date_time = Some(cap_idx),
                Some("msg") => line_capture_idx_msg = Some(cap_idx),
                Some("level") => line_capture_idx_level = Some(cap_idx),
                Some("tag") => line_capture_idx_tag = Some(cap_idx),
                _ => {}
            };
        }

        let line_capture_idx_date_time = line_capture_idx_date_time.unwrap(); // todo err handling
        let line_capture_idx_level = line_capture_idx_level.unwrap(); // todo err handling
        let line_capture_idx_tag = line_capture_idx_tag.unwrap(); // todo err handling
        let line_capture_idx_msg = line_capture_idx_msg.unwrap(); // todo err handling

        GenLog2DltMsgIterator {
            lines: reader.lines(),
            index: start_index,
            namespace,
            log,
            line_regex,
            line_capture_locations,
            line_capture_idx_date_time,
            line_capture_idx_level,
            line_capture_idx_tag,
            line_capture_idx_msg,
            htyp,
            len_wo_payload,
            ecu: DltChar4::from_str(format!("GL{:02}", namespace % 100).as_str()).unwrap(),
            ctid: DltChar4::from_buf(b"GenL"),
            lines_processed: 0,
            lines_skipped: 0,
            msgs_deque: VecDeque::with_capacity(4),
            tag_apid_map: HashMap::new(),
            first_reception_time_us: None,
        }
    }

    fn parse_log_level(&self, level_str: &str) -> DltMessageLogType {
        match level_str {
            "INF" => DltMessageLogType::Info,
            "WRN" => DltMessageLogType::Warn,
            "ERR" => DltMessageLogType::Error,
            "VER" => DltMessageLogType::Verbose,
            "FAT" | "SEV" => DltMessageLogType::Fatal,
            _ => DltMessageLogType::Debug,
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
            timestamp_dms: (timestamp_us / 100) as u32,
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

impl<R: BufRead> Iterator for GenLog2DltMsgIterator<'_, R> {
    type Item = DltMessage;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(msg) = self.msgs_deque.pop_front() {
            return Some(msg);
        }
        for line in self.lines.by_ref() {
            self.lines_processed += 1;
            match &line {
                Ok(line) => {
                    if let Some(captures) = self
                        .line_regex
                        .captures_read(&mut self.line_capture_locations, line)
                    {
                        let cap_str = captures.as_str();

                        // absolute date/time:
                        let loc_date_time = self
                            .line_capture_locations
                            .get(self.line_capture_idx_date_time)
                            .unwrap_or_default();
                        let date_time = &cap_str[loc_date_time.0..loc_date_time.1];
                        let date_time =
                            NaiveDateTime::parse_from_str(date_time, "%Y-%m-%d %H:%M:%S%.3f")
                                .unwrap_or_default();

                        // log level:
                        let loc_level = self
                            .line_capture_locations
                            .get(self.line_capture_idx_level)
                            .unwrap_or_default();
                        let log_level = self.parse_log_level(&cap_str[loc_level.0..loc_level.1]);

                        // tag -> APID:
                        let loc_tag = self
                            .line_capture_locations
                            .get(self.line_capture_idx_tag)
                            .unwrap_or_default();
                        let tag = &cap_str[loc_tag.0..loc_tag.1];
                        let (new_apid, apid) = self.get_apid(tag);

                        // log message:
                        let loc_msg = self
                            .line_capture_locations
                            .get(self.line_capture_idx_msg)
                            .unwrap_or_default();

                        let payload = vec![];
                        let mtin: u8 = log_level as u8;

                        let reception_time = date_time.and_utc().timestamp_micros();
                        let reception_time_us = if reception_time < 0 {
                            0
                        } else {
                            reception_time as u64
                        };
                        let timestamp_us =
                            if let Some(first_reception_time_us) = self.first_reception_time_us {
                                reception_time_us.saturating_sub(first_reception_time_us)
                            } else {
                                self.first_reception_time_us = Some(reception_time_us);
                                0
                            };

                        let apid_info_msg = if new_apid {
                            self.get_apid_info_msg(&apid, tag, reception_time_us, timestamp_us)
                        } else {
                            None
                        };

                        let index = self.index;
                        self.index += 1;

                        let msg = DltMessage {
                            index,
                            ecu: self.ecu.to_owned(),
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
                            payload_text: Some(cap_str[loc_msg.0..loc_msg.1].to_owned()),
                            lifecycle: 0,
                            reception_time_us,
                            timestamp_dms: (timestamp_us / 100) as u32,
                        };
                        return if apid_info_msg.is_some() {
                            // return a GET_LOG_INFO message for the new apid and put the log_msg in queue for next iteration
                            self.msgs_deque.push_back(msg);
                            apid_info_msg
                        } else {
                            Some(msg)
                        };
                    } else {
                        self.lines_skipped += 1;
                    }
                }
                Err(e) => {
                    if let Some(log) = self.log {
                        error!(
                            log,
                            "GenLog2DltMsgIterator.next got err {} at line #{}",
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
    use super::*;
    use crate::{
        dlt::DLT_MAX_STORAGE_MSG_SIZE,
        utils::{get_new_namespace, LowMarkBufReader},
    };
    use slog::{o, Drain, Logger};
    use std::fs::File;

    fn new_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, o!())
    }

    #[test]
    fn genlog_basic1() {
        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        test_dir.push("genlog_example1.log");
        let fi = File::open(&test_dir).unwrap();
        let start_index = 1000;
        let log = new_logger();
        let mut it = GenLog2DltMsgIterator::new(
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

            println!(
                "#{}: {} {} {} {} {} {}",
                m.index,
                m.reception_time(),
                m.timestamp_dms,
                m.ecu,
                m.apid().unwrap(),
                m.ctid().unwrap(),
                m.payload_as_text().unwrap()
            );
            iterated_msgs += 1;
        }
        assert_eq!(iterated_msgs, 57 + 9); // 9 APID infos
        assert_eq!(it.lines_processed, 59);
        assert_eq!(it.lines_skipped, 2);
    }
}
