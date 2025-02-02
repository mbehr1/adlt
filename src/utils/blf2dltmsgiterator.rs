use std::{
    collections::{HashMap, VecDeque},
    io::{BufRead, Seek},
    str::FromStr,
};

use crate::{
    dlt::{
        DltChar4, DltExtendedHeader, DltMessage, DltMessageIndexType, DltStandardHeader,
        DLT_EXT_HEADER_SIZE, DLT_MIN_STD_HEADER_SIZE, DLT_STD_HDR_BIG_ENDIAN,
        DLT_STD_HDR_HAS_ECU_ID, DLT_STD_HDR_HAS_EXT_HDR, DLT_STD_HDR_HAS_TIMESTAMP,
        DLT_STD_HDR_VERSION, SERVICE_ID_GET_LOG_INFO,
    },
    dlt_args,
};
use ablf::{BlfFile, BlfFileStats, Object, ObjectIterator, ObjectTypes};
use quick_xml::{events::Event, Reader};
use serde_json::json;

use super::asc2dltmsgiterator::get_ecuid_for_namespace;

pub struct BLF2DltMsgIterator<'a, R: BufRead + Seek> {
    blf_iter: ObjectIterator<R>,
    namespace: u32,
    log: Option<&'a slog::Logger>,

    measurement_start_us: u64,
    index: DltMessageIndexType,
    msgs_deque: VecDeque<DltMessage>,
    can_id_ecu_map: HashMap<u16, DltChar4>,
}

const LEN_WO_PAYLOAD: u16 = (DLT_MIN_STD_HEADER_SIZE + 4 + 4 + DLT_EXT_HEADER_SIZE) as u16;
const HTYP: u8 = DLT_STD_HDR_VERSION
    | DLT_STD_HDR_HAS_ECU_ID
    | DLT_STD_HDR_HAS_TIMESTAMP
    | DLT_STD_HDR_HAS_EXT_HDR
    | if 1u32.to_be() == 1u32 {
        DLT_STD_HDR_BIG_ENDIAN
    } else {
        0u8
    };

impl<'a, R: BufRead + Seek> BLF2DltMsgIterator<'a, R> {
    pub fn new(
        start_index: DltMessageIndexType,
        reader: R,
        namespace: u32,
        timestamp_reference_time_us: Option<u64>,
        log: Option<&'a slog::Logger>,
    ) -> BLF2DltMsgIterator<'a, R> {
        let blf = match BlfFile::from_reader(reader) {
            Ok(blf) => blf,
            Err((e, reader)) => {
                if let Some(log) = log {
                    slog::warn!(log, "error parsing blf"; "error" => format!("{:?}", e));
                }
                BlfFile {
                    reader,
                    file_stats: BlfFileStats::default(),
                }
            }
        };

        // log api_version, application_id, application-version

        // parse file_stats:
        let stats = &blf.file_stats;
        let measurement_start_us = if let Some(date_time) = stats.measurement_start_time() {
            date_time.and_utc().timestamp_micros() as u64
        } else {
            timestamp_reference_time_us.unwrap_or(0)
        };

        let blf_iter = blf.into_iter();
        BLF2DltMsgIterator {
            blf_iter,
            namespace,
            log,
            measurement_start_us,
            index: start_index,
            msgs_deque: VecDeque::with_capacity(4),
            can_id_ecu_map: HashMap::new(),
        }
    }

    fn get_ecu(&mut self, channel_id: u16, name: &Option<&str>) -> DltChar4 {
        self.can_id_ecu_map
            .entry(channel_id)
            .or_insert_with(|| get_ecuid_for_namespace(self.namespace, name))
            .to_owned()
    }

    fn msg_from_object(&mut self, obj: &Object) -> DltMessage {
        let (ecu, apid, ctid, payload, timestamp_ns, verb_mstp_mtin, noar, payload_text) =
            match &obj.data {
                ObjectTypes::CanMessage86(can_msg) => {
                    let ecu = self.get_ecu(can_msg.channel, &None);
                    let mut p = Vec::with_capacity(can_msg.data.len() + 4);
                    p.extend(can_msg.id.to_ne_bytes());
                    p.extend(&can_msg.data);
                    (
                        ecu,
                        DltChar4::from_buf(b"CAN\0"),
                        DltChar4::from_buf(b"TC\0\0"),
                        p,
                        can_msg.header.timestamp_ns,
                        (2u8 << 1) | (2u8 << 4),
                        2,
                        None,
                    ) // NwTrace CAN, non verb.
                }
                ObjectTypes::CanErrorExt73(can_error) => {
                    let ecu = self.get_ecu(can_error.channel, &None);
                    let mut p = vec![];
                    let error_json = json!({
                      "id": can_error.id,
                      "length": can_error.length,
                      "flags": can_error.flags,
                      "ecc": can_error.ecc,
                      "pos": can_error.position,
                      "dlc": can_error.dlc,
                      "flagsExt": can_error.flags_ext,
                      // todo data?? (with lower 4 bits of dlc len?)
                    });
                    p.extend(can_error.id.to_ne_bytes());
                    (
                        ecu,
                        DltChar4::from_buf(b"CAN\0"),
                        DltChar4::from_buf(b"TC\0\0"),
                        p,
                        can_error.header.timestamp_ns,
                        1u8 | (2u8 << 4), // verb., Error
                        0,
                        Some(format!("Error Frame:{}", error_json)),
                    )
                }
                ObjectTypes::AppText65(app_text) => {
                    // ctid for source:
                    let ctid = match app_text.source {
                        0 => DltChar4::from_buf(b"ACMT"), // app comment
                        1 => DltChar4::from_buf(b"CINF"), // db channel info
                        2 => DltChar4::from_buf(b"META"), // meta data
                        3..=999 => {
                            DltChar4::from_str(format!("S{:03}", app_text.source).as_str()).unwrap()
                        }
                        _ => DltChar4::from_buf(b"UNKN"),
                    };
                    // similar to BusMapping use the metadata to map
                    // ecu to apid desc
                    if app_text.source == 2 {
                        let info_msgs = self.process_metadata(&app_text.to_string());
                        self.msgs_deque.extend(info_msgs);
                    }
                    let (noar, payload) = dlt_args!(app_text.to_string()).unwrap();
                    (
                        DltChar4::from_buf(b"ABLF"),
                        DltChar4::from_buf(b"AppT"),
                        ctid,
                        payload,
                        app_text.header.timestamp_ns,
                        1u8 | (4u8 << 4),
                        noar,
                        None,
                    ) //
                }
                _ => (
                    DltChar4::from_buf(b"ABLF"),
                    DltChar4::from_buf(b"UNKN"),
                    DltChar4::from_buf(b"UNKN"),
                    vec![],
                    0,
                    0,
                    0,
                    None,
                ),
            };

        let dlt_msg = DltMessage {
            index: self.index,
            reception_time_us: self.measurement_start_us + (timestamp_ns / 1000),
            ecu,
            timestamp_dms: (timestamp_ns / 100_000) as u32,
            standard_header: DltStandardHeader {
                htyp: HTYP,
                mcnt: (self.index & 0xff) as u8,
                len: LEN_WO_PAYLOAD + (payload.len() as u16),
            },
            extended_header: Some(DltExtendedHeader {
                verb_mstp_mtin,
                noar,
                apid,
                ctid,
            }),
            payload,
            payload_text,
            lifecycle: 0,
        };
        self.index += 1;
        dlt_msg
    }

    fn process_metadata(&mut self, text: &str) -> Vec<DltMessage> {
        let mut msgs = Vec::new();
        // text is supposed to be an xml:
        let mut reader = Reader::from_str(text);
        reader.config_mut().trim_text(true);
        let mut buf = Vec::new();
        let mut scope: Vec<String> = Vec::with_capacity(8);
        let channels = vec!["channels".to_string()];
        loop {
            match reader.read_event_into(&mut buf) {
                Err(e) => {
                    if let Some(log) = self.log {
                        slog::warn!(log, "xml parse error"; "error" => format!("{:?}", e));
                    }
                }
                Ok(Event::Eof) => break,
                Ok(Event::Start(e)) => {
                    // println!("start: {:?}", e);
                    let scope_name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();

                    let mut ch_nr = None;
                    let mut ch_type = None;
                    let mut ch_network = None;

                    if scope_name == "channel" && scope.ends_with(&channels) {
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"number" => {
                                    ch_nr = attr
                                        .unescape_value()
                                        .unwrap_or_default()
                                        .parse::<u16>()
                                        .ok();
                                }
                                b"type" => {
                                    ch_type = attr.unescape_value().ok();
                                }
                                b"network" => {
                                    ch_network = attr.unescape_value().ok();
                                }
                                _ => {
                                    println!("unknown channel attr: {:?}", attr);
                                }
                            }
                        }

                        if ch_nr.is_some() && ch_type.is_some() && ch_network.is_some() {
                            let ch_nr = ch_nr.unwrap();
                            let ch_type = ch_type.unwrap();
                            let ch_network = ch_network.unwrap();
                            if ch_type == "CAN" {
                                let ecu = self.get_ecu(ch_nr, &Some(&ch_network));
                                /*println!(
                                    "ecu:'{:?}' assigned to ch_nr:{}, name:'{}'",
                                    ecu, ch_nr, ch_network
                                );*/
                                // create the get_log_info msg:
                                let mut payload: Vec<u8> =
                                    SERVICE_ID_GET_LOG_INFO.to_ne_bytes().into();
                                let apid_buf = b"CAN\0";
                                let name = ch_network;
                                payload.extend(
                                    [7u8]
                                        .into_iter()
                                        .chain(1u16.to_ne_bytes()) // 1 app id, CAN plugin expects == 1
                                        .chain(apid_buf.iter().copied())
                                        .chain(0u16.to_ne_bytes()) // 0 ctx ids
                                        .chain((name.len() as u16).to_ne_bytes()) // len of apid desc
                                        .chain(name.as_bytes().iter().copied()),
                                );
                                let dlt_msg = DltMessage {
                                    index: 0, // will be changed later on dequeue
                                    reception_time_us: self.measurement_start_us,
                                    ecu,
                                    timestamp_dms: 0,
                                    standard_header: DltStandardHeader {
                                        htyp: HTYP,
                                        mcnt: 0,
                                        len: LEN_WO_PAYLOAD + payload.len() as u16,
                                    },
                                    extended_header: Some(DltExtendedHeader {
                                        verb_mstp_mtin: (3u8 << 1) | (2u8 << 4), // control, non verb
                                        noar: 2,
                                        apid: DltChar4::from_buf(b"CAN\0"),
                                        ctid: DltChar4::from_buf(b"TC\0\0"),
                                    }),
                                    payload,
                                    payload_text: None,
                                    lifecycle: 0,
                                };
                                msgs.push(dlt_msg);
                            } else if let Some(log) = self.log {
                                slog::warn!(log, "ignoring channel type"; "type" => ch_type.to_string(), "network" => ch_network.to_string(), "nr" => ch_nr);
                            }
                        } else {
                            for attr in e.attributes() {
                                if let Some(log) = self.log {
                                    slog::warn!(log, "unknown channel attr: {:?}", attr; "type" => ch_type.as_deref(), "network" => ch_network.as_deref(), "nr" => &ch_nr);
                                } else {
                                    println!("unknown channel attr: {:?}", attr);
                                }
                            }
                        }
                    }

                    scope.push(scope_name.to_string());
                }
                Ok(Event::End(e)) => {
                    //println!("end: {:?}", e);
                    if let Some(last) = scope.pop() {
                        let scope_name =
                            String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                        if last != scope_name {
                            if let Some(log) = self.log {
                                slog::warn!(log, "xml parse error"; "error" => "scope mismatch");
                            }
                        }
                    }
                }
                Ok(Event::Text(_e)) => {
                    //  println!("{:?} text: {:?}", scope, e);
                }
                _ => (),
            }
            buf.clear();
        }

        msgs
    }
}

impl<R> Iterator for BLF2DltMsgIterator<'_, R>
where
    R: BufRead + Seek,
{
    type Item = DltMessage;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(mut msg) = self.msgs_deque.pop_front() {
            msg.index = self.index;
            self.index += 1;
            msg.standard_header.mcnt = (msg.index & 0xff) as u8; // this is wrong... (as it should be per apid/ctid)
            return Some(msg);
        }
        loop {
            match self.blf_iter.next() {
                Some(obj) if [86, 73, 65].contains(&obj.object_type) => {
                    let dlt_msg = self.msg_from_object(&obj);
                    return Some(dlt_msg);
                }
                Some(_obj) => {
                    // println!("skipping object_type: {}", obj.object_type);
                }
                None => break,
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use ablf::BlfFile;

    use slog::{o, Drain, Logger};

    use crate::utils::{get_new_namespace, LowMarkBufReader};

    use super::BLF2DltMsgIterator;

    fn new_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, o!())
    }

    #[test]
    fn parse_metadata() {
        let m_text1 = r#"<?xml version="1.0" encoding="UTF-8"?>  <general version="1">    <general_properties>      <configuration file="ZST.cfg" path="D:\ZST\ecu\ZST_V3.13.9-R-24-01\Release\Generated\ZST\"></configuration>      <user name="007" computer="PC0815" os="Windows 8" />      <application name="CANoe" version="12.0.216" platform="64bit">CANoe.CAN.Ethernet /pro </application>      <description></description>    </general_properties>  </general>"#;
        let m_text2 = r#"<?xml version="1.0" encoding="UTF-8"?>  <channels version="1">    <channel number="1" type="CAN" network="MiniPLC">      <databases>        <database file="MiniPLC.dbc" path="D:\ZST\ecu\ZST_V3.13.9-R-24-01\Release\Generated\ZST\MiniPLC\" cluster="MiniPLC" />      </databases>    </channel>    <channel number="2" type="CAN" network="IuK_CAN"></channel>  </channels>"#;

        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        test_dir.push("can_example1.blf");
        let log = new_logger();
        let fi = File::open(&test_dir).unwrap();
        let reader = std::io::BufReader::new(fi);
        let mut blf_iter = super::BLF2DltMsgIterator::new(0, reader, 0, None, Some(&log));

        let md1 = blf_iter.process_metadata(m_text1);
        println!("md1: {:?}", md1);
        assert!(md1.is_empty());

        let md2 = blf_iter.process_metadata(m_text2);
        println!("md2: {:?}", md2);
        assert_eq!(md2.len(), 2);
    }

    #[test]
    fn blf_empty1() {
        let log = new_logger();
        let data = vec![0u8; 1024];
        let reader = std::io::Cursor::new(data);
        let mut blf_iter = super::BLF2DltMsgIterator::new(0, reader, 0, None, Some(&log));
        let msg = blf_iter.next();
        assert_eq!(msg, None);
    }
    #[test]
    fn blf_can_example1() {
        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        test_dir.push("can_example1.blf");
        let fi = File::open(&test_dir).unwrap();
        let start_index = 1000;
        let log = new_logger();
        let mut it = BLF2DltMsgIterator::new(
            start_index,
            LowMarkBufReader::new(fi, 512 * 1024, 128 * 1024),
            get_new_namespace(),
            None,
            Some(&log),
        );
        let mut iterated_msgs = 0;
        for m in &mut it {
            assert_eq!(m.index, start_index + iterated_msgs);
            iterated_msgs += 1;
        }
        assert_eq!(iterated_msgs, 2);
    }

    #[test]
    fn blf_can_example_errorframeext() {
        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        test_dir.push("can_example2.blf"); // test_CanErrorFrameExt
        let fi = File::open(&test_dir).unwrap();
        let start_index = 1;
        let log = new_logger();
        let mut it = BLF2DltMsgIterator::new(
            start_index,
            LowMarkBufReader::new(fi, 512 * 1024, 128 * 1024),
            get_new_namespace(),
            None,
            Some(&log),
        );
        let mut iterated_msgs = 0;
        for m in &mut it {
            assert_eq!(m.index, start_index + iterated_msgs);
            assert!(m.payload_text.unwrap().starts_with("Error Frame:{"));
            iterated_msgs += 1;
        }
        assert_eq!(iterated_msgs, 2);
    }

    #[test]
    fn blf_can_example_apptext() {
        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        test_dir.push("can_example3.blf"); // test_AppText
        let fi = File::open(&test_dir).unwrap();
        let start_index = 1;
        let log = new_logger();
        let mut it = BLF2DltMsgIterator::new(
            start_index,
            LowMarkBufReader::new(fi, 512 * 1024, 128 * 1024),
            get_new_namespace(),
            None,
            Some(&log),
        );
        let mut iterated_msgs = 0;
        for m in &mut it {
            assert_eq!(m.index, start_index + iterated_msgs);
            assert!(m.payload_as_text().unwrap() == "xyz");
            iterated_msgs += 1;
        }
        assert_eq!(iterated_msgs, 2);
    }

    #[test]
    fn blf_can_example_large() {
        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        test_dir.push("can_example_large.blf");
        if let Ok(fi) = File::open(&test_dir) {
            let reader = LowMarkBufReader::new(fi, 512 * 1024, 128 * 1024); // std::io::BufReader::new(fi);

            let blf = BlfFile::from_reader(reader);
            assert!(blf.is_ok());
            let blf = blf.unwrap();

            let blf_iter = blf.into_iter();
            assert_eq!(blf_iter.count(), 1933994);

            let fi = File::open(&test_dir).unwrap();
            let start_index = 1000;
            let log = new_logger();
            let mut it = BLF2DltMsgIterator::new(
                start_index,
                LowMarkBufReader::new(fi, 512 * 1024, 256 * 1024),
                get_new_namespace(),
                None,
                Some(&log),
            );
            let mut iterated_msgs = 0;
            for m in &mut it {
                assert_eq!(
                    m.index,
                    start_index + iterated_msgs,
                    "index={} m={:?}",
                    m.index,
                    m
                );
                iterated_msgs += 1;
            }
            println!("iterated_msgs: {}", iterated_msgs);
            assert!(iterated_msgs >= 1854000); // e.g. 7 LOG_INFOs
        }
    }
}
