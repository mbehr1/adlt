// copyright Matthias Behr, (c) 2022
//
// todos:
// [ ] remove old partial segmented data... (e.g. by max time)
// [ ] modify timestamp of last segment of a segmented msg reflect the time from first msg

use crate::{
    dlt::{DltChar4, DltMessage, DltMessageNwType, DltMessageType},
    plugins::plugin::Plugin,
};
use afibex::fibex::{get_all_fibex_in_dir, load_all_fibex, FibexData, FibexError};
use asomeip::utils::decode_someip_header_and_payload;
use std::{collections::HashMap, error::Error, fmt, path::Path};

#[derive(Debug)]
struct SomeipPluginError {
    msg: String,
}

impl SomeipPluginError {
    fn new(msg: &str) -> Self {
        SomeipPluginError {
            msg: msg.to_string(),
        }
    }
}

impl fmt::Display for SomeipPluginError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.msg)
    }
}

impl Error for SomeipPluginError {}

#[derive(Debug)]
pub struct SomeipPlugin {
    name: String,
    enabled: bool,
    _fibex_dir: String,
    mstp: DltMessageType,
    ctid: Option<DltChar4>,

    fibex_data: FibexData,

    segmented_msgs_map: HashMap<u32, SegmentedMsgInfo>,
}

// segmented msgs support:
#[derive(Debug, PartialEq)]
enum SegmentedType {
    None,         // no someip msg detected, ignore
    NotSegmented, // main type
    Start,        // segmented start
    Chunk,        // segmented chunks
    End,          // end of segmented chunks
}

#[derive(Debug)]
struct SegmentedMsgInfo {
    expected_nr_chunks: u16,
    chunk_size: u16,
    inst_id: u32,
    raw_buf: Vec<u8>,
}

impl<'a> Plugin for SomeipPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn process_msg(&mut self, msg: &mut DltMessage) -> bool {
        if self.mstp == msg.mstp()
            && msg.noar() >= 2
            && (self.ctid.is_none()
                || (self.ctid.is_some()
                    && matches!(msg.ctid(), Some(ctid) if ctid == &self.ctid.unwrap())))
        {
            let mut inst_id: u32 = 0;
            let mut decoded_header = None;

            let mut segmented_type: SegmentedType = SegmentedType::None;
            let mut segment_id: u32 = 0;
            let mut chunk_nr: u16 = u16::MAX;
            let mut start_expected_nr_chunk: u16 = u16::MIN;

            for (nr_arg, arg) in msg.into_iter().enumerate() {
                // enumerate is faster than collecting in a vec. but a bit more unreadable from the code
                match nr_arg {
                    0 => {
                        // ip_from, ip_to and instid

                        // is it a segmented msg? string: NWST, NWCH or NWEN?
                        if arg.is_string() && arg.scod() == 0 {
                            match arg.payload_raw {
                                b"NWST\0" => segmented_type = SegmentedType::Start,
                                b"NWCH\0" => segmented_type = SegmentedType::Chunk,
                                b"NWEN\0" => segmented_type = SegmentedType::End,
                                _ => {}
                            }
                        } else {
                            // todo verify type_info RAWD and endianess?
                            let buf = arg.payload_raw;
                            inst_id = match buf.len() {
                                9 => {
                                    segmented_type = SegmentedType::NotSegmented;
                                    u8::from_be_bytes([buf[8]]) as u32
                                }
                                10 => {
                                    segmented_type = SegmentedType::NotSegmented;
                                    u16::from_be_bytes([buf[8], buf[9]]) as u32
                                }
                                12 => {
                                    segmented_type = SegmentedType::NotSegmented;
                                    u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]])
                                }
                                _ => {
                                    segmented_type = SegmentedType::None;
                                    0
                                } // unknown..
                            }
                        }
                        if segmented_type == SegmentedType::None {
                            break; // unknown, dont process the other args
                        }
                    }
                    1 => {
                        // 2nd args
                        match segmented_type {
                            SegmentedType::NotSegmented => {
                                // someip msgs
                                decoded_header = Some(decode_someip_header_and_payload(
                                    &self.fibex_data,
                                    inst_id,
                                    arg.payload_raw,
                                    if arg.payload_raw.len() >= 16 {
                                        &arg.payload_raw[16..]
                                    } else {
                                        &[]
                                    },
                                ));
                                break; // done with arg parsing, ignore any further
                            }
                            SegmentedType::Start | SegmentedType::Chunk | SegmentedType::End => {
                                // 2nd parameter: segment id
                                let buf = arg.payload_raw;
                                if buf.len() == 4 {
                                    segment_id =
                                        u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                                    if segmented_type == SegmentedType::End {
                                        if let Some(smi) =
                                            self.segmented_msgs_map.remove(&segment_id)
                                        {
                                            // todo change timestamp to the one from the start... to keep better timing?
                                            if smi.raw_buf.len()
                                                > (smi.expected_nr_chunks as usize - 1)
                                                    * smi.chunk_size as usize
                                            {
                                                // all data available:
                                                decoded_header =
                                                    Some(decode_someip_header_and_payload(
                                                        &self.fibex_data,
                                                        smi.inst_id,
                                                        &smi.raw_buf,
                                                        if smi.raw_buf.len() >= 16 {
                                                            &smi.raw_buf[16..]
                                                        } else {
                                                            &[]
                                                        },
                                                    ));
                                            } else {
                                                decoded_header = Some(Err(FibexError {
                                                    msg: format!(
                                                        "SOME/IP segmented message NWEN {} with too little data: {} vs: >{}!",
                                                        segment_id, smi.raw_buf.len(), (smi.expected_nr_chunks as usize - 1)
                                                        * smi.chunk_size as usize
                                                    ),
                                                }));
                                            }
                                        }
                                        break;
                                    }
                                }
                            }
                            _ => break,
                        }
                    }
                    2 => {
                        match segmented_type {
                            SegmentedType::Start => {
                                // 3rd parameter: header raw
                                let buf = arg.payload_raw;
                                inst_id = match buf.len() {
                                    9 => u8::from_be_bytes([buf[8]]) as u32,
                                    10 => u16::from_be_bytes([buf[8], buf[9]]) as u32,
                                    12 => u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
                                    _ => {
                                        decoded_header = Some(Err(FibexError {
                                            msg: format!(
                                                "SOME/IP segmented message NWST id: {} with unknown 2nd arg len of {}!",
                                                segment_id, buf.len()
                                            ),
                                        }));
                                        0
                                    } // unknown..
                                }
                            }
                            SegmentedType::Chunk => {
                                // 3rd parameter: chunk nr
                                let buf = arg.payload_raw;
                                if buf.len() == 2 {
                                    chunk_nr = u16::from_le_bytes([buf[0], buf[1]]);
                                } // else invalid? could remove/free msg already here, keep chunk_nr at max
                            }
                            _ => break,
                        }
                    }
                    3 => {
                        match segmented_type {
                            SegmentedType::Start => {
                                // unknown parameter?  todo investigate
                            }
                            SegmentedType::Chunk => {
                                // 4th arg: raw payload, add to segment
                                if let Some(smi) = self.segmented_msgs_map.get_mut(&segment_id) {
                                    let buf = arg.payload_raw;
                                    // is this the next expected chunk?
                                    // we expect chunks per segment to be in order!
                                    // multiple segment transfer can occur simul.
                                    let got_chunks = smi.raw_buf.len() / smi.chunk_size as usize; // checked for >0 at insert
                                    if chunk_nr as usize == got_chunks
                                        && chunk_nr < smi.expected_nr_chunks
                                        && (buf.len() == smi.chunk_size as usize
                                            || (chunk_nr + 1) == smi.expected_nr_chunks)
                                    // last chunk can have any size (should be smaller but not worth checking)
                                    {
                                        smi.raw_buf.extend(buf); // buf must not be mut
                                        decoded_header = Some(Ok(format!(
                                            "SOME/IP segmented message NWCH {} ({})",
                                            segment_id, chunk_nr
                                        )));
                                    } else {
                                        decoded_header = Some(Ok(format!(
                                            "SOME/IP segmented message NWCH {} ({}) chunk out-of-sequence! (got chunks={} / exp {}) or wrong size!",
                                            segment_id, chunk_nr, got_chunks, smi.expected_nr_chunks
                                        )));
                                    }
                                } else {
                                    decoded_header = Some(Ok(format!(
                                        "SOME/IP segmented message NWCH {} ({}) for unknown id!",
                                        segment_id, chunk_nr
                                    )));
                                }

                                break;
                            }
                            _ => break,
                        }
                    }
                    4 => {
                        // can only be start 5th parameter:
                        let buf = arg.payload_raw;
                        if buf.len() == 2 {
                            start_expected_nr_chunk = u16::from_le_bytes([buf[0], buf[1]]);
                        }
                    }
                    5 => {
                        // can only be start 6th parameter: chunk_size
                        let buf = arg.payload_raw;
                        if buf.len() == 2 {
                            let chunk_size = u16::from_le_bytes([buf[0], buf[1]]);
                            decoded_header = Some(Ok(format!(
                                "SOME/IP segmented message NWST id: {} amount: {}",
                                segment_id, start_expected_nr_chunk
                            )));
                            // some sanity check that chunk_size * size < e.g. 1MB
                            if chunk_size > 0
                                && start_expected_nr_chunk > 0
                                && start_expected_nr_chunk < 0xffff
                                && (chunk_size as usize * start_expected_nr_chunk as usize)
                                    < 1_000_000
                            {
                                let smi = SegmentedMsgInfo {
                                    expected_nr_chunks: start_expected_nr_chunk,
                                    chunk_size,
                                    raw_buf: Vec::with_capacity(
                                        chunk_size as usize * start_expected_nr_chunk as usize,
                                    ),
                                    inst_id,
                                };
                                self.segmented_msgs_map.insert(segment_id, smi);
                            }
                            break;
                        } // todo: else print invalid msg...
                    }
                    _ => break,
                }
            }

            if segmented_type != SegmentedType::None {
                if let Some(Ok(text)) = decoded_header {
                    msg.set_payload_text(text);
                } else {
                    msg.set_payload_text(format!(
                        "someip plugin! got decoding err={:?}",
                        decoded_header
                    ));
                }
            } // for None do nothing
        }
        true
    }
}

impl SomeipPlugin {
    pub fn from_json(
        config: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<SomeipPlugin, Box<dyn Error>> {
        let name = match &config["name"] {
            serde_json::Value::String(s) => Some(s.clone()),
            _ => None,
        }; // todo check name for SomeIp
        if name.is_none() {
            return Err(SomeipPluginError::new("SomeipPlugin: name missing").into());
        }

        // todo parse ctid and mtin

        let enabled = match &config["enabled"] {
            serde_json::Value::Bool(b) => *b,
            serde_json::Value::Null => true,
            _ => false,
        };

        let fibex_dir = if let serde_json::Value::String(s) = &config["fibexDir"] {
            s.clone()
        } else {
            return Err(
                SomeipPluginError::new("SomeipPlugin: fibexDir missing or invalid type").into(),
            );
        };

        let ctid = Some(DltChar4::from_buf(b"TC\0\0"));

        let files = get_all_fibex_in_dir(Path::new(&fibex_dir), false)?; // todo or recursive
        let fibex_data = load_all_fibex(&files)?;

        Ok(SomeipPlugin {
            name: name.unwrap(),
            enabled,
            _fibex_dir: fibex_dir,
            mstp: DltMessageType::NwTrace(DltMessageNwType::Ipc),
            ctid,
            fibex_data,
            segmented_msgs_map: HashMap::with_capacity(16),
        })
    }
}
