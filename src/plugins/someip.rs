// copyright Matthias Behr, (c) 2022
//
// todos:
// [ ] support segmented msgs (e.g. 20220225... msgs 152411-152414)

use crate::{
    dlt::{DltChar4, DltMessage, DltMessageNwType, DltMessageType},
    plugins::plugin::Plugin,
};
use afibex::fibex::{get_all_fibex_in_dir, load_all_fibex, FibexData};
use asomeip::utils::decode_someip_header_and_payload;
use std::{error::Error, fmt, path::Path};

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
            for (nr_arg, arg) in msg.into_iter().enumerate() {
                match nr_arg {
                    0 => {
                        // ip_from, ip_to and instid
                        // todo verify type_info and endianess?
                        let buf = arg.payload_raw;
                        inst_id = match buf.len() {
                            9 => u8::from_be_bytes([buf[8]]) as u32,
                            10 => u16::from_be_bytes([buf[8], buf[9]]) as u32,
                            12 => u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
                            _ => 0,
                        }
                    }
                    1 => {
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
                    }
                    _ => break,
                }
            }

            if let Some(Ok(text)) = decoded_header {
                msg.set_payload_text(text);
            } else {
                msg.set_payload_text(format!(
                    "someip plugin! got decoding err={:?}",
                    decoded_header
                ));
            }
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
        })
    }
}
