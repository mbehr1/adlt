// copyright Matthias Behr, (c) 2022
//
// todos:
// [ ] show frames in dlt-logs tree...

use crate::{
    dlt::{
        DltArg, DltChar4, DltMessage, DLT_SCOD_ASCII, DLT_SCOD_UTF8, DLT_TYLE_16BIT,
        DLT_TYLE_32BIT, DLT_TYLE_64BIT, DLT_TYLE_8BIT, DLT_TYPE_INFO_BOOL, DLT_TYPE_INFO_FLOA,
        DLT_TYPE_INFO_RAWD, DLT_TYPE_INFO_SINT, DLT_TYPE_INFO_STRG, DLT_TYPE_INFO_UINT,
    },
    //filter::Filter,
    plugins::plugin::Plugin,
};
use afibex::fibex::{get_all_fibex_in_dir, Ecu, Elements, FibexData, Frame};
use std::{collections::HashMap, error::Error, fmt, path::Path, str::FromStr};

#[derive(Debug)]
struct NonVerboseFibexData {
    frames_map_by_id: HashMap<u32, NVFrame>,
}

/// a preprocessed frame with the data needed for the nonverbose plugin
#[derive(Debug)]
struct NVFrame {
    byte_length: u32,
    pdus: Vec<NVPdu>,
}

#[derive(Debug)]
struct NVPdu {
    type_info: u32, // in format like DltArg.type_info
    byte_length: usize,
    text: Option<String>, // from DESC, static text to use
}

struct NVArgsIterator<'a> {
    frame: &'a NVFrame,
    is_big_endian: bool,
    msg_payload: &'a [u8],
    index: usize, // the next argument/pdu that gets returned
    bytes_used: usize,
}

impl<'a> NVArgsIterator<'a> {
    fn new(frame: &'a NVFrame, is_big_endian: bool, msg_payload: &'a [u8]) -> NVArgsIterator<'a> {
        NVArgsIterator {
            frame,
            is_big_endian,
            msg_payload,
            index: 0,
            bytes_used: 0,
        }
    }
}

impl<'a> Iterator for NVArgsIterator<'a> {
    type Item = DltArg<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.frame.pdus.len() {
            let pdu = &self.frame.pdus[self.index];
            let payload_raw = if let Some(text) = pdu.text.as_ref() {
                text.as_bytes()
            } else {
                &self.msg_payload[self.bytes_used..self.bytes_used + pdu.byte_length]
            };
            self.index += 1;
            self.bytes_used += pdu.byte_length;
            return Some(DltArg {
                type_info: pdu.type_info,
                is_big_endian: self.is_big_endian,
                payload_raw,
            });
        }
        None
    }
}

impl NonVerboseFibexData {
    fn parse_pdus(frame: &Frame, elements: &Elements) -> Vec<NVPdu> {
        let mut pdus: Vec<NVPdu> = Vec::with_capacity(frame.pdu_instances.len());

        for pdu in &frame.pdu_instances {
            let pdu_ref = &pdu.pdu_ref;
            // find the pdu for it:
            let pdu = elements.pdus_map_by_id.get(pdu_ref);
            if let Some(pdu) = pdu {
                let type_info = if pdu.byte_length == 0 {
                    DLT_TYPE_INFO_STRG | DLT_SCOD_UTF8
                } else if pdu.signal_instances.len() == 1 {
                    match pdu.signal_instances[0].signal_ref.as_str() {
                        "S_UINT64" => DLT_TYPE_INFO_UINT | DLT_TYLE_64BIT as u32,
                        "S_SINT64" => DLT_TYPE_INFO_SINT | DLT_TYLE_64BIT as u32,
                        "S_UINT32" => DLT_TYPE_INFO_UINT | DLT_TYLE_32BIT as u32,
                        "S_SINT32" => DLT_TYPE_INFO_SINT | DLT_TYLE_32BIT as u32,
                        "S_UINT16" => DLT_TYPE_INFO_UINT | DLT_TYLE_16BIT as u32,
                        "S_SINT16" => DLT_TYPE_INFO_SINT | DLT_TYLE_16BIT as u32,
                        "S_UINT8" => DLT_TYPE_INFO_UINT | DLT_TYLE_8BIT as u32,
                        "S_SINT8" => DLT_TYPE_INFO_SINT | DLT_TYLE_8BIT as u32,
                        "S_BOOL" => DLT_TYPE_INFO_BOOL | DLT_TYLE_8BIT as u32,
                        "S_FLOA16" => DLT_TYPE_INFO_FLOA | DLT_TYLE_16BIT as u32, // todo???
                        "S_FLOA32" => DLT_TYPE_INFO_FLOA | DLT_TYLE_32BIT as u32,
                        "S_FLOA64" => DLT_TYPE_INFO_FLOA | DLT_TYLE_64BIT as u32,
                        "S_STRG_UTF8" => DLT_TYPE_INFO_STRG | DLT_SCOD_UTF8,
                        "S_STRG_ASCII" => DLT_TYPE_INFO_STRG | DLT_SCOD_ASCII,
                        "S_RAWD" | "S_RAW" => DLT_TYPE_INFO_RAWD, // todo verify!
                        _ => {
                            println!(
                                "NonVerbosePlugin: unknown signal_ref {}",
                                pdu.signal_instances[0].signal_ref
                            );
                            0u32
                        }
                    }
                } else {
                    // else warn???
                    println!(
                        "NonVerbosePlugin: unknown signal_instances {:?}",
                        pdu.signal_instances
                    );
                    0u32
                };

                pdus.push(NVPdu {
                    type_info,
                    byte_length: pdu.byte_length as usize,
                    text: if pdu.byte_length == 0 {
                        pdu.desc.as_ref().map(|s| {
                            let mut s = s.clone();
                            s.push('\0'); // we expect it zero terminated
                            s
                        })
                    } else {
                        None
                    },
                })
            } else {
                // no way to handle that as we dont know the byte-length:
                // todo warning
                return vec![];
            }
        }

        pdus
    }

    fn insert_frames(&mut self, fd: &FibexData) {
        for frame in &fd.elements.frames_map_by_id {
            if frame.1.id.starts_with("ID_") {
                let id = frame.1.id[3..].parse::<u32>();
                if let Ok(id) = id {
                    let pdus = NonVerboseFibexData::parse_pdus(frame.1, &fd.elements);

                    // todo verify here that byte_length matches sum of pdu byte_length
                    if frame.1.byte_length as usize
                        != pdus.iter().map(|p| p.byte_length).sum::<usize>()
                    {
                        // todo warn
                    } else {
                        self.frames_map_by_id.insert(
                            id,
                            NVFrame {
                                byte_length: frame.1.byte_length,
                                pdus,
                            },
                        );
                    }
                }
            }
        }
    }

    fn from_fibex(fd: FibexData) -> NonVerboseFibexData {
        let frames_map_by_id = HashMap::with_capacity(fd.elements.frames_map_by_id.len());
        let mut s = NonVerboseFibexData { frames_map_by_id };
        s.insert_frames(&fd);
        s
    }
}

#[derive(Debug)]
pub struct NonVerbosePlugin {
    name: String,
    enabled: bool,
    pub fibex_dir: String,
    //mstp: DltMessageType,
    //fibex_data: FibexData,
    /// FibexData is organized by ECU and SW-Versions
    fibex_map_by_ecu: HashMap<DltChar4, Vec<(String, NonVerboseFibexData)>>,
}

impl<'a> Plugin for NonVerbosePlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn process_msg(&mut self, msg: &mut DltMessage) -> bool {
        if !self.enabled || msg.is_verbose() {
            return true;
        }
        // at least the message id payload is expected
        let mut args = msg.into_iter();
        let message_id_arg = args.next();
        if let Some(a) = message_id_arg {
            if a.payload_raw.len() >= 4 {
                let message_id = if a.is_big_endian {
                    u32::from_be_bytes(a.payload_raw.get(0..4).unwrap().try_into().unwrap())
                } else {
                    u32::from_le_bytes(a.payload_raw.get(0..4).unwrap().try_into().unwrap())
                };
                // check whether message_id is known
                // for that ECU and best-case for a matching SW-version:
                // todo cache last
                if let Some(versions) = self.fibex_map_by_ecu.get(&msg.ecu) {
                    if !versions.is_empty() {
                        // for now use the first (aka youngest) version:
                        let version = &versions[0].1;
                        if let Some(frame) = version.frames_map_by_id.get(&message_id) {
                            let payload_arg = args.next();
                            let (payload, is_big_endian) = match payload_arg {
                                Some(a) => (a.payload_raw, a.is_big_endian),
                                None => (&a.payload_raw[4..], a.is_big_endian),
                            };
                            // process payload...
                            if payload.len() as u32 >= frame.byte_length {
                                /*msg.payload_text = Some(format!(
                                    "NVP: found frame {:?} payload: {:?}",
                                    frame, payload
                                ));*/
                                let args = NVArgsIterator::new(frame, is_big_endian, payload);
                                let mut text = String::with_capacity(256);
                                if DltMessage::process_msg_arg_iter(args, &mut text).is_ok() {
                                    msg.payload_text = Some(text);
                                } else {
                                    // todo write error?
                                    msg.payload_text = Some(format!(
                                        "NVP: found frame {:?} but processing err! payload: {:?}",
                                        frame, payload
                                    ));
                                }
                            } else {
                                // todo warn?
                                msg.payload_text = Some(format!(
                                    "NVP: found frame {:?} but payload too small! payload: {:?}",
                                    frame, payload
                                ));
                            }
                        } else {
                            /*msg.payload_text =
                            Some(format!("NVP: didnt found frame {}", message_id));*/
                        }
                    } else {
                        //msg.payload_text = Some(format!("NVP:no versions for ecu {:?}", msg.ecu));
                    }
                } else {
                    //msg.payload_text = Some(format!("NVP: didnt found ecu {:?}", msg.ecu));
                }
            } else {
                msg.payload_text = Some(format!("NVP: wrong payload len {}", a.payload_raw.len()));
            }
        }
        true
    }
}

impl NonVerbosePlugin {
    pub fn from_json(
        config: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<NonVerbosePlugin, Box<dyn Error>> {
        let name = match &config.get("name") {
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => return Err(NonVerbosePluginError::from("config 'name' missing").into()),
        };
        let enabled = match &config.get("enabled") {
            Some(serde_json::Value::Bool(b)) => *b,
            None => true, // default to true
            _ => return Err(NonVerbosePluginError::from("config 'enabled' not an bool").into()),
        };

        let fibex_dir = if let Some(serde_json::Value::String(s)) = &config.get("fibexDir") {
            s.clone()
        } else {
            return Err(
                NonVerbosePluginError::from("config 'fibexDir' missing or not a string").into(),
            );
        };

        let files = get_all_fibex_in_dir(Path::new(&fibex_dir), false)?; // todo or recursive
        let mut fibex_map_by_ecu: HashMap<DltChar4, Vec<(String, NonVerboseFibexData)>> =
            HashMap::new();
        for file in files {
            let mut fd = FibexData::new();
            if let Err(e) = fd.load_fibex_file(&file) {
                println!("load_fibex_file(file={:?}) failed with:{}", file, e);
            } else {
                // is it a non-verbose describing fibex?

                // [Dlt402] only one ECU XML element
                if fd.elements.ecus.len() == 1 {
                    let ecu: &Ecu = &fd.elements.ecus[0];
                    let ecu_id = DltChar4::from_str(&ecu.id);
                    if let Ok(ecu_id) = ecu_id {
                        // [Dlt403] shall be extended by SW_VERSION
                        if let Some(manuf_ext) = &ecu.manufacturer_extension {
                            let sw_version = manuf_ext
                                .child_by_name("SW_VERSION")
                                .and_then(|e| e.text.to_owned());
                            if let Some(sw_version) = sw_version {
                                if let std::collections::hash_map::Entry::Vacant(e) =
                                    fibex_map_by_ecu.entry(ecu_id)
                                {
                                    e.insert(vec![(
                                        sw_version,
                                        NonVerboseFibexData::from_fibex(fd),
                                    )]);
                                } else {
                                    // add as new sw-version or add to the existing one:
                                    let versions = fibex_map_by_ecu.get_mut(&ecu_id).unwrap();

                                    match versions.binary_search_by(|a| sw_version.cmp(&a.0)) {
                                        Ok(idx) => {
                                            // add to existing one
                                            versions[idx].1.insert_frames(&fd);
                                        }
                                        Err(idx) => {
                                            // insert at proper position
                                            versions.insert(
                                                idx,
                                                (sw_version, NonVerboseFibexData::from_fibex(fd)),
                                            );
                                        }
                                    };
                                }
                            } else {
                                println!(
                                    "NonVerbosePlugin ignoring ECU '{}' due to missing SW_VERSION",
                                    ecu.id
                                );
                            }
                        } else {
                            println!("NonVerbosePlugin ignoring ECU '{}' due to missing MANUFACTURER-EXTENSION", ecu.id);
                        }
                    } else {
                        println!(
                            "NonVerbosePlugin ignoring ECU '{}' due to wrongly formatted id",
                            ecu.id
                        );
                    }
                }

                // and then all FRAMES with ID_<u32>
            }
        }

        // todo sort versions by youngest first

        Ok(NonVerbosePlugin {
            name,
            enabled,
            fibex_dir,
            fibex_map_by_ecu, //fibex_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlt::DltChar4;
    use serde_json::json;

    #[test]
    fn init_plugin() {
        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        // good case:
        let cfg = json!({"name":"foo","enabled": false, "fibexDir":test_dir});
        let p = NonVerbosePlugin::from_json(cfg.as_object().unwrap());
        assert!(p.is_ok());
        let p = p.unwrap();
        assert_eq!(p.name, "foo");
        assert!(!p.enabled);
        let ecu_id = DltChar4::from_buf(b"Ecu1");
        assert!(p.fibex_map_by_ecu.contains_key(&ecu_id));
        let versions = p.fibex_map_by_ecu.get(&ecu_id).unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].0, "1.0.1"); // newest sw first

        // both frames available even though splitted in two sep. files:
        let frame = versions[0].1.frames_map_by_id.get(&805834673).unwrap();
        assert_eq!(11, frame.byte_length);
        let frame = versions[0].1.frames_map_by_id.get(&805312382).unwrap();
        assert_eq!(0, frame.byte_length);

        // name missing: -> err
        let cfg = json!({"enabled": false, "fibexDir":test_dir});
        let p = NonVerbosePlugin::from_json(cfg.as_object().unwrap());
        assert!(p.is_err());

        // enabled missing -> default true
        let cfg = json!({"name": "f", "fibexDir":test_dir});
        let p = NonVerbosePlugin::from_json(cfg.as_object().unwrap()).unwrap();
        assert!(p.enabled);

        // fibexDir missing -> err
        let cfg = json!({"name": "f"});
        let p = NonVerbosePlugin::from_json(cfg.as_object().unwrap());
        assert!(p.is_err());
    }

    #[test]
    fn rewrite_msg() {
        let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests");
        let cfg = json!({"name":"foo","enabled": true, "fibexDir":d});
        let mut p = NonVerbosePlugin::from_json(cfg.as_object().unwrap()).unwrap();

        let mut m = DltMessage::for_test();
        assert!(!m.is_verbose());
        assert!(!m.is_big_endian());
        m.ecu = DltChar4::from_buf(b"Ecu1");
        m.payload = 805312382u32.to_le_bytes().into();
        assert!(p.process_msg(&mut m));
        assert_eq!(
            m.payload_as_text(),
            Ok("FooStateMachine, Enter ON State".to_owned())
        );

        let payload: Vec<Vec<u8>> = vec![
            805834673u32.to_le_bytes().into(),
            12345678u32.to_le_bytes().into(),
            (-23456789i32).to_le_bytes().into(),
            4711u16.to_le_bytes().into(),
            42u8.to_le_bytes().into(),
        ];
        m.payload = payload.into_iter().flatten().collect();
        assert!(p.process_msg(&mut m));
        assert_eq!(
            m.payload_as_text(),
            Ok("DTC set but env data was not yet fetched, lldErrorStatus= 12345678 , lldStatus= -23456789 , lldBcklTemp= 4711 , lldVccVoltage= 42".to_owned())
        );
    }
}

#[derive(Debug)]
struct NonVerbosePluginError {
    msg: String,
}

impl NonVerbosePluginError {}

impl From<String> for NonVerbosePluginError {
    fn from(err: String) -> NonVerbosePluginError {
        NonVerbosePluginError { msg: err }
    }
}

impl From<&str> for NonVerbosePluginError {
    fn from(err: &str) -> NonVerbosePluginError {
        NonVerbosePluginError::from(err.to_owned())
    }
}

impl fmt::Display for NonVerbosePluginError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NonVerbosePlugin error:{}", &self.msg)
    }
}

impl Error for NonVerbosePluginError {}
