// copyright Matthias Behr, (c) 2022
//
// todos:
// [ ] show frames in dlt-logs tree...

use crate::{
    dlt::{
        DltArg, DltChar4, DltExtendedHeader, DltMessage, DLT_SCOD_ASCII, DLT_SCOD_UTF8,
        DLT_TYLE_16BIT, DLT_TYLE_32BIT, DLT_TYLE_64BIT, DLT_TYLE_8BIT, DLT_TYPE_INFO_BOOL,
        DLT_TYPE_INFO_FLOA, DLT_TYPE_INFO_RAWD, DLT_TYPE_INFO_SINT, DLT_TYPE_INFO_STRG,
        DLT_TYPE_INFO_UINT,
    },
    //filter::Filter,
    plugins::plugin::{Plugin, PluginState},
    utils::eac_stats::EacStats,
};
use afibex::fibex::{get_all_fibex_in_dir, Ecu, Elements, FibexData, Frame};
use std::{
    collections::HashMap,
    error::Error,
    fmt,
    path::Path,
    str::FromStr,
    sync::{Arc, RwLock},
};

#[derive(Debug)]
struct NonVerboseFibexData {
    frames_map_by_id: HashMap<u32, NVFrame>,
}

/// a preprocessed frame with the data needed for the nonverbose plugin
#[derive(Debug)]
struct NVFrame {
    byte_length: u32,
    ext_header: Option<DltExtendedHeader>,
    _source_file: Option<String>,
    _line_number: Option<u32>,
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

    fn insert_frames(&mut self, fd: &FibexData, mut warnings: Option<&mut Vec<String>>) {
        for frame in &fd.elements.frames_map_by_id {
            if frame.1.id.starts_with("ID_") {
                let id = frame.1.id[3..].parse::<u32>();
                if let Ok(id) = id {
                    let pdus = NonVerboseFibexData::parse_pdus(frame.1, &fd.elements);

                    // todo verify here that byte_length matches sum of pdu byte_length
                    let pdu_sum = pdus.iter().map(|p| p.byte_length).sum::<usize>();
                    if frame.1.byte_length as usize != pdu_sum {
                        // todo warn
                        if let Some(ref mut warnings) = warnings {
                            warnings.push(format!(
                                "frame ID_{} has byte_length mismatch. Expected {} vs {} from PDUs",
                                id, frame.1.byte_length, pdu_sum
                            ));
                        }
                    } else {
                        let frame = frame.1;
                        let apid = frame
                            .manufacturer_extension
                            .as_ref()
                            .and_then(|e| e.child_by_name("APPLICATION_ID"))
                            .and_then(|a| a.text.as_ref())
                            .and_then(|text| DltChar4::from_str(text).ok());

                        let ctid = frame
                            .manufacturer_extension
                            .as_ref()
                            .and_then(|e| e.child_by_name("CONTEXT_ID"))
                            .and_then(|a| a.text.as_ref())
                            .and_then(|text| DltChar4::from_str(text).ok());
                        let source_file = frame
                            .manufacturer_extension
                            .as_ref()
                            .and_then(|e| e.child_by_name("MESSAGE_SOURCE_FILE"))
                            .and_then(|a| a.text.to_owned());
                        let line_number = frame
                            .manufacturer_extension
                            .as_ref()
                            .and_then(|e| e.child_by_name("MESSAGE_LINE_NUMBER"))
                            .and_then(|a| a.text.as_ref())
                            .and_then(|t| t.parse::<u32>().ok());

                        let ext_header = if let Some(apid) = apid {
                            if let Some(ctid) = ctid {
                                let message_info = frame
                                    .manufacturer_extension
                                    .as_ref()
                                    .and_then(|e| e.child_by_name("MESSAGE_INFO"))
                                    .and_then(|a| a.text.as_deref());
                                let mtin = match message_info {
                                    Some("DLT_LOG_ERROR") => 2u8,
                                    Some("DLT_LOG_WARN") => 3,
                                    Some("DLT_LOG_INFO") => 4,
                                    Some("DLT_LOG_DEBUG") => 5,
                                    Some("DLT_LOG_VERBOSE") => 6,
                                    _ => 1, // default to FATAL
                                };
                                let mstp = 0u8; // todo match MESSAGE_TYPE

                                let verb_mstp_mtin = (mtin << 4) | (mstp << 1);
                                Some(DltExtendedHeader {
                                    verb_mstp_mtin,
                                    noar: 0, // todo or to nr pdus?
                                    apid,
                                    ctid,
                                })
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        match self.frames_map_by_id.entry(id) {
                            std::collections::hash_map::Entry::Vacant(e) => {
                                e.insert(NVFrame {
                                    byte_length: frame.byte_length,
                                    ext_header,
                                    _source_file: source_file,
                                    _line_number: line_number,
                                    pdus,
                                });
                            }
                            std::collections::hash_map::Entry::Occupied(e) => {
                                // throw warning if the entries are different!
                                let ex_frame = e.get();
                                if ex_frame.byte_length != frame.byte_length
                                    && ex_frame.ext_header != ext_header
                                    && ex_frame.pdus.len() != pdus.len()
                                {
                                    if let Some(ref mut warnings) = warnings {
                                        warnings.push(format!(
                                            "frame ID_{} {:?} exists already with different content. Ignoring!",
                                            id, if let Some(ext_header)=ext_header {format!("apid: '{}', ctid: '{}'", ext_header.apid, ext_header.ctid)} else {"<no apid/ctid>".to_string()}
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn from_fibex(fd: FibexData) -> NonVerboseFibexData {
        let frames_map_by_id = HashMap::with_capacity(fd.elements.frames_map_by_id.len());
        let mut s = NonVerboseFibexData { frames_map_by_id };
        s.insert_frames(&fd, None);
        s
    }
}

#[derive(Debug)]
pub struct NonVerbosePlugin {
    name: String,
    enabled: bool,
    state: Arc<RwLock<PluginState>>,
    pub fibex_dir: String,
    //mstp: DltMessageType,
    //fibex_data: FibexData,
    /// FibexData is organized by ECU and SW-Versions
    fibex_map_by_ecu: HashMap<DltChar4, Vec<(String, NonVerboseFibexData)>>,
}

impl Plugin for NonVerbosePlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn state(&self) -> Arc<RwLock<PluginState>> {
        self.state.clone()
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
                                    if let Some(ext_header) = &frame.ext_header {
                                        if msg.extended_header.is_none() {
                                            msg.extended_header = Some(ext_header.to_owned());
                                        }
                                    }
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
        eac_stats: &mut EacStats,
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

        let mut state: PluginState = Default::default();

        let fibex_dir = if let Some(serde_json::Value::String(s)) = &config.get("fibexDir") {
            s.clone()
        } else {
            return Err(
                NonVerbosePluginError::from("config 'fibexDir' missing or not a string").into(),
            );
        };

        let mut warnings: Vec<String> = Vec::new();

        let files = get_all_fibex_in_dir(Path::new(&fibex_dir), false)?; // todo or recursive
        let mut fibex_map_by_ecu: HashMap<DltChar4, Vec<(String, NonVerboseFibexData)>> =
            HashMap::new();
        let files_len = files.len();
        for file in files {
            let mut fd = FibexData::new();
            if let Err(e) = fd.load_fibex_file(&file) {
                let warning = format!("load_fibex_file(file={:?}) failed with:{}", file, e);
                println!("{}", warning);
                warnings.push(warning);
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
                                // add apid/ctid infos if available
                                let applications = manuf_ext.child_by_name("APPLICATIONS");
                                if let Some(applications) = applications {
                                    for application in &applications.children {
                                        let apid = application
                                            .child_by_name("APPLICATION_ID")
                                            .and_then(|e| e.text.as_deref())
                                            .and_then(|t| DltChar4::from_str(t).ok());
                                        if let Some(apid) = apid {
                                            let desc = application
                                                .child_by_name("APPLICATION_DESCRIPTION")
                                                .and_then(|e| e.text.as_deref());
                                            if let Some(desc) = desc {
                                                eac_stats.add_desc(desc, &ecu_id, &apid, None);
                                            }
                                            if let Some(childs) =
                                                application.child_by_name("CONTEXTS")
                                            {
                                                for child in &childs.children {
                                                    let ctid = child
                                                        .child_by_name("CONTEXT_ID")
                                                        .and_then(|e| e.text.as_deref())
                                                        .and_then(|t| DltChar4::from_str(t).ok());
                                                    if let Some(ctid) = ctid {
                                                        let desc = child
                                                            .child_by_name("CONTEXT_DESCRIPTION")
                                                            .and_then(|e| e.text.as_deref());
                                                        if let Some(desc) = desc {
                                                            eac_stats.add_desc(
                                                                desc,
                                                                &ecu_id,
                                                                &apid,
                                                                Some(&ctid),
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

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
                                            versions[idx].1.insert_frames(&fd, Some(&mut warnings));
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
                                warnings.push(format!(
                                    "NonVerbosePlugin ignoring ECU '{}' due to missing SW_VERSION",
                                    ecu.id
                                ));
                            }
                        } else {
                            warnings.push(format!("NonVerbosePlugin ignoring ECU '{}' due to missing MANUFACTURER-EXTENSION", ecu.id));
                        }
                    } else {
                        warnings.push(format!(
                            "NonVerbosePlugin ignoring ECU '{}' due to wrongly formatted id",
                            ecu.id
                        ));
                    }
                }
            }
        }
        if files_len == 0 {
            warnings.push(format!("No fibex files found in directory: {}", fibex_dir));
        } else if fibex_map_by_ecu.is_empty() {
            warnings.push(format!(
                "No fibex data parsed from fibex files found in directory: {}",
                fibex_dir
            ));
        }
        // update state:
        state.value = serde_json::json!({"name":name, "treeItems":[
                if !warnings.is_empty() {
                    serde_json::json!({
                        "label": format!("Warnings #{}", warnings.len()),
                        "iconPath":"warning",
                        "children": warnings.iter().map(|w|{serde_json::json!({"label":w})}).collect::<Vec<serde_json::Value>>()
                    })
                } else {
                    serde_json::json!(null)
                },
                {"label": format!("ECUs #{}", fibex_map_by_ecu.len()),
                "children":
                    fibex_map_by_ecu.iter().map(|(ecu, versions)|{serde_json::json!(
                        {"label":format!("ECU '{}', SW-versions #{}",ecu, versions.len()),
                        "children": versions.iter().map(|(v, nfd)|{serde_json::json!(
                            {"label":format!("SW: '{}', frames #{}", v, nfd.frames_map_by_id.len()),
                            "children":nfd.frames_map_by_id.iter().map(|(id,frame)|{serde_json::json!(
                                {"label":format!("ID_{}: {}", id, if let Some(exth) = &frame.ext_header {format!("apid: {}, ctid: {}", exth.apid, exth.ctid)}else{"<no apid/ctid>".to_owned()})}
                            )}).collect::<Vec<serde_json::Value>>()
                        })}).collect::<Vec<serde_json::Value>>()
                    })})
                    .collect::<Vec<serde_json::Value>>()
                }
            ],
        "warnings":warnings});
        state.generation += 1;

        Ok(NonVerbosePlugin {
            name,
            enabled,
            state: Arc::new(RwLock::new(state)),
            fibex_dir,
            fibex_map_by_ecu, //fibex_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlt::{DltChar4, DltMessageLogType, DltMessageType};
    use serde_json::json;

    #[test]
    fn init_plugin() {
        let mut eac_stats = EacStats::new();

        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        // good case:
        let cfg = json!({"name":"foo","enabled": false, "fibexDir":test_dir});
        let p = NonVerbosePlugin::from_json(cfg.as_object().unwrap(), &mut eac_stats);
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

        let state = p.state();
        let state = state.read().unwrap();
        assert_eq!(state.generation, 1); // first update done
        let state_value = &state.value;
        assert!(state_value.is_object());
        let state_obj = state_value.as_object().unwrap();
        assert!(state_obj.contains_key("name"));
        assert!(state_obj.contains_key("treeItems"));

        // name missing: -> err
        let cfg = json!({"enabled": false, "fibexDir":test_dir});
        let p = NonVerbosePlugin::from_json(cfg.as_object().unwrap(), &mut eac_stats);
        assert!(p.is_err());

        // enabled missing -> default true
        let cfg = json!({"name": "f", "fibexDir":test_dir});
        let p = NonVerbosePlugin::from_json(cfg.as_object().unwrap(), &mut eac_stats).unwrap();
        assert!(p.enabled);

        // fibexDir missing -> err
        let cfg = json!({"name": "f"});
        let p = NonVerbosePlugin::from_json(cfg.as_object().unwrap(), &mut eac_stats);
        assert!(p.is_err());
    }

    #[test]
    fn rewrite_msg() {
        let mut eac_stats = EacStats::new();
        let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests");
        let cfg = json!({"name":"foo","enabled": true, "fibexDir":d});
        let mut p = NonVerbosePlugin::from_json(cfg.as_object().unwrap(), &mut eac_stats).unwrap();

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
        // verify that mstp, APID, CTID are updated as well:
        assert_eq!(m.mstp(), DltMessageType::Log(DltMessageLogType::Debug));
        assert_eq!(m.apid(), Some(&DltChar4::from_buf(b"HLD\0")));
        assert_eq!(m.ctid(), Some(&DltChar4::from_buf(b"MAIN")));

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

    #[test]
    fn eac_stats() {
        let mut eac_stats = EacStats::new();
        let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests");
        let cfg = json!({"name":"foo","enabled": true, "fibexDir":d});
        let _p = NonVerbosePlugin::from_json(cfg.as_object().unwrap(), &mut eac_stats).unwrap();

        // eac_stats are filled with the apid/ctid info from fx:ECU/manuf.ext/...
        assert_eq!(eac_stats.ecu_map.len(), 1);
        let ecu_stat = eac_stats.ecu_map.get(&DltChar4::from_buf(b"Ecu1")).unwrap();
        assert_eq!(ecu_stat.apids.len(), 1); // HLD
        let apid_stat = ecu_stat.apids.get(&DltChar4::from_buf(b"HLD\0")).unwrap();
        assert_eq!(apid_stat.desc, Some("Description for apid HLD".to_owned()));
        assert_eq!(apid_stat.ctids.len(), 2); // ERR, MAIN
        let ctid_stat = apid_stat.ctids.get(&DltChar4::from_buf(b"MAIN")).unwrap();
        assert_eq!(
            ctid_stat.desc,
            Some("Description for apid:context HLD:MAIN".to_owned())
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
