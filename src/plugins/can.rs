// copyright Matthias Behr, (c) 2022
//
// todos:

use crate::{
    dlt::{
        control_msgs::parse_ctrl_log_info_payload, DltChar4, DltMessage, DltMessageNwType,
        DltMessageType, SERVICE_ID_GET_LOG_INFO,
    },
    plugins::plugin::{Plugin, PluginState},
};
use afibex::fibex::{
    get_all_fibex_in_dir, load_all_fibex, CompuCategory, CompuMethod, FibexData, PduInstance,
    SignalInstance, XsDouble,
};
use asomeip::utils_can::decode_can_frame;
use lazy_static::lazy_static;
use serde_json::json;
use std::{
    collections::HashMap,
    error::Error,
    fmt,
    ops::Bound,
    path::Path,
    sync::{Arc, RwLock},
};

lazy_static! {
    static ref EMPTY_STATIC_STRING: String = "".to_string();
}

#[derive(Debug)]
struct CanPluginError {
    msg: String,
}

impl CanPluginError {
    fn new(msg: &str) -> Self {
        CanPluginError {
            msg: msg.to_string(),
        }
    }
}

impl fmt::Display for CanPluginError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.msg)
    }
}

impl Error for CanPluginError {}

#[derive(Debug)]
pub struct CanPlugin {
    name: String,
    enabled: bool,
    state: Arc<RwLock<PluginState>>,
    _fibex_dir: String,
    mstp: DltMessageType,
    ctid: Option<DltChar4>,

    log_info_apid: DltChar4, // needs to be in sync with the asc2dltmsgiterator.rs
    log_info_ctid: DltChar4, //  is used to get the proper channel, otherwise wild card search is used
    fibex_data: FibexData,
    channel_id_by_char4: HashMap<DltChar4, String>,
}

impl<'a> Plugin for CanPlugin {
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
        if self.mstp == msg.mstp()
            && msg.noar() >= 2
            && (self.ctid.is_none()
                || (self.ctid.is_some()
                    && matches!(msg.ctid(), Some(ctid) if ctid == &self.ctid.unwrap())))
        {
            let mut frame_id: u32 = 0;
            let mut decoded_header = None;

            // current assumption is that the ecu is unique per channel and the
            // channel name is encoded in the APID CAN for that ecu:
            let channel_id = self.channel_id_by_char4.get(&msg.ecu);

            for (nr_arg, arg) in msg.into_iter().enumerate() {
                // enumerate is faster than collecting in a vec. but a bit more unreadable from the code
                match nr_arg {
                    0 => {
                        // frame_id
                        let buf = arg.payload_raw;
                        frame_id = match buf.len() {
                            4 => {
                                if arg.is_big_endian {
                                    u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]])
                                } else {
                                    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
                                }
                            }
                            _ => 0, // unknown..
                        };
                        if frame_id == 0 {
                            break; // unknown, dont process the other args
                        }
                    }
                    1 => {
                        // 2nd args, pure can payload
                        // can msgs
                        decoded_header = Some(decode_can_frame(
                            &self.fibex_data,
                            true,
                            &channel_id,
                            frame_id,
                            arg.payload_raw,
                            true,
                            false,
                        ));
                        break; // done with arg parsing, ignore any further
                    }
                    _ => break,
                }
            }

            if let Some(Ok(text)) = decoded_header {
                msg.set_payload_text(text);
            } else {
                msg.set_payload_text(format!("can plugin! got decoding err={:?}", decoded_header));
            }
        } else if msg.is_ctrl_response()
            && !msg.is_verbose()
            && msg.apid() == Some(&self.log_info_apid)
            && msg.ctid() == Some(&self.log_info_ctid)
        {
            let mut args = msg.into_iter();
            let message_id_arg = args.next();
            let message_id = match message_id_arg {
                Some(a) => {
                    if a.payload_raw.len() == 4 {
                        if a.is_big_endian {
                            u32::from_be_bytes(a.payload_raw.get(0..4).unwrap().try_into().unwrap())
                        } else {
                            u32::from_le_bytes(a.payload_raw.get(0..4).unwrap().try_into().unwrap())
                        }
                    } else {
                        0
                    }
                }
                None => 0,
            };
            if message_id == SERVICE_ID_GET_LOG_INFO {
                let payload_arg = args.next();
                let (payload, is_big_endian) = match payload_arg {
                    Some(a) => (a.payload_raw, a.is_big_endian),
                    None => (&[] as &[u8], false),
                };

                if !payload.is_empty() {
                    // query info on the channel names:
                    let retval = payload.get(0).unwrap();
                    let payload = &payload[1..];
                    let apids = parse_ctrl_log_info_payload(*retval, is_big_endian, payload);
                    if apids.len() == 1 {
                        let apid_info = &apids[0];
                        if let Some(desc) = apid_info.desc.as_deref() {
                            // now search fd for a channel with that name:
                            let channel_id = self
                                .fibex_data
                                .elements
                                .channels
                                .iter()
                                .find(|c| c.1.short_name.as_deref() == Some(desc))
                                .map(|c| &c.1.id);
                            if let Some(channel) = channel_id {
                                self.channel_id_by_char4
                                    .insert(msg.ecu.to_owned(), channel.to_owned());
                            }
                        }
                    }
                }
            }
        }
        true
    }
}

fn sorted_frames(frames: &HashMap<u32, String>) -> Vec<(&u32, &String)> {
    let mut v = frames.iter().collect::<Vec<_>>();
    v.sort_unstable_by(|a, b| a.0.cmp(b.0));
    v
}

fn tree_item_for_frame(
    fd: &FibexData,
    channel_short_name: &str,
    identifier: &u32,
    frame_ref: &String,
) -> serde_json::Value {
    let no_name = "<no shortname>";
    let no_desc = "<no desc>";

    let frame = fd.elements.frames_map_by_id.get(frame_ref);
    if let Some(frame) = frame {
        let short_name = frame.short_name.as_deref().unwrap_or(no_name);

        json!({ "label": format!("0x{:03x} ({}) '{}'", identifier, identifier, short_name),
            "tooltip": format!("description:\n{}\nbyte length: {}\nPDUs:\n{}",
                frame.desc.as_deref().unwrap_or(no_desc),
                frame.byte_length,
                frame.pdu_instances.iter().map(|p|format!("{}:tbd", p.pdu_ref.as_str(), )).collect::<Vec<_>>().join("\n")
            ),
            "filterFrag":
                serde_json::json!({"apid":"CAN", "ctid":"TC", "payloadRegex":format!("^. {} 0x{:03x} ", channel_short_name, identifier)}),
            "children": frame.pdu_instances.iter().map(|pdu_instance|{tree_item_for_pdu(fd, pdu_instance)}).collect::<Vec<serde_json::Value>>(),
        })
    } else {
        json!({ "label": format!("0x{:03x} frame ref {} unknown!", identifier, frame_ref) })
    }
}

fn tree_item_for_pdu(fd: &FibexData, pdu_instance: &PduInstance) -> serde_json::Value {
    let no_name = "<no shortname>";
    let no_desc = "<no desc>";

    let pdu = fd.elements.pdus_map_by_id.get(&pdu_instance.pdu_ref);
    if let Some(pdu) = pdu {
        let short_name = pdu.short_name.as_deref().unwrap_or(no_name);
        json!({ "label": format!("{}", short_name),
            "tooltip": format!("description:\n{}\nbyte length: {}\nsignals:\n{}",
                pdu.desc.as_deref().unwrap_or(no_desc),
                pdu.byte_length,
                pdu.signal_instances.iter().map(|s|format!("{}:tbd", s.signal_ref.as_str(), )).collect::<Vec<_>>().join("\n")
            ),
            "children": pdu.signal_instances.iter().map(|signal_instance|{tree_item_for_signal(fd, signal_instance
            )}).collect::<Vec<serde_json::Value>>(),
        })
    } else {
        json!({ "label": format!("pdu ref {} unknown!", pdu_instance.pdu_ref) })
    }
}

fn tree_item_for_signal(fd: &FibexData, signal_instance: &SignalInstance) -> serde_json::Value {
    let no_name = "<no shortname>";
    let no_desc = "<no desc>";

    let signal = fd
        .elements
        .signals_map_by_id
        .get(&signal_instance.signal_ref);
    if let Some(signal) = signal {
        let short_name = signal.short_name.as_deref().unwrap_or(no_name);
        let bit_pos_str = signal_instance
            .bit_position
            .map(|bp| format!("bit {:2}.. ", bp))
            .unwrap_or_else(|| "         ".to_string());
        json!({ "label": format!("{}: {}", bit_pos_str, short_name),
            "tooltip": format!("description:\n{}\n\n{}",
                signal.desc.as_deref().unwrap_or(no_desc),
                md_for_coding(fd, &signal.coding_ref)
            ),
        })
    } else {
        json!({ "label": format!("pdu ref {} unknown!", signal_instance.signal_ref) })
    }
}

fn md_for_coding(fd: &FibexData, coding_ref: &str) -> String {
    let no_name = "<no shortname>";

    if let Some(cod) = fd.pi.codings.get(coding_ref) {
        // .coded_type, .compu_methods
        format!(
            "Coding '{}'\nCOMPU-METHODS:#{}\n{}",
            cod.short_name.as_deref().unwrap_or(no_name),
            cod.compu_methods.len(),
            md_for_compu_methods(&cod.compu_methods),
        )
    } else {
        format!("<unknown coding_ref '{}'>", coding_ref)
    }
}

fn md_for_compu_methods(compu_methods: &Vec<CompuMethod>) -> String {
    let mut r = String::with_capacity(1024);
    for cm in compu_methods {
        match cm.category {
            CompuCategory::TextTable => {
                r += "Text table:\n";
                r += &cm
                    .internal_to_phys_scales
                    .iter()
                    .map(|cs| format!("{}", cs))
                    .collect::<Vec<_>>()
                    .join("\n");
            }
            CompuCategory::BitfieldTextTable => {
                r += "Bitfield text table:\n";
                // sort by mask value for now

                let mut masks = cm
                    .internal_to_phys_scales
                    .iter()
                    .filter(|cs| cs.mask.is_some())
                    .filter(|cs| {
                        if let Some(lower_limit) = &cs.lower_limit {
                            if let Some(upper_limit) = &cs.upper_limit {
                                return lower_limit.0 == upper_limit.0
                                    && !(lower_limit.0 == Bound::Included(XsDouble::I64(0)));
                            }
                        }
                        false
                    })
                    .map(|cs| (cs.mask.unwrap(), &cs.lower_limit.as_ref().unwrap().0, cs))
                    .collect::<Vec<_>>();
                masks.sort_by(|a, b| a.0.cmp(&b.0));
                let def_v = XsDouble::I64(0);
                r += &masks
                    .iter()
                    .map(|cs| {
                        format!(
                            "{} -> {}",
                            if let Bound::Included(v) = &cs.1 {
                                v
                            } else {
                                &def_v
                            },
                            if let Some(cc) = &cs.2.compu_const {
                                format!("{}", cc)
                            } else {
                                "<none>".to_string()
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
            }
            _ => {
                r += format!("'{:?}': nyi!", cm.category).as_str();
            }
        }
        r += "\n";
    }
    r += "\n";
    r
}

impl CanPlugin {
    pub fn from_json(
        config: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<CanPlugin, Box<dyn Error>> {
        let name = match &config["name"] {
            serde_json::Value::String(s) => Some(s.clone()),
            _ => None,
        }; // todo check name for Can?
        if name.is_none() {
            return Err(CanPluginError::new("CanPlugin: name missing").into());
        }

        // todo parse ctid and mtin

        let enabled = match &config.get("enabled") {
            Some(serde_json::Value::Bool(b)) => *b,
            None => true, // default to true
            _ => return Err(CanPluginError::new("CanPlugin: config 'enabled' not an bool").into()),
        };

        let fibex_dir = if let Some(serde_json::Value::String(s)) = &config.get("fibexDir") {
            s.clone()
        } else {
            return Err(CanPluginError::new("CanPlugin: fibexDir missing or invalid type").into());
        };

        let mut state: PluginState = Default::default();
        let warnings: Vec<String> = Vec::new();

        let ctid = Some(DltChar4::from_buf(b"TC\0\0"));

        let files = get_all_fibex_in_dir(Path::new(&fibex_dir), false)?; // todo or recursive
        let fibex_data = load_all_fibex(&files)?;

        // update state:

        let mut channels_by_name = fibex_data
            .elements
            .channels
            .iter()
            .map(|c| c.1)
            .collect::<Vec<_>>();
        channels_by_name.sort_unstable_by(|a, b| a.short_name.cmp(&b.short_name));

        state.value = json!({"name":name, "treeItems":[
            if !warnings.is_empty() {
                json!({
                    "label": format!("Warnings #{}", warnings.len()),
                    "iconPath":"warning",
                    "children": warnings.iter().map(|w|{json!({"label":w})}).collect::<Vec<serde_json::Value>>()
                })
            } else {
                json!(null)
            },
            {"label":format!("Channels #{}", fibex_data.elements.channels.len()),
            "children":channels_by_name.iter().map(|channel|{
                let channel_short_name = channel.short_name.as_ref().unwrap_or(&EMPTY_STATIC_STRING);
                serde_json::json!({
                "label":format!("{}, channel id: {}", channel_short_name, channel.id),
                "tooltip":channel.desc,
                "children": sorted_frames(&channel.frame_ref_by_frame_triggering_identifier).iter().map(|(identifier, frame)|{tree_item_for_frame(&fibex_data, channel_short_name, identifier, frame)}).collect::<Vec<serde_json::Value>>(),
            })}).collect::<Vec<serde_json::Value>>(),
            },
            /*{"label":format!("Channels #{}, sorted by name", fibex_data.elements.services_map_by_sid_major.len()),
            "children":channels_by_name.iter().map(|((sid, major), service)|{serde_json::json!({
                "label":format!("{} v{}.{}, service id: {:5} (0x{:04x})", service[0].short_name.as_ref().unwrap_or(&"".to_string()), major, service[0].api_version.1, sid, sid),
                "tooltip":service[0].desc,
                "children": sorted_mids(&service[0].methods_by_mid).iter().map(|(mid, method)|{tree_item_for_mid(mid, method)}).collect::<Vec<serde_json::Value>>(),
            })}).collect::<Vec<serde_json::Value>>(),
            },*/

            {"label":format!("Signals #{}", fibex_data.elements.signals_map_by_id.len())},
            {"label":format!("Codings #{}", fibex_data.pi.codings.len())},
        ]});
        state.generation += 1;

        Ok(CanPlugin {
            name: name.unwrap(),
            enabled,
            state: Arc::new(RwLock::new(state)),
            _fibex_dir: fibex_dir,
            mstp: DltMessageType::NwTrace(DltMessageNwType::Can),
            ctid,
            fibex_data,
            channel_id_by_char4: HashMap::new(),
            log_info_apid: DltChar4::from_buf(b"CAN\0"),
            log_info_ctid: DltChar4::from_buf(b"TC\0\0"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn init_plugin() {
        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        // good case:
        let cfg = json!({"name":"foo","enabled": true, "fibexDir":test_dir});
        let p = CanPlugin::from_json(cfg.as_object().unwrap());
        assert!(p.is_ok());
        let p = p.unwrap();
        assert_eq!(p.name, "foo");
        assert!(p.enabled);
        assert_eq!(p.ctid, Some(DltChar4::from_buf(b"TC\0\0")));

        let state = p.state();
        let state = state.read().unwrap();
        assert_eq!(state.generation, 1); // first update done
        let state_value = &state.value;
        assert!(state_value.is_object());
        let state_obj = state_value.as_object().unwrap();
        assert!(state_obj.contains_key("name"));
        assert!(state_obj.contains_key("treeItems"));
    }
}
