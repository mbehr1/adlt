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
    /// Map channel.short_name -> HashMap frame_id->(channel.id, frame_ref)
    /// Items are in this map as long as they are not mapped/used by an ECUID. Then they are moved to channel_map_by_ecuid.
    channels_frame_ref_map: HashMap<String, HashMap<u32, (String, String)>>,
    /// Map ecuid -> HashMap frame_id->(channel.id, frame_ref)
    channel_map_by_ecuid: HashMap<DltChar4, HashMap<u32, (String, String)>>,
}

impl Plugin for CanPlugin {
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
                        // current assumption is that the ecu is unique per channel and the
                        // channel name is encoded in the APID CAN for that ecu:
                        let channel_map = self.channel_map_by_ecuid.get(&msg.ecu);

                        let channel_id = channel_map
                            .and_then(|m| m.get(&frame_id).or_else(|| m.get(&0)))
                            .map(|p| &p.0);
                        // to avoid the problem that for unknown frames no channel_id is passed we store the first matching channel_id in frame id 0

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
            } else if msg.payload_text.is_none() {
                // else keep the existing payload_text (e.g. Error Frame)
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
                    let retval = payload.first().unwrap();
                    let payload = &payload[1..];
                    let apids = parse_ctrl_log_info_payload(*retval, is_big_endian, payload);
                    if apids.len() == 1 {
                        let apid_info = &apids[0];
                        if let Some(desc) = apid_info.desc.as_deref() {
                            // now search fd for a channel with that name and move from channels_frame_ref_map to channel_map_by_ecuid
                            if let std::collections::hash_map::Entry::Vacant(entry) =
                                self.channel_map_by_ecuid.entry(msg.ecu.to_owned())
                            {
                                let channel_name = if self.channels_frame_ref_map.contains_key(desc)
                                {
                                    Some(desc.to_owned())
                                } else {
                                    // if no full matchen then search a matching name
                                    // currently: that starts with e.g. for cases like "IuK_CAN 431" -> "IuK_CAN"
                                    self.channels_frame_ref_map
                                        .keys()
                                        .find(|&key| desc.starts_with(key))
                                        .map(|k| k.to_owned())
                                };
                                if let Some(channel_name) = &channel_name {
                                    let channel_map =
                                        self.channels_frame_ref_map.remove(channel_name);
                                    if let Some(channel_map) = channel_map {
                                        entry.insert(channel_map);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        true
    }
}

fn sorted_frames(
    frames: Option<&HashMap<u32, (String, String)>>,
) -> Vec<(&u32, &(String, String))> {
    if let Some(frames) = frames {
        let mut v = frames.iter().collect::<Vec<_>>();
        v.sort_unstable_by(|a, b| a.0.cmp(b.0));
        v
    } else {
        vec![]
    }
}

// todo fix BigInt conversion "23n" -> BigInt("23n") ? (can report handle really big ints?)
/**
A very simple javascript function that is used as conversionFunction (see dlt-logs/report-generation)
to parse the json data from the textual representation of a frame to a report.

It should be extended/replaced by a better mechanism where more type info from the fibex is used
(e.g. invalid values, *bitfields*, min/max, mapping to enums (as they are not printed)...)
 */
const JS_FRAME_CONVERSION_FUNCTION: &str = r#"
const r=params.localObj.r || (params.localObj.r=/]:{"(.+?)":(.+)}$/);
const m=r.exec(params.msg.payloadString);
let o={};
if(m!==null){
    const v=JSON5.parse(m[2]);
    const fn=(p,v,o)=> {
        switch(typeof v){
            case 'number': o[p]=v;break;
            case 'string': o[`STATE_${p}`]=v;break;
            case 'object': Object.keys(v).forEach(vc=>{fn(`${p}.${vc}`, v[vc],o);}); break;
        }
    };
    fn(m[1],v,o);
}
return o;
"#;

// todos/ideas:
// + (done using array with tuple/array mask/v/text) add bitfield text table as sep. EVENTs (or STATE with auto null?) (own graph for each of those?)
// - add stable order to enums (e.g. by key value) (currently it's by: occurrence in data)
// - add scale support incl. units (e.g. 4000 -> 1000V for a *0.25 scale)
// - remove CRC&ALIVE? (or at least as EVENTS to prevent lines?)
// + (done using stSet) optimize case STATE+EVENT cases to not always set the STATE_p=null if EVENT_p is used

const JS_FRAME_CONVERSION_FUNCTION_MAP: &str = r#"
const r=params.localObj.r || (params.localObj.r=/]:{"(.+?)":(.+)}$/);
const m=r.exec(params.msg.payloadString);
let o={};
if(m!==null){
    const map=params.localObj.vMap || (params.localObj.stSet=new Set(), params.localObj.vMap=new Map([{{VMAP}}]));
    const stSet = params.localObj.stSet;
    const v=JSON5.parse(m[2]);
    const fn=(p,v,o,m)=> {
        switch(typeof v){
            case 'number': if(m){
                if (Array.isArray(m)){
                    let f=false;
                    for (const tup of m){
                        const [mask,val,tex]=tup;
                        const nam = `TL_${p}_${tex}`
                        if ((v & mask) === val){
                            f=true;
                            o[nam]='0x'+val.toString(16)+'|0x'+v.toString(16)+'|lightblue';
                            stSet.add(nam);
                        }else{
                            if (stSet.has(nam)){
                                o[nam]='off||grey|';
                                stSet.delete(nam);
                            }
                        }
                    };
                    if (!f){
                        o[`EVENT_${p}`]=v;
                    }
                }else{
                    const mv=m.get(v);
                    if (mv!==undefined){
                        o[`STATE_${p}`]=mv;
                        stSet.add(p);
                    } else {
                        if (stSet.has(p)){
                            o[`STATE_${p}`]=null;
                            stSet.delete(p);
                        }
                        o[`EVENT_${p}`]=v;
                    }
                }
            } else { o[p]=v; }
            break;
            case 'string': o[`STATE_${p}`]=v;break;
            case 'object': Object.keys(v).forEach(vc=>{const oM=m ? m.get(vc):undefined; fn(`${p}.${vc}`, v[vc],o, oM);}); break;
        }
    };
    fn(m[1],v,o,map);
}
return o;
"#;

fn js_frame_conversion_function(js_value_map: &str) -> String {
    if js_value_map.is_empty() {
        JS_FRAME_CONVERSION_FUNCTION.to_string()
    } else {
        JS_FRAME_CONVERSION_FUNCTION_MAP.replace("{{VMAP}}", js_value_map)
    }
}

fn tree_item_for_frame(
    fd: &FibexData,
    channel_short_name: &str,
    identifier: &u32,
    channel_id_frame_ref: &(String, String),
) -> serde_json::Value {
    let no_name = "<no shortname>";
    let no_desc = "<no desc>";
    let (_channel_id, frame_ref) = channel_id_frame_ref;

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
                serde_json::json!({
                    "apid":"CAN",
                    "ctid":"TC",
                    "payloadRegex":format!("^. {} 0x{:03x} ", channel_short_name, identifier),
                    "reportOptions":{
                        "conversionFunction": JS_FRAME_CONVERSION_FUNCTION
                    }
                }),
            "children": frame.pdu_instances.iter().map(|pdu_instance|{tree_item_for_pdu(fd, pdu_instance, channel_short_name, identifier)}).collect::<Vec<serde_json::Value>>(),
        })
    } else {
        json!({ "label": format!("0x{:03x} frame ref {} unknown!", identifier, frame_ref) })
    }
}

fn tree_item_for_pdu(
    fd: &FibexData,
    pdu_instance: &PduInstance,
    channel_short_name: &str,
    identifier: &u32,
) -> serde_json::Value {
    let no_name = "<no shortname>";
    let no_desc = "<no desc>";

    let pdu = fd.elements.pdus_map_by_id.get(&pdu_instance.pdu_ref);
    if let Some(pdu) = pdu {
        let short_name = pdu.short_name.as_deref().unwrap_or(no_name);

        // do we have a js mapping table?
        let js_map = pdu
            .signal_instances
            .iter()
            .filter_map(|signal_instance| js_for_signal(fd, signal_instance))
            .collect::<Vec<String>>()
            .join(",");

        let filter_frag = if js_map.is_empty() {
            json!(null)
        } else {
            serde_json::json!({
                "apid":"CAN",
                "ctid":"TC",
                "payloadRegex":format!("^. {} 0x{:03x} ", channel_short_name, identifier),
                "reportOptions":{
                    "conversionFunction": js_frame_conversion_function(&js_map)
                }
            })
        };

        json!({ "label": format!("{}", short_name),
            "tooltip": format!("description:\n{}\nbyte length: {}\nsignals:\n{}",
                pdu.desc.as_deref().unwrap_or(no_desc),
                pdu.byte_length,
                pdu.signal_instances.iter().map(|s|format!("{}:tbd", s.signal_ref.as_str(), )).collect::<Vec<_>>().join("\n")
            ),
            "filterFrag": filter_frag,
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

fn js_for_signal(fd: &FibexData, signal_instance: &SignalInstance) -> Option<String> {
    let no_name = "<no shortname>";

    let signal = fd
        .elements
        .signals_map_by_id
        .get(&signal_instance.signal_ref);
    if let Some(signal) = signal {
        let short_name = signal.short_name.as_deref().unwrap_or(no_name);
        Some(format!(
            "[\"{}\",{}]",
            short_name,
            js_for_coding(fd, &signal.coding_ref)
        ))
    } else {
        None
    }
}

fn js_for_coding(fd: &FibexData, coding_ref: &str) -> String {
    if let Some(cod) = fd.pi.codings.get(coding_ref) {
        js_for_compu_methods(&cod.compu_methods)
    } else {
        js_for_compu_methods(&vec![])
    }
}

/// Generate javascript code that defines a map initializer
/// that maps values to enums/text table entries.
///
/// returns 'undefined' for no text table entries or 'new Map([[key1, value1],...])' where key1 = raw value, value1 = enum/text
fn js_for_compu_methods(compu_methods: &Vec<CompuMethod>) -> String {
    let mut r = String::with_capacity(1024);
    let initial_r_len = r.len();
    let mut closing_str = String::with_capacity(2);
    for cm in compu_methods {
        match cm.category {
            CompuCategory::TextTable => {
                if r.len() == initial_r_len {
                    // we support only either a TextTable or  Bitfield
                    r += "new Map(["; // texttable uses a Map
                    closing_str += "])";
                    r += &cm
                        .internal_to_phys_scales
                        .iter()
                        .filter(|cs| cs.get_single_value().is_some() && cs.compu_const.is_some())
                        .map(|cs| {
                            format!(
                                "[{},{:?}]",
                                cs.get_single_value().unwrap(),
                                if let Some(afibex::fibex::VvT::VT(en)) = &cs.compu_const {
                                    en // todo needs escaping of "!
                                } else {
                                    ""
                                }
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                }
            }
            CompuCategory::BitfieldTextTable => {
                if r.len() == initial_r_len {
                    // we encode the bitfields as an array or tuple(array) with mask/value/text
                    r += "[";
                    r += &cm
                        .internal_to_phys_scales
                        .iter()
                        .filter(|cs| {
                            cs.get_single_value().is_some()
                                && cs.mask.is_some()
                                && cs.compu_const.is_some()
                                && cs.get_single_value().unwrap() != &XsDouble::I64(0)
                        })
                        .map(|cs| {
                            let v = cs.get_single_value().unwrap();
                            let mask = cs.mask.unwrap();
                            format!(
                                "[{},{},{:?}]",
                                mask,
                                v,
                                if let Some(afibex::fibex::VvT::VT(en)) = &cs.compu_const {
                                    en // todo needs escaping of "!
                                } else {
                                    ""
                                }
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    closing_str += "]";
                }
            }
            _ => {}
        }
    }
    if r.len() == initial_r_len {
        r.clear();
        r += "undefined";
        r
    } else {
        r += &closing_str;
        r
    }
}

impl CanPlugin {
    /// inserts all frames from to_merge into the target hashmap
    /// where the frame.id is not yet contained.
    /// For each frame inserted the channel_id and frame_ref will be inserted.
    /// If the target is empty a special id 0 is inserted with the channel id only.
    fn insert_missing_frame_ref(
        target: &mut HashMap<u32, (String, String)>,
        to_merge: &afibex::fibex::Channel,
    ) {
        if target.is_empty() {
            // insert frame id 0 with channel_id
            target.insert(0, (to_merge.id.to_owned(), "".to_owned()));
        }

        for frame_to_merge in to_merge.frame_ref_by_frame_triggering_identifier.iter() {
            if !target.contains_key(frame_to_merge.0) {
                target.insert(
                    *frame_to_merge.0,
                    (to_merge.id.to_owned(), frame_to_merge.1.to_owned()),
                );
            }
        }
    }

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

        // we merge the channels by channel short-name to support multiple fibex
        // map channel short-name -> Map with frame-id -> Channel_id/frame_ref
        let mut channels_frame_ref_map: HashMap<String, HashMap<u32, (String, String)>> =
            HashMap::new();

        for channel in fibex_data.elements.channels.values() {
            if let Some(short_name) = &channel.short_name {
                let channel_map = channels_frame_ref_map
                    .entry(short_name.to_string())
                    .or_default();
                Self::insert_missing_frame_ref(channel_map, channel);
            }
        }

        let mut channels_by_name = channels_frame_ref_map
            .iter()
            .map(|c| c.0.to_owned())
            .collect::<Vec<_>>();
        channels_by_name.sort_unstable();

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
            {"label":format!("Channels #{}", channels_by_name.len()),
            "children":channels_by_name.iter().map(|channel_short_name|{
                let channel_map = channels_frame_ref_map.get(channel_short_name);
                serde_json::json!({
                "label":format!("{}, frames: {}", channel_short_name, channel_map.map(|m|m.len()-1).unwrap_or(0)),
                // todo collect all desc! "tooltip":channel.desc,
                "children": sorted_frames(channel_map).iter().skip(1).map(|(identifier, channel_id)|{tree_item_for_frame(&fibex_data, channel_short_name, identifier, channel_id)}).collect::<Vec<serde_json::Value>>(),
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
            channels_frame_ref_map,
            channel_map_by_ecuid: HashMap::new(),
            log_info_apid: DltChar4::from_buf(b"CAN\0"),
            log_info_ctid: DltChar4::from_buf(b"TC\0\0"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afibex::fibex::{CompuScale, IntervalType};
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

    #[test]
    fn js_for_compu_methods_test1() {
        let cm = vec![];
        let r = js_for_compu_methods(&cm);
        assert_eq!(r, "undefined");

        let cm = vec![CompuMethod {
            category: CompuCategory::TextTable,
            internal_to_phys_scales: vec![],
        }];
        let r = js_for_compu_methods(&cm);
        assert_eq!(r, "new Map([])");

        let v1: XsDouble = XsDouble::I64(1_i64);

        let cm = vec![CompuMethod {
            category: CompuCategory::TextTable,
            internal_to_phys_scales: vec![CompuScale {
                mask: None,
                lower_limit: Some(IntervalType(std::ops::Bound::Included(v1.clone()))),
                upper_limit: Some(IntervalType(std::ops::Bound::Included(v1.clone()))),
                compu_const: Some(afibex::fibex::VvT::VT("foo".to_string())),
            }],
        }];
        let r = js_for_compu_methods(&cm);
        assert_eq!(r, r##"new Map([[1,"foo"]])"##);

        let v2: XsDouble = XsDouble::I64(2_i64);
        let cm = vec![CompuMethod {
            category: CompuCategory::BitfieldTextTable,
            internal_to_phys_scales: vec![
                CompuScale {
                    mask: Some(1u64),
                    lower_limit: Some(IntervalType(std::ops::Bound::Included(v1.clone()))),
                    upper_limit: Some(IntervalType(std::ops::Bound::Included(v1))),
                    compu_const: Some(afibex::fibex::VvT::VT("mask1".to_string())),
                },
                CompuScale {
                    mask: Some(2u64),
                    lower_limit: Some(IntervalType(std::ops::Bound::Included(v2.clone()))),
                    upper_limit: Some(IntervalType(std::ops::Bound::Included(v2))),
                    compu_const: Some(afibex::fibex::VvT::VT("mask2".to_string())),
                },
            ],
        }];
        let r = js_for_compu_methods(&cm);
        assert_eq!(r, r##"[[1,1,"mask1"],[2,2,"mask2"]]"##);

        // todo think about BigInt support...
    }
}
