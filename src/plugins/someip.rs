// copyright Matthias Behr, (c) 2022
//
// todos:
// [ ] remove old partial segmented data... (e.g. by max time)
// [ ] modify timestamp of last segment of a segmented msg reflect the time from first msg

use crate::{
    dlt::{DltChar4, DltMessage, DltMessageNwType, DltMessageType},
    plugins::plugin::{LcsRType, Plugin, PluginState, TreeItem},
};
use afibex::fibex::{
    get_all_fibex_in_dir, load_all_fibex, FibexData, FibexError, MethodIdType, Service,
};
use asomeip::utils::decode_someip_header_and_payload;
use serde_json::json;
use std::{
    collections::HashMap,
    error::Error,
    fmt,
    path::Path,
    sync::{Arc, RwLock},
};

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
    state: Arc<RwLock<PluginState>>,
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

impl Plugin for SomeipPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn state(&self) -> Arc<RwLock<PluginState>> {
        self.state.clone()
    }
    fn set_lifecycle_read_handle(&mut self, _lcs_r: &LcsRType) {}

    fn sync_all(&mut self) {}

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
                                        } else {
                                            decoded_header = Some(Ok(format!(
                                                "SOME/IP segmented message NWEN {segment_id} for unknown id!"
                                            )));
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
                                            "SOME/IP segmented message NWCH {segment_id} ({chunk_nr})"
                                        )));
                                    } else {
                                        decoded_header = Some(Ok(format!(
                                            "SOME/IP segmented message NWCH {} ({}) chunk out-of-sequence! (got chunks={} / exp {}) or wrong size!",
                                            segment_id, chunk_nr, got_chunks, smi.expected_nr_chunks
                                        )));
                                    }
                                } else {
                                    decoded_header = Some(Ok(format!(
                                        "SOME/IP segmented message NWCH {segment_id} ({chunk_nr}) for unknown id!"
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
                                "SOME/IP segmented message NWST id: {segment_id} amount: {start_expected_nr_chunk}"
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
                match decoded_header {
                    Some(Ok(text)) => {
                        msg.set_payload_text(text);
                    }
                    Some(Err(e)) => {
                        msg.set_payload_text(format!("someip plugin! got decoding err={e:?}"));
                    }
                    None => {
                        // no header decoded, but segmented msg
                        let cur_payload = msg.payload_as_text();
                        msg.set_payload_text(format!(
                            "someip plugin! cannot decode: {cur_payload:?}"
                        ));
                    }
                }
            } // for None do nothing
        }
        true
    }
}

enum MethodTreeType<'a> {
    Method(&'a afibex::fibex::Method),
    Event(&'a afibex::fibex::Method),
    Field {
        field: &'a Arc<afibex::fibex::Parameter>,
        getter: Option<u16>,
        setter: Option<u16>,
        notifier: Option<u16>,
    },
}

/**
sort the methods into a tree-alike structure with
* methods first
* events
* fields (instead of 3 single items per getter,setter, notifier)
*/
fn sorted_mids_by_type(methods: &HashMap<u16, MethodIdType>) -> Vec<(u16, MethodTreeType)> {
    let mut v = vec![];
    for method in methods {
        match method.1 {
            MethodIdType::Method(m) => v.push((*method.0, MethodTreeType::Method(m))),
            MethodIdType::Event(m) => v.push((*method.0, MethodTreeType::Event(m))),
            MethodIdType::Setter { field }
            | MethodIdType::Getter { field }
            | MethodIdType::Notifier { field } => {
                let is_setter = matches!(method.1, MethodIdType::Setter { field: _ });
                let is_getter = matches!(method.1, MethodIdType::Getter { field: _ });
                let is_notifier = matches!(method.1, MethodIdType::Notifier { field: _ });
                // do we have this Parameter already?
                let nfield = field;
                let p = v.iter_mut().find(|(_m, p)| {
                    if let MethodTreeType::Field {
                        field,
                        getter: _,
                        setter: _,
                        notifier: _,
                    } = p
                    {
                        field.id == nfield.id
                    } else {
                        false
                    }
                });
                if let Some(p) = p {
                    if let MethodTreeType::Field {
                        field: _,
                        getter,
                        setter,
                        notifier,
                    } = &mut p.1
                    {
                        if is_getter {
                            *getter = Some(*method.0);
                        }
                        if is_setter {
                            *setter = Some(*method.0);
                        }
                        if is_notifier {
                            *notifier = Some(*method.0);
                        }
                        if *method.0 < p.0 {
                            // update mid in vec used for sorting
                            p.0 = *method.0;
                        }
                    }
                } else {
                    v.push((
                        *method.0,
                        MethodTreeType::Field {
                            field,
                            getter: if is_getter { Some(*method.0) } else { None },
                            setter: if is_setter { Some(*method.0) } else { None },
                            notifier: if is_notifier { Some(*method.0) } else { None },
                        },
                    ));
                }
            }
        }
    }
    v.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    v
}

/// create a tree item for a parameter of an event
fn tree_item_for_event_parameter(
    service: &Service,
    event_name: &str,
    p: &afibex::fibex::Parameter,
) -> TreeItem {
    let no_name = "<no shortname>";
    let no_desc = "<no desc>";

    TreeItem {
        label: p.short_name.as_deref().unwrap_or(no_name).to_string(),
        tooltip: Some(format!(
            "datatype:\n{}{}\ndescription:\n{}",
            p.datatype_ref, if p.mandatory {""} else {" optional"},
            p.desc.as_deref().unwrap_or(no_desc)
        )),
        filter_frag: service.short_name.as_ref().map(|service_name| {
            serde_json::json!({
                    "ctid":"TC",
                    "payloadRegex":format!("^\\* \\(....:....\\) {}\\(....\\)\\.{}{{", service_name, event_name),
                    "reportOptions":{
                        "conversionFunction": js_conv_fn_for_parameter(p.short_name.as_deref().unwrap_or(no_name))
                    }
            })
        }),
        ..Default::default()
    }
}

fn tree_item_for_mid_types(
    mid: &u16,
    method: &MethodTreeType,
    service: &Service,
) -> serde_json::Value {
    let no_name = "<no shortname>";
    let no_desc = "<no desc>";
    match method {
        MethodTreeType::Method(m) => {
            let method_name = m.short_name.as_deref().unwrap_or(no_name);
            json!({ "label": format!("0x{:04x} Method: {}", mid, method_name),
                "tooltip": format!("description:\n{}\ninput parameter:\n{}\nreturn parameter:\n{}",
                    m.desc.as_deref().unwrap_or(no_desc),
                    m.input_params.iter().map(|p|format!("{}:{}", p.short_name.as_deref().unwrap_or(no_name), p.datatype_ref)).collect::<Vec<_>>().join("\n"),
                    m.return_params.iter().map(|p|format!("{}:{}", p.short_name.as_deref().unwrap_or(no_name), p.datatype_ref)).collect::<Vec<_>>().join("\n")
                ),
                "filterFrag": if let Some(service_name)=service.short_name.as_ref() {
                    serde_json::json!({
                        "ctid":"TC",
                        "payloadRegex":format!("^(.) \\((....:....)\\) ({})\\(....\\)\\.({}){{(.*?)}}\\[.*\\]$", service_name, method_name), // todo use ctid var and better filter for payload_raw!
                        "reportOptions":{
                            "conversionFunction": JS_METHOD_CONVERSION_FUNCTION
                        }
                })}else{
                    serde_json::Value::Null
                },
            })
        }
        MethodTreeType::Event(m) => {
            let event_name = m.short_name.as_deref().unwrap_or(no_name);
            json!({
            "label": format!("0x{:04x} Event: {}", mid, event_name),
            "tooltip": format!("description:\n{}\ninput parameter:\n{}",
                m.desc.as_deref().unwrap_or(no_desc),
                m.input_params.iter().map(|p|format!("{}:{}", p.short_name.as_deref().unwrap_or(no_name), p.datatype_ref)).collect::<Vec<_>>().join("\n")),
            "filterFrag": if let Some(service_name)=service.short_name.as_ref() {
                serde_json::json!({
                    "ctid":"TC",
                    "payloadRegex":format!("^\\* \\(....:....\\) {}\\(....\\)\\.{}{{", service_name, event_name), // todo use ctid var and better filter for payload_raw!
                    "reportOptions":{
                        "conversionFunction": JS_EVENT_CONVERSION_FUNCTION
                    }
            })}else{
                serde_json::Value::Null
            },
            "children":m.input_params.iter().map(|p|tree_item_for_event_parameter(service, event_name, p)).collect::<Vec<TreeItem>>(),
            })
        }
        MethodTreeType::Field {
            field,
            getter,
            setter,
            notifier,
        } => {
            let field_name = field.short_name.as_deref().unwrap_or(no_name);
            json!({
                "label":
                    format!(
                        "0x{:04x} Field: {} - {}{}{}",
                        mid,
                        field_name,
                        if let Some(g) = getter {
                            format!("Getter({g:04x}) ")
                        } else {
                            "".to_owned()
                        },
                        if let Some(g) = setter {
                            format!("Setter({g:04x}) ")
                        } else {
                            "".to_owned()
                        },
                        if let Some(g) = notifier {
                            format!("Notifier({g:04x})")
                        } else {
                            "".to_owned()
                        },
                    ),
                "filterFrag": if let Some(short_name)=service.short_name.as_ref() {
                    let mut filter_frags = vec![
                        serde_json::json!({
                        "ctid":"TC",
                        "payloadRegex":format!("^. \\(....:....\\) {}\\(....\\)\\.(?:changed|set|get)_{}_field", short_name, field_name),
                        "reportOptions":{
                            "conversionFunction": JS_FIELD_CONVERSION_FUNCTION
                        }})];
                    if getter.is_some() || setter.is_some(){
                        filter_frags.push(serde_json::json!({
                            "ctid":"TC",
                            "payloadRegex":format!("^(.) \\((....:....)\\) ({})\\(....\\)\\.((?:set|get)_{}_field){{(.*?)}}\\[.*\\]$", short_name, field_name),
                            "reportOptions":{
                                "conversionFunction": JS_METHOD_CONVERSION_FUNCTION
                            }}));
                    }
                    filter_frags
                }else{
                    vec![]
                },
            })
        }
    }
}

// todo check behaviour for overlapping calls (e.g. call1, call2, resp1, resp2 or call1, call2, resp2, resp1)
// todo check err != [OK] and add different represenation
const JS_METHOD_CONVERSION_FUNCTION: &str = r#"
const isResp = matches[1]==='<'
const isFireForget = matches[1]==='\\'
const isCall = matches[1]==='>' || isFireForget
const sName = matches[3]
const sidReq = matches[2]
const fnName = matches[4]
const callParams = matches[5]
const map = params.localObj.pendingCallsMap || (params.localObj.pendingCallsMap=new Map())

let tl
if (isCall){
  tl = new uv0.TL(sName, fnName, `(${callParams})`, { tooltip: matches[0], color: isFireForget? 'GreenYellow':'red', tlEnds: isFireForget, lateEval:true})  
  map.set(sidReq, tl)
}else if (isResp){
  tl = map.get(sidReq)
  if (tl === undefined){
    tl = new uv0.TL(sName, fnName, `=${callParams}`, { tooltip: matches[0], color: 'yellow', tlEnds: isResp })
  }else{
    tl.color='green'
    tl.value = tl.value + '=' + callParams
    tl.tooltip = tl.tooltip + '\n' + matches[0]
    tl = new uv0.TL(sName, fnName, tl.value, { color: 'green', tlEnds: true })
    map.delete(sidReq)
  }
}     
return tl
"#;

// todo fix BigInt conversion "23n" -> BigInt("23n") ? (can report handle really big ints?)
// todo map someip events to events (EVENT_) and someip fields to STATE_ or values ...
// field = combination of getter/setter/notifier
/**
A very simple javascript function that is used as conversionFunction (see dlt-logs/report-generation)
to parse the json data from fields to a report.

It should be extended/replaced by a better mechanism where more type info from the fibex is used
(e.g. invalid values, *bitfields*, min/max,...)
 */
const JS_FIELD_CONVERSION_FUNCTION: &str = r#"
const r=/\.(?:changed|set|get)_.*?_field{"(.+?)":(.+)}\[OK\]$/;
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

// map events
// events w.o. parameter get mapped to EVENT_<name> to use scatter and no charts/lines
// events with parameter are treated like regular fields
// it can be:
// * (0000:0000) VehicleInformation(0001).RelativeTime1{}[OK]
// * (0000:0000) VehicleInformation(0001).RelativeTime2{"timeSecondCounterRelative":94198733}[OK]
// * (0000:0000) VehicleInformation(0001).RelativeTime3{"timeSecondCounterRelative":94198733,"timeDayCounterAbsolute":8284}[OK]
// * (0000:0000) VehicleInformation(0001).RelativeTime4{"timeSecondCounterRelative":94198733,"timeDayCounterAbsoluteO":{"valid":true}}}[OK]

// todo add a try/catch around json.parse

const JS_EVENT_CONVERSION_FUNCTION: &str = r"
const r=/\)\.(.+?)(?={)(.*)\[OK\]$/;
const m=r.exec(params.msg.payloadString);
let o={};
if(m!==null){
    const evName=m[1];
    if (m[2].length>2){
        const v=JSON5.parse(m[2]);
        const fn=(p,v,o)=> {
            switch(typeof v){
                case 'number': o[p]=v;break;
                case 'string': o[`STATE_${p}`]=v;break;
                case 'object': Object.keys(v).forEach(vc=>{fn(`${p}.${vc}`, v[vc],o);}); break;
            }
        };
        fn(`${evName}`,v,o);
    }else{
        o[`EVENT_${evName}`]=1.0; // map to 1.0
    }
}
return o;
";

/// similar to the static JS_EVENT_CONVERSION_FUNCTION but with a parameter name
/// that is used to extract the value from the json data
///
/// todo refactor into single functions or some better replacement mechanism
fn js_conv_fn_for_parameter(parameter_name: &str) -> String {
    const JS_EVENT_P_CONVERSION_FUNCTION: &str = r"
const r=/\)\.(.+?)(?={)(.*)\[OK\]$/;
const m=r.exec(params.msg.payloadString);
let o={};
if(m!==null){
    const evName=m[1];
    if (m[2].length>2){
        const v=JSON5.parse(m[2]);
        const fn=(p,v,o)=> {
            switch(typeof v){
                case 'number': o[p]=v;break;
                case 'string': o[`STATE_${p}`]=v;break;
                case 'object': Object.keys(v).forEach(vc=>{fn(`${p}.${vc}`, v[vc],o);}); break;
            }
        };
        fn(`${evName}.${pname}`,v[pname],o);
    }else{
        o[`EVENT_${evName}`]=1.0; // map to 1.0
    }
}
return o;
";

    format!("const pname='{parameter_name}';{JS_EVENT_P_CONVERSION_FUNCTION}")
}

// todo add overview for methods as well
// nicest way would be to be able to set an array of filterFrags... but that needs support in dlt-logs first!

fn tree_item_for_service(
    ((sid, major), service): &(&(u16, u8), &Vec<Service>),
) -> serde_json::Value {
    serde_json::json!({
        "label":format!("{} v{}.{}, service id: {:5} (0x{:04x})", service[0].short_name.as_ref().unwrap_or(&"".to_string()), major, service[0].api_version.1, sid, sid),
        "tooltip":service[0].desc,
        "filterFrag": if let Some(short_name)=service[0].short_name.as_ref() {
            vec![
                serde_json::json!({
                    "ctid":"TC",
                    "payloadRegex":format!("^. \\(....:....\\) {}\\(....\\)", short_name), // todo use ctid var and better filter for payload_raw!
                    "reportOptions":{ // todo add only (set to null) if fields (others than methods are available)
                        "conversionFunction": JS_FIELD_CONVERSION_FUNCTION
                    }
                }),
                serde_json::json!({
                    "ctid":"TC",
                    "payloadRegex":format!("^(.) \\((....:....)\\) ({})\\(....\\)\\.(.*?){{(.*?)}}\\[.*\\]$", short_name),
                    "reportOptions":{
                        "conversionFunction": JS_METHOD_CONVERSION_FUNCTION
                    }
                })]
        }else{
            vec![]
        },
        "children": sorted_mids_by_type (&service[0].methods_by_mid).iter().map(|(mid, method)|{tree_item_for_mid_types(mid, method, &service[0])}).collect::<Vec<serde_json::Value>>(),
    })
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

        let enabled = match &config.get("enabled") {
            Some(serde_json::Value::Bool(b)) => *b,
            None => true, // default to true
            _ => {
                return Err(
                    SomeipPluginError::new("SomeipPlugin: config 'enabled' not an bool").into(),
                )
            }
        };

        let fibex_dir = if let Some(serde_json::Value::String(s)) = &config.get("fibexDir") {
            s.clone()
        } else {
            return Err(
                SomeipPluginError::new("SomeipPlugin: fibexDir missing or invalid type").into(),
            );
        };

        let mut state: PluginState = Default::default();
        let mut warnings: Vec<String> = Vec::new();

        let ctid = Some(DltChar4::from_buf(b"TC\0\0"));

        let files = get_all_fibex_in_dir(Path::new(&fibex_dir), false)?; // todo or recursive
        let fibex_data = load_all_fibex(&files)?;

        if files.is_empty() {
            warnings.push(format!("No fibex files found in directory: {fibex_dir}"));
        } else if fibex_data.projects.is_empty() {
            warnings.push(format!(
                "No fibex projects parsed from fibex files found in directory: {fibex_dir}"
            ));
        }
        // add any of those warnings after the prev one.
        for warning in &fibex_data.parse_warnings {
            warnings.push(warning.clone());
        }

        // update state:
        let mut services_by_name = fibex_data
            .elements
            .services_map_by_sid_major
            .iter()
            .collect::<Vec<_>>();
        services_by_name.sort_unstable_by(|a, b| a.1[0].short_name.cmp(&b.1[0].short_name));

        let mut services_by_id = services_by_name.clone();
        services_by_id.sort_unstable_by(|a, b| a.0 .0.cmp(&b.0 .0));

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
            {"label":format!("Services #{}, sorted by name", fibex_data.elements.services_map_by_sid_major.len()),
            "children":services_by_name.iter().map(tree_item_for_service).collect::<Vec<serde_json::Value>>(),
            },
            {"label":format!("Services #{}, sorted by service id", fibex_data.elements.services_map_by_sid_major.len()),
            "children":services_by_id.iter().map(tree_item_for_service).collect::<Vec<serde_json::Value>>(),
            },
            {"label":format!("Datatypes #{}", fibex_data.elements.datatypes_map_by_id.len())},
            {"label":format!("Codings #{}", fibex_data.pi.codings.len())},
        ],
        "warnings":warnings});
        state.generation += 1;

        Ok(SomeipPlugin {
            name: name.unwrap(),
            enabled,
            state: Arc::new(RwLock::new(state)),
            _fibex_dir: fibex_dir,
            mstp: DltMessageType::NwTrace(DltMessageNwType::Ipc),
            ctid,
            fibex_data,
            segmented_msgs_map: HashMap::with_capacity(16),
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
        let p = SomeipPlugin::from_json(cfg.as_object().unwrap());
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
