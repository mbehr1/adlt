use crate::{
    dlt::{DltArg, DltChar4, DltMessage, DLT_TYPE_INFO_UINT},
    plugins::plugin::{Plugin, PluginError, PluginState},
    utils::get_all_files_with_ext_in_dir,
};

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::json;

use std::{
    collections::HashMap,
    error::Error,
    path::Path,
    sync::{Arc, RwLock},
};

#[derive(Debug)]
struct ConfigPerEcu {
    #[allow(dead_code)]
    version: String,
    #[allow(dead_code)]
    git: String,
    model_hash: String,
}

// static Default Config:
lazy_static! {
    static ref DEFAULT_CONFIG_PER_ECU: ConfigPerEcu = ConfigPerEcu {
        version: String::from("20.48"),
        git: String::from(""),
        model_hash: String::from("0"),
    };
}

#[derive(Debug)]
pub struct MuniicPlugin {
    name: String,
    enabled: bool,
    state: Arc<RwLock<PluginState>>,
    msg_ctid: DltChar4,
    config_ctid: DltChar4,
    config_regex: regex::Regex,
    json_config: MuniicJsonConfig,
    config_data_per_ecu: HashMap<DltChar4, ConfigPerEcu>,
}

impl Plugin for MuniicPlugin {
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
        if let Some(ext_header) = &msg.extended_header {
            if ext_header.is_verbose() {
                if ext_header.ctid == self.msg_ctid {
                    if ext_header.noar == 13 {
                        // println!("MuniicPlugin: got msg msg {:?}", msg);
                        // get config for this ecu:
                        let config = self
                            .config_data_per_ecu
                            .get(&msg.ecu)
                            .unwrap_or(&DEFAULT_CONFIG_PER_ECU);
                        // parse arguments:
                        // 7 = interface id
                        // 8 = message id
                        // 12 = payload
                        let args = msg.into_iter();
                        let mut interface_id: Option<u32> = None;
                        let mut message_id: Option<u32> = None;
                        let mut new_payload_text: Option<String> = None;
                        for (nr_arg, arg) in args.enumerate() {
                            match nr_arg {
                                7 | 8 => {
                                    // interface or method id
                                    if (arg.type_info & DLT_TYPE_INFO_UINT) > 0
                                        && arg.payload_raw.len() == 4
                                    {
                                        let val: u32 = if arg.is_big_endian {
                                            u32::from_be_bytes(arg.payload_raw.try_into().unwrap())
                                        } else {
                                            u32::from_le_bytes(arg.payload_raw.try_into().unwrap())
                                        };
                                        match nr_arg {
                                            7 => interface_id = Some(val),
                                            8 => message_id = Some(val),
                                            _ => {}
                                        }
                                    }
                                }
                                12 => {
                                    if let Some(interface_id) = interface_id {
                                        if let Some(interface) = get_interface(
                                            &self.json_config,
                                            &config.model_hash,
                                            interface_id,
                                        ) {
                                            /*println!(
                                                "MuniicPlugin: got msg with interface_id {} interface={:?}",
                                                interface_id, interface
                                            );*/
                                            if let Some(message_id) = message_id {
                                                if let Some(method_or_attribute) =
                                                    get_method_or_attribute(interface, message_id)
                                                {
                                                    match method_or_attribute {
                                                        MethodOrAttribute::Method(method) => {
                                                            //println!("MuniicPlugin: got msg with interface_id {} message_id {} method={:?}", interface_id, message_id, method);
                                                            new_payload_text =
                                                                decode_method(method, &arg);
                                                        }
                                                        MethodOrAttribute::Attribute(attribute) => {
                                                            //println!("MuniicPlugin: got msg with interface_id {} message_id {} attribute={:?}", interface_id, message_id, attribute);
                                                            if let Some((
                                                                payload_text,
                                                                rem_payload,
                                                            )) = decode_attribute(
                                                                attribute,
                                                                arg.payload_raw,
                                                                None,
                                                            ) {
                                                                new_payload_text =
                                                                    Some(payload_text);
                                                                if !rem_payload.is_empty() {
                                                                    // println!("MuniicPlugin: got msg with interface_id {} message_id {} attribute={:?} but payload not empty: {:?}", interface_id, message_id, attribute, rem_payload);
                                                                    // todo add to warnings (just once for each interface_id/message_id)
                                                                }
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    // println!("MuniicPlugin: got msg with interface_id {} but no method or attribute found", interface_id);
                                                }
                                            } else {
                                                println!(
                                                "MuniicPlugin: got msg with no message_id msg={:?}",
                                                msg
                                            )
                                            }
                                        } else {
                                            println!("MuniicPlugin: got msg with interface_id {} but no interface found", interface_id);
                                        }
                                    } else {
                                        println!(
                                            "MuniicPlugin: got msg with no interval_id msg={:?}",
                                            msg
                                        )
                                    }
                                }
                                _ => {}
                            }
                        }
                        if let Some(new_payload_text) = new_payload_text {
                            // keep all info but the last arg and replace last arg with payload text:
                            let mut text: String = String::with_capacity(200); // todo good size?
                            let args = msg.into_iter().scan(0usize, |state, arg| {
                                let nr_arg = *state;
                                *state += 1;
                                if nr_arg == 12 {
                                    None
                                } else {
                                    Some(arg)
                                }
                            });
                            if DltMessage::process_msg_arg_iter(args, &mut text).is_ok() {
                                if !new_payload_text.is_empty() {
                                    text += " ";
                                    text += new_payload_text.as_str();
                                }
                                msg.set_payload_text(text);
                                // todo it would be safer for interaction with other plugins to modify the args instead of the payload text
                            }
                        }
                    } else {
                        /*println!(
                            "MuniicPlugin: got msg with noar {} != 13 {:?}",
                            ext_header.noar, msg
                        );*/
                    }
                } else if ext_header.ctid == self.config_ctid {
                    self.process_cfg_msg(msg);
                }
            }
        }
        true // forward msg to next plugins or outflow
    }
}

impl MuniicPlugin {
    pub fn from_json(
        config: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<MuniicPlugin, Box<dyn Error>> {
        let name = match &config["name"] {
            serde_json::Value::String(s) => Some(s.clone()),
            _ => None,
        };
        if name.is_none() {
            return Err(PluginError::new("MuniicPlugin: name missing").into());
        }

        let enabled = match &config.get("enabled") {
            Some(serde_json::Value::Bool(b)) => *b,
            None => true, // default to true
            _ => return Err(PluginError::new("MuniicPlugin: config 'enabled' not an bool").into()),
        };
        let json_dir = if let Some(serde_json::Value::String(s)) = &config.get("jsonDir") {
            s.clone()
        } else {
            return Err(PluginError::new("MuniicPlugin: jsonDir missing or invalid type").into());
        };

        let mut state: PluginState = Default::default();
        let mut warnings: Vec<String> = Vec::new();

        let files = get_all_files_with_ext_in_dir(Path::new(&json_dir), &["json"], false)?; // todo or recursive
        let mut cfg: MuniicJsonConfig = Default::default();

        if files.is_empty() {
            warnings.push(format!("No json files found in directory: {}", json_dir));
        } else {
            for file in &files {
                let cfg_file: Result<MuniicJsonConfig, _> =
                    serde_json::from_str(&std::fs::read_to_string(file).unwrap());
                if let Ok(cfg_file) = cfg_file {
                    cfg.map.extend(cfg_file.map);
                    cfg.interfaces.extend(cfg_file.interfaces);
                } else {
                    warnings.push(format!("Error parsing json file: {:?}", file));
                }
            }
        }

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
          /*{"label":format!("Services #{}, sorted by name", fibex_data.elements.services_map_by_sid_major.len()),
          "children":services_by_name.iter().map(tree_item_for_service).collect::<Vec<serde_json::Value>>(),
          },*/
          {"label":format!("Interfaces #{}", cfg.interfaces.len())},
      ],
      "warnings":warnings});
        state.generation += 1;
        Ok(MuniicPlugin {
            name: name.unwrap(),
            enabled,
            state: Arc::new(RwLock::new(state)),
            msg_ctid: DltChar4::from_buf(b"MMSG"),
            config_ctid: DltChar4::from_buf(b"MDLT"),
            config_regex: regex::Regex::new(r"Version: (\d+.\d+), git: (\w+), model hash: (\d+)")
                .unwrap(),
            json_config: cfg,
            config_data_per_ecu: HashMap::new(),
        })
    }

    fn process_cfg_msg(&mut self, msg: &mut DltMessage) {
        // get msg payload text:
        let payload_text = msg.payload_as_text();
        if let Ok(payload_text) = payload_text {
            /*println!(
                "MuniicPlugin: ecu {:?} got config msg {}",
                msg.ecu, payload_text
            );*/
            let captures = self.config_regex.captures(&payload_text);
            if let Some(captures) = captures {
                // todo or update only existing? avoid to_string()...
                // todo if it changes update state

                let version = captures.get(1).unwrap().as_str().to_string();
                let git = captures.get(2).unwrap().as_str().to_string();
                let model_hash = captures.get(3).unwrap().as_str().to_string();
                /*println!(
                    "MuniicPlugin: ecu {:?} got config msg version {} git {} model_hash {}",
                    msg.ecu, version, git, model_hash
                );*/
                self.config_data_per_ecu.insert(
                    msg.ecu, // todo store per ecu and apid?
                    ConfigPerEcu {
                        version,
                        git,
                        model_hash,
                    },
                );
            } else {
                println!(
                    "MuniicPlugin: got config msg without regex match, msg={:?}",
                    msg
                );
            }
        } else {
            println!(
                "MuniicPlugin: got config msg without text, err= {:?}, msg={:?}",
                payload_text.err(),
                msg
            );
        }
    }
}

fn decode_method(method: &MuniicMethod, arg: &DltArg) -> Option<String> {
    let mut text: String = String::with_capacity(200); // todo good size?
    text += format!("{}(Method) = [", method.name).as_str();
    // UInt16 with Int.Request ID
    let mut processed_payload = 0usize;
    let payload = arg.payload_raw;
    if payload.len() >= 2 {
        processed_payload += 2;
        let val = u16::from_be_bytes([payload[0], payload[1]]);
        text += format!("Int.Request ID() = {}", val).as_str();

        let mut attr_payload = &payload[processed_payload..];
        // [In]
        if !method.in_args.is_empty() {
            if let Some((atext, rem_payload)) =
                decode_attribute(&method.in_args[0], attr_payload, Some("[In]"))
            {
                text += ", ";
                text += atext.as_str();
                attr_payload = rem_payload;
            }
        }
        // [Out]
        if !method.out_args.is_empty() {
            if let Some((atext, _rem_payload)) =
                decode_attribute(&method.out_args[0], attr_payload, Some("[Out]"))
            {
                text += ", ";
                text += atext.as_str();
                // attr_payload = rem_payload;
            }
        }
        // processed_payload = payload.len() - attr_payload.len();
    }

    text += "]";
    /*if processed_payload < payload.len() {
        println!(
            "MuniicPlugin: got method with payload not empty/unknown: {:?}",
            &payload[processed_payload..]
        );
    }*/
    Some(text)
}

fn decode_attribute<'a>(
    attribute: &MuniicAttribute,
    payload: &'a [u8],
    name_postfix: Option<&str>,
) -> Option<(String, &'a [u8])> {
    let mut text: String = String::with_capacity(200); // todo good size?
    text += format!(
        "{}{}({}) = ",
        attribute.name,
        name_postfix.unwrap_or_default(),
        attribute.a_type
    )
    .as_str();
    let mut processed_payload = 0;
    match attribute.a_type.as_str() {
        "Boolean" => {
            if !payload.is_empty() {
                processed_payload += 1;
                text += if payload[0] != 0 { "1" } else { "0" };
            } else {
                return None;
            }
        }
        "Int8" => {
            if !payload.is_empty() {
                processed_payload += 1;
                let val: i8 = i8::from_be_bytes([payload[0]]);
                text += format!("{}", val).as_str();
            } else {
                return None;
            }
        }
        "UInt8" => {
            if !payload.is_empty() {
                processed_payload += 1;
                text += format!("{}", payload[0]).as_str();
            } else {
                return None;
            }
        }
        "Int16" => {
            if payload.len() >= 2 {
                processed_payload += 2;
                let val = i16::from_be_bytes([payload[0], payload[1]]);
                text += format!("{}", val).as_str();
            } else {
                return None;
            }
        }
        "UInt16" => {
            if payload.len() >= 2 {
                processed_payload += 2;
                let val = u16::from_be_bytes([payload[0], payload[1]]);
                text += format!("{}", val).as_str();
            } else {
                return None;
            }
        }
        "Int32" => {
            if payload.len() >= 4 {
                processed_payload += 4;
                let val = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                text += format!("{}", val).as_str();
            } else {
                return None;
            }
        }
        "UInt32" => {
            if payload.len() >= 4 {
                processed_payload += 4;
                let val = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                text += format!("{}", val).as_str();
            } else {
                return None;
            }
        }
        "Int64" => {
            if payload.len() >= 8 {
                processed_payload += 8;
                let val = i64::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    payload[6], payload[7],
                ]);
                text += format!("{}", val).as_str();
            } else {
                return None;
            }
        }
        "UInt64" => {
            if payload.len() >= 8 {
                processed_payload += 8;
                let val = u64::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    payload[6], payload[7],
                ]);
                text += format!("{}", val).as_str();
            } else {
                return None;
            }
        }
        "Float" => {
            if payload.len() >= 4 {
                processed_payload += 4;
                let val = f32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                text += format!("{:.6}", val).as_str();
            } else {
                return None;
            }
        }
        "struct" => {
            text += "[";
            let mut struct_payload = payload;
            for (nr_elem, element) in attribute.elements.iter().enumerate() {
                if nr_elem > 0 {
                    text += ", ";
                }
                if let Some((payload_text, rem_payload)) =
                    decode_attribute(element, struct_payload, None)
                {
                    text += payload_text.as_str();
                    struct_payload = rem_payload;
                } else {
                    return None;
                }
            }
            text += "]";
            processed_payload = payload.len() - struct_payload.len();
        }
        "array" => {
            if let Some(array_type) = &attribute.array_type {
                // determine array size:
                let array_size = if let Some(max_size) = attribute.max_size {
                    // read u32 as dynamic size
                    if payload.len() >= 4 {
                        let dyn_size =
                            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        processed_payload += 4;
                        if dyn_size > max_size {
                            max_size
                        } else {
                            dyn_size
                        }
                    } else {
                        0
                    }
                } else {
                    attribute.size
                };
                if array_size > 0 {
                    text += "[";
                    let mut array_payload = &payload[processed_payload..];
                    for nr_elem in 0..array_size {
                        if nr_elem > 0 {
                            text += ", ";
                        }
                        if let Some((payload_text, rem_payload)) =
                            decode_attribute(array_type, array_payload, None)
                        {
                            text += payload_text.as_str();
                            array_payload = rem_payload;
                        } else {
                            return None;
                        }
                    }
                    text += "]";
                    processed_payload = payload.len() - array_payload.len();
                }
            } else {
                return None;
            }
        }
        "enumeration" => {
            if let Some(base_type) = &attribute.base_type {
                match base_type.as_str() {
                    "uint8" | "UInt8" => {
                        if !payload.is_empty() {
                            processed_payload += 1;
                            let val = payload[0];
                            if let Some(values) = &attribute.values {
                                for (name, value) in values {
                                    if *value == val as i64 {
                                        text += name;
                                        break;
                                    }
                                }
                            } else {
                                text += format!("{}", val).as_str();
                            }
                        } else {
                            return None;
                        }
                    }
                    "uint16" | "UInt16" => {
                        if payload.len() >= 2 {
                            processed_payload += 2;
                            let val = u16::from_be_bytes([payload[0], payload[1]]);
                            if let Some(values) = &attribute.values {
                                for (name, value) in values {
                                    if *value == val as i64 {
                                        text += name;
                                        break;
                                    }
                                }
                            } else {
                                text += format!("{}", val).as_str();
                            }
                        } else {
                            return None;
                        }
                    }
                    "uint32" | "UInt32" => {
                        if payload.len() >= 4 {
                            processed_payload += 4;
                            let val = u32::from_be_bytes([
                                payload[0], payload[1], payload[2], payload[3],
                            ]);
                            if let Some(values) = &attribute.values {
                                for (name, value) in values {
                                    if *value == val as i64 {
                                        text += name;
                                        break;
                                    }
                                }
                            } else {
                                text += format!("{}", val).as_str();
                            }
                        } else {
                            return None;
                        }
                    }
                    _ => {
                        text += format!("<enum unknown base type {}>", base_type).as_str();
                    }
                }
            } else {
                return None;
            }
        }
        _ => {
            text += format!("<unknown type {}>", attribute.a_type).as_str();
        }
    }
    // <name>(<type>) = <value>
    // <name>(<type>) = [<elem>, <elem>, ...]]
    Some((text, &payload[processed_payload..]))
}

fn get_interface<'a>(
    cfg: &'a MuniicJsonConfig,
    if_version_hash: &str,
    interface_id: u32,
) -> Option<&'a MuniicInterface> {
    let interface_hash = cfg.map.get(&interface_id)?.get(if_version_hash)?;
    cfg.interfaces.get(interface_hash)
}

fn get_method_or_attribute(interface: &MuniicInterface, id: u32) -> Option<MethodOrAttribute> {
    // todo change to hashmap!
    for method in &interface.methods {
        if method.id == id {
            return Some(MethodOrAttribute::Method(method));
        }
    }
    for attribute in &interface.attributes {
        if attribute.id == id {
            return Some(MethodOrAttribute::Attribute(attribute));
        }
    }
    None
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct MuniicAttribute {
    name: String,
    #[serde(default)]
    id: u32,
    #[serde(rename = "type")]
    a_type: String,
    #[serde(default)]
    size: u32,
    #[serde(default)]
    elements: Vec<MuniicAttribute>,
    #[serde(rename = "enumType")]
    enum_type: Option<String>,
    #[serde(rename = "baseType")]
    base_type: Option<String>,
    values: Option<HashMap<String, i64>>, // todo serialize as HashMap<Value, String>...
    array_type: Option<Box<MuniicAttribute>>,
    max_size: Option<u32>,
    #[serde(default)] // todo could skip as well
    cdc_id: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug)]
struct MuniicMethod {
    name: String,
    id: u32,
    in_args: Vec<MuniicAttribute>,
    out_args: Vec<MuniicAttribute>,
}

#[derive(Serialize, Deserialize, Debug)]
struct MuniicInterface {
    name: String,
    id: u32,
    #[serde(default)]
    integrity_protected: bool,
    attributes: Vec<MuniicAttribute>,
    #[serde(default)]
    methods: Vec<MuniicMethod>,
}

enum MethodOrAttribute<'a> {
    Method(&'a MuniicMethod),
    Attribute(&'a MuniicAttribute),
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct MuniicJsonConfig {
    /// map of interface id to object of hash/version to interface hash
    map: HashMap<u32, HashMap<String, String>>,
    /// map of interface hash to interface object
    interfaces: HashMap<String, MuniicInterface>,
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use crate::{
        dlt::{DltMessageIndexType, DLT_MAX_STORAGE_MSG_SIZE},
        utils::sorting_multi_readeriterator::SequentialMultiIterator,
        utils::{get_dlt_message_iterator, LowMarkBufReader},
    };

    use super::*;
    use serde_json::json;

    #[test]
    fn init_plugin() {
        let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_dir.push("tests");
        test_dir.push("muniic");
        let config = json!({"name":"Muniic", "enabled":true, "jsonDir":test_dir});
        let plugin = MuniicPlugin::from_json(config.as_object().unwrap());
        assert!(plugin.is_ok());
        let plugin = plugin.unwrap();
        assert_eq!(plugin.name, "Muniic");
        assert!(plugin.enabled);
    }

    #[test]
    fn parse_json() {
        let cfg: Result<MuniicJsonConfig, _> = serde_json::from_str(
            r#"{
              "map":{
                "1228779599": {
                  "2944352002": "30bd25090b7a2a064b71ebcbf30882130cc68ed7",
                  "2874425776": "30bd25090b7a2a064b71ebcbf30882130cc68ed7"
                }
              },
              "interfaces":{
                "30bd25090b7a2a064b71ebcbf30882130cc68ed7": {
                  "name": "InitialData",
                  "id": 1228779599,
                  "integrity_protected": false,
                  "attributes": [
                    {
                      "name": "InitialDataApp1",
                      "id": 3478824001,
                      "type": "struct",
                      "elements": [
                        {
                          "name": "DataReady",
                          "type": "Boolean"
                        }
                      ]
                    }
                  ],
                  "methods":[]
                }
              }}"#,
        );
        assert!(cfg.is_ok(), "{:?}", cfg.err());
        let cfg: Result<MuniicJsonConfig, _> =
            serde_json::from_str(r#"{"map":{}, "interface":{}}"#);
        assert!(cfg.is_err());
    }

}
