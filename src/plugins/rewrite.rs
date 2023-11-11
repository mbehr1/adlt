// copyright Matthias Behr, (c) 2022
//
// todos:
// [ ] show rewrites in dlt-logs...
// [ ] investigate using e.g. deno for full javascript/typescript support

use crate::{dlt::DltMessage, filter::Filter, plugins::plugin::Plugin};
use fancy_regex::Regex;
use serde_json::json;
use std::{
    error::Error,
    fmt,
    sync::{Arc, RwLock},
};

use super::plugin::PluginState;

#[derive(Debug)]
struct RewritePluginError {
    msg: String,
}

impl RewritePluginError {}

impl From<String> for RewritePluginError {
    fn from(err: String) -> RewritePluginError {
        RewritePluginError { msg: err }
    }
}

impl From<&str> for RewritePluginError {
    fn from(err: &str) -> RewritePluginError {
        RewritePluginError::from(err.to_owned())
    }
}

impl fmt::Display for RewritePluginError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.msg)
    }
}

impl Error for RewritePluginError {}

#[derive(Debug)]
pub struct RewriteConfig {
    pub name: String,
    filter: Filter,
    payload_regex: Regex,
}

impl RewriteConfig {
    pub fn from_json(cfg: &serde_json::Value) -> Result<RewriteConfig, Box<dyn Error>> {
        if let serde_json::Value::Object(config) = cfg {
            let name = match &config.get("name") {
                Some(serde_json::Value::String(s)) => s.clone(),
                _ => return Err(RewritePluginError::from("rewrites object: name missing").into()),
            };

            let mut filter_cfg_obj = config
                .get("filter")
                .and_then(|f| f.as_object())
                .ok_or_else(|| {
                    Box::new(RewritePluginError::from(
                        "rewrites object: filter not an object",
                    ))
                })?
                .clone();
            if !filter_cfg_obj.contains_key("type") {
                // we default to pos. filter
                filter_cfg_obj.insert("type".to_owned(), serde_json::Value::from(0u64));
            }

            let filter = Filter::from_json(&serde_json::Value::Object(filter_cfg_obj).to_string())?;

            let payload_regex =
                if let Some(Some(s)) = config.get("payloadRegex").map(|s| s.as_str()) {
                    Regex::new(s).map_err(|e| {
                        Box::new(RewritePluginError::from(format!(
                            "regex error parsing '{}':{:?}",
                            s, e
                        )))
                    })?
                } else {
                    return Err(
                        RewritePluginError::from("rewrites object: payloadRegex missing").into(),
                    );
                };

            Ok(RewriteConfig {
                name,
                filter,
                payload_regex,
            })
        } else {
            Err(RewritePluginError::from("'rewrites' elements not an Object").into())
        }
    }
}

#[derive(Debug)]
pub struct RewritePlugin {
    name: String,
    enabled: bool,
    state: Arc<RwLock<PluginState>>,
    rewrites: Vec<RewriteConfig>,
}

impl Plugin for RewritePlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn state(&self) -> Arc<RwLock<PluginState>> {
        self.state.clone()
    }

    /// check a msg for rewrite.
    /// returns false if the msg should be discarded, true otherwise
    /// we do check all rewrite configs. So one config could change a msg for further processing with next config
    /// currently the rewrite array with javascrip functions is not supported.
    /// Instead the replacement is done based on the capture group names:
    ///  - text -> setting payloadText
    ///  - timeStamp -> setting the timestamp_dms with the value captured in Seconds (can include parts of) (multiplied by 10_000)
    fn process_msg(&mut self, msg: &mut DltMessage) -> bool {
        if !self.enabled {
            return true;
        }
        for r in &self.rewrites {
            if r.filter.matches(msg) {
                if let Ok(payload_text) = msg.payload_as_text() {
                    if let Ok(Some(captures)) = r.payload_regex.captures(&payload_text) {
                        for (idx, capt_name) in r.payload_regex.capture_names().enumerate() {
                            match capt_name {
                                Some("text") => {
                                    msg.payload_text =
                                        captures.get(idx).map(|v| v.as_str().to_owned());
                                }
                                Some("timeStamp") => {
                                    let new_timestamp = captures
                                        .get(idx)
                                        .and_then(|v| v.as_str().parse::<f64>().ok())
                                        .map(|v| (v * 10000.0).round() as u32);
                                    if let Some(new_timestamp) = new_timestamp {
                                        msg.timestamp_dms = new_timestamp;
                                    }
                                }
                                _ => {
                                    // todo print err but just once!
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

impl RewritePlugin {
    pub fn from_json(
        config: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<RewritePlugin, Box<dyn Error>> {
        let name = match &config.get("name") {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            _ => return Err(RewritePluginError::from("config 'name' not a string/missing").into()),
        }; // todo check name for SomeIp
        if name.is_none() {
            return Err(RewritePluginError::from("RewritePlugin: name missing").into());
        }
        let enabled = match &config.get("enabled") {
            Some(serde_json::Value::Bool(b)) => *b,
            None => true, // default to true
            _ => return Err(RewritePluginError::from("config 'enabled' not an bool").into()),
        };
        let rewrites = if let Some(serde_json::Value::Array(cfgs)) = &config.get("rewrites") {
            let mut rewrites = vec![];
            for cfg in cfgs {
                let rewrite = RewriteConfig::from_json(cfg)?;
                rewrites.push(rewrite);
            }
            rewrites
        } else {
            return Err(RewritePluginError::from("config 'rewrites' not an array").into());
        };

        let state = PluginState {
            value: serde_json::json!({"name":name, "treeItems":
                rewrites.iter().map(|r|{json!({
                    "label":format!("{}",r.name),
                    "tooltip":format!("for msgs matching '{:?}' replace regex: '{}'", r.filter, r.payload_regex),
                })}).collect::<Vec<serde_json::Value>>()
            }),
            generation: 1,
            ..Default::default()
        };
        /*
            "rewrites":[
                {
                    "name":"SYS/JOUR timestamp",
                    "filter":{
                        "apid":"SYS",
                        "ctid":"JOUR"
                    },
                    "payloadRegex":"^.*? .*? (?<timeStamp>\\d+\\.\\d+) (?<text>.*)$",
                    "rewrite":{
                        "timeStamp":"function(m,msg){ if (!m) {return undefined; } return Math.round(Number(m.groups?.['timeStamp']) * 10000)}",
                        "payloadText":"function(m,msg){ if (!m) {return undefined; } return m.groups?.['text']}"
                    }
                }
            ]

        */
        Ok(RewritePlugin {
            name: name.unwrap(),
            enabled,
            state: Arc::new(RwLock::new(state)),
            rewrites,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::Char4OrRegex;
    use crate::filter::FilterKind;
    use serde_json::json;

    #[test]
    fn init_rewrite_config() {
        // good case:
        let cfg = json!({"name":"a","filter":{"apid": "foo"},"payloadRegex":"^foo"});
        let p = RewriteConfig::from_json(&cfg).unwrap();
        assert!(p.filter.enabled);
        assert_eq!(p.filter.kind, FilterKind::Positive); // default to pos filter
        assert_eq!(p.filter.apid, Char4OrRegex::from_buf(b"foo\0").ok());
        assert_eq!(
            p.payload_regex.as_str(),
            Regex::new("^foo").unwrap().as_str()
        );

        // name missing:
        let cfg = json!({"filter":{},"payloadRegex":""});
        let p = RewriteConfig::from_json(&cfg);
        assert!(p.is_err());

        // filter missing:
        let cfg = json!({"name":"a","payloadRegex":""});
        let p = RewriteConfig::from_json(&cfg);
        assert!(p.is_err());

        // payloadRegex missing:
        let cfg = json!({"name":"a","filter":{}});
        let p = RewriteConfig::from_json(&cfg);
        assert!(p.is_err());
    }

    #[test]
    fn init_plugin() {
        // good case:
        let cfg = json!({"name":"foo","enabled": false, "rewrites":[{"name":"a","filter":{},"payloadRegex":""}]});
        let p = RewritePlugin::from_json(cfg.as_object().unwrap());
        assert!(p.is_ok());
        let p = p.unwrap();
        assert_eq!(p.name, "foo");
        assert!(!p.enabled);
        assert_eq!(1, p.rewrites.len());

        let state = p.state();
        let state = state.read().unwrap();
        assert_eq!(state.generation, 1); // first update done
        let state_value = &state.value;
        assert!(state_value.is_object());
        let state_obj = state_value.as_object().unwrap();
        assert!(state_obj.contains_key("name"));
        assert!(state_obj.contains_key("treeItems"));
        let tree_items = state_obj.get("treeItems").unwrap();
        assert!(tree_items.is_array());
        assert_eq!(tree_items.as_array().unwrap().len(), 1);
        // state can be debug printed:
        assert!(!format!("{:?}", state).is_empty());

        // name missing: -> err
        let cfg = json!({"enabled": false, "rewrites":[]});
        let p = RewritePlugin::from_json(cfg.as_object().unwrap());
        assert!(p.is_err());

        // enabled missing -> default true
        let cfg = json!({"name": "f", "rewrites":[]});
        let p = RewritePlugin::from_json(cfg.as_object().unwrap()).unwrap();
        assert!(p.enabled);

        // rewrites missing -> err
        let cfg = json!({"name": "f"});
        let p = RewritePlugin::from_json(cfg.as_object().unwrap());
        assert!(p.is_err());
    }

    #[test]
    fn rewrite_msg() {
        let cfg = json!({"name":"foo", "rewrites":[{"name":"a","filter":{},"payloadRegex":"bar (?<timeStamp>.*?) (?<text>.*)"}]});
        let mut p = RewritePlugin::from_json(cfg.as_object().unwrap()).unwrap();
        let mut m = DltMessage::for_test();
        m.payload_text = Some("bar 12.345678 only wanted text".to_owned());
        let r = p.process_msg(&mut m);
        assert!(r); // dont throw away the msg
        assert_eq!(m.timestamp_dms, 123457);
        assert_eq!(m.payload_as_text(), Ok("only wanted text".to_owned()));

        // not matching payload regex (but matching filter)
        m.payload_text = Some("baf 12.345678 only wanted text".to_owned());
        m.timestamp_dms = 1;
        let r = p.process_msg(&mut m);
        assert!(r); // dont throw away the msg
        assert_eq!(m.timestamp_dms, 1);
        assert_eq!(
            m.payload_as_text(),
            Ok("baf 12.345678 only wanted text".to_owned())
        );

        // not matching filter:
        let cfg = json!({"name":"foo", "rewrites":[{"name":"a","filter":{"payloadRegex": "^baf"},"payloadRegex":"bar (?<timeStamp>.*?) (?<text>.*)"}]});
        let mut p = RewritePlugin::from_json(cfg.as_object().unwrap()).unwrap();
        m.payload_text = Some("bar 12.345678 only wanted text".to_owned());
        m.timestamp_dms = 2;
        let r = p.process_msg(&mut m);
        assert!(r); // dont throw away the msg
        assert_eq!(m.timestamp_dms, 2);
        assert_eq!(
            m.payload_as_text(),
            Ok("bar 12.345678 only wanted text".to_owned())
        );

        // matching filter but wrong capture group names:
        let cfg = json!({"name":"foo","rewrites":[{"name":"a","filter":{},"payloadRegex":"bar (?<timestamp>.*?) (?<text2>.*)"}]});
        let mut p = RewritePlugin::from_json(cfg.as_object().unwrap()).unwrap();
        m.payload_text = Some("bar 12.345678 only wanted text".to_owned());
        m.timestamp_dms = 2;
        let r = p.process_msg(&mut m);
        assert!(r); // dont throw away the msg
        assert_eq!(m.timestamp_dms, 2); // time unchanged
        assert_eq!(
            // unchanged
            m.payload_as_text(),
            Ok("bar 12.345678 only wanted text".to_owned())
        );
    }
}
