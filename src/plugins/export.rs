// copyright Matthias Behr, (c) 2024
//
// todos:
// [] implement "sort"
// [] implement "rewrite recepetion/recorded time"

use nohash_hasher::NoHashHasher;
use serde_json::json;
use std::{
    collections::HashSet,
    error::Error,
    fs::File,
    hash::BuildHasherDefault,
    io::Write,
    str::FromStr,
    sync::{Arc, RwLock},
};

use crate::{
    dlt::{
        DltChar4, DltExtendedHeader, DltMessage, DltStandardHeader, DLT_STD_HDR_BIG_ENDIAN,
        DLT_STD_HDR_HAS_EXT_HDR, DLT_STD_HDR_HAS_TIMESTAMP, DLT_STD_HDR_VERSION,
    },
    dlt_args,
    filter::{Filter, FilterKind, FilterKindContainer},
    lifecycle::{Lifecycle, LifecycleId},
    plugins::plugin::{LcsRType, Plugin, PluginError, PluginState},
    utils::remote_utils::match_filters,
    version,
};

// we cannot use the filter with lifecycle.id directly on open as we want to support the "non collect" case.
#[derive(Debug)]
struct LifecycleInfo {
    ecu: DltChar4,
    start_time: u64,
    resume_time: Option<u64>,
    end_time: u64,
}

#[derive(Debug)]
pub struct ExportPlugin {
    name: String,
    enabled: bool,
    export_file_name: String,
    filters: FilterKindContainer<Vec<Filter>>,
    lifecycles_to_keep: Vec<LifecycleInfo>, // will be added as negative, not, lifecycle filter
    recorded_time_from: Option<u64>,
    recorded_time_to: Option<u64>,
    info_texts: Vec<String>, // will be written as 2nd, 3rd, ... info msg

    lcs_r: Option<LcsRType>,
    checked_lc_ids: HashSet<LifecycleId, BuildHasherDefault<NoHashHasher<u32>>>,

    // dynamic state:
    state: Arc<RwLock<PluginState>>,
    export_file: Option<File>,
    lifecycles_exported: Vec<LifecycleId>,
    nr_exported_msgs: usize,
    nr_processed_msgs: usize,
}

impl ExportPlugin {
    pub fn from_json(
        config: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<ExportPlugin, Box<dyn Error>> {
        let name = match &config.get("name") {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            _ => return Err(PluginError::new("config 'name' not a string/missing").into()),
        };
        if name.is_none() {
            return Err(PluginError::new("ExportPlugin: name missing").into());
        }
        let enabled = match &config.get("enabled") {
            Some(serde_json::Value::Bool(b)) => *b,
            None => true, // default to true
            _ => return Err(PluginError::new("config 'enabled' not a bool").into()),
        };

        let export_file_name = match &config.get("exportFileName") {
            Some(serde_json::Value::String(s)) => s.to_owned(),
            _ => return Err(PluginError::new("config 'exportFileName' not a string").into()),
        };

        let mut filters: FilterKindContainer<Vec<Filter>> = Default::default();
        let filters_json = match &config.get("filters") {
            Some(serde_json::Value::Array(a)) => a,
            _ => return Err(PluginError::new("config 'filters' not an array").into()),
        };
        for filter_json in filters_json {
            let filter = match Filter::from_json(&filter_json.to_string()) {
                Ok(f) => f,
                Err(e) => {
                    return Err(PluginError::new(
                        format!("filter '{}' invalid:{}", &filter_json.to_string(), e).as_str(),
                    )
                    .into())
                }
            };
            if filter.enabled {
                // otherwise the no pos filter -> ... logic doesnt work
                filters[filter.kind].push(filter);
            }
        }

        let lifecycles_to_keep = match &config.get("lifecyclesToKeep") {
            Some(serde_json::Value::Array(a)) => {
                let exp_len = a.len();
                let lcis = a
                    .iter()
                    .filter_map(ExportPlugin::parse_lifecycle_info)
                    .collect::<Vec<LifecycleInfo>>();
                if lcis.len() != exp_len {
                    return Err(PluginError::new(
                        format!(
                            "config 'lifecyclesToKeep' has {} entries but only {} valid ones",
                            exp_len,
                            lcis.len()
                        )
                        .as_str(),
                    )
                    .into());
                }
                lcis
            }
            None => vec![],
            _ => return Err(PluginError::new("config 'lifecyclesToKeep' not an array").into()),
        };

        if !lifecycles_to_keep.is_empty() {
            // we set the lc filter to a never matching one for now, will be updated later
            filters[FilterKind::Negative].push(Filter::from_json(
                &json!({"type": 1, "not":true, "lifecycles": [u32::MAX]}).to_string(),
            )?);
        }

        let recorded_time_from = match &config.get("recordedTimeFromMs") {
            Some(serde_json::Value::Number(n)) => Some(n.as_u64().unwrap_or(0) * 1000),
            Some(serde_json::Value::String(n)) if n.ends_with('n') => {
                Some(n[..n.len() - 1].parse::<u64>().unwrap_or(0) * 1000)
            }
            _ => None,
        };
        let recorded_time_to = match &config.get("recordedTimeToMs") {
            Some(serde_json::Value::Number(n)) => Some(n.as_u64().unwrap_or(0) * 1000),
            Some(serde_json::Value::String(n)) if n.ends_with('n') => {
                Some(n[..n.len() - 1].parse::<u64>().unwrap_or(0) * 1000)
            }
            _ => None,
        };

        let info_texts = match &config.get("infoTexts") {
            Some(serde_json::Value::Array(a)) => a
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<String>>(),
            None => [].to_vec(),
            _ => return Err(PluginError::new("config 'filters' not an array").into()),
        };

        // need to try whether we can access the file
        let export_file = match File::create(&export_file_name) {
            Ok(f) => f,
            Err(e) => {
                return Err(PluginError::new(
                    format!(
                        "ExportPlugin: could not create file '{}': {}",
                        export_file_name, e
                    )
                    .as_str(),
                )
                .into())
            }
        };

        // close the file again
        drop(export_file);
        // delete the file (we want the file only if there are real messages to export)
        std::fs::remove_file(&export_file_name)?;

        let state = PluginState {
            value: json!({"name":name, "treeItems":[]}),
            generation: 1,
            apply_command: None,
            internal_data: None,
        };

        let lifecycles_to_keep_len = lifecycles_to_keep.len();
        Ok(ExportPlugin {
            name: name.unwrap(),
            enabled,
            export_file_name,
            filters,
            lifecycles_to_keep,
            recorded_time_from,
            recorded_time_to,
            info_texts,
            lcs_r: None,
            checked_lc_ids: Default::default(),
            state: Arc::new(RwLock::new(state)),
            export_file: None,
            nr_exported_msgs: 0,
            nr_processed_msgs: 0,
            lifecycles_exported: Vec::with_capacity(lifecycles_to_keep_len),
        })
    }

    fn get_info_msg(
        &self,
        mcnt: u8,
        from_msg: &DltMessage,
        noar: u8,
        payload: Vec<u8>,
    ) -> DltMessage {
        let is_big_endian = cfg!(target_endian = "big");
        DltMessage {
            index: 0, // doesn't matter
            reception_time_us: from_msg.reception_time_us,
            ecu: from_msg.ecu,
            timestamp_dms: from_msg.timestamp_dms,
            standard_header: DltStandardHeader {
                mcnt,
                len: 0, // will be automatically set on to_write
                htyp: DLT_STD_HDR_HAS_EXT_HDR
                    | DLT_STD_HDR_HAS_TIMESTAMP
                    | DLT_STD_HDR_VERSION
                    | if is_big_endian {
                        // keep current endianess
                        DLT_STD_HDR_BIG_ENDIAN
                    } else {
                        0u8
                    },
            },
            extended_header: Some(DltExtendedHeader {
                verb_mstp_mtin: (4 << 4) | 1, // verbose, mstp=0 (Log), mtin=4 (Info)
                noar,
                apid: DltChar4::from_buf(b"VsDl"),
                ctid: DltChar4::from_buf(b"Info"),
            }),
            payload,
            payload_text: None,
            lifecycle: 0,
        }
    }

    fn get_export_file(&mut self, msg: &DltMessage) -> Option<&mut File> {
        if self.export_file.is_none() {
            if let Ok(mut export_file) = File::create(&self.export_file_name) {
                // todo better error handling! might fail now...

                // write the export info
                // 1st message with adlt version and date

                let (v_maj, v_min, v_pat) = version();
                let (noar, payload) = dlt_args!(format!(
                    "File created by adlt v{}.{}.{} on {}",
                    v_maj,
                    v_min,
                    v_pat,
                    chrono::Utc::now().to_rfc2822()
                ))
                .unwrap_or_default();

                let info_msg1 = self.get_info_msg(0, msg, noar, payload);
                let _ = info_msg1.to_write(&mut export_file);

                for (idx, info_text) in self.info_texts.iter().enumerate() {
                    if !info_text.is_empty() {
                        let (noar, payload) = dlt_args!(info_text).unwrap_or_default();
                        if noar > 0 {
                            let info_msg =
                                self.get_info_msg(((idx + 1) % 256) as u8, msg, noar, payload);
                            let _ = info_msg.to_write(&mut export_file);
                        }
                    }
                }

                self.export_file = Some(export_file);
            }
        }
        self.export_file.as_mut()
    }

    /// determine whether the lc is the one referenced by lci
    ///
    /// As we do want to support two pass filtering so avoid keeping all messages cached so that we can process
    /// really large dlt files for export we cannot use the lifecycle.id
    ///
    /// So we do assume the following:
    ///
    /// 1. the lci information is from a "matured" lifecycle (i.e. we have seen all (or at least most) messages of it)
    /// 2. we do the check very early for the lc as we determine it from the first messages that have a "not seen yet"
    ///    lifecycle.id.
    ///
    /// So the lc lifecycle the start can move to earlier and the end will grow to later.
    ///  
    fn keep_lifecycle(lci: &LifecycleInfo, ecu: &DltChar4, lc: &Lifecycle) -> bool {
        // start_time for BinLifecycle was lc.resume_start_time, resume_time was resume_time(), end_time was end_time()
        if lci.ecu != *ecu {
            return false;
        }
        if let Some(resume_time) = lci.resume_time {
            // we do have a resume time, todo we might as well iterate through all lcs_r lifecycles and check which one is closest (and within a limit)
            if !lc.is_resume() {
                // but the lifecycle is not a resume
                return false;
            }
            lc.resume_start_time() >= lci.start_time && lc.end_time() <= lci.end_time &&
            // resume time close to (+/-1.9s) the resume time of the lifecycle
            if lc.resume_time() > resume_time {
                lc.resume_time() - resume_time < 1_900_000
            } else {
                resume_time - lc.resume_time() < 1_900_000
            }
        } else {
            // we do not have a resume time
            if lc.is_resume() {
                // but the lifecycle is a resume
                return false;
            }
            lc.start_time >= lci.start_time && lc.end_time() <= lci.end_time
        }
    }

    fn update_state(&self) {
        if let Ok(mut state) = self.state.write() {
            state.value = json!({"name":self.name, "treeItems":[],
                "infos":{"nrProcessedMsgs": self.nr_processed_msgs, "nrExportedMsgs": self.nr_exported_msgs, "lifecyclesExported":self.lifecycles_exported}});
            state.generation += 1;
        }
    }

    fn parse_lifecycle_info(v: &serde_json::Value) -> Option<LifecycleInfo> {
        if let serde_json::Value::Object(o) = v {
            let ecu = match &o.get("ecu") {
                Some(serde_json::Value::String(s)) => DltChar4::from_str(s),
                _ => return None,
            };
            let start_time = match &o.get("startTime") {
                Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
                Some(serde_json::Value::String(n)) if n.ends_with('n') => {
                    n[..n.len() - 1].parse::<u64>().unwrap_or(0)
                } // for bigints encoded as string with "n" at the end like "12345678901234567890n"
                _ => return None,
            };
            let resume_time = match &o.get("resumeTime") {
                Some(serde_json::Value::Number(n)) => Some(n.as_u64().unwrap_or(0)),
                Some(serde_json::Value::String(n)) if n.ends_with('n') => {
                    Some(n[..n.len() - 1].parse::<u64>().unwrap_or(0))
                } // for bigints encoded as string with "n" at the end like "12345678901234567890n"
                _ => None,
            };
            let end_time = match &o.get("endTime") {
                Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
                Some(serde_json::Value::String(n)) if n.ends_with('n') => {
                    n[..n.len() - 1].parse::<u64>().unwrap_or(0)
                } // for bigints encoded as string with "n" at the end like "12345678901234567890n"
                _ => return None,
            };
            if let Ok(ecu) = ecu {
                Some(LifecycleInfo {
                    ecu,
                    start_time,
                    resume_time,
                    end_time,
                })
            } else {
                None // todo and warnings!
            }
        } else {
            None
        }
    }
}

impl Plugin for ExportPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    fn process_msg(&mut self, msg: &mut DltMessage) -> bool {
        if !self.enabled {
            return true;
        }

        if !self.lifecycles_to_keep.is_empty() {
            // we do need to check for the new lifecycles and create a filter then with the new id
            if !self.checked_lc_ids.contains(&msg.lifecycle) {
                if let Some(lcs_r) = &self.lcs_r {
                    // is this one we're missing?
                    if let Some(lc) = lcs_r.get_one(&msg.lifecycle) {
                        // check whether we need to keep this lifecycle
                        if let Some(idx) = self
                            .lifecycles_to_keep
                            .iter()
                            .position(|lctk| ExportPlugin::keep_lifecycle(lctk, &msg.ecu, &lc))
                        {
                            self.lifecycles_exported.push(msg.lifecycle);
                            let filter = Filter::from_json(
                                &json!({"type": 1, "not":true, "lifecycles": self.lifecycles_exported})
                                    .to_string(),
                            )
                            .unwrap();
                            println!(
                                "ExportPlugin: found lifecycle to keep: {:?}, added filter: {:?}",
                                lc, filter
                            );
                            // we assume the last neg filter is the lifecycleToKeep filter:
                            self.filters[FilterKind::Negative].pop();
                            self.filters[FilterKind::Negative].push(filter);

                            self.lifecycles_to_keep.remove(idx);
                        }
                    } else {
                        panic!("unknown lifecycle: {} for msg {:?}", msg.lifecycle, msg);
                    }

                    // mark as checked
                    self.checked_lc_ids.insert(msg.lifecycle);
                }
            }
        }

        if match_filters(msg, &self.filters) {
            let mut do_write = true;
            // check for recorded time: (todo move to filter logic)
            if let Some(recorded_time_from) = self.recorded_time_from {
                if msg.reception_time_us < recorded_time_from {
                    do_write = false;
                }
            }
            if let Some(recorded_time_to) = self.recorded_time_to {
                if msg.reception_time_us > recorded_time_to {
                    do_write = false;
                }
            }

            if do_write {
                // just print the message
                //println!("ExportPlugin: matched {:?}", msg);
                // write the message to the file
                if let Some(file) = self.get_export_file(msg) {
                    // todo treat a msg with a "payload_text" field set (set by a prev plugin) differently?
                    match msg.to_write(file) {
                        Ok(_) => {
                            self.nr_exported_msgs += 1;
                        }
                        Err(e) => {
                            println!("ExportPlugin: could not write message to file: {}", e);
                            // todo ... write to pluginstate
                        }
                    }
                }
            }
        }
        self.nr_processed_msgs += 1;
        if self.nr_processed_msgs % 10_000 == 0 {
            self.update_state()
        }
        true
    }

    fn state(&self) -> Arc<RwLock<PluginState>> {
        self.state.clone()
    }

    fn set_lifecycle_read_handle(&mut self, lcs_r: &LcsRType) {
        self.lcs_r = Some(lcs_r.clone());
    }

    fn sync_all(&mut self) {
        self.update_state();
        if let Some(mut file) = self.export_file.as_ref() {
            let _ = file.flush();
            // we might close as well but then would have to reopen if some more messages are processed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dlt::{DltStandardHeader, DLT_MAX_STORAGE_MSG_SIZE, DLT_STD_HDR_HAS_TIMESTAMP},
        utils::{
            get_dlt_message_iterator, get_new_namespace,
            sorting_multi_readeriterator::SequentialMultiIterator, LowMarkBufReader,
        },
    };
    use serde_json::json;

    #[test]
    fn export_plugin_process_msg() {
        let export_file = tempfile::Builder::new()
            .prefix("adlt_export_")
            .suffix(".dlt")
            .tempfile()
            .unwrap();
        let export_file_name = export_file.path().to_str().unwrap().to_owned();
        drop(export_file); // close and delete the file (as we want to see whether the plugin creates it)

        // todo add check that plugin overwrites existing files

        assert!(!std::path::Path::new(&export_file_name).exists());

        let config = json!({
            "name": "Export",
            "enabled": true,
            "exportFileName": export_file_name,
            "filters":[{"type":1, "ecu":"ECU0"}],
            "infoTexts":["Filters used: !ECU0", "Sort by index"]
        });

        let mut plugin = ExportPlugin::from_json(config.as_object().unwrap()).unwrap();
        let mut msg_ecu0 = msg_for_test(0);
        let mut msg_ecu1 = msg_for_test(1);

        plugin.process_msg(&mut msg_ecu0);
        plugin.process_msg(&mut msg_ecu1);

        assert_eq!(plugin.nr_exported_msgs, 1);
        assert_eq!(plugin.nr_processed_msgs, 2);
        drop(plugin);

        // check that the file was created:
        assert!(std::path::Path::new(&export_file_name).exists());

        // verify the content of the file
        let msgs = msgs_from_file(&[&export_file_name]);
        assert_eq!(msgs.len(), 3 + 1); // 3 with export info, 1 with the message

        assert_eq!(msgs[msgs.len() - 1].ecu, DltChar4::from_buf(b"ECU1"));

        // delete the file again
        std::fs::remove_file(export_file_name).unwrap();
        // println!("exported to: {}", export_file_name);
        // assert!(false);
    }

    // copied from ... (todo move to a common test module)
    fn msg_for_test(index: u32) -> DltMessage {
        let timestamp_us = 100u64 * (1 + index as u64);
        DltMessage {
            index,
            reception_time_us: 100_000 + timestamp_us,
            ecu: if index % 2 == 0 {
                DltChar4::from_buf(b"ECU0")
            } else {
                DltChar4::from_buf(b"ECU1")
            },
            timestamp_dms: (timestamp_us / 100) as u32,
            standard_header: DltStandardHeader {
                htyp: DLT_STD_HDR_HAS_TIMESTAMP,
                len: 0,
                mcnt: 0,
            },
            extended_header: None,
            payload: [].to_vec(),
            payload_text: None,
            lifecycle: 0,
        }
    }
    // copied from src/lifecycle/mod.rs (todo move to a common test module)
    fn get_file_iterator(file_name: &str, namespace: u32) -> Box<dyn Iterator<Item = DltMessage>> {
        let fi = File::open(file_name).unwrap();
        const BUFREADER_CAPACITY: usize = 512 * 1024;
        let buf_reader = LowMarkBufReader::new(fi, BUFREADER_CAPACITY, DLT_MAX_STORAGE_MSG_SIZE);
        let it = get_dlt_message_iterator(
            std::path::Path::new(file_name)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or(""),
            0,
            buf_reader,
            namespace,
            None,
            None,
            None,
        );
        it
    }

    fn msgs_from_file(file_names: &[&str]) -> Vec<DltMessage> {
        let namespace = get_new_namespace();
        let its = file_names
            .iter()
            .map(|file_name| get_file_iterator(file_name, namespace));
        let it = SequentialMultiIterator::new_or_single_it(0, its);
        it.collect::<Vec<DltMessage>>()
    }

    #[test]
    fn export_plugin_from_json() {
        let config = json!({
            "name": "Export",
            "enabled": true,
            "exportFileName": "tests/tmp_exported_tmp1.dlt",
            "filters":[]
        });

        let plugin = ExportPlugin::from_json(config.as_object().unwrap()).unwrap();
        assert_eq!(plugin.name(), "Export");
        assert!(plugin.enabled());
        println!("got plugin:{:?}", plugin);

        // enabled default to true
        let config = json!({
            "name": "Export",
            "exportFileName": "tests/tmp_exported_tmp1.dlt",
            "filters":[]
        });

        let plugin = ExportPlugin::from_json(config.as_object().unwrap()).unwrap();
        assert_eq!(plugin.name(), "Export");
        assert!(plugin.enabled());

        // enabled needs to be a bool
        let config = json!({
            "name": "Export",
            "enabled":1,
            "exportFileName": "tests/tmp_exported_tmp1.dlt",
            "filters":[]
        });

        let plugin = ExportPlugin::from_json(config.as_object().unwrap());
        assert!(plugin.is_err());
    }

    #[test]
    fn export_plugin_from_json_export_file_no_access() {
        let config = json!({
            "name": "Export",
            "enabled": true,
            "exportFileName": "tests/tests/tests/tmp_exported_tmp1.dlt",
            "filters":[]
        });

        let plugin = ExportPlugin::from_json(config.as_object().unwrap());
        assert!(plugin.is_err());
    }

    #[test]
    fn export_plugin_from_json_missing_filters() {
        let config = json!({
            "name": "Export",
            "enabled": true,
            "exportFileName": "tests/tmp_exported_tmp3.dlt",
        });

        let plugin = ExportPlugin::from_json(config.as_object().unwrap());
        assert!(plugin.is_err());
    }

    #[test]
    fn export_plugin_from_json_missing_name() {
        let config = json!({
            "enabled": true,
            "exportFileName": "exported.dlt",
            "filters":[]
        });

        let plugin = ExportPlugin::from_json(config.as_object().unwrap());
        assert!(plugin.is_err());
    }

    #[test]
    fn export_plugin_from_json_missing_export_file_name() {
        let config = json!({
            "name": "Export",
            "enabled": true,
            "filters":[]
        });

        let plugin = ExportPlugin::from_json(config.as_object().unwrap());
        assert!(plugin.is_err());
    }

    #[test]
    fn export_plugin_from_json_with_lci() {
        let config = json!({
            "name": "Export",
            "enabled": true,
            "exportFileName": "tests/tmp_exported_tmp1.dlt",
            "filters":[],
            "lifecyclesToKeep":[]
        });
        let plugin = ExportPlugin::from_json(config.as_object().unwrap()).unwrap();
        assert_eq!(plugin.name(), "Export");
        assert!(plugin.enabled());
        assert_eq!(plugin.lifecycles_to_keep.len(), 0);

        let config = json!({
            "name": "Export",
            "enabled": true,
            "exportFileName": "tests/tmp_exported_tmp1.dlt",
            "filters":[],
            "lifecyclesToKeep":[{}]
        });
        let plugin = ExportPlugin::from_json(config.as_object().unwrap());
        assert!(plugin.is_err());

        let config = json!({
            "name": "Export",
            "enabled": true,
            "exportFileName": "tests/tmp_exported_tmp1.dlt",
            "filters":[],
            "lifecyclesToKeep":[{"ecu": "FOO", "startTime": 1, "endTime": 2}]
        });
        let plugin = ExportPlugin::from_json(config.as_object().unwrap()).unwrap();
        assert_eq!(plugin.lifecycles_to_keep.len(), 1);
        let lci = &plugin.lifecycles_to_keep[0];
        assert_eq!(lci.ecu, DltChar4::from_buf(b"FOO\0"));
        assert_eq!(lci.start_time, 1);
        assert_eq!(lci.end_time, 2);
        assert!(lci.resume_time.is_none());
        assert!(plugin.recorded_time_from.is_none());
        assert!(plugin.recorded_time_to.is_none());

        let config = json!({
            "name": "Export",
            "enabled": true,
            "exportFileName": "tests/tmp_exported_tmp1.dlt",
            "filters":[],
            "lifecyclesToKeep":[{"ecu": "FOO", "startTime": 1, "endTime": 2}],
            "recordedTimeFromMs": "3n",
            "recordedTimeToMs": "4n"
        });
        let plugin = ExportPlugin::from_json(config.as_object().unwrap()).unwrap();
        assert_eq!(plugin.lifecycles_to_keep.len(), 1);
        assert_eq!(plugin.recorded_time_from, Some(3_000));
        assert_eq!(plugin.recorded_time_to, Some(4_000));

        let config = json!({
            "name": "Export",
            "enabled": true,
            "exportFileName": "tests/tmp_exported_tmp1.dlt",
            "filters":[],
            "lifecyclesToKeep":[{"ecu": "FOO", "startTime": 1, "endTime": 2}],
            "recordedTimeFromMs": 3,
            "recordedTimeToMs": 4
        });
        let plugin = ExportPlugin::from_json(config.as_object().unwrap()).unwrap();
        assert_eq!(plugin.lifecycles_to_keep.len(), 1);
        assert_eq!(plugin.recorded_time_from, Some(3_000));
        assert_eq!(plugin.recorded_time_to, Some(4_000));

        let cur_gen = plugin.state().read().unwrap().generation;
        plugin.update_state();
        assert_eq!(plugin.state().read().unwrap().generation, cur_gen + 1);
    }

    #[test]
    fn parse_lifecycle_info_1() {
        // parse with json bignumber in "...n" format:
        let lci = ExportPlugin::parse_lifecycle_info(
            &json!({"ecu":"foo", "startTime": "18446744073709551615n", "endTime":"0n", "resumeTime": "4294967295n"}),
        )
        .unwrap();
        println!("lci:{:?}", lci);
        assert_eq!(lci.ecu, DltChar4::from_buf(b"foo\0"));
        assert_eq!(lci.start_time, u64::MAX);
        assert_eq!(lci.end_time, 0);
        assert_eq!(lci.resume_time, Some(u32::MAX as u64));
    }
}
