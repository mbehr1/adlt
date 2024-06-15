// copyright Matthias Behr, (c) 2022
//
// todos:

use crate::{
    dlt::{
        DltChar4, DltMessage, DLT_SCOD_UTF8, DLT_TYPE_INFO_STRG, SERVICE_ID_GET_LOG_INFO,
        SERVICE_ID_GET_SOFTWARE_VERSION,
    },
    plugins::plugin::{LcsRType, Plugin, PluginState},
};
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, RwLock},
};

#[derive(Debug)]
pub struct ApidData {
    apid: DltChar4,
    ctid_map: HashMap<DltChar4, DltChar4>,
}

#[derive(Debug)]
pub struct EcuData {
    ecu: DltChar4,
}

#[derive(Debug)]
pub struct AnonymizePlugin {
    name: String,
    enabled: bool,
    state: Arc<RwLock<PluginState>>,
    ecu_map: HashMap<DltChar4, EcuData>,
    apid_maps: HashMap<DltChar4, HashMap<DltChar4, ApidData>>, // map new_ecu ->map old_apid -> new ApidData
}

impl AnonymizePlugin {
    pub fn new(name: &str) -> AnonymizePlugin {
        AnonymizePlugin {
            name: name.to_owned(),
            enabled: true,
            state: Arc::new(RwLock::new(PluginState::default())),
            ecu_map: HashMap::new(),
            apid_maps: HashMap::new(),
        }
    }

    fn ecu_anon(&mut self, msg: &mut DltMessage) {
        if self.ecu_map.contains_key(&msg.ecu) {
            self.ecu_map
                .get(&msg.ecu)
                .unwrap()
                .ecu
                .clone_into(&mut msg.ecu);
        } else {
            let new_ecu = DltChar4::from_str(format!("E{:03}", self.ecu_map.len() + 1).as_str())
                .unwrap_or_else(|_| DltChar4::from_buf(b"E99A"));
            // todo, what if that key exists already? (overflow...) handle properly (not creating new EcuData)
            self.ecu_map.insert(msg.ecu, EcuData { ecu: new_ecu });
            msg.ecu = new_ecu;
        }
    }

    fn apid_ctid_anon(&mut self, msg: &mut DltMessage) {
        if let Some(cur_apid) = msg.apid() {
            let apid_map = self.apid_maps.entry(msg.ecu).or_default();
            if !apid_map.contains_key(cur_apid) {
                let new_apid = DltChar4::from_str(format!("A{:03}", apid_map.len() + 1).as_str())
                    .unwrap_or_else(|_| DltChar4::from_buf(b"A99A"));
                apid_map.insert(
                    *cur_apid,
                    ApidData {
                        apid: new_apid,
                        ctid_map: HashMap::new(),
                    },
                );
            };
            let apid_data = apid_map.get_mut(cur_apid).unwrap(); // does always exist

            // ctid does always exist if apid exists
            let cur_ctid = msg.ctid().unwrap();
            let new_ctid = if apid_data.ctid_map.contains_key(cur_ctid) {
                *apid_data.ctid_map.get(cur_ctid).unwrap()
            } else {
                let new_ctid =
                    DltChar4::from_str(format!("C{:03}", apid_data.ctid_map.len() + 1).as_str())
                        .unwrap_or_else(|_| DltChar4::from_buf(b"C99A"));
                apid_data.ctid_map.insert(*cur_ctid, new_ctid);
                new_ctid
            };

            if let Some(extended_header) = msg.extended_header.as_mut() {
                extended_header.apid = apid_data.apid;
                extended_header.ctid = new_ctid;
            }
        }
    }

    fn ctrl_msgs_anon(&mut self, msg: &mut DltMessage) {
        if msg.is_ctrl_response() {
            let mut args = msg.into_iter();
            let message_id_arg = args.next();
            let message_id = match message_id_arg {
                Some(a) => {
                    if a.is_big_endian {
                        u32::from_be_bytes(a.payload_raw.get(0..4).unwrap().try_into().unwrap())
                    } else {
                        u32::from_le_bytes(a.payload_raw.get(0..4).unwrap().try_into().unwrap())
                    }
                }
                None => 0,
            };
            match message_id {
                SERVICE_ID_GET_SOFTWARE_VERSION => {
                    let sw_version = "adlt --anon removed sw_version";
                    let payload = vec![
                        crate::to_endian_vec!(message_id, msg.is_big_endian()),
                        vec![0u8], // ret code
                        crate::to_endian_vec!(sw_version.len() as u32, msg.is_big_endian()),
                        sw_version.as_bytes().to_vec(),
                    ];
                    msg.payload = payload.into_iter().flatten().collect::<Vec<u8>>();
                }
                SERVICE_ID_GET_LOG_INFO => {
                    // insert just a payload with the message id (so its corrupt...)
                    msg.payload = crate::to_endian_vec!(message_id, msg.is_big_endian());
                }
                _ => {} // keep unmodified
            }
        }
    }
    fn payload_anon(&mut self, msg: &mut DltMessage) {
        if !msg.is_ctrl_request() && !msg.is_ctrl_response() {
            // todo might exclude other than log as well (nw trace,...)
            if !msg.is_verbose() {
                if msg.payload.len() >= 4 {
                    // keep only the msg id and add the reception time in ms as 64bit value
                    msg.payload = vec![
                        msg.payload[0..4].to_owned(),
                        crate::to_endian_vec!(msg.reception_time_us / 1000, msg.is_big_endian()),
                    ]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<u8>>();
                }
            } else {
                // insert sample string
                let sample_payload =
                    format!("--anon,reception_time:{}ms", msg.reception_time_us / 1000);
                let payload = vec![
                    crate::to_endian_vec!(
                        (DLT_TYPE_INFO_STRG | DLT_SCOD_UTF8),
                        msg.is_big_endian()
                    ),
                    crate::to_endian_vec!((sample_payload.len() + 1) as u16, msg.is_big_endian()),
                    sample_payload.as_bytes().to_vec(),
                    vec![0u8], // zero term
                ];
                msg.payload = payload.into_iter().flatten().collect::<Vec<u8>>();
            }
        }
    }
}

impl Plugin for AnonymizePlugin {
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
        if !self.enabled {
            return true;
        }
        // anonymize...
        self.ecu_anon(msg);
        self.apid_ctid_anon(msg);
        self.ctrl_msgs_anon(msg);
        self.payload_anon(msg);

        true
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn basic() {
        // todo add tests
    }
}
