/// todo:
/// [ ] think about removing 3 hashmaps to 1 or 2 to improve performance (120Melem/s->34Melem/s)
use crate::{
    dlt::{
        control_msgs::parse_ctrl_log_info_payload, DltChar4, DltMessage, DltMessageIndexType,
        SERVICE_ID_GET_LOG_INFO,
    },
    utils::remote_types,
};
use std::collections::HashMap;

#[derive(Debug)]
pub struct ApidStats {
    pub ctids: HashMap<
        DltChar4,
        CtidStats,
        std::hash::BuildHasherDefault<nohash_hasher::NoHashHasher<DltChar4>>,
    >,
    pub desc: Option<String>,
}
impl ApidStats {
    pub fn new() -> Self {
        Self {
            desc: None,
            ctids: HashMap::with_capacity_and_hasher(
                64,
                nohash_hasher::BuildNoHashHasher::<DltChar4>::default(),
            ),
        }
    }

    /// return the number of msgs for that apid
    ///
    /// gets calculated as the sum of all nr_msgs of the ctids
    /// as each msg has always apid/ctid set
    pub fn nr_msgs(&self) -> DltMessageIndexType {
        self.ctids.iter().map(|e| e.1.nr_msgs).sum()
    }
}

impl Default for ApidStats {
    fn default() -> Self {
        Self::new()
    }
}

impl From<(&DltChar4, &ApidStats)> for remote_types::BinApidInfo {
    fn from(e: (&DltChar4, &ApidStats)) -> Self {
        Self {
            apid: e.0.as_u32le(),
            desc: e.1.desc.to_owned(),
            ctids: e
                .1
                .ctids
                .iter()
                .map(remote_types::BinCtidInfo::from)
                .collect(),
        }
    }
}

#[derive(Debug)]
pub struct CtidStats {
    pub nr_msgs: DltMessageIndexType,
    pub desc: Option<String>,
}
impl CtidStats {
    pub fn new() -> Self {
        Self {
            nr_msgs: 0,
            desc: None,
        }
    }
}

impl Default for CtidStats {
    fn default() -> Self {
        Self::new()
    }
}

impl From<(&DltChar4, &CtidStats)> for remote_types::BinCtidInfo {
    fn from(e: (&DltChar4, &CtidStats)) -> Self {
        Self {
            ctid: e.0.as_u32le(),
            nr_msgs: e.1.nr_msgs,
            desc: e.1.desc.to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct EcuStats {
    pub nr_msgs: DltMessageIndexType,
    pub apids: HashMap<
        DltChar4,
        ApidStats,
        std::hash::BuildHasherDefault<nohash_hasher::NoHashHasher<DltChar4>>,
    >,
}

impl EcuStats {
    pub fn new() -> Self {
        Self {
            nr_msgs: 0,
            apids: HashMap::with_capacity_and_hasher(
                128,
                nohash_hasher::BuildNoHashHasher::<DltChar4>::default(),
            ),
        }
    }

    /// add description for apid or ctid
    ///
    /// Inserts entries for ecu/apid/ctid if not existing yet (with nr_msgs 0).
    ///
    /// *Warning:* if the description exists already it does not get overwritten!
    pub fn add_desc(&mut self, desc: &str, apid: &DltChar4, ctid: Option<&DltChar4>) {
        let apid = self.apids.entry(*apid).or_default();
        if let Some(ctid) = ctid {
            let ctid = apid
                .ctids
                .entry(*ctid) // if apid is avail, ctid is avail as well
                .or_default();
            if ctid.desc.is_none() {
                ctid.desc = Some(desc.to_owned());
            }
        } else {
            // set apid desc:
            if apid.desc.is_none() {
                apid.desc = Some(desc.to_owned());
            }
        }
    }
}

impl Default for EcuStats {
    fn default() -> Self {
        Self::new()
    }
}

impl From<(&DltChar4, &EcuStats)> for remote_types::BinEcuStats {
    fn from(e: (&DltChar4, &EcuStats)) -> Self {
        Self {
            ecu: e.0.as_u32le(),
            nr_msgs: e.1.nr_msgs,
            apids: e
                .1
                .apids
                .iter()
                .map(remote_types::BinApidInfo::from)
                .collect(),
        }
    }
}

#[derive(Debug)]
pub struct EacStats {
    pub ecu_map: HashMap<
        DltChar4,
        EcuStats,
        std::hash::BuildHasherDefault<nohash_hasher::NoHashHasher<DltChar4>>,
    >,
}

impl EacStats {
    pub fn new() -> Self {
        let ecu_map = HashMap::with_capacity_and_hasher(
            16,
            nohash_hasher::BuildNoHashHasher::<DltChar4>::default(),
        );

        EacStats { ecu_map }
    }
    pub fn add_msg(&mut self, msg: &DltMessage) {
        let ecu_stat = self.ecu_map.entry(msg.ecu).or_default();
        ecu_stat.nr_msgs += 1;

        if let Some(m_apid) = msg.apid() {
            let apid = ecu_stat.apids.entry(*m_apid).or_default();
            let ctid = apid
                .ctids
                .entry(*msg.ctid().unwrap()) // if apid is avail, ctid is avail as well
                .or_default();
            ctid.nr_msgs += 1;

            // is SERVICE_ID_GET_LOG_INFO message?
            if msg.is_ctrl_response() && !msg.is_verbose() {
                let mut args = msg.into_iter();
                let message_id_arg = args.next();
                let message_id = match message_id_arg {
                    Some(a) => {
                        if a.payload_raw.len() == 4 {
                            if a.is_big_endian {
                                u32::from_be_bytes(
                                    a.payload_raw.get(0..4).unwrap().try_into().unwrap(),
                                )
                            } else {
                                u32::from_le_bytes(
                                    a.payload_raw.get(0..4).unwrap().try_into().unwrap(),
                                )
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

                    // todo add desc for entries...
                    if !payload.is_empty() {
                        let retval = payload.first().unwrap();
                        let payload = &payload[1..];
                        let apids = parse_ctrl_log_info_payload(*retval, is_big_endian, payload);
                        if !apids.is_empty() {
                            // let ecu_stats = let ecu = self.ecu_map.entry(*ecu).or_insert_with(EcuStats::new);
                            for apid_info in &apids {
                                if let Some(desc) = apid_info.desc.as_deref() {
                                    ecu_stat.add_desc(desc, &apid_info.apid, None);
                                }
                                for ctid_info in &apid_info.ctids {
                                    if let Some(desc) = ctid_info.desc.as_deref() {
                                        ecu_stat.add_desc(
                                            desc,
                                            &apid_info.apid,
                                            Some(&ctid_info.ctid),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// return the number of msgs in total
    ///
    /// gets calculated as the sum of all nr_msgs of the ecus
    /// as each msg has always an ECU set
    pub fn nr_msgs(&self) -> DltMessageIndexType {
        self.ecu_map.iter().map(|e| e.1.nr_msgs).sum()
    }

    /// add description for apid or ctid
    ///
    /// Inserts entries for ecu/apid/ctid if not existing yet (with nr_msgs 0).
    ///
    /// *Warning:* if the description exists already it does not get overwritten!
    pub fn add_desc(
        &mut self,
        desc: &str,
        ecu: &DltChar4,
        apid: &DltChar4,
        ctid: Option<&DltChar4>,
    ) {
        let ecu = self.ecu_map.entry(*ecu).or_default();
        ecu.add_desc(desc, apid, ctid);
    }
}

impl Default for EacStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlt::DltExtendedHeader;

    #[test]
    fn init() {
        let eac = EacStats::new();
        assert_eq!(eac.nr_msgs(), 0);

        let a_s: ApidStats = Default::default();
        assert_eq!(a_s.nr_msgs(), 0);

        let c_s: CtidStats = Default::default();
        assert_eq!(c_s.nr_msgs, 0);
    }

    #[test]
    fn basic() {
        let mut eac = EacStats::new();

        // add a msg without apid/ctid:
        let m1 = DltMessage::for_test();
        eac.add_msg(&m1);
        assert_eq!(eac.nr_msgs(), 1);
        let ecu_test = eac.ecu_map.get(&DltChar4::from_buf(b"TEST")).unwrap();
        assert_eq!(ecu_test.nr_msgs, 1);
        assert_eq!(ecu_test.apids.len(), 0);

        // add a 2nd msg with apid/ctid:
        let mut m1 = DltMessage::for_test();
        m1.extended_header = Some(DltExtendedHeader {
            verb_mstp_mtin: 0,
            noar: 0,
            apid: DltChar4::from_buf(b"APID"),
            ctid: DltChar4::from_buf(b"CTID"),
        });
        eac.add_msg(&m1);
        assert_eq!(eac.nr_msgs(), 2);
        let ecu = DltChar4::from_buf(b"TEST");
        let apid = DltChar4::from_buf(b"APID");
        {
            let ecu_test = eac.ecu_map.get(&ecu).unwrap();
            assert_eq!(ecu_test.nr_msgs, 2);
            assert_eq!(ecu_test.apids.len(), 1);
            let apid_s = ecu_test.apids.get(&apid).unwrap();
            assert_eq!(apid_s.nr_msgs(), 1);
            assert!(apid_s.desc.is_none());
            assert_eq!(apid_s.ctids.len(), 1);
        }
        eac.add_desc("a desc", &ecu, &apid, None);
        let ecu_test = eac.ecu_map.get(&ecu).unwrap();
        let apid_s = ecu_test.apids.get(&apid).unwrap();
        assert_eq!(apid_s.desc, Some("a desc".to_owned()));
    }

    #[test]
    fn desc() {
        let mut eac = EacStats::new();
        // set desc for non existing apid:
        let ecu = DltChar4::from_buf(b"ECU1");
        let apid = DltChar4::from_buf(b"APID");
        eac.add_desc("an apid", &ecu, &apid, None);
        let ecu_stat = eac.ecu_map.get(&ecu).unwrap();
        let apid_stat = ecu_stat.apids.get(&apid).unwrap();
        assert_eq!(apid_stat.desc, Some("an apid".to_owned()));
        // set desc for existing apid, non ex ctid:
        let ctid = DltChar4::from_buf(b"CTID");
        eac.add_desc("a ctid 1", &ecu, &apid, Some(&ctid));
        let ecu_stat = eac.ecu_map.get(&ecu).unwrap();
        let apid_stat = ecu_stat.apids.get(&apid).unwrap();
        let ctid_stat = apid_stat.ctids.get(&ctid).unwrap();
        assert_eq!(ctid_stat.desc, Some("a ctid 1".to_owned()));

        // set desc for a non existing apid/ctid:
        let apid = DltChar4::from_buf(b"API2");
        eac.add_desc("a ctid", &ecu, &apid, Some(&ctid));
        let ecu_stat = eac.ecu_map.get(&ecu).unwrap();
        let apid_stat = ecu_stat.apids.get(&apid).unwrap();
        let ctid_stat = apid_stat.ctids.get(&ctid).unwrap();
        assert_eq!(ctid_stat.desc, Some("a ctid".to_owned()));
    }

    #[test]
    fn ctrl_info() {
        let mut eac = EacStats::new();
        // check parsing of GET_LOG_INFO message. here with 1 apid: APID/desc, 0 ctids
        let m = DltMessage::get_testmsg_control(
            false,
            1,
            &[
                3, 0, 0, 0, 7, 1, 0, b'A', b'P', b'I', b'D', 0, 0, 4, 0, b'd', b'e', b's', b'c',
            ],
        );
        eac.add_msg(&m);
        let ecu_stat = eac.ecu_map.get(&m.ecu).unwrap();
        let apid_stat = ecu_stat.apids.get(&DltChar4::from_buf(b"APID")).unwrap();
        assert_eq!(apid_stat.desc, Some("desc".to_owned()));
    }

    #[test]
    fn remote_types() {
        let ctid = DltChar4::from_buf(b"CTID");
        let a_s = ApidStats {
            desc: Some("apid desc".into()),
            ctids: vec![(
                ctid,
                CtidStats {
                    desc: Some("ctid desc".into()),
                    ..Default::default()
                },
            )]
            .into_iter()
            .collect(),
        };

        let apid = DltChar4::from_buf(b"APID");
        let bin_as = remote_types::BinApidInfo::from((&apid, &a_s));
        assert_eq!(bin_as.apid, apid.as_u32le());
        assert_eq!(bin_as.desc.as_deref(), Some("apid desc"));
        assert_eq!(bin_as.ctids.len(), 1);
        assert_eq!(bin_as.ctids[0].ctid, ctid.as_u32le());
        assert_eq!(bin_as.ctids[0].desc.as_deref(), Some("ctid desc"));

        let e_s = EcuStats {
            apids: vec![(apid, a_s)].into_iter().collect(),
            ..Default::default()
        };
        let ecu = DltChar4::from_buf(b"Ecu1");
        let bin_es = remote_types::BinEcuStats::from((&ecu, &e_s));
        assert_eq!(bin_es.ecu, ecu.as_u32le());
        assert_eq!(bin_es.apids.len(), 1);
    }
}
