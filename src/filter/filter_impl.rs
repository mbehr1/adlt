use crate::dlt::DltChar4;
use crate::dlt::DltMessage;
use crate::dlt::Error; // todo??? or in crate::?
use crate::dlt::ErrorKind;
use regex::Regex;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use serde_json::Value;
use std::str::FromStr; // todo??? or in crate::?

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum FilterKind {
    Positive = 0,
    Negative = 1,
    Marker = 2,
    Event = 3, // filter that collects data. Is basically a pos. filter
}
impl FilterKind {
    /*    fn value(&self) -> u8 {
        match *self {
            FilterKind::Positive => 0,
            FilterKind::Negative => 1,
            FilterKind::Marker => 2,
            FilterKind::Event => 3,
        }
    }*/
}

#[derive(Debug, Default)]
pub struct FilterKindContainer<T: Default> {
    e: [T; 4],
}

impl<T: Default> std::ops::Index<FilterKind> for FilterKindContainer<T> {
    type Output = T;
    fn index(&self, kind: FilterKind) -> &Self::Output {
        match kind {
            FilterKind::Positive => &self.e[0],
            FilterKind::Negative => &self.e[1],
            FilterKind::Marker => &self.e[2],
            FilterKind::Event => &self.e[3],
        }
    }
}

impl<T: Default> std::ops::IndexMut<FilterKind> for FilterKindContainer<T> {
    fn index_mut(&mut self, kind: FilterKind) -> &mut Self::Output {
        match kind {
            FilterKind::Positive => &mut self.e[0],
            FilterKind::Negative => &mut self.e[1],
            FilterKind::Marker => &mut self.e[2],
            FilterKind::Event => &mut self.e[3],
        }
    }
}

#[derive(Debug)]
pub struct Filter {
    pub kind: FilterKind,
    pub enabled: bool, // defaults to true

    at_load_time: bool, // defaults to false
    negate_match: bool, // defaults to false
    // filter values
    // if multiple are set, all have to match
    // if none are set, it matches
    pub ecu: Option<DltChar4>,
    pub apid: Option<DltChar4>,
    pub ctid: Option<DltChar4>,
    pub payload: Option<String>,
    pub payload_regex: Option<Regex>,
}

impl Filter {
    pub fn from_json(json_str: &str) -> Result<Filter, Error> {
        // Parse the string of data into serde_json::Value.
        let v = serde_json::from_str(json_str);
        if v.is_err() {
            return Err(Error::new(ErrorKind::InvalidData(format!(
                "json err '{:?}' parsing '{}'",
                v.unwrap_err(),
                json_str
            ))));
        }
        let v: Value = v.unwrap();
        println!("Filter::from_json got {:?}", v);
        let kind: FilterKind = match v["type"].as_u64() {
            Some(0) => FilterKind::Positive,
            Some(1) => FilterKind::Negative,
            Some(2) => FilterKind::Marker,
            Some(3) => FilterKind::Event,
            _ => {
                return Err(Error::new(ErrorKind::InvalidData(String::from(
                    "unsupported type",
                ))))
            }
        };

        let mut enabled = true;
        if let Some(b) = v["enabled"].as_bool() {
            enabled = b;
        }

        let mut negate_match = false;
        if let Some(b) = v["not"].as_bool() {
            negate_match = b;
        }

        let mut at_load_time = false;
        if let Some(b) = v["atLoadTime"].as_bool() {
            at_load_time = b;
        }

        let mut ecu = None;
        if let Some(s) = v["ecu"].as_str() {
            ecu = DltChar4::from_str(s).ok();
        }

        let mut apid = None;
        if let Some(s) = v["apid"].as_str() {
            apid = DltChar4::from_str(s).ok();
        }

        let mut ctid = None;
        if let Some(s) = v["ctid"].as_str() {
            ctid = DltChar4::from_str(s).ok();
        }

        let mut payload = None;
        let mut payload_regex = None;
        if let Some(s) = v["payloadRegex"].as_str() {
            payload_regex = Regex::new(s).ok();
        } else if let Some(s) = v["payload"].as_str() {
            payload = Some(s.to_string());
        }

        Ok(Filter {
            kind,
            enabled,
            at_load_time,
            negate_match,
            ecu,
            apid,
            ctid,
            payload,
            payload_regex,
        })
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap() // should never fail
    }

    /// return a filter from a dlt_viewer dlf xml stream
    ///
    /// it's assumed that the starting <filter> was already parsed but if there it's ignored!
    /// Parsing stops at the </filter> tag.
    /// default values are used (new(positive))
    pub fn from_quick_xml_reader<B: std::io::BufRead>(
        reader: &mut quick_xml::Reader<B>,
    ) -> Result<Filter, quick_xml::Error> {
        let mut filter = Filter::new(FilterKind::Positive);
        let mut buf = Vec::new();
        let mut attrs = std::collections::HashMap::<String, String>::with_capacity(32);

        let mut last_entry = None;
        loop {
            match reader.read_event(&mut buf) {
                Ok(quick_xml::events::Event::Start(ref e)) => match e.local_name() {
                    b"filter" => {} // ignore filter start (no nested ones)
                    _ => {
                        last_entry = Some(String::from_utf8(e.local_name().to_vec()).unwrap());
                    }
                },
                Ok(quick_xml::events::Event::Text(t)) => {
                    let text = String::from_utf8(t.unescaped()?.to_vec());
                    if text.is_err() {
                        return Err(quick_xml::Error::TextNotFound);
                    }
                    if last_entry.is_some() {
                        attrs.insert(last_entry.take().unwrap(), text.unwrap());
                    }
                }
                Ok(quick_xml::events::Event::End(ref e)) => {
                    if let b"filter" = e.local_name() {
                        break;
                    }
                }
                Ok(quick_xml::events::Event::Eof) => {
                    return Err(quick_xml::Error::UnexpectedEof(
                        "</filter> missing!".to_string(),
                    ))
                }
                Err(e) => return Err(e),
                _ => {}
            }
            buf.clear();
        }
        if let Some(s) = attrs.get("type") {
            filter.kind = match s.parse::<u8>().unwrap_or_default() {
                0 => FilterKind::Positive,
                1 => FilterKind::Negative,
                2 => FilterKind::Marker,
                3 => FilterKind::Event,
                _ => FilterKind::Positive,
            };
        }
        filter.enabled = attrs.get("enablefilter") == Some(&"1".to_string());

        // todo name, headertext,
        if attrs.get("enableecuid") == Some(&"1".to_string()) {
            if let Some(s) = attrs.get("ecuid") {
                filter.ecu = DltChar4::from_str(s).ok();
            }
        }
        if attrs.get("enableapplicationid") == Some(&"1".to_string()) {
            if let Some(s) = attrs.get("applicationid") {
                filter.apid = DltChar4::from_str(s).ok();
            }
        }
        if attrs.get("enablecontextid") == Some(&"1".to_string()) {
            if let Some(s) = attrs.get("contextid") {
                filter.ctid = DltChar4::from_str(s).ok();
            }
        }
        if attrs.get("enablepayloadtext") == Some(&"1".to_string()) {
            if let Some(s) = attrs.get("payloadtext") {
                if attrs.get("enableregexp_Payload") == Some(&"1".to_string()) {
                    filter.payload_regex = Regex::new(s).ok();
                } else {
                    filter.payload = Some(s.clone());
                }
            }
        }
        // todo remaining parts from qdltfilter

        Ok(filter)
    }

    pub fn new(kind: FilterKind) -> Filter {
        Filter {
            kind,
            enabled: true,
            at_load_time: false,
            negate_match: false,
            ecu: None,
            apid: None,
            ctid: None,
            payload: None,
            payload_regex: None,
        }
    }

    pub fn matches(&self, msg: &DltMessage) -> bool {
        if !self.enabled {
            return false;
        }
        let negated = self.negate_match;

        if let Some(aecu) = &self.ecu {
            if aecu != &msg.ecu {
                return negated;
            }
        }
        if let Some(aapid) = &self.apid {
            if let Some(mapid) = msg.apid() {
                if aapid != mapid {
                    return negated;
                }
            } else {
                return negated;
            }
        }
        if let Some(actid) = &self.ctid {
            if let Some(mctid) = msg.ctid() {
                if actid != mctid {
                    return negated;
                }
            } else {
                return negated;
            }
        }
        // todo payload and payloadRegex: cache payload_as_text()?
        // and think about plugins that convert the payload
        if let Some(payload_regex) = &self.payload_regex {
            let payload_text = msg.payload_as_text();
            if let Ok(payload_text) = payload_text {
                if !payload_regex.is_match(&payload_text) {
                    return negated;
                }
            } else {
                return negated;
            }
        } else if let Some(payload) = &self.payload {
            let payload_text = msg.payload_as_text();
            if let Ok(payload_text) = payload_text {
                if !payload_text.contains(payload) {
                    return negated;
                }
            } else {
                return negated;
            }
        }

        !negated
    }
}

impl Serialize for Filter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Filter", 7)?;
        let kind: u8 = self.kind as u8;
        state.serialize_field("type", &kind)?;
        if !self.enabled {
            state.serialize_field("enabled", &self.enabled)?;
        }
        if self.at_load_time {
            state.serialize_field("atLoadTime", &self.at_load_time)?;
        }
        if self.negate_match {
            state.serialize_field("not", &self.negate_match)?;
        }

        if let Some(s) = &self.ecu {
            state.serialize_field("ecu", &s)?;
        }
        if let Some(s) = &self.apid {
            state.serialize_field("apid", &s)?;
        }
        if let Some(s) = &self.ctid {
            state.serialize_field("ctid", &s)?;
        }
        if let Some(s) = &self.payload_regex {
            state.serialize_field("payloadRegex", s.as_str())?;
        } else if let Some(s) = &self.payload {
            state.serialize_field("payload", &s)?;
        }

        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlt::DltExtendedHeader;

    #[test]
    fn default_values() {
        let f = Filter::new(FilterKind::Positive);
        assert_eq!(f.kind, FilterKind::Positive);
        assert!(f.enabled);
        assert!(!f.negate_match);
    }

    #[test]
    fn disabled_dont_match() {
        let mut f = Filter::new(FilterKind::Positive);
        let m = DltMessage::for_test();
        assert!(f.matches(&m));
        f.enabled = false;
        assert!(!f.matches(&m));
    }
    #[test]
    fn disabled_dont_match_even_negated() {
        let mut f = Filter::new(FilterKind::Positive);
        let m = DltMessage::for_test();
        assert!(f.matches(&m));
        f.enabled = false;
        f.negate_match = true;
        assert!(!f.matches(&m));
    }

    #[test]
    fn match_ecu() {
        let mut f = Filter::new(FilterKind::Positive);
        let m = DltMessage::for_test();
        f.ecu = Some(DltChar4::from_buf(b"ECU1"));
        assert!(!f.matches(&m));
        f.ecu = Some(m.ecu);
        assert!(f.matches(&m));
        // and now negated:
        f.negate_match = true;
        assert!(!f.matches(&m));
        f.ecu = Some(DltChar4::from_buf(b"ECU1"));
        assert!(f.matches(&m));
    }

    #[test]
    fn match_ecu_and_apid() {
        let mut f = Filter::new(FilterKind::Positive);
        let mut m = DltMessage::for_test();
        f.ecu = Some(DltChar4::from_buf(b"ECU1"));
        f.apid = Some(DltChar4::from_buf(b"APID"));
        // neither ecu nor apid match
        assert!(!f.matches(&m));
        f.ecu = Some(m.ecu);
        // now ecu matches but not apid
        assert!(!f.matches(&m));
        m.extended_header = Some(DltExtendedHeader {
            apid: DltChar4::from_buf(b"APID"),
            noar: 0,
            ctid: DltChar4::from_buf(b"CTID"),
            verb_mstp_mtin: 0,
        });
        // now both match:
        assert!(f.matches(&m));
        f.ecu = Some(DltChar4::from_buf(b"ECU1"));
        // now apid matches but not ecu:
        assert!(!f.matches(&m));
    }
    #[test]
    fn match_ecu_and_apid_and_ctid() {
        let mut f = Filter::new(FilterKind::Positive);
        let mut m = DltMessage::for_test();
        f.ecu = Some(DltChar4::from_buf(b"ECU1"));
        f.apid = Some(DltChar4::from_buf(b"APID"));
        f.ctid = Some(DltChar4::from_buf(b"CTID"));
        // neither ecu nor apid match
        assert!(!f.matches(&m));
        f.ecu = Some(m.ecu);
        // now ecu matches but not apid
        assert!(!f.matches(&m));
        m.extended_header = Some(DltExtendedHeader {
            apid: DltChar4::from_buf(b"APID"),
            noar: 0,
            ctid: DltChar4::from_buf(b"CTID"),
            verb_mstp_mtin: 0,
        });
        // now all match:
        assert!(f.matches(&m));
        f.ctid = Some(DltChar4::from_buf(b"CTIF"));
        // now apid,ecu matches but not ctid:
        assert!(!f.matches(&m));
    }

    #[test]
    fn match_payload() {
        let mut f = Filter::new(FilterKind::Positive);
        f.payload = Some("answer".to_string());

        let v = crate::utils::hex_to_bytes("3d 0a 00 af 4d 4d 4d 41 00 00 03 48 00 75 7d 16 41 08 4c 52 4d 46 55 44 53 00 00 82 00 00 1c 00 46 69 6e 61 6c 20 61 6e 73 77 65 72 20 61 72 72 69 76 65 64 20 61 66 74 65 72 20 00 23 00 00 00 93 01 00 00 00 82 00 00 21 00 75 73 20 66 72 6f 6d 20 74 68 65 20 6a 6f 62 20 68 61 6e 64 6c 65 72 20 5b 73 74 61 74 65 3a 20 00 00 82 00 00 0a 00 41 6e 73 77 65 72 69 6e 67 00 00 82 00 00 0b 00 2c 20 61 6e 73 77 65 72 3a 20 00 10 00 00 00 01 00 82 00 00 10 00 5d 20 66 6f 72 20 72 65 71 75 65 73 74 20 23 00 43 00 00 00 dc 05 00 00").unwrap();
        assert_eq!(175, v.len());
        let sh = crate::dlt::DltStorageHeader {
            secs: 0,
            micros: 0,
            ecu: DltChar4::from_str("ECU1").unwrap(),
        };
        let stdh = crate::dlt::DltStandardHeader::from_buf(&v).unwrap();
        let payload_offset = stdh.std_ext_header_size() as usize;
        let m = DltMessage::from_headers(
            1423084,
            sh,
            stdh,
            &v[crate::dlt::DLT_MIN_STD_HEADER_SIZE..payload_offset],
            v[payload_offset..].to_vec(),
        );
        println!("payload_as_text='{}'", m.payload_as_text().unwrap());
        assert!(f.matches(&m));
        f.payload = Some("ANswer".to_string());
        assert!(!f.matches(&m));
        f.payload = None;
        f.payload_regex = Regex::from_str("1500$").ok(); // ends with
        assert!(f.matches(&m));
        f.payload_regex = Regex::from_str("^Final answer").ok(); // starts with
        assert!(f.matches(&m));
        f.payload_regex = Regex::from_str("^answer").ok(); // doesn't start with
        assert!(!f.matches(&m));
    }

    #[test]
    fn from_json() {
        // missing type
        let f = Filter::from_json(r#""#);
        assert!(f.is_err());

        // wrong type
        let f = Filter::from_json(r#"{"type": 4}"#);
        assert!(f.is_err());

        // proper type
        let f = Filter::from_json(r#"{"type": 3}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Event);
        assert!(f.enabled);

        // proper type and enabled
        let f = Filter::from_json(r#"{"type": 0, "enabled": false}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert!(!f.enabled);

        // proper type and ecu
        let f = Filter::from_json(r#"{"type": 0, "ecu": "AbC"}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.ecu, Some(DltChar4::from_buf(b"AbC\0")));

        // proper type and ecu with lower ascii range... (json strings are in unicode / rfc7159)
        let f = Filter::from_json(r#"{"type": 0, "ecu": "A\u0001C"}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.ecu, Some(DltChar4::from_buf(&[0x41, 1, 0x43, 0])));

        // payload
        let f = Filter::from_json(r#"{"type": 0, "payload":"\\fOo"}"#).unwrap();
        assert!(f.payload_regex.is_none());
        assert_eq!(f.payload, Some("\\fOo".to_string()));

        // payload and payloadRegex (both set -> prefer regex)
        let f =
            Filter::from_json(r#"{"type": 0, "payload":"fOo", "payloadRegex":"^fOo"}"#).unwrap();
        assert!(f.payload.is_none());
        assert_eq!(f.payload_regex.unwrap().as_str(), "^fOo");
    }

    #[test]
    fn to_json() {
        let f = Filter::from_json(r#"{"type": 3}"#).unwrap();
        let s = f.to_json();
        assert_eq!(s, r#"{"type":3}"#);

        // field enabled and "not"
        let f = Filter::from_json(r#"{"type": 0, "enabled":false,"not":true}"#).unwrap();
        let s = f.to_json();
        assert!(s.contains(r#""type":0"#));
        assert!(s.contains(r#""enabled":false"#));
        assert!(s.contains(r#""not":true"#));

        // field ecu
        let f = Filter::from_json(r#"{"type": 0, "ecu":"ec1"}"#).unwrap();
        let s = f.to_json();
        assert!(s.contains(r#""ecu":"ec1""#), "ecu wrong in {}", &s);

        // field apid
        let f = Filter::from_json(r#"{"type": 0, "apid":"ap1"}"#).unwrap();
        let s = f.to_json();
        assert!(
            s.contains(r#""apid":"ap1""#),
            "apid wrong in {:?} as {}",
            f,
            &s
        );

        // field ctid
        let f = Filter::from_json(r#"{"type": 0, "ctid":"CTID"}"#).unwrap();
        let s = f.to_json();
        assert!(s.contains(r#""ctid":"CTID""#), "ctid wrong in {}", &s);

        // field ecu with 5 chars (should lead to parser error? todo)
        let f = Filter::from_json(r#"{"type": 0, "ecu":"12345"}"#).unwrap();
        let s = f.to_json();
        assert!(s.contains(r#""ecu":"1234""#), "ecu wrong in {}", &s);

        // field payload
        let f = Filter::from_json(r#"{"type": 0, "payload":"fOo"}"#).unwrap();
        let s = f.to_json();
        assert!(s.contains(r#""payload":"fOo""#), "payload wrong in {}", &s);
        // field payloadRegex
        let f = Filter::from_json(r#"{"type": 0, "payloadRegex":"^fOo"}"#).unwrap();
        let s = f.to_json();
        assert!(
            s.contains(r#""payloadRegex":"^fOo""#),
            "payloadRegex wrong in {}",
            &s
        );
        // field payloadRegex and payload -> only payloadRegex expected
        let f =
            Filter::from_json(r#"{"type": 0, "payload":"fOo", "payloadRegex":"^fOo"}"#).unwrap();
        assert!(f.payload.is_none());
        let s = f.to_json();
        assert!(!s.contains(r#""payload""#), "payload unexpected in {}", &s);
        assert!(
            s.contains(r#""payloadRegex":"^fOo""#),
            "payloadRegex wrong in {}",
            &s
        );
    }

    mod from_dlf {
        use super::*;
        use quick_xml::Reader;
        #[test]
        fn default() {
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(r#""#));
            assert!(r.is_err());

            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(r#"<filter></filter>"#));
            assert!(r.is_ok(), "got err {:?}", r.err());
            assert_eq!(r.unwrap().kind, FilterKind::Positive);
        }

        #[test]
        fn kind_type_enabled() {
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><type>0</type></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.kind, FilterKind::Positive);
            assert!(!r.enabled);

            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><type>1</type><enablefilter>0</enablefilter></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.kind, FilterKind::Negative);
            assert!(!r.enabled);

            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><type>2</type><enablefilter>1</enablefilter></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.kind, FilterKind::Marker);
            assert!(r.enabled);
        }

        #[test]
        fn ecu() {
            // ecuid set but not enableecuid
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><ecuid>foo</ecuid></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.ecu, None);

            // ecuid set but not enableecuid
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><ecuid>foo</ecuid><enableecuid>0</enableecuid></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.ecu, None);

            // ecuid not set but enableecuid -> no filter (might use a Some(...) as well)
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><enableecuid>1</enableecuid></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.ecu, None);

            // ecuid set and enableecuid
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><ecuid>fOo</ecuid><enableecuid>1</enableecuid></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.ecu, DltChar4::from_str("fOo").ok());
        }
        #[test]
        fn apid() {
            // apid set but not enableapid
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><applicationid>foo</applicationid></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.apid, None);

            // apid set and enableapid
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><applicationid>fOo</applicationid><enableapplicationid>1</enableapplicationid></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.apid, DltChar4::from_str("fOo").ok());
        }
        #[test]
        fn ctid() {
            // ctid set and enablectid
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><contextid>fOo</contextid><enablecontextid>1</enablecontextid></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.ctid, DltChar4::from_str("fOo").ok());
        }

        #[test]
        fn payload_text() {
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><payloadtext>fOo</payloadtext><enablepayloadtext>1</enablepayloadtext></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.payload, Some("fOo".to_string()));
            assert!(r.payload_regex.is_none());

            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><payloadtext>&amp;fOo&lt;&gt;</payloadtext><enableregexp_Payload>1</enableregexp_Payload><enablepayloadtext>1</enablepayloadtext></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.payload_regex.unwrap().as_str(), "&fOo<>");
            assert!(r.payload.is_none());
        }
    }
}
