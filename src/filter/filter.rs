use serde_json::{Value};
use serde::ser::{Serialize, Serializer, SerializeStruct};
use crate::dlt::DltChar4;
use crate::dlt::DltMessage;
use crate::dlt::Error; // todo??? or in crate::?
use crate::dlt::ErrorKind; // todo??? or in crate::?

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
}

impl Filter {
    pub fn from_json(json_str: &str) -> Result<Filter, Error> {
        // Parse the string of data into serde_json::Value.
        let v = serde_json::from_str(json_str);
        if v.is_err() {
            return Err(Error::new(ErrorKind::InvalidData(String::from(format!("json err '{:?}' parsing '{}'",v.unwrap_err(),json_str)))));
        }
        let v :Value = v.unwrap();
        println!("Filter::from_json got {:?}", v);
        let kind:FilterKind = match v["type"].as_u64() {
            Some(0) => FilterKind::Positive,
            Some(1) => FilterKind::Negative,
            Some(2) => FilterKind::Marker,
            Some(3) => FilterKind::Event,
            _ => return Err(Error::new(ErrorKind::InvalidData(String::from("unsupported type"))))
        };

        let mut enabled = true;
        if let Some(b) = v["enabled"].as_bool() { enabled = b; }

        let mut negate_match = false;
        if let Some(b) = v["not"].as_bool() { negate_match = b; }

        let mut at_load_time = false;
        if let Some(b) = v["atLoadTime"].as_bool() { at_load_time = b; }

        let mut ecu = None;
        if let Some(s) = v["ecu"].as_str() { ecu = DltChar4::from_str(s); }

        let mut apid = None;
        if let Some(s) = v["apid"].as_str() { apid = DltChar4::from_str(s); }

        let mut ctid = None;
        if let Some(s) = v["ctid"].as_str() { ctid = DltChar4::from_str(s); }

        Ok(Filter {
            kind,
            enabled,
            at_load_time,
            negate_match,
            ecu,
            apid,
            ctid,
        })
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap() // should never fail
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

        return !negated;
    }
}

impl Serialize for Filter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Filter", 7)?;
        let kind :u8 = (&self).kind as u8;
        state.serialize_field("type", &kind)?;
        if !self.enabled { state.serialize_field("enabled", &self.enabled)?; }
        if self.at_load_time { state.serialize_field("atLoadTime", &self.at_load_time)?; }
        if self.negate_match { state.serialize_field("not", &self.negate_match)?; }

        if let Some(s) = &self.ecu { state.serialize_field("ecu", &s)?; }
        if let Some(s) = &self.apid { state.serialize_field("apid", &s)?; }
        if let Some(s) = &self.ctid { state.serialize_field("ctid", &s)?; }

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
        assert_eq!(f.enabled, true);
        assert_eq!(f.negate_match, false);
    }

    #[test]
    fn disabled_dont_match() {
        let mut f = Filter::new(FilterKind::Positive);
        let m = DltMessage::for_test();
        assert_eq!(f.matches(&m), true);
        f.enabled = false;
        assert_eq!(f.matches(&m), false);
    }
    #[test]
    fn disabled_dont_match_even_negated() {
        let mut f = Filter::new(FilterKind::Positive);
        let m = DltMessage::for_test();
        assert_eq!(f.matches(&m), true);
        f.enabled = false;
        f.negate_match = true;
        assert_eq!(f.matches(&m), false);
    }

    #[test]
    fn match_ecu() {
        let mut f = Filter::new(FilterKind::Positive);
        let m = DltMessage::for_test();
        f.ecu = Some(DltChar4::from_buf(b"ECU1"));
        assert_eq!(f.matches(&m), false);
        f.ecu = Some(m.ecu.clone());
        assert_eq!(f.matches(&m), true);
        // and now negated:
        f.negate_match = true;
        assert_eq!(f.matches(&m), false);
        f.ecu = Some(DltChar4::from_buf(b"ECU1"));
        assert_eq!(f.matches(&m), true);
    }

    #[test]
    fn match_ecu_and_apid() {
        let mut f = Filter::new(FilterKind::Positive);
        let mut m = DltMessage::for_test();
        f.ecu = Some(DltChar4::from_buf(b"ECU1"));
        f.apid = Some(DltChar4::from_buf(b"APID"));
        // neither ecu nor apid match
        assert_eq!(f.matches(&m), false);
        f.ecu = Some(m.ecu.clone());
        // now ecu matches but not apid
        assert_eq!(f.matches(&m), false);
        m.extended_header = Some(DltExtendedHeader {
            apid: DltChar4::from_buf(b"APID"),
            noar: 0,
            ctid: DltChar4::from_buf(b"CTID"),
            verb_mstp_mtin: 0,
        });
        // now both match:
        assert_eq!(f.matches(&m), true);
        f.ecu = Some(DltChar4::from_buf(b"ECU1"));
        // now apid matches but not ecu:
        assert_eq!(f.matches(&m), false);
    }
    #[test]
    fn match_ecu_and_apid_and_ctid() {
        let mut f = Filter::new(FilterKind::Positive);
        let mut m = DltMessage::for_test();
        f.ecu = Some(DltChar4::from_buf(b"ECU1"));
        f.apid = Some(DltChar4::from_buf(b"APID"));
        f.ctid = Some(DltChar4::from_buf(b"CTID"));
        // neither ecu nor apid match
        assert_eq!(f.matches(&m), false);
        f.ecu = Some(m.ecu.clone());
        // now ecu matches but not apid
        assert_eq!(f.matches(&m), false);
        m.extended_header = Some(DltExtendedHeader {
            apid: DltChar4::from_buf(b"APID"),
            noar: 0,
            ctid: DltChar4::from_buf(b"CTID"),
            verb_mstp_mtin: 0,
        });
        // now all match:
        assert_eq!(f.matches(&m), true);
        f.ctid = Some(DltChar4::from_buf(b"CTIF"));
        // now apid,ecu matches but not ctid:
        assert_eq!(f.matches(&m), false);
    }

    #[test]
    fn from_json() {
        // missing type
        let f = Filter::from_json(r#""#);
        assert_eq!(f.is_err(), true);

        // wrong type
        let f = Filter::from_json(r#"{"type": 4}"#);
        assert_eq!(f.is_err(), true);

        // proper type
        let f = Filter::from_json(r#"{"type": 3}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Event);
        assert_eq!(f.enabled, true);
        
        // proper type and enabled
        let f = Filter::from_json(r#"{"type": 0, "enabled": false}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.enabled, false);

        // proper type and ecu
        let f = Filter::from_json(r#"{"type": 0, "ecu": "AbC"}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.ecu, Some(DltChar4::from_buf(b"AbC\0")));

        // proper type and ecu with lower ascii range... (json strings are in unicode / rfc7159)
        let f = Filter::from_json(r#"{"type": 0, "ecu": "A\u0001C"}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.ecu, Some(DltChar4::from_buf(&[0x41,1 ,0x43, 0 ])));
    }

    #[test]
    fn to_json() {
        let f = Filter::from_json(r#"{"type": 3}"#).unwrap();
        let s = f.to_json();
        assert_eq!(s, r#"{"type":3}"#);

        // field enabled and "not"
        let f = Filter::from_json(r#"{"type": 0, "enabled":false,"not":true}"#).unwrap();
        let s = f.to_json();
        assert_eq!(s.contains(r#""type":0"#), true);
        assert_eq!(s.contains(r#""enabled":false"#), true);
        assert_eq!(s.contains(r#""not":true"#), true);

        // field ecu
        let f = Filter::from_json(r#"{"type": 0, "ecu":"ec1"}"#).unwrap();
        let s = f.to_json();
        assert_eq!(s.contains(r#""ecu":"ec1""#), true, "ecu wrong in {}", &s);

        // field apid
        let f = Filter::from_json(r#"{"type": 0, "apid":"ap1"}"#).unwrap();
        let s = f.to_json();
        assert_eq!(s.contains(r#""apid":"ap1""#), true, "apid wrong in {:?} as {}", f, &s);

        // field ctid
        let f = Filter::from_json(r#"{"type": 0, "ctid":"CTID"}"#).unwrap();
        let s = f.to_json();
        assert_eq!(s.contains(r#""ctid":"CTID""#), true, "ctid wrong in {}", &s);
        

        // field ecu with 5 chars (should lead to parser error? todo)
        let f = Filter::from_json(r#"{"type": 0, "ecu":"12345"}"#).unwrap();
        let s = f.to_json();
        assert_eq!(s.contains(r#""ecu":"1234""#), true, "ecu wrong in {}", &s);
        
    }
}
