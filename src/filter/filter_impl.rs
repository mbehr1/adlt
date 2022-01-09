use crate::dlt::DltChar4;
use crate::dlt::DltMessage;
use crate::dlt::Error; // todo??? or in crate::?
use crate::dlt::ErrorKind;
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
    }
}
