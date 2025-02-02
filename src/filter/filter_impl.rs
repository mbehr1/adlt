use crate::dlt;
use crate::dlt::DltChar4;
use crate::dlt::DltMessage;
use crate::dlt::Error; // todo??? or in crate::?
use crate::dlt::ErrorKind;
use crate::utils::contains_regex_chars;
use fancy_regex::Regex;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use serde_json::Value;
use std::str::FromStr; // todo??? or in crate::?

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
/// An enum representing either a 4-character (ascii) string/DltChar4 or a regular expression (non utf8!).
///
pub enum Char4OrRegex {
    DltChar4(DltChar4),
    Regex(regex::bytes::Regex),
}

impl Char4OrRegex {
    pub fn from_str(s: &str, is_regex: bool) -> Result<Self, dlt::Error> {
        if is_regex {
            regex::bytes::Regex::new(s)
                .map(Char4OrRegex::Regex)
                .map_err(|e| {
                    Error::new(ErrorKind::InvalidData(format!(
                        "Char4OrRegex failed regex with {:?}",
                        e
                    )))
                })
        } else {
            DltChar4::from_str(s)
                .map(Char4OrRegex::DltChar4)
                .map_err(|e| {
                    Error::new(ErrorKind::InvalidData(format!(
                        "Char4OrRegex failed non regex with {:?}",
                        e
                    )))
                })
        }
    }

    pub fn from_buf(buf: &[u8]) -> Result<Self, dlt::Error> {
        if buf.len() == 4 {
            Ok(Char4OrRegex::DltChar4(DltChar4::from_buf(buf)))
        } else {
            Err(Error::new(ErrorKind::InvalidData(format!(
                "buf len {:?} != 4",
                buf.len()
            ))))
        }
    }
}

impl From<DltChar4> for Char4OrRegex {
    fn from(d: DltChar4) -> Self {
        Char4OrRegex::DltChar4(d)
    }
}

impl From<regex::bytes::Regex> for Char4OrRegex {
    fn from(r: regex::bytes::Regex) -> Self {
        Char4OrRegex::Regex(r)
    }
}

impl PartialEq for Char4OrRegex {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Char4OrRegex::DltChar4(d1), Char4OrRegex::DltChar4(d2)) => d1 == d2,
            (Char4OrRegex::Regex(r1), Char4OrRegex::Regex(r2)) => r1.as_str() == r2.as_str(),
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Filter {
    pub kind: FilterKind,
    pub enabled: bool, // defaults to true

    at_load_time: bool, // defaults to false
    negate_match: bool, // defaults to false
    // filter values
    // if multiple are set, all have to match
    // if none are set, it matches
    pub ecu: Option<Char4OrRegex>,
    pub apid: Option<Char4OrRegex>,
    pub ctid: Option<Char4OrRegex>,
    /// match for verb_mstp_mtin with a mask
    /// the from_json contains a logic to set an ignore for mtin if mtin is 0
    /// can match for mstp and all mtins (mtin part 0) or specific mtin (mtin !=0)
    /// mtin is the upper 4 bits, mstp the bits 3..1, verbose the lowest bit
    /// e.g.  0<<4 | 3<<1 = all ctrl messages, non verbose
    /// 2<<4 | 3<<1 = all ctrl, response messages, non verbose
    pub verb_mstp_mtin: Option<(u8, u8)>, // value and mask
    pub payload: Option<String>,
    pub payload_regex: Option<Regex>,
    pub ignore_case_payload: bool, // for both payload or payload_regex (limited to first group!)
    payload_as_regex: Option<regex::Regex>, // caches the payload converted to a regex if ignore_case_payload is set and non regex
    pub loglevel_min: Option<u8>,           // could use DltMessageLogType here but has no cmp op
    pub loglevel_max: Option<u8>,
    // filter on lifecycles. This is not the lifecycle.id but the persistentId
    pub lifecycles: Option<Vec<u32>>,
}

impl Filter {
    /// parse a filter from the json resprentation
    ///
    /// # Supported json format
    /// object with the following fields:
    /// * type: number (0=positive, 1=negative, 2=marker, 3=event)
    /// * enabled: bool (optional, defaults to true)
    /// * not: bool (optional, defaults to false)
    /// * atLoadTime: bool (optional, defaults to false)
    /// * ecu: string (optional, defaults to no filter for ecu)
    /// * ecuIsRegex: bool (optional, default handling see below)
    ///
    ///   if true ecu is interpreted as a regex (e.g. 'ECU' matches all ecus containing 'ECU'). Regex for ecu/apic/ctid are ascii and not utf-8 based!
    ///
    ///   Syntax supported is the one from crate regex::bytes see https://docs.rs/regex/1.10.2/regex/index.html
    ///
    ///   if false ecu is interpreted as a DltChar4 (e.g. 'ECU' matches 'ECU\0' so starting with and not 4th char)
    ///
    ///   if not provided an autodetection is done with the following rules:
    ///
    ///    * if any regex character like ^$*+?()[]{}|.-\=!<, is in the string it's interpreted as regex
    ///
    /// * apid: string (optional, defaults to no filter for apids / all apids)
    /// * apidIsRegex: bool (optional, see ecuIsRegex)
    /// * ctid: string (optional, defaults to no filter for ctids / all ctids)
    /// * ctidIsRegex: bool (optional, see ecuIsRegex)
    /// * verb_mstp_mtin: u8 (optional, defaults to all messages)
    /// * payload: string (optional, defaults to all payloads)
    /// * payloadRegex: string (optional, defaults to all payloads)
    /// * ignoreCasePayload: bool (optional, defaults to false)
    /// * logLevelMin: u8 (optional, defaults to all loglevels)
    /// * logLevelMax: u8 (optional, defaults to all loglevels)
    /// * lifecycles: array of u32 (optional, defaults to all lifecycles)
    /// * verb_mstp_mtin: u8 (optional, defaults to all messages) or
    /// * mstp: u8 (optional, defaults to all messages)
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
        //println!("Filter::from_json got {:?}", v);
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

        let mut ecu: Option<Char4OrRegex> = None;

        if let Some(s) = v["ecu"].as_str() {
            let ecu_is_regex = v["ecuIsRegex"]
                .as_bool()
                .unwrap_or_else(|| contains_regex_chars(s));
            ecu = Some(Char4OrRegex::from_str(s, ecu_is_regex).map_err(|e| {
                Error::new(ErrorKind::InvalidData(format!(
                    "error parsing ecu '{}' ecuIsRegex={}:{:?}",
                    s, ecu_is_regex, e
                )))
            })?)
        }

        let mut apid = None;
        if let Some(s) = v["apid"].as_str() {
            let apid_is_regex = v["apidIsRegex"]
                .as_bool()
                .unwrap_or_else(|| contains_regex_chars(s));
            apid = Some(Char4OrRegex::from_str(s, apid_is_regex).map_err(|e| {
                Error::new(ErrorKind::InvalidData(format!(
                    "error parsing apid '{}' apidIsRegex={}:{:?}",
                    s, apid_is_regex, e
                )))
            })?)
        }

        let mut ctid = None;
        if let Some(s) = v["ctid"].as_str() {
            let ctid_is_regex = v["ctidIsRegex"]
                .as_bool()
                .unwrap_or_else(|| contains_regex_chars(s));
            ctid = Some(Char4OrRegex::from_str(s, ctid_is_regex).map_err(|e| {
                Error::new(ErrorKind::InvalidData(format!(
                    "error parsing ctid '{}' ctidIsRegex={}:{:?}",
                    s, ctid_is_regex, e
                )))
            })?)
        }

        let mut ignore_case_payload = false;
        if let Some(b) = v["ignoreCasePayload"].as_bool() {
            ignore_case_payload = b;
        }

        let mut payload = None;
        let mut payload_as_regex = None;
        let mut payload_regex = None;
        if let Some(s) = v["payloadRegex"].as_str() {
            // sadly this regex is python syntax and not ecmascript
            // so convert ecmascript capture groups to python ones
            // not needed any longer with fancy_regex let s = s.replace("(?<", "(?P<");
            if ignore_case_payload {
                let s = "(?i)".to_owned() + s;
                payload_regex = Some(Regex::new(&s).map_err(|e| {
                    Error::new(ErrorKind::InvalidData(format!(
                        "regex error parsing '{}':{:?}",
                        s, e
                    )))
                })?);
            } else {
                payload_regex = Some(Regex::new(s).map_err(|e| {
                    Error::new(ErrorKind::InvalidData(format!(
                        "regex error parsing '{}':{:?}",
                        s, e
                    )))
                })?);
            }
        } else if let Some(s) = v["payload"].as_str() {
            payload = Some(s.to_string());
            if ignore_case_payload {
                // create regex
                payload_as_regex = Some(
                    regex::RegexBuilder::new(&regex::escape(s))
                        .case_insensitive(true)
                        .build()
                        .map_err(|e| {
                            Error::new(ErrorKind::InvalidData(format!(
                                "regex error parsing escaped '{}':{:?}",
                                s, e
                            )))
                        })?,
                );
            }
        }

        let mut loglevel_min = None;
        if let Some(lvl) = v["logLevelMin"].as_u64() {
            if lvl <= 6 {
                // verbose
                loglevel_min = Some(lvl as u8);
            } else {
                return Err(Error::new(ErrorKind::InvalidData(String::from(
                    "unsupported loglevelMin value",
                ))));
            }
        }
        let mut loglevel_max = None;
        if let Some(lvl) = v["logLevelMax"].as_u64() {
            if lvl <= 6 {
                // verbose
                loglevel_max = Some(lvl as u8);
            } else {
                return Err(Error::new(ErrorKind::InvalidData(String::from(
                    "unsupported loglevelMax value",
                ))));
            }
        }

        let lifecycles = v["lifecycles"].as_array().map(|lcs| {
            lcs.iter()
                .map(|l| l.as_u64())
                .filter(|l| l.is_some())
                .map(|l| l.unwrap() as u32)
                .collect()
        });

        // we prefer verb_mstp_mtin higher than mstp
        // todo add unit tests
        let verb_mstp_mtin = if let Some(mstp) = v["verb_mstp_mtin"].as_u64() {
            let verb_mstp_mtin = (mstp & 0xff) as u8;
            // special handling: if mtin here is 0 we want it to be ignored (as mtin 0 is a special value)
            let mtin = (verb_mstp_mtin >> 4) & 0xf;
            let mask = if mtin == 0 { 0x0fu8 } else { 0xffu8 };
            Some((verb_mstp_mtin, mask))
        } else if let Some(mstp) = v["mstp"].as_u64() {
            // match mstp to verb_mstp_mtin logic
            // we ignore mtin and verb
            let verb_mstp_mtin = ((mstp & 0x07) << 1) as u8;
            Some((verb_mstp_mtin, 0x07 << 1))
        } else {
            None
        };

        Ok(Filter {
            kind,
            enabled,
            at_load_time,
            negate_match,
            ecu,
            apid,
            ctid,
            verb_mstp_mtin,
            payload,
            payload_regex,
            ignore_case_payload,
            payload_as_regex,
            loglevel_min,
            loglevel_max,
            lifecycles,
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
            match reader.read_event_into(&mut buf) {
                Ok(quick_xml::events::Event::Start(ref e)) => match e.local_name().as_ref() {
                    b"filter" => {} // ignore filter start (no nested ones)
                    _ => {
                        last_entry =
                            Some(String::from_utf8_lossy(e.local_name().as_ref()).into_owned());
                    }
                },
                Ok(quick_xml::events::Event::Text(t)) => match t.unescape() {
                    Ok(text) => {
                        if last_entry.is_some() {
                            attrs.insert(last_entry.take().unwrap().to_string(), text.to_string());
                        }
                    }
                    Err(e) => return Err(e),
                },
                Ok(quick_xml::events::Event::End(ref e)) => {
                    if let b"filter" = e.local_name().as_ref() {
                        break;
                    }
                }
                Ok(quick_xml::events::Event::Eof) => {
                    return Err(quick_xml::Error::IllFormed(
                        quick_xml::errors::IllFormedError::MissingEndTag("filter".to_string()),
                    ));
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
                // enableRegexp_Ecu doesnt exist
                // shall we autodetect?
                filter.ecu = Char4OrRegex::from_str(s, false).ok(); // dlt-viewer supports no regex for ecu
            }
        }
        if attrs.get("enableapplicationid") == Some(&"1".to_string()) {
            if let Some(s) = attrs.get("applicationid") {
                let apid_is_regex = if let Some(ir) = attrs.get("enableregexp_Appid") {
                    ir == &"1".to_string()
                } else {
                    contains_regex_chars(s) // autodetect
                };
                filter.apid = Char4OrRegex::from_str(s, apid_is_regex).ok();
            }
        }
        if attrs.get("enablecontextid") == Some(&"1".to_string()) {
            if let Some(s) = attrs.get("contextid") {
                let ctid_is_regex = if let Some(ir) = attrs.get("enableregexp_Context") {
                    ir == &"1".to_string()
                } else {
                    contains_regex_chars(s) // autodetect
                };
                filter.ctid = Char4OrRegex::from_str(s, ctid_is_regex).ok();
            }
        }
        if attrs.get("enablecontrolmsgs") == Some(&"1".to_string()) {
            filter.verb_mstp_mtin = Some((0x03u8 << 1, (7u8 << 1))); // filter only on mstp
        }
        if attrs.get("enablepayloadtext") == Some(&"1".to_string()) {
            filter.ignore_case_payload = attrs.get("ignoreCase_Payload") == Some(&"1".to_string());
            if let Some(s) = attrs.get("payloadtext") {
                if attrs.get("enableregexp_Payload") == Some(&"1".to_string()) {
                    if filter.ignore_case_payload {
                        let s = "(?i)".to_owned() + s;
                        filter.payload_regex = Regex::new(&s).ok();
                    } else {
                        filter.payload_regex = Regex::new(s).ok();
                    }
                } else {
                    filter.payload = Some(s.clone());
                    filter.payload_as_regex = Some(
                        regex::RegexBuilder::new(&regex::escape(s))
                            .case_insensitive(true)
                            .build()
                            .map_err(|e| {
                                quick_xml::Error::IllFormed(
                                    quick_xml::errors::IllFormedError::MissingEndTag(format!(
                                        "regex error parsing escaped '{}':{:?}",
                                        s, e
                                    )),
                                )
                            })?,
                    );
                }
            }
        }
        if attrs.get("enableLogLevelMax") == Some(&"1".to_string()) {
            if let Some(s) = attrs.get("logLevelMax") {
                let lvl = s.parse::<u8>().unwrap_or(0xff);
                if lvl <= 6 {
                    filter.loglevel_max = Some(lvl);
                } // silently fail?
            }
        }
        if attrs.get("enableLogLevelMin") == Some(&"1".to_string()) {
            if let Some(s) = attrs.get("logLevelMin") {
                let lvl = s.parse::<u8>().unwrap_or(0xff);
                if lvl <= 6 {
                    filter.loglevel_min = Some(lvl);
                } // silently fail?
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
            verb_mstp_mtin: None,
            payload: None,
            payload_regex: None,
            ignore_case_payload: false,
            payload_as_regex: None,
            loglevel_min: None,
            loglevel_max: None,
            lifecycles: None,
        }
    }

    // MARK: matches
    pub fn matches(&self, msg: &DltMessage) -> bool {
        if !self.enabled {
            return false;
        }
        let negated = self.negate_match;

        // this seems to be fastest under the assumption that most of the times non regex is wanted
        // faster than match &self.ecu and if let Some(ecu)=&self.ecu { match ...}
        if let Some(Char4OrRegex::DltChar4(dltc4)) = &self.ecu {
            if dltc4 != &msg.ecu {
                return negated;
            }
        } else if let Some(Char4OrRegex::Regex(regex)) = &self.ecu {
            if !regex.is_match(msg.ecu.as_buf()) {
                return negated;
            }
        }

        if let Some(Char4OrRegex::DltChar4(dltc4)) = &self.apid {
            if let Some(mapid) = msg.apid() {
                if dltc4 != mapid {
                    return negated;
                }
            } else {
                return negated;
            }
        } else if let Some(Char4OrRegex::Regex(regex)) = &self.apid {
            if let Some(mapid) = msg.apid() {
                if !regex.is_match(mapid.as_buf()) {
                    return negated;
                }
            } else {
                return negated;
            }
        }

        if let Some(Char4OrRegex::DltChar4(dltc4)) = &self.ctid {
            if let Some(mctid) = msg.ctid() {
                if dltc4 != mctid {
                    return negated;
                }
            } else {
                return negated;
            }
        } else if let Some(Char4OrRegex::Regex(regex)) = &self.ctid {
            if let Some(mctid) = msg.ctid() {
                if !regex.is_match(mctid.as_buf()) {
                    return negated;
                }
            } else {
                return negated;
            }
        }

        if let Some((verb_mstp_mtin, mask)) = &self.verb_mstp_mtin {
            if let Some(msg_vmm) = msg.verb_mstp_mtin() {
                if (msg_vmm & mask) != *verb_mstp_mtin {
                    return negated;
                }
            } else {
                return negated;
            }
        }

        if let Some(loglevel_min) = &self.loglevel_min {
            if let Some(msg_vmm) = msg.verb_mstp_mtin() {
                let mstp = (msg_vmm >> 1) & 0x07u8;
                let mtin = (msg_vmm >> 4) & 0x0fu8;
                if !(mstp == 0 && mtin >= *loglevel_min) {
                    return negated;
                }
            } else {
                return negated;
            }
        }

        if let Some(loglevel_max) = &self.loglevel_max {
            if let Some(msg_vmm) = msg.verb_mstp_mtin() {
                let mstp = (msg_vmm >> 1) & 0x07u8;
                let mtin = (msg_vmm >> 4) & 0x0fu8;
                if !(mstp == 0 && mtin <= *loglevel_max) {
                    return negated;
                }
            } else {
                return negated;
            }
        }

        if let Some(payload_regex) = &self.payload_regex {
            let payload_text = msg.payload_as_text();
            if let Ok(payload_text) = payload_text {
                if !payload_regex.is_match(&payload_text).unwrap_or(false) {
                    return negated;
                }
            } else {
                return negated;
            }
        } else if let Some(payload_as_regex) = &self.payload_as_regex {
            // we assert this to be set only if ignore_case_payload is set!
            let payload_text = msg.payload_as_text();
            if let Ok(payload_text) = payload_text {
                if !payload_as_regex.is_match(&payload_text) {
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

        if let Some(lcs) = &self.lifecycles {
            if !lcs.is_empty() && !lcs.contains(&msg.lifecycle) {
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
            match s {
                Char4OrRegex::DltChar4(dltc4) => {
                    state.serialize_field("ecu", &dltc4)?;
                    state.serialize_field("ecuIsRegex", &false)?;
                }
                Char4OrRegex::Regex(regex) => {
                    state.serialize_field("ecu", &regex.as_str())?;
                    state.serialize_field("ecuIsRegex", &true)?;
                }
            }
        }
        if let Some(s) = &self.apid {
            match s {
                Char4OrRegex::DltChar4(dltc4) => {
                    state.serialize_field("apid", &dltc4)?;
                    state.serialize_field("apidIsRegex", &false)?;
                }
                Char4OrRegex::Regex(regex) => {
                    state.serialize_field("apid", &regex.as_str())?;
                    state.serialize_field("apidIsRegex", &true)?;
                }
            }
        }
        if let Some(s) = &self.ctid {
            match s {
                Char4OrRegex::DltChar4(dltc4) => {
                    state.serialize_field("ctid", &dltc4)?;
                    state.serialize_field("ctidIsRegex", &false)?;
                }
                Char4OrRegex::Regex(regex) => {
                    state.serialize_field("ctid", &regex.as_str())?;
                    state.serialize_field("ctidIsRegex", &true)?;
                }
            }
        }
        if let Some(s) = &self.payload_regex {
            if self.ignore_case_payload {
                let s = s.as_str().replacen("(?i)", "", 1);
                state.serialize_field("payloadRegex", &s)?;
            } else {
                state.serialize_field("payloadRegex", s.as_str())?;
            }
        } else if let Some(s) = &self.payload {
            state.serialize_field("payload", &s)?;
        }
        if self.ignore_case_payload {
            state.serialize_field("ignoreCasePayload", &self.ignore_case_payload)?;
        }
        if let Some(lvl) = &self.loglevel_min {
            state.serialize_field("logLevelMin", lvl)?;
        }
        if let Some(lvl) = &self.loglevel_max {
            state.serialize_field("logLevelMax", lvl)?;
        }
        if let Some(lcs) = &self.lifecycles {
            state.serialize_field("lifecycles", &lcs)?;
        }
        state.end()
    }
}

// MARK: tests
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
        assert!(!f.ignore_case_payload);
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
        f.ecu = Char4OrRegex::from_buf(b"ECU1").ok();
        assert!(!f.matches(&m));
        f.ecu = Some(Into::into(m.ecu));
        assert!(f.matches(&m));
        // and now negated:
        f.negate_match = true;
        assert!(!f.matches(&m));
        f.ecu = Char4OrRegex::from_buf(b"ECU1").ok();
        assert!(f.matches(&m));
    }

    #[test]
    fn match_ecu_regex() {
        let mut f = Filter::new(FilterKind::Positive);
        let m = DltMessage::for_test(); // ecu = TEST
        f.ecu = Char4OrRegex::from_str("ECU1", false).ok();
        assert!(!f.matches(&m));
        f.ecu = Char4OrRegex::from_str("ECU1|TEST", true).ok();
        assert!(f.matches(&m));
        f.ecu = Char4OrRegex::from_str("ECU1|ECU2", true).ok();
        assert!(!f.matches(&m));
        f.ecu = Char4OrRegex::from_str("TES", false).ok();
        assert!(!f.matches(&m));
        f.ecu = Char4OrRegex::from_str("EST", false).ok();
        assert!(!f.matches(&m));
        f.ecu = Char4OrRegex::from_str("TES", true).ok();
        assert!(f.matches(&m));
        f.ecu = Char4OrRegex::from_str("EST", true).ok();
        assert!(f.matches(&m));
    }

    #[test]
    fn match_apid_regex() {
        let mut f = Filter::new(FilterKind::Positive);
        let m = DltMessage::get_testmsg_control(true, 0, &[]); // apid = DA1
        f.apid = Char4OrRegex::from_str("APID", false).ok();
        assert!(!f.matches(&m));
        f.apid = Char4OrRegex::from_str("APID|DA1", true).ok();
        assert!(f.matches(&m));
        f.apid = Char4OrRegex::from_str("APID|DA2", true).ok();
        assert!(!f.matches(&m));
        f.apid = Char4OrRegex::from_str("DA", false).ok();
        assert!(!f.matches(&m));
        f.apid = Char4OrRegex::from_str("A1", false).ok();
        assert!(!f.matches(&m));
        f.apid = Char4OrRegex::from_str("DA", true).ok();
        assert!(f.matches(&m));
        f.apid = Char4OrRegex::from_str("A1", true).ok();
        assert!(f.matches(&m));
    }

    #[test]
    fn match_ctid_regex() {
        let mut f = Filter::new(FilterKind::Positive);
        let m = DltMessage::get_testmsg_control(true, 0, &[]); // ctid = DC1
        f.ctid = Char4OrRegex::from_str("CTID", false).ok();
        assert!(!f.matches(&m));
        f.ctid = Char4OrRegex::from_str("CTID|DC1", true).ok();
        assert!(f.matches(&m));
        f.ctid = Char4OrRegex::from_str("CTID|DC2", true).ok();
        assert!(!f.matches(&m));
        f.ctid = Char4OrRegex::from_str("DC", false).ok();
        assert!(!f.matches(&m));
        f.ctid = Char4OrRegex::from_str("C1", false).ok();
        assert!(!f.matches(&m));
        f.ctid = Char4OrRegex::from_str("DC", true).ok();
        assert!(f.matches(&m));
        f.ctid = Char4OrRegex::from_str("C1", true).ok();
        assert!(f.matches(&m));
        f.ctid = Char4OrRegex::from_str("", true).ok();
        assert!(f.matches(&m)); // empty regex matches!
        f.ctid = Char4OrRegex::from_str(".", true).ok();
        assert!(f.matches(&m));
    }

    #[test]
    fn match_ecu_and_apid() {
        let mut f = Filter::new(FilterKind::Positive);
        let mut m = DltMessage::for_test();
        f.ecu = Char4OrRegex::from_buf(b"ECU1").ok();
        assert!(f.ecu.is_some());
        f.apid = Char4OrRegex::from_buf(b"APID").ok();
        // neither ecu nor apid match
        assert!(!f.matches(&m));
        f.ecu = Some(Into::into(m.ecu));
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
        f.ecu = Some(Into::into(DltChar4::from_buf(b"ECU1")));
        // now apid matches but not ecu:
        assert!(!f.matches(&m));
    }
    #[test]
    fn match_ecu_and_apid_and_ctid() {
        let mut f = Filter::new(FilterKind::Positive);
        let mut m = DltMessage::for_test();
        f.ecu = Some(Into::into(DltChar4::from_buf(b"ECU1")));
        f.apid = Some(Into::into(DltChar4::from_buf(b"APID")));
        f.ctid = Some(Into::into(DltChar4::from_buf(b"CTID")));
        // neither ecu nor apid match
        assert!(!f.matches(&m));
        f.ecu = Some(Into::into(m.ecu));
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
        f.ctid = Some(Char4OrRegex::from_buf(b"CTIF").unwrap());
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
        let mut m = DltMessage::from_headers(
            1423084,
            sh,
            stdh,
            &v[crate::dlt::DLT_MIN_STD_HEADER_SIZE..payload_offset],
            v[payload_offset..].to_vec(),
        );
        println!("payload_as_text='{}'", m.payload_as_text().unwrap());
        assert!(f.matches(&m));
        f.payload = Some("ANswer".to_string());
        assert!(!f.matches(&m)); // wrong case, default case sensitive
        f.payload = None;
        f.payload_regex = Regex::from_str("1500$").ok(); // ends with
        assert!(f.matches(&m));
        f.payload_regex = Regex::from_str("^Final answer").ok(); // starts with
        assert!(f.matches(&m));
        f.payload_regex = Regex::from_str("^(?P<state>Final) answer").ok(); // starts with
        assert!(f.matches(&m));
        f.payload_regex = Regex::from_str("^answer").ok(); // doesn't start with
        assert!(!f.matches(&m));

        // ecmascript capture groups (?<name>...) instead of (?P<name>...) from json only:
        let f =
            Filter::from_json(r#"{"type": 0, "payloadRegex":"^(?<state>Final) answer"}"#).unwrap();
        assert!(f.payload_regex.is_some());
        assert!(f.matches(&m));

        // ^Git hash/version  (.*)$
        m.payload_text = Some("Git hash/version v1.0.0-deadbeef".to_string());
        let f =
            Filter::from_json(r#"{"type": 0, "payloadRegex":"^Git hash\/version (.*)$"}"#).unwrap();
        assert!(f.payload_regex.is_some());
        assert!(f.matches(&m));
        let f =
            Filter::from_json(r#"{"type": 0, "payloadRegex":"^Git hash/version (.*)$"}"#).unwrap();
        assert!(f.payload_regex.is_some());
        assert!(f.matches(&m));

        // lookahead regex
        // ^New process crash: name=(?!\"crashtest\"|\"test_app\")\"(.*?)\"
        m.payload_text = Some("New process crash: name=\"crashtest\"".to_string());
        let f =
            Filter::from_json(r#"{"type": 0, "payloadRegex":"^New process crash: name=(?!\"crashtest\"|\"test_app\")\"(.*?)\""}"#).unwrap();
        assert!(f.payload_regex.is_some());
        assert!(!f.matches(&m));
        m.payload_text = Some("New process crash: name=\"foo\"".to_string());
        assert!(f.matches(&m));
    }

    #[test]
    fn match_lifecycle() {
        let mut f = Filter::new(FilterKind::Positive);

        // empty one should match all
        f.lifecycles = Some(vec![]);

        // no lifecycle -> should match
        let mut m = DltMessage::for_test();
        assert!(f.matches(&m));

        m.lifecycle = 1;
        assert!(f.matches(&m));

        // real match
        f.lifecycles = Some(vec![1]);
        assert!(f.matches(&m));

        // array supported as well (non sorted)
        f.lifecycles = Some(vec![2, 1]);
        assert!(f.matches(&m));

        // mismatch
        f.lifecycles = Some(vec![2, 3]);
        assert!(!f.matches(&m));

        // msg without lifecycle should match as well?
        m.lifecycle = 0;
        f.lifecycles = Some(vec![1]);
        assert!(!f.matches(&m)); // todo??? (dlt-logs does treat the msgs without as matching)

        // typical use case
        let mut f = Filter::new(FilterKind::Negative);
        f.negate_match = true;

        f.lifecycles = Some(vec![]);
        m.lifecycle = 1;
        assert!(!f.matches(&m)); // should not remove this msg as no lifecycle is chosen

        f.lifecycles = Some(vec![1]);
        m.lifecycle = 1;
        assert!(!f.matches(&m)); // should not remove this msg as lifecycle fits

        f.lifecycles = Some(vec![1]);
        m.lifecycle = 2;
        assert!(f.matches(&m)); // should remove this msg as lifecycle not fitting
    }

    #[test]
    fn match_mstp() {
        let f = Filter::from_json(r#"{"type": 0, "verb_mstp_mtin": 6}"#).unwrap(); // 3u8<<1
        let mut m = DltMessage::for_test();
        assert!(!f.matches(&m));

        m.extended_header = Some(DltExtendedHeader {
            apid: DltChar4::from_buf(b"APID"),
            noar: 0,
            ctid: DltChar4::from_buf(b"CTID"),
            verb_mstp_mtin: 2u8 << 1,
        });
        // no match, diff mstp
        assert!(!f.matches(&m));

        m.extended_header = Some(DltExtendedHeader {
            apid: DltChar4::from_buf(b"APID"),
            noar: 0,
            ctid: DltChar4::from_buf(b"CTID"),
            verb_mstp_mtin: 3u8 << 1,
        });
        // match, same mstp
        assert!(f.matches(&m));

        m.extended_header = Some(DltExtendedHeader {
            apid: DltChar4::from_buf(b"APID"),
            noar: 0,
            ctid: DltChar4::from_buf(b"CTID"),
            verb_mstp_mtin: 1u8 << 4 | 3u8 << 1,
        });
        // still match, msg has more, but filter has mtin 0
        assert!(f.matches(&m));

        let f = Filter::from_json(r#"{"type": 0, "verb_mstp_mtin": 22}"#).unwrap(); // 1u8<<4|3u8<<1

        // still match, msg has same
        assert!(f.matches(&m));

        let f = Filter::from_json(r#"{"type": 0, "verb_mstp_mtin": 38}"#).unwrap(); // 2u8<<4|3u8<<1

        // no match, same mstp but dif mtin
        assert!(!f.matches(&m));

        // check that if only mstp is set verb and mtin are ignored
        let f = Filter::from_json(r#"{"type": 0, "mstp": 3}"#).unwrap();
        m.extended_header = Some(DltExtendedHeader {
            apid: DltChar4::from_buf(b"APID"),
            noar: 0,
            ctid: DltChar4::from_buf(b"CTID"),
            verb_mstp_mtin: 3u8 << 1,
        });
        assert!(f.matches(&m));

        m.extended_header = Some(DltExtendedHeader {
            apid: DltChar4::from_buf(b"APID"),
            noar: 0,
            ctid: DltChar4::from_buf(b"CTID"),
            verb_mstp_mtin: 1u8 << 4 | 3u8 << 1,
        });
        assert!(f.matches(&m));
        m.extended_header = Some(DltExtendedHeader {
            apid: DltChar4::from_buf(b"APID"),
            noar: 0,
            ctid: DltChar4::from_buf(b"CTID"),
            verb_mstp_mtin: 1u8 << 4 | 3u8 << 1 | 1,
        });
        assert!(f.matches(&m));
    }

    #[test]
    fn match_loglevel() {
        let mut f = Filter::from_json(r#"{"type": 0, "mstp": 0}"#).unwrap();
        // dlt-logs sets this together with loglevel so that only LOG msgs are checked
        let mut m = DltMessage::for_test();
        f.loglevel_min = Some(2);
        assert!(!f.matches(&m));

        m.extended_header = Some(DltExtendedHeader {
            apid: DltChar4::from_buf(b"APID"),
            noar: 0,
            ctid: DltChar4::from_buf(b"CTID"),
            verb_mstp_mtin: 2u8 << 4, // 0 MSTP, 2 MTIN (Error)
        });
        // match
        assert!(f.matches(&m));

        f.loglevel_max = Some(3);
        assert!(f.matches(&m));
        m.extended_header = Some(DltExtendedHeader {
            apid: DltChar4::from_buf(b"APID"),
            noar: 0,
            ctid: DltChar4::from_buf(b"CTID"),
            verb_mstp_mtin: 3u8 << 4, // 0 MSTP, 3 MTIN (Warn)
        });
        assert!(f.matches(&m));

        m.extended_header = Some(DltExtendedHeader {
            apid: DltChar4::from_buf(b"APID"),
            noar: 0,
            ctid: DltChar4::from_buf(b"CTID"),
            verb_mstp_mtin: 4u8 << 4, // 0 MSTP, 4 MTIN (Info)
        });
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
        assert_eq!(f.ecu, Char4OrRegex::from_buf(b"AbC\0").ok());

        // proper type and ecu (but too long -> gets ignored)
        let f = Filter::from_json(r#"{"type": 0, "ecu": "AbCde"}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.ecu, Char4OrRegex::from_str("AbCd", false).ok());

        // proper type and ecu (but invalid regex)
        let f = Filter::from_json(r#"{"type": 0, "ecu": "AbCd|\\"}"#);
        assert!(f.is_err());

        // proper type and ecu
        let f = Filter::from_json(r#"{"type": 0, "ecu": "AbC", "ecuIsRegex":false}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.ecu, Char4OrRegex::from_buf(b"AbC\0").ok());

        // proper type and ecu
        let f = Filter::from_json(r#"{"type": 0, "ecu": "AbC", "ecuIsRegex":true}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.ecu, Char4OrRegex::from_str("AbC", true).ok());

        // proper type and ecu with lower ascii range... (json strings are in unicode / rfc7159)
        let f = Filter::from_json(r#"{"type": 0, "ecu": "A\u0001C"}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(
            f.ecu,
            Some(Into::into(DltChar4::from_buf(&[0x41, 1, 0x43, 0])))
        );

        // proper type and apid
        let f = Filter::from_json(r#"{"type": 0, "apid": "AbC"}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.apid, Char4OrRegex::from_buf(b"AbC\0").ok());

        // proper type and apid regex autodetect
        let f = Filter::from_json(r#"{"type": 0, "apid": "AbC|def"}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.apid, Char4OrRegex::from_str("AbC|def", true).ok());

        // proper type and apid regex
        let f = Filter::from_json(r#"{"type": 0, "apid": "AbC", "apidIsRegex":true}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.apid, Char4OrRegex::from_str("AbC", true).ok());

        // proper type and apid regex
        let f = Filter::from_json(r#"{"type": 0, "apid": "AbC", "apidIsRegex":false}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.apid, Char4OrRegex::from_str("AbC", false).ok());

        // proper type and ctid
        let f = Filter::from_json(r#"{"type": 0, "ctid": "AbC"}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.ctid, Char4OrRegex::from_buf(b"AbC\0").ok());

        // proper type and ctid regex autodetect
        let f = Filter::from_json(r#"{"type": 0, "ctid": "AbC|def"}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.ctid, Char4OrRegex::from_str("AbC|def", true).ok());

        // proper type and ctid regex
        let f = Filter::from_json(r#"{"type": 0, "ctid": "AbC", "ctidIsRegex":true}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.ctid, Char4OrRegex::from_str("AbC", true).ok());

        // proper type and ctid regex
        let f = Filter::from_json(r#"{"type": 0, "ctid": "AbC", "ctidIsRegex":false}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.ctid, Char4OrRegex::from_str("AbC", false).ok());

        // payload
        let f = Filter::from_json(r#"{"type": 0, "payload":"\\fOo"}"#).unwrap();
        assert!(f.payload_regex.is_none());
        assert_eq!(f.payload, Some("\\fOo".to_string()));

        // payload and payloadRegex (both set -> prefer regex)
        let f =
            Filter::from_json(r#"{"type": 0, "payload":"fOo", "payloadRegex":"^fOo"}"#).unwrap();
        assert!(f.payload.is_none());
        assert_eq!(f.payload_regex.unwrap().as_str(), "^fOo");
        assert!(f.lifecycles.is_none());

        // payloadRegex ignoring case
        let f = Filter::from_json(
            r#"{"type": 0, "ignoreCasePayload":true, "payloadRegex":"^fOo|bla"}"#,
        )
        .unwrap();
        assert!(f.ignore_case_payload);
        assert_eq!(f.payload_regex.as_ref().unwrap().as_str(), "(?i)^fOo|bla");
        assert!(&f
            .payload_regex
            .as_ref()
            .unwrap()
            .is_match("fOo bla")
            .unwrap());
        assert!(&f
            .payload_regex
            .as_ref()
            .unwrap()
            .is_match("FoO bla")
            .unwrap());
        assert!(&f.payload_regex.as_ref().unwrap().is_match("Bla").unwrap());

        // lifecycles
        let f = Filter::from_json(r#"{"type": 1, "lifecycles":[]}"#).unwrap();
        assert!(f.lifecycles.is_some());
        assert_eq!(f.lifecycles, Some(vec![]));

        let f = Filter::from_json(r#"{"type": 1, "lifecycles":[47,11]}"#).unwrap();
        assert!(f.lifecycles.is_some());
        assert_eq!(f.lifecycles, Some(vec![47, 11]));

        // invalid one (no array)
        let f = Filter::from_json(r#"{"type": 1, "lifecycles":1}"#).unwrap();
        assert!(f.lifecycles.is_none());

        // invalid one (array of strings and not numbers)
        let f = Filter::from_json(r#"{"type": 1, "lifecycles":["1"]}"#).unwrap();
        assert!(f.lifecycles.is_some());
        assert_eq!(f.lifecycles, Some(vec![]));

        // proper type and mstp
        let f = Filter::from_json(r#"{"type": 0, "mstp": 3}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.verb_mstp_mtin, Some(((3u8 << 1), (7u8 << 1))));

        // proper type and mstp and verb_mstp_mtin (has a higher prio)
        let f = Filter::from_json(r#"{"type": 0, "verb_mstp_mtin":42,"mstp": 2}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.verb_mstp_mtin, Some((42u8, 0xffu8)));

        // logLevelMin/Max:
        let f = Filter::from_json(r#"{"type": 0, "logLevelMin":1}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.loglevel_min, Some(1u8));
        assert_eq!(f.loglevel_max, None);

        let f = Filter::from_json(r#"{"type": 0, "logLevelMax":2}"#).unwrap();
        assert_eq!(f.kind, FilterKind::Positive);
        assert_eq!(f.loglevel_max, Some(2u8));
        assert_eq!(f.loglevel_min, None);
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
        assert!(s.contains(r#""ecuIsRegex":false"#), "ecu wrong in {}", &s);

        let f = Filter::from_json(r#"{"type": 0, "ecu":"ec1|ec2"}"#).unwrap();
        let s = f.to_json();
        assert!(s.contains(r#""ecu":"ec1|ec2""#), "ecu wrong in {}", &s);
        assert!(s.contains(r#""ecuIsRegex":true"#), "ecu wrong in {}", &s);

        // field apid
        let f = Filter::from_json(r#"{"type": 0, "apid":"ap1"}"#).unwrap();
        let s = f.to_json();
        assert!(
            s.contains(r#""apid":"ap1""#),
            "apid wrong in {:?} as {}",
            f,
            &s
        );
        assert!(
            s.contains(r#""apidIsRegex":false"#),
            "apidIsRegex wrong in {:?} as {}",
            f,
            &s
        );
        // field apid with regex
        let f = Filter::from_json(r#"{"type": 0, "apid":"ap1|ap2"}"#).unwrap();
        let s = f.to_json();
        assert!(
            s.contains(r#""apid":"ap1|ap2""#),
            "apid wrong in {:?} as {}",
            f,
            &s
        );
        assert!(
            s.contains(r#""apidIsRegex":true"#),
            "apidIsRegex wrong in {:?} as {}",
            f,
            &s
        );

        // field ctid
        let f = Filter::from_json(r#"{"type": 0, "ctid":"CTID"}"#).unwrap();
        let s = f.to_json();
        assert!(s.contains(r#""ctid":"CTID""#), "ctid wrong in {}", &s);
        assert!(
            s.contains(r#""ctidIsRegex":false"#),
            "ctidIsRegex wrong in {}",
            &s
        );

        let f = Filter::from_json(r#"{"type": 0, "ctid":"CTID", "ctidIsRegex":true}"#).unwrap();
        let s = f.to_json();
        assert!(s.contains(r#""ctid":"CTID""#), "ctid wrong in {}", &s);
        assert!(
            s.contains(r#""ctidIsRegex":true"#),
            "ctidIsRegex wrong in {}",
            &s
        );

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
        assert!(
            !s.contains(r#""lifecycles""#),
            "lifecycles not expected in {}",
            &s
        );

        // field lifecycles
        let f = Filter::from_json(r#"{"type": 1, "lifecycles":[47,11]}"#).unwrap();
        let s = f.to_json();
        assert!(
            s.contains(r#""lifecycles":[47,11]"#),
            "lifecycles unexpected in {}",
            &s
        );

        let f = Filter::from_json(r#"{"type": 0, "logLevelMax":2}"#).unwrap();
        let s = f.to_json();
        assert!(
            s.contains(r#""logLevelMax":2"#),
            "logLevelMax unexpected in {}",
            &s
        );

        let f = Filter::from_json(r#"{"type": 0, "logLevelMin":1}"#).unwrap();
        let s = f.to_json();
        assert!(
            s.contains(r#""logLevelMin":1"#),
            "logLevelMin unexpected in {}",
            &s
        );

        // todo verb_mstp_mtin...
    }

    #[test]
    fn payload_regex() {
        let f =
            Filter::from_json(r#"{"type": 0, "payloadRegex":"foo|bla", "ignoreCasePayload":true}"#)
                .unwrap();
        assert!(f.ignore_case_payload);
        assert!(f.payload_regex.as_ref().unwrap().is_match("foo").unwrap());
        assert!(f.payload_regex.as_ref().unwrap().is_match("fOo").unwrap());
        assert!(f.payload_regex.as_ref().unwrap().is_match("bla").unwrap());
        assert!(f.payload_regex.as_ref().unwrap().is_match("Bla").unwrap());
        assert!(!f.payload_regex.as_ref().unwrap().is_match("blub").unwrap());

        let f = Filter::from_json(
            r#"{"type": 0, "payloadRegex":"(foo)|(bla)", "ignoreCasePayload":true}"#,
        )
        .unwrap();
        assert!(f.ignore_case_payload);
        assert!(f.payload_regex.as_ref().unwrap().is_match("foo").unwrap());
        assert!(f.payload_regex.as_ref().unwrap().is_match("fOo").unwrap());
        assert!(f.payload_regex.as_ref().unwrap().is_match("bla").unwrap());
        assert!(f.payload_regex.as_ref().unwrap().is_match("Bla").unwrap());
    }

    #[test]
    fn payload_ignore_case() {
        let f = Filter::from_json(r#"{"type": 0, "payload":"foo|^bla", "ignoreCasePayload":true}"#)
            .unwrap();
        let mut m = DltMessage::for_test();
        assert!(!f.matches(&m));
        m.payload_text = Some("blub foo|^bla foo".to_owned());
        assert!(f.matches(&m));
        m.payload_text = Some("bluB Foo|^bLa foo".to_owned());
        assert!(f.matches(&m));
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

            // invalid one:
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(r#"<filter>"#));
            assert!(r.is_err());

            // invalid regex:
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><enablepayloadtext>1</enablepayloadtext><enableregexp_Payload>1</enableregexp_Payload><payloadtext>^(.*</payloadtext></filter>"#,
            ));
            assert!(r.is_ok(), "got err {:?}", r.err());
            assert!(r.unwrap().payload_regex.is_none()); // this is bad... better throw an error?
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
            assert_eq!(r.ecu, DltChar4::from_str("fOo").ok().map(Into::into));
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
            )).unwrap();
            assert_eq!(r.apid, Char4OrRegex::from_str("fOo", false).ok());

            // apid set and enableapid, regex autodetect
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><applicationid>fOo|bla</applicationid><enableapplicationid>1</enableapplicationid></filter>"#,
            )).unwrap();
            assert_eq!(r.apid, Char4OrRegex::from_str("fOo|bla", true).ok());

            // apid set and enableapid regex
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><applicationid>fOo</applicationid><enableapplicationid>1</enableapplicationid><enableregexp_Appid>1</enableregexp_Appid></filter>"#,
            )).unwrap();
            assert_eq!(r.apid, Char4OrRegex::from_str("fOo", true).ok());
            // apid set and enableapid regex
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><applicationid>fOo</applicationid><enableapplicationid>1</enableapplicationid><enableregexp_Appid>0</enableregexp_Appid></filter>"#,
            )).unwrap();
            assert_eq!(r.apid, Char4OrRegex::from_str("fOo", false).ok());
        }
        #[test]
        fn ctid() {
            // ctid set and enablectid
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><contextid>fOo</contextid><enablecontextid>1</enablecontextid></filter>"#,
            )).unwrap();
            assert_eq!(r.ctid, Char4OrRegex::from_str("fOo", false).ok());

            // ctid set and enablectid regex autodetect
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><contextid>^fOo</contextid><enablecontextid>1</enablecontextid></filter>"#,
            )).unwrap();
            assert_eq!(r.ctid, Char4OrRegex::from_str("^fOo", true).ok());

            // ctid set and enablectid regex
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><contextid>fOo</contextid><enablecontextid>1</enablecontextid><enableregexp_Context>1</enableregexp_Context></filter>"#,
            )).unwrap();
            assert_eq!(r.ctid, Char4OrRegex::from_str("fOo", true).ok());
            // ctid set and enablectid regex
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><contextid>fOo</contextid><enablecontextid>1</enablecontextid><enableregexp_Context>0</enableregexp_Context></filter>"#,
            )).unwrap();
            assert_eq!(r.ctid, Char4OrRegex::from_str("fOo", false).ok());
        }

        #[test]
        fn control() {
            // ctid set and enablectid
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><enablecontrolmsgs>1</enablecontrolmsgs></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.verb_mstp_mtin, Some((3u8 << 1, 7u8 << 1)));
        }

        #[test]
        fn payload_text() {
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><payloadtext>fOo</payloadtext><enablepayloadtext>1</enablepayloadtext></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.payload, Some("fOo".to_string()));
            assert!(r.payload_regex.is_none());
            assert!(!r.ignore_case_payload);

            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><payloadtext>&amp;fOo&lt;&gt;</payloadtext><enableregexp_Payload>1</enableregexp_Payload><enablepayloadtext>1</enablepayloadtext><ignoreCase_Payload>1</ignoreCase_Payload></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.payload_regex.unwrap().as_str(), "(?i)&fOo<>");
            assert!(r.payload.is_none());
            assert!(r.ignore_case_payload);
        }

        #[test]
        fn loglevel() {
            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><logLevelMax>2</logLevelMax><enableLogLevelMax>1</enableLogLevelMax><enableLogLevelMin>0</enableLogLevelMin></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.loglevel_max, Some(2));
            assert_eq!(r.loglevel_min, None);

            let r = Filter::from_quick_xml_reader(&mut Reader::from_str(
                r#"<filter><logLevelMin>1</logLevelMin><enableLogLevelMin>1</enableLogLevelMin></filter>"#,
            ))
            .unwrap();
            assert_eq!(r.loglevel_min, Some(1));
            assert_eq!(r.loglevel_max, None);
        }
    }
}
