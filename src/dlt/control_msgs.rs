use super::{DltChar4, RE_NEW_LINE};
use encoding_rs::WINDOWS_1252;
use serde::Serialize;
use std::convert::TryFrom;

/// parse the payload for a CTRL_RESPONSE 19 GET_SW_VERSION
/// payload must already point to the data after the CtrlServiceId and CtrlReturnType
pub fn parse_ctrl_sw_version_payload(is_big_endian: bool, payload: &[u8]) -> Option<String> {
    if payload.len() >= 4 {
        let sw_len = if is_big_endian {
            u32::from_be_bytes(payload.get(0..4).unwrap().try_into().unwrap())
        } else {
            u32::from_le_bytes(payload.get(0..4).unwrap().try_into().unwrap())
        } as usize;
        let payload: &[u8] = &payload[4..];
        if payload.len() >= sw_len {
            let (s, _) = WINDOWS_1252.decode_without_bom_handling(&payload[0..sw_len]);
            let s2 = RE_NEW_LINE.replace_all(&s, " ");
            return Some(String::from(s2));
        }
    }
    None
}

/// Context ids info type according to Dlt spec 7.7.7.1.5.3 ContextIDsInfoType
/// returned within DLT control message GET_LOG_INFO [AppIdsType]
#[derive(Serialize)]
pub struct ContextIdsInfoType {
    pub ctid: DltChar4,
    pub log_level: Option<i8>,
    pub trace_status: Option<i8>,
    pub desc: Option<String>,
}

/// App ids info type according to Dlt spec 7.7.7.1.5.2 AppIDsType
/// this is returned via DLT control message GET_LOG_INFO from [parse_ctrl_log_info_payload]
#[derive(Serialize)]
pub struct AppIdsType {
    pub apid: DltChar4,
    pub ctids: Vec<ContextIdsInfoType>,
    pub desc: Option<String>,
}

fn parse_payload_int<'a, T>(is_big_endian: bool, payload: &'a [u8], offset: usize) -> Option<T>
where
    T: funty::Integral,
    <T as funty::Numeric>::Bytes: TryFrom<&'a [u8]>,
{
    let t_byte_len: usize = core::mem::size_of::<T>();
    if payload.len() < offset + t_byte_len {
        None
    } else {
        let buf: &'a [u8] = payload.get(offset..offset + t_byte_len).unwrap();
        let bytes = buf.try_into();
        if let Ok(bytes) = bytes {
            if is_big_endian {
                Some(T::from_be_bytes(bytes))
            } else {
                Some(T::from_le_bytes(bytes))
            }
        } else {
            None
        }
    }
}

/// parse the payload = response parameter for a Get Log Info control message
/// Details see requirement `[Dlt197]`.
/// payload must point to the bytes after the status byte
pub fn parse_ctrl_log_info_payload(
    status: u8,
    is_big_endian: bool,
    payload: &[u8],
) -> Vec<AppIdsType> {
    if (3..=7).contains(&status) {
        let has_log_level = (status == 4) || (status == 6) || (status == 7);
        let has_trace_status = (status == 5) || (status == 6) || (status == 7);
        let has_descr = status == 7;

        if payload.len() >= 2 {
            let count_app_ids: u16 = parse_payload_int(is_big_endian, payload, 0).unwrap();
            let mut apids = Vec::with_capacity(count_app_ids as usize);
            let mut offset = 2usize;
            let mut avail = payload.len() - 2;

            for _i in 0..count_app_ids {
                if avail < 6 {
                    // app_id and count_context_ids min
                    break;
                }
                let mut apid_info = AppIdsType {
                    apid: DltChar4::from_buf(payload.get(offset..offset + 4).unwrap()),
                    desc: None,
                    ctids: vec![],
                };

                let count_context_ids: u16 =
                    parse_payload_int(is_big_endian, payload, offset + 4).unwrap();
                offset += 6;
                avail -= 6;
                for _c in 0..count_context_ids {
                    if avail < 4 {
                        return vec![]; // abort
                    }
                    let mut ctid_info = ContextIdsInfoType {
                        ctid: DltChar4::from_buf(payload.get(offset..offset + 4).unwrap()),
                        log_level: None,
                        trace_status: None,
                        desc: None,
                    };
                    avail -= 4;
                    offset += 4;
                    if has_log_level {
                        if avail < 1 {
                            return vec![];
                        }
                        ctid_info.log_level = parse_payload_int(is_big_endian, payload, offset);
                        avail -= 1;
                        offset += 1;
                    }
                    if has_trace_status {
                        if avail < 1 {
                            return vec![];
                        }
                        ctid_info.trace_status = parse_payload_int(is_big_endian, payload, offset);
                        avail -= 1;
                        offset += 1;
                    }
                    if has_descr {
                        if avail >= 2 {
                            let len_desc: u16 =
                                parse_payload_int(is_big_endian, payload, offset).unwrap();
                            let len_desc = len_desc as usize;
                            offset += 2;
                            avail -= 2;
                            if len_desc > 0 && avail >= len_desc {
                                let (s, _) = WINDOWS_1252.decode_without_bom_handling(
                                    &payload[offset..offset + len_desc],
                                );
                                let s2 = RE_NEW_LINE.replace_all(&s, " ");
                                ctid_info.desc = Some(String::from(s2)); // todo optimize with returning Cow?
                                offset += len_desc;
                                avail -= len_desc;
                            }
                        } else {
                            return vec![];
                        }
                    }

                    apid_info.ctids.push(ctid_info);
                }
                if has_descr {
                    if avail >= 2 {
                        let len_desc: u16 =
                            parse_payload_int(is_big_endian, payload, offset).unwrap();
                        let len_desc = len_desc as usize;
                        offset += 2;
                        avail -= 2;
                        if len_desc > 0 && avail >= len_desc {
                            let (s, _) = WINDOWS_1252
                                .decode_without_bom_handling(&payload[offset..offset + len_desc]);
                            let s2 = RE_NEW_LINE.replace_all(&s, " ");
                            apid_info.desc = Some(String::from(s2)); // todo optimize with returning Cow?
                            offset += len_desc;
                            avail -= len_desc;
                        }
                    } else {
                        break;
                    }
                }
                apids.push(apid_info);
            }

            apids
        } else {
            vec![]
        }
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::parse_ctrl_log_info_payload;
    use crate::dlt::DltChar4;

    #[test]
    fn ctrl_info_payload_valid() {
        // 3 only APID, CTID without log level or trace status
        let v = parse_ctrl_log_info_payload(3, false, &[1, 0]);
        assert_eq!(v.len(), 0); // too short

        // 3 only APID, CTID without log level or trace status
        let v = parse_ctrl_log_info_payload(
            3,
            false,
            &[
                2, 0, b'A', b'P', b'I', b'D', 0, 0, b'A', b'P', b'I', b'F', 0, 0,
            ],
        );
        assert_eq!(v.len(), 2); // enough
        assert_eq!(v[0].apid, DltChar4::from_buf(b"APID"));
        assert_eq!(v[1].apid, DltChar4::from_buf(b"APIF"));

        // 7 APID, CTID with full info. here 1 apid, 0 ctids
        let v = parse_ctrl_log_info_payload(
            7,
            false,
            &[1, 0, b'A', b'P', b'I', b'D', 0, 0, 3, 0, b'f', b'o', b'o'],
        );
        assert_eq!(v.len(), 1); // enough
        assert_eq!(v[0].apid, DltChar4::from_buf(b"APID"));
        assert_eq!(v[0].desc.as_ref().unwrap().as_str(), "foo");

        // 7 APID, CTID with full info. here 1 apid, 0 ctids
        let v = parse_ctrl_log_info_payload(
            7,
            false,
            &[
                1, 0, b'A', b'P', b'I', b'D', 1, 0, b'C', b'T', b'I', b'D', 42, 43, 2, 0, b'a',
                b'h', 3, 0, b'f', b'o', b'o',
            ],
        );
        assert_eq!(v.len(), 1); // enough
        let apid_info = &v[0];
        assert_eq!(apid_info.apid, DltChar4::from_buf(b"APID"));
        assert_eq!(apid_info.desc.as_ref().unwrap().as_str(), "foo");
        assert_eq!(apid_info.ctids.len(), 1);
        assert_eq!(apid_info.ctids[0].ctid, DltChar4::from_buf(b"CTID"));
        assert_eq!(apid_info.ctids[0].log_level, Some(42i8));
        assert_eq!(apid_info.ctids[0].trace_status, Some(43i8));
        assert_eq!(apid_info.ctids[0].desc.as_ref().unwrap().as_str(), "ah");
    }

    #[test]
    fn ctrl_log_info_json() {
        // 7 APID, CTID with full info. here 1 apid, 0 ctids
        let v = parse_ctrl_log_info_payload(
            7,
            false,
            &[
                1, 0, b'A', b'P', b'I', b'D', 1, 0, b'C', b'T', b'I', b'D', 42, 43, 2, 0, b'a',
                b'h', 3, 0, b'a', b'"', b'b',
            ],
        );
        let j = serde_json::to_string(&v).unwrap();
        // incl. escaping of "
        assert_eq!(
            j,
            r#"[{"apid":"APID","ctids":[{"ctid":"CTID","log_level":42,"trace_status":43,"desc":"ah"}],"desc":"a\"b"}]"#
        );
    }

    #[test]
    fn ctrl_info_payload_invalid() {
        // invalid status
        let v = parse_ctrl_log_info_payload(0, false, &[1, 2, 3]);
        assert_eq!(v.len(), 0);
        // status NOT_SUPPORTED
        let v = parse_ctrl_log_info_payload(1, false, &[2, 3, 4]);
        assert_eq!(v.len(), 0);
        // status ERROR
        let v = parse_ctrl_log_info_payload(2, false, &[2, 3, 4]);
        assert_eq!(v.len(), 0);
        // status NO match ...
        let v = parse_ctrl_log_info_payload(8, false, &[2, 3, 4]);
        assert_eq!(v.len(), 0);
        // status RESPONSE DATA OVERFLOW
        let v = parse_ctrl_log_info_payload(9, false, &[2, 3, 4]);
        assert_eq!(v.len(), 0);
    }
}
