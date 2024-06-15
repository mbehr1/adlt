#![no_main]

use adlt::dlt::{
    DltChar4, DltExtendedHeader, DltMessage, DltStandardHeader, DLT_MIN_STD_HEADER_SIZE,
};
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|data: Vec<u8>| -> Corpus {
    if data.len() + DLT_MIN_STD_HEADER_SIZE + 4 + 10 > u16::MAX as usize {
        return Corpus::Reject;
    }
    // create a verbose msg with that payload:
    let msg = DltMessage {
        index: data.len() as u32,
        reception_time_us: data.len() as u64,
        ecu: DltChar4::from_buf(b"ECU1"),
        timestamp_dms: 42,
        standard_header: DltStandardHeader {
            htyp: 0,
            mcnt: 0,
            len: (DLT_MIN_STD_HEADER_SIZE + 4 + 10 + data.len()) as u16,
        },
        extended_header: Some(DltExtendedHeader {
            verb_mstp_mtin: 0x01,
            noar: 1,
            apid: DltChar4::from_buf(b"APID"),
            ctid: DltChar4::from_buf(b"CTID"),
        }),
        payload: data,
        payload_text: None,
        lifecycle: 0,
    };

    let _ = msg.payload_as_text();
    Corpus::Keep
});
