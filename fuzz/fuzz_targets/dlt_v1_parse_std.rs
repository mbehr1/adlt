#![no_main]

use adlt::dlt::parse_dlt_with_storage_header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((_res, msg)) = parse_dlt_with_storage_header(0, data) {
        let _ = format!("{:?}", msg);
        let _ = format!("{}{:?}{:?}", msg.ecu, msg.apid(), msg.ctid(),);
        let _ = msg.payload_as_text();
    }
});
