
use std::{env, io::{self, Read}, u16};

use adlt::{dlt::{DltChar4, DltExtendedHeader, DltMessage, DltStandardHeader}, dlt_args};

enum DdDltMode {
    Utf8,
    Raw
}

fn main() -> Result<(), std::io::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: {} <ecu_id> <app_id> <payload_size> <utf8|raw>", args[0]);
        eprintln!("  reads input form stdin and write valid DLT verbose mode to stdout.");

        return Ok(());
    }

    let ecuid = args[1].as_bytes();
    let appid = args[2].as_bytes();

    let mut payload_size: u16 = match args[3].parse::<u16>() {
        Ok(val) => val,
        Err(_) => panic!("wrong parameter"),
    };

    let mode = match args[4].as_str() {
        "string" => DdDltMode::Utf8,
        "raw" => DdDltMode::Raw,
        _ => panic!("wrong parameter")
    };

    let mut buf = vec![0u8; payload_size as usize];
    let mut count = 0;
    let mut nr_args = 0;

    loop {
        match io::stdin().lock().read_exact(&mut buf) {
            Ok(_) => (),
            _ => {break;}
        };

        // we need to wrap the raw bytes into ByteBuf in order to make the serialization work
        let bytes = serde_bytes::ByteBuf::from(buf.as_slice());

        // arbitrary args, taken from dlt_benches::dlt_payload_verb
        let payload: Vec<u8>;
        match mode {
            DdDltMode::Raw =>  {(nr_args, payload) = dlt_args!(bytes).expect("wrong parameter");},
            DdDltMode::Utf8 => {(nr_args, payload) = dlt_args!(std::str::from_utf8(buf.as_slice()).expect("input is not convertable to UTF-8")).expect("wrong parameter");},
        }

        payload_size = payload.len() as u16;
        let len: u16 = 4 + 10 + 4 + payload_size;

        let m = DltMessage {
            index: 0,
            reception_time_us: 0,
            ecu: DltChar4::from_buf(ecuid.try_into().expect("ecuid wrong")),
            timestamp_dms: count * 1000,
            standard_header: DltStandardHeader {
                htyp: 0x1 << 5,
                    //DLT_STD_HDR_VERSION,
                len,
                mcnt: count as u8,
            },
            extended_header: Some(DltExtendedHeader {
                verb_mstp_mtin: 1,
                noar: nr_args,
                apid: DltChar4::from_buf(appid.try_into().expect("app id incorrect")),
                ctid: DltChar4::from_buf(appid.try_into().expect("app id incorrect")),
            }),
            lifecycle: 0,
            payload,
            payload_text: None,
        };

        // eprintln!("{:?}", m);
        m.to_write(&mut io::stdout()).expect("error writing to stdout");
        count += 1;
    }
    eprintln!("wrote {} DLT messages with {} arguments and payload size={}b, ", count, nr_args, payload_size);
    Ok(())
}