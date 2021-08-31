use slog::{crit, debug, info, warn};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek};
use chrono::{TimeZone, Local};

/// same as genivi dlt dlt-convert binary
/// log the files to console
pub fn convert(log: slog::Logger, sub_m: &clap::ArgMatches) -> std::io::Result<()> {
    let input_file_names: Vec<&str> = sub_m.values_of("file").unwrap().collect();
    let index_first: adlt::dlt::DltMessageIndexType = match sub_m.value_of("index_first") {
        None => 0,
        Some(s) => match s.parse::<adlt::dlt::DltMessageIndexType>() {
            Ok(n) => n,
            Err(_) => {
                crit!(log, "index_first '{}' is not a number/index type!", s);
                0 // lets default to 0. could stop as well with u64::MAX
            }
        },
    };
    let index_last: adlt::dlt::DltMessageIndexType = match sub_m.value_of("index_last") {
        None => adlt::dlt::DltMessageIndexType::MAX,
        Some(s) => match s.parse::<adlt::dlt::DltMessageIndexType>() {
            Ok(n) => n,
            Err(_) => {
                crit!(log, "index_last '{}' is not a number/index type!", s);
                0 // let it fail here
            }
        },
    };
    // }.unwrap_or(u64::MAX);
    info!(log, "convert have {} input files", input_file_names.len(); "index_first"=>index_first, "index_last"=>index_last);
    debug!(log, "convert "; "input_file_names" => format!("{:?}",&input_file_names));

    // if we have multiple files we do need to sort them first by the first log reception_time!
    if input_file_names.len() > 1 {
        warn!(
            log,
            "input files wont be sorted yet by timestamp but will be read in the order specified!"
        );
    }

    let mut f: Option<BufReader<File>> = None;

    let mut bytes_processed: u64 = 0;
    let mut bytes_per_file: u64 = 0;
    let mut number_messages: adlt::dlt::DltMessageIndexType = 0;
    let mut input_file_names_iter = input_file_names.iter();
    let mut last_data = false;

    let default_apid_ctid = adlt::dlt::DltChar4::from_str("----").unwrap();
    loop {
        if f.is_none() {
            // load next file
            let input_file_name = input_file_names_iter.next();
            match input_file_name {
                None => {
                    break;
                }
                Some(input_file_name) => {
                    let fi = File::open(input_file_name)?;
                    info!(log, "opened file {} {:?}", &input_file_name, &fi);
                    const BUFREADER_CAPACITY: usize = 0x10000 * 50;
                    f = Some(BufReader::with_capacity(BUFREADER_CAPACITY, fi));
                }
            }
        }
        assert!(!f.is_none());
        let reader: &mut BufReader<File> = f.as_mut().unwrap();
        match adlt::dlt::parse_dlt_with_storage_header(number_messages, &mut *reader) {
            Ok((res, msg)) => {
                bytes_per_file += res as u64;
                number_messages += 1;

                // start with a simple dump of the msgs similar to dlt_message_header
                if msg.index >= index_first && msg.index <= index_last {
                    println!(
                        "{index} {reception_time} {timestamp_dms:10} {mcnt:03} {ecu} {apid:-<4} {ctid:-<4}",
                        index = msg.index,
                        reception_time = Local.from_utc_datetime(&msg.reception_time()).format("%Y/%m/%d %H:%M:%S%.6f"),
                        timestamp_dms= msg.timestamp_dms,
                        mcnt = msg.mcnt(),
                        ecu = msg.ecu,
                        apid=msg.apid().unwrap_or(&default_apid_ctid).to_string(),
                        ctid=msg.ctid().unwrap_or(&default_apid_ctid).to_string(),
                    );
                }

                // get more data from BufReader:
                if !last_data && (reader.buffer().len() < 0x10000) {
                    // read more data
                    let pos = std::io::SeekFrom::Start(bytes_per_file);
                    reader.seek(pos).unwrap();
                    reader.fill_buf().expect("fill_buf 2 failed!");
                    last_data = reader.buffer().len() < 0x10000;
                }
            }
            Err(error) => match error.kind() {
                adlt::dlt::ErrorKind::InvalidData(_str) => {
                    bytes_per_file += 1;
                    reader.consume(1); // skip 1 byte and check for new valid storage_header
                    info!(log, "skipped 1 byte at {}", bytes_per_file);
                }
                _ => {
                    debug!(log, "finished processing a file"; "bytes_per_file"=>bytes_per_file, "number_messages"=>number_messages);
                    f.unwrap();
                    f = None; // check for next file on next it
                    last_data = false;
                    bytes_processed += bytes_per_file;
                    bytes_per_file = 0;
                    info!(log, "got Error {}", error);
                }
            },
        }
    }
    info!(log, "finished processing"; "bytes_processed"=>bytes_processed, "number_messages"=>number_messages);

    Ok(())
}
