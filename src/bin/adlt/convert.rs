use chrono::{Local, TimeZone};
use clap::{App, Arg, SubCommand};
use slog::{crit, debug, error, info, warn};
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;
use std::sync::mpsc::channel;

use adlt::dlt::DLT_MAX_STORAGE_MSG_SIZE;
use adlt::filter::functions::{filters_from_convert_format, filters_from_dlf};
use adlt::utils::{buf_as_hex_to_io_write, DltMessageIterator, LowMarkBufReader};

#[derive(Clone, Copy)]
enum OutputStyle {
    Hex,
    Ascii,
    Mixed,
    HeaderOnly,
    None,
}

pub fn add_subcommand<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.subcommand(
        SubCommand::with_name("convert").about("Open DLT files and show on console or export to DLT file")
             .arg(
                Arg::with_name("hex")
                    .short("x")
                    .group("style")
                    .display_order(2)
                    .help("print DLT file; payload as hex"),
            )
            .arg(
                Arg::with_name("ascii")
                    .short("a")
                    .group("style")
                    .display_order(1)
                    .help("print DLT file; payload as ASCII"),
            )
            /* .arg(
                Arg::with_name("mixed")
                    .short("m")
                    .group("style")
                    .display_order(1)
                    .help("print DLT file; payload as ASCII and hex"),
            )*/
            .arg(
                Arg::with_name("headers")
                    .short("s")
                    .group("style")
                    .display_order(1)
                    .help("print DLT file; only headers"),
            )
            .arg(
                Arg::with_name("filter_file")
                .short("f")
                .takes_value(true)
                .help("file with filters to apply. Can be in dlt-convert format or dlt-viewer dlf format.")
            )
            .arg(
                Arg::with_name("file")
                    .required(true)
                    .multiple(true)
                    .min_values(1)
                    .help("input DLT files to process. If multiple files are provided they are sorted by their first DLT message reception time."),
            ).arg(
                Arg::with_name("index_first")
                .short("b")
                .takes_value(true)
                .help("first message (index) to be handled. Index is from the original file before any filters are applied.")
            ).arg(
                Arg::with_name("index_last")
                .short("e")
                .takes_value(true)
                .help("last message (index) to be handled")
            ).arg(
                Arg::with_name("filter_lc_ids")
                .short("l")
                .long("lcs")
                .multiple(true)
                .min_values(1)
                .help("filter for the specified lifecycle ids.")
            ).arg(
                Arg::with_name("output_file")
                .short("o")
                .takes_value(true)
                .help("output messages in new DLT file")
            ).arg(
                Arg::with_name("sort")
                .long("sort")
                .takes_value(false)
                .help("sort by timestamp. Sorts by timestamp per lifecycle.")
            ),
    )
}

#[allow(dead_code)] // we currently use it only for test
pub struct ConvertResult<W: std::io::Write + Send + 'static> {
    messages_processed: adlt::dlt::DltMessageIndexType,
    messages_output: adlt::dlt::DltMessageIndexType,
    writer_screen: Option<W>,
}

/// same as genivi dlt dlt-convert binary
///
/// log the files to console
///
/// supports additional lifecycle detection and sort by timestamp
pub fn convert<W: std::io::Write + Send + 'static>(
    log: &slog::Logger,
    sub_m: &clap::ArgMatches,
    mut writer_screen: W,
) -> std::io::Result<ConvertResult<W>> {
    let mut input_file_names: Vec<&str> = sub_m.values_of("file").unwrap().collect();

    let output_style: OutputStyle = if sub_m.is_present("hex") {
        OutputStyle::Hex
    } else if sub_m.is_present("ascii") {
        OutputStyle::Ascii
    } else if sub_m.is_present("mixed") {
        OutputStyle::Mixed
    } else if sub_m.is_present("headers") {
        OutputStyle::HeaderOnly
    } else {
        OutputStyle::None
    };

    let sort_by_time = sub_m.is_present("sort");

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

    let filter_lc_ids: std::collections::BTreeSet<u32> = match sub_m.values_of("filter_lc_ids") {
        None => std::collections::BTreeSet::new(),
        Some(s) => s
            .map(|s| s.parse::<u32>())
            .filter(|a| !a.is_err())
            .map(|s| s.unwrap())
            .collect(),
    };

    // parse filter file if provided:
    let filter_file = sub_m.value_of("filter_file");
    let filters = if let Some(filter_file) = filter_file {
        // try to open the file in either dlf/xml format or dlt-convert "APID CTID " format.
        let file = File::open(filter_file)?;
        let reader = std::io::BufReader::new(file);
        let filters = filters_from_dlf(reader);
        if let Ok(filters) = filters {
            info!(log, "parsed dlf format file with {} filters", filters.len());
            filters
        } else {
            // parse as dlt-convert format
            let file = File::open(filter_file)?;
            let reader = std::io::BufReader::new(file);

            let filters = filters_from_convert_format(reader)?;
            info!(
                log,
                "parsed dlt-convert format file with {:?} filters", filters
            );
            filters
        }
    } else {
        vec![]
    };

    let output_file = sub_m.value_of("output_file").map(|s| s.to_string());
    info!(log, "convert have {} input files", input_file_names.len(); "index_first"=>index_first, "index_last"=>index_last);
    debug!(log, "convert "; "input_file_names" => format!("{:?}",&input_file_names), "filter_lc_ids" => format!("{:?}",filter_lc_ids), "sort_by_time" => sort_by_time, "output_file" => &output_file, "filter_file" => &filter_file, "filters" =>  format!("{:?}",&filters) );

    // if we have multiple files we do need to sort them first by the first log reception_time!
    if input_file_names.len() > 1 {
        // map input_file_names to name/first msg
        let file_msgs = input_file_names.iter().map(|&f_name| {
            let fi = File::open(f_name);
            match fi {
                Ok(mut f) => {
                    let m1 = adlt::utils::get_first_message_from_file(&mut f, 512 * 1024);
                    if m1.is_none() {
                        warn!(log, "file {} doesn't contain a DLT message in first 0.5MB. Skipping!", f_name;);
                    }
                    (f_name, m1)
                }
                _ => {
                    warn!(log, "couldn't open {}. Skipping!", f_name;);
                    (f_name, None)
                }
            }
        });
        let mut file_msgs: Vec<_> = file_msgs.filter(|(_a, b)| b.is_some()).collect();
        file_msgs.sort_by(|a, b| {
            a.1.as_ref()
                .unwrap()
                .reception_time_us
                .cmp(&b.1.as_ref().unwrap().reception_time_us)
        });
        input_file_names = file_msgs.iter().map(|(a, _b)| *a).collect();
        debug!(log, "sorted input_files by first message reception time:"; "input_file_names" => format!("{:?}",&input_file_names));
    }

    // setup (thread) filter chain:
    let (tx, rx) = channel(); // msg -> parse_lifecycles (t2)
    let (tx2, rx2) = channel(); // parse_lifecycles -> buffer_sort_messages (t3)
                                // let (tx3, rx3) = channel(); // buffer_sort_messages -> print/output (t4)

    let (lcs_r, lcs_w) =
        evmap::new::<adlt::lifecycle::LifecycleId, adlt::lifecycle::LifecycleItem>();
    let t2 = std::thread::spawn(move || {
        adlt::lifecycle::parse_lifecycles_buffered_from_stream(lcs_w, rx, tx2)
    });
    let t3_lcs_r = lcs_r.clone();
    let (t3, t4_input) = if sort_by_time {
        let (tx3, rx3) = channel();
        (
            Some(std::thread::spawn(move || {
                adlt::utils::buffer_sort_messages(
                    rx2,
                    tx3,
                    &t3_lcs_r,
                    3,
                    2 * adlt::utils::US_PER_SEC,
                )
                /*
                adlt::utils::buffer_elements( // todo we buffer here only to let the lifecycle start times become a bit more stable. need a better way...
                    // its only needed to have msgs from different lifecycles sorted as well. within one lifecycle they will be sorted fine
                    // the diff is usually just a few (<20) ms...
                    rx2,
                    tx3,
                    adlt::utils::BufferElementsOptions {
                        amount: adlt::utils::BufferElementsAmount::NumberElements(1000), // todo how to determine constant...
                    },
                )*/
            })),
            rx3,
        )
    } else {
        (None, rx2)
    };

    // if we have filters we use a filter thread:
    let (thread_filter, t4_input) = if !filters.is_empty() {
        let (tx_filter, rx_filter) = channel();
        (
            Some(std::thread::spawn(move || {
                adlt::filter::functions::filter_as_streams(&filters, &t4_input, &tx_filter)
            })),
            rx_filter,
        )
    } else {
        (None, t4_input)
    };

    let t4 = std::thread::spawn(
        move || -> Result<(adlt::dlt::DltMessageIndexType, W), Box<dyn std::error::Error + Send + Sync>> {
            let mut output_file = if let Some(s) = output_file {
                match std::fs::File::create(s) {
                    Ok(f) => Ok(BufWriter::new(f)),
                    Err(e) => Err(e),
                }
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "no output_file param",
                ))
            };

            let mut output : adlt::dlt::DltMessageIndexType= 0;
            let mut writer_screen_flush_pending = false;

            for msg in t4_input {

                // from time to time (all ~0.5mio msgs) we flush the writer_screen to get a fast output 
                // and not at the end only the last chunk:
                if writer_screen_flush_pending && (msg.index & 0x7ffff == 0) {
                    writer_screen.flush()?;
                    writer_screen_flush_pending = false;
                }

                // lifecycle filtered?
                if !filter_lc_ids.is_empty() && !filter_lc_ids.contains(&msg.lifecycle) {
                    continue;
                }
                // start with a simple dump of the msgs similar to dlt_message_header
                if msg.index >= index_first && msg.index <= index_last {
                    // if print header, ascii, hex or mixed: todo
                    let mut did_output = false;
                    match output_style {
                        OutputStyle::HeaderOnly => {
                            msg.header_as_text_to_write( &mut writer_screen)?;
                            writer_screen.write_all(&[b'\n'])?;
                            did_output = true;
                        }
                        OutputStyle::Ascii => {
                            msg.header_as_text_to_write(&mut writer_screen)?;
                            writeln!(writer_screen, " [{}]", msg.payload_as_text()?)?;
                            did_output = true;
                        }
                        OutputStyle::Hex => {
                            msg.header_as_text_to_write(&mut writer_screen)?;
                            writer_screen.write_all(&[b' ',b'['])?;
                            buf_as_hex_to_io_write(&mut writer_screen, &msg.payload)?;
                            writer_screen.write_all(&[b']',b'\n'])?;
                            did_output = true;
                        }
                        _ => {
                            // todo... mixed? (the dlt-convert output is not nicely readable...)
                        }
                    }
                     if did_output {
                        writer_screen_flush_pending = true;
                    }
                    // if output to file:
                    if let Ok(ref mut file) = output_file {
                        msg.to_write(file)?;
                        did_output = true;
                    }
                    if did_output{ output += 1;}
                }
            }
            if let Ok(mut writer) = output_file {
                writer.flush()?;
                drop(writer); // close, happens anyhow autom...
            }

            Ok((output, writer_screen))
        },
    );
    const BUFREADER_CAPACITY: usize = 512 * 1024;
    // we use a relatively small 512kb chunk size as we're processing
    // the data multithreaded reader in bigger chunks slows is in total slower

    //assert!(BUFREADER_CAPACITY > DLT_MAX_STORAGE_MSG_SIZE);

    let mut bytes_processed: u64 = 0;
    let mut messages_processed: adlt::dlt::DltMessageIndexType = 0;
    let mut messages_output: adlt::dlt::DltMessageIndexType = 0;

    for input_file_name in input_file_names {
        let fi = File::open(input_file_name)?;
        info!(log, "opened file {} {:?}", &input_file_name, &fi);
        let buf_reader = LowMarkBufReader::new(fi, BUFREADER_CAPACITY, DLT_MAX_STORAGE_MSG_SIZE);
        let mut it = DltMessageIterator::new(messages_processed, buf_reader);
        it.log = Some(log);
        loop {
            match it.next() {
                Some(msg) => {
                    tx.send(msg).unwrap(); // todo handle error
                }
                None => {
                    messages_processed = it.index;
                    debug!(log, "finished processing a file"; "bytes_processed"=>it.bytes_processed, "bytes_skipped"=>it.bytes_skipped, "messages_processed"=>messages_processed);
                    bytes_processed += (it.bytes_processed + it.bytes_skipped) as u64;
                    break;
                }
            }
        }
    }
    drop(tx);
    let _lcs_w = t2.join().unwrap();

    if let Some(t) = t3 {
        match t.join() {
            Err(s) => error!(log, "t3 join got Error {:?}", s),
            Ok(s) => debug!(log, "t3 join was Ok {:?}", s),
        };
    }

    if let Some(t) = thread_filter {
        match t.join() {
            Err(s) => error!(log, "thread_filter join got Error {:?}", s),
            Ok(s) => debug!(log, "thread_filter join was Ok {:?}", s),
        };
    }

    let mut writer_screen = match t4.join() {
        Err(s) => {
            error!(log, "t4 join got Error {:?}", s);
            None
        }
        Ok(s) => {
            if let Ok(s) = s {
                debug!(log, "t4 join was Ok {:?}", s.0);
                messages_output += s.0;
                Some(s.1)
            } else {
                None
            }
        }
    };

    info!(log, "finished processing"; "bytes_processed"=>bytes_processed, "messages_processed"=>messages_processed);

    // print lifecycles:
    if let OutputStyle::None = output_style {
        if let Some(..) = writer_screen {
            let writer_screen = writer_screen.as_mut().unwrap();
            if let Some(a) = lcs_r.read() {
                let sorted_lcs = adlt::lifecycle::get_sorted_lifecycles_as_vec(&a);
                writeln!(writer_screen, "have {} lifecycles:", sorted_lcs.len(),)?;
                // todo to output_screen!
                // output lifecycles
                for lc in sorted_lcs {
                    writeln!(
                        writer_screen,
                        "LC#{:3}: {:4} {} - {} #{:8} {}",
                        lc.id(),
                        lc.ecu,
                        Local
                            .from_utc_datetime(&adlt::utils::utc_time_from_us(lc.start_time))
                            .format("%Y/%m/%d %H:%M:%S%.6f"),
                        Local
                            .from_utc_datetime(&adlt::utils::utc_time_from_us(lc.end_time()))
                            .format("%H:%M:%S"),
                        lc.nr_msgs,
                        if lc.only_control_requests() {
                            "CTRL_REQUESTS_ONLY"
                        } else {
                            ""
                        }
                    )?;
                }
            }
        }
    }

    Ok(ConvertResult {
        messages_processed,
        messages_output,
        writer_screen,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use adlt::*;
    use slog::{o, Drain, Logger};
    use tempfile::NamedTempFile;

    fn new_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, o!())
    }

    #[test]
    fn params1() {
        let logger = new_logger();
        let arg_vec = vec!["t", "convert", "foo.dlt"];
        let sub_c = add_subcommand(App::new("t")).get_matches_from(arg_vec);
        let (c, sub_m) = sub_c.subcommand();
        assert_eq!("convert", c);
        let sub_m = sub_m.expect("no matches?");
        assert!(sub_m.is_present("file"));
        let r = convert(&logger, sub_m, std::io::stdout());
        assert!(r.is_err());
    }

    #[test]
    fn empty1() {
        let logger = new_logger();

        let file = NamedTempFile::new().unwrap();
        let file_path = file.path().to_str().unwrap();

        let arg_vec = vec!["t", "convert", file_path];
        let sub_c = add_subcommand(App::new("t")).get_matches_from(arg_vec);
        let (c, sub_m) = sub_c.subcommand();
        assert_eq!("convert", c);
        let sub_m = sub_m.expect("no matches?");
        assert!(sub_m.is_present("file"));

        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(0, r.messages_output);
        assert_eq!(0, r.messages_processed);
        assert!(file.close().is_ok());
    }

    #[test]
    fn non_empty1() {
        let logger = new_logger();

        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        // persist some messages (more than the 512kb chunk size -> 20 byte per msg)
        let persisted_msgs: adlt::dlt::DltMessageIndexType = 1024 * 1024 / 20;
        let ecu = dlt::DltChar4::from_buf(b"ECU1");
        for i in 0..persisted_msgs {
            let sh = adlt::dlt::DltStorageHeader {
                secs: (1640995200000000 / utils::US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu,
            };
            let standard_header = adlt::dlt::DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
            m.to_write(&mut file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();

        let arg_vec = vec!["t", "convert", file_path.as_str()];
        let sub_c = add_subcommand(App::new("t")).get_matches_from(arg_vec);
        let (c, sub_m) = sub_c.subcommand();
        assert_eq!("convert", c);
        let sub_m = sub_m.expect("no matches?");
        assert!(sub_m.is_present("file"));

        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(0, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);
        assert!(file.close().is_ok());
    }

    #[test]
    fn non_empty_invalid_bytes() {
        let logger = new_logger();

        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        // persist some messages
        let persisted_msgs: adlt::dlt::DltMessageIndexType = 10;
        let ecu = dlt::DltChar4::from_buf(b"ECU1");

        // random bytes buffer:
        // todo needs better parsing heuristics let invalid_data = [b'D', b'L', b'T', 0x1];
        let invalid_data = [b'D', b'L', b'T', 0x2];

        for i in 0..persisted_msgs {
            // put some random bytes between (in front) of messages:
            file.write_all(&invalid_data[0..i as usize % (invalid_data.len() + 1)])
                .unwrap();

            let sh = adlt::dlt::DltStorageHeader {
                secs: (1640995200000000 / utils::US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu,
            };
            let standard_header = adlt::dlt::DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
            m.to_write(&mut file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();

        let arg_vec = vec!["t", "convert", "-s", "-b2", "-e5", file_path.as_str()];
        let sub_c = add_subcommand(App::new("t")).get_matches_from(arg_vec);
        let (c, sub_m) = sub_c.subcommand();
        assert_eq!("convert", c);
        let sub_m = sub_m.expect("no matches?");
        assert!(sub_m.is_present("file"));

        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(5 - 2 + 1, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);
        assert!(file.close().is_ok());
    }

    #[test]
    fn hex_output() {
        let logger = new_logger();

        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        // persist some messages
        let persisted_msgs: adlt::dlt::DltMessageIndexType = 2;
        let ecu = dlt::DltChar4::from_buf(b"ECU1");

        for i in 0..persisted_msgs {
            let sh = adlt::dlt::DltStorageHeader {
                secs: i + (1640995200000000 / utils::US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu,
            };
            let standard_header = adlt::dlt::DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = adlt::dlt::DltMessage::from_headers(
                i,
                sh,
                standard_header,
                &[],
                vec![(i % 256) as u8, ((i + 1) % 256) as u8],
            );
            m.to_write(&mut file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();

        let arg_vec = vec!["t", "convert", "-x", "-e2", file_path.as_str()];
        let sub_c = add_subcommand(App::new("t")).get_matches_from(arg_vec);
        let (_c, sub_m) = sub_c.subcommand();
        let sub_m = sub_m.expect("no matches?");

        let output_buf = Vec::new();
        let output = std::io::BufWriter::new(output_buf);
        let r = convert(&logger, sub_m, output).unwrap();
        assert_eq!(2, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);
        file.close().unwrap();
        assert!(r.writer_screen.is_some());
        let output_buf = r.writer_screen.unwrap().into_inner().unwrap();
        assert!(!output_buf.is_empty());
        let s = String::from_utf8(output_buf).unwrap();
        //println!("{}", s);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(persisted_msgs as usize, lines.len());
        assert_eq!(
            ":00.000000          0 000 ECU1 ---- ---- --- --- N - 0 [00 01]",
            &lines[0][18..] // time is in local format. so ignore here
        );
        assert_eq!(
            ":01.000000          0 001 ECU1 ---- ---- --- --- N - 0 [01 02]",
            &lines[1][18..]
        );
    }

    #[test]
    fn non_empty_sort_sorted_check_mcnt() {
        let logger = new_logger();

        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        // persist some messages
        let persisted_msgs: adlt::dlt::DltMessageIndexType = 10;
        let ecu = dlt::DltChar4::from_buf(b"ECU1");
        for i in 0..persisted_msgs {
            let sh = adlt::dlt::DltStorageHeader {
                secs: (1640995200000000 / utils::US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu,
            };
            let standard_header = adlt::dlt::DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
            m.to_write(&mut file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();

        let arg_vec = vec!["t", "convert", "-a", "--sort", file_path.as_str()];
        let sub_c = add_subcommand(App::new("t")).get_matches_from(arg_vec);
        let (c, sub_m) = sub_c.subcommand();
        assert_eq!("convert", c);
        let sub_m = sub_m.expect("no matches?");
        assert!(sub_m.is_present("file"));

        let output_buf = Vec::new();
        let output = std::io::BufWriter::new(output_buf);

        let r = convert(&logger, sub_m, output).unwrap();
        assert_eq!(persisted_msgs, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);
        assert!(file.close().is_ok());
        // check output but we get the output only in the integration tests...
        assert!(r.writer_screen.is_some());
        let output_buf = r.writer_screen.unwrap().into_inner().unwrap();
        assert!(!output_buf.is_empty());
        let s = String::from_utf8(output_buf).unwrap();
        //println!("{}", s);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(persisted_msgs as usize, lines.len());
        for (i, line) in lines.iter().enumerate() {
            // in this case the output should be sorted with mcnt from 0 to 9 (as all have timestamp 0 -> stable order)
            // mcnt is the 4th " " splitted
            let parts: Vec<&str> = line.split_ascii_whitespace().collect();
            assert_eq!(parts[4].parse::<u8>().unwrap(), (i % 256) as u8);
        }
    }

    #[test]
    fn non_empty_sort_sorted_check_mcnt_multiple() {
        // create two files and provide them in wrong order:

        let logger = new_logger();

        let mut file1 = NamedTempFile::new().unwrap();
        let file1_path = String::from(file1.path().to_str().unwrap());
        let mut file2 = NamedTempFile::new().unwrap();
        let file2_path = String::from(file2.path().to_str().unwrap());

        // provide a 3rd existing file that contains no dlt
        let mut file3 = NamedTempFile::new().unwrap();
        let file3_path = String::from(file3.path().to_str().unwrap());
        file3.write_all(b"this is a text only file").unwrap();
        file3.flush().unwrap();

        let file4_path = file3_path.clone() + "invalid";

        // persist some messages (15 each per file)
        let persisted_msgs: adlt::dlt::DltMessageIndexType = 30;
        let ecu = dlt::DltChar4::from_buf(b"ECU1");
        for i in 0..persisted_msgs {
            let sh = adlt::dlt::DltStorageHeader {
                secs: i as u32 + (1640995200000000 / utils::US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu,
            };
            let standard_header = adlt::dlt::DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
            m.to_write(if i < persisted_msgs / 2 {
                &mut file1
            } else {
                &mut file2
            })
            .unwrap(); // will persist with timestamp
        }
        file1.flush().unwrap();
        file2.flush().unwrap();

        let arg_vec = vec![
            "t",
            "convert",
            "-a",
            "--sort",
            file2_path.as_str(),
            file4_path.as_str(),
            file3_path.as_str(),
            file1_path.as_str(),
        ];
        let sub_c = add_subcommand(App::new("t")).get_matches_from(arg_vec);
        let (_c, sub_m) = sub_c.subcommand();
        let sub_m = sub_m.expect("no matches?");

        let output_buf = Vec::new();
        let output = std::io::BufWriter::new(output_buf);

        let r = convert(&logger, sub_m, output).unwrap();
        assert_eq!(persisted_msgs, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);
        assert!(file1.close().is_ok());
        assert!(file2.close().is_ok());

        // check output but we get the output only in the integration tests...
        assert!(r.writer_screen.is_some());
        let output_buf = r.writer_screen.unwrap().into_inner().unwrap();
        assert!(!output_buf.is_empty());
        let s = String::from_utf8(output_buf).unwrap();
        //println!("{}", s);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(persisted_msgs as usize, lines.len());
        for (i, line) in lines.iter().enumerate() {
            // in this case the output should be sorted with mcnt from 0 to 9 (as all have timestamp 0 -> stable order)
            // mcnt is the 4th " " splitted
            let parts: Vec<&str> = line.split_ascii_whitespace().collect();
            assert_eq!(parts[4].parse::<u8>().unwrap(), (i % 256) as u8);
        }
    }

    #[test]
    fn output_to_file() {
        let logger = new_logger();

        let mut file = NamedTempFile::new().unwrap();
        let file_path = String::from(file.path().to_str().unwrap());

        // persist some messages
        let persisted_msgs: adlt::dlt::DltMessageIndexType = 10;
        let ecu = dlt::DltChar4::from_buf(b"ECU1");
        for i in 0..persisted_msgs {
            let sh = adlt::dlt::DltStorageHeader {
                secs: (1640995200000000 / utils::US_PER_SEC) as u32, // 1.1.22, 00:00:00 as GMT
                micros: 0,
                ecu,
            };
            let standard_header = adlt::dlt::DltStandardHeader {
                htyp: 1 << 5, // vers 1
                mcnt: (i % 256) as u8,
                len: 4,
            };

            let m = adlt::dlt::DltMessage::from_headers(i, sh, standard_header, &[], vec![]);
            m.to_write(&mut file).unwrap(); // will persist with timestamp
        }
        file.flush().unwrap();

        let output_file = NamedTempFile::new().unwrap();
        let output_file_path = String::from(output_file.path().to_str().unwrap());

        let arg_vec = vec![
            "t",
            "convert",
            "-b2",
            "-e5",
            file_path.as_str(),
            "-o",
            &output_file_path,
        ];
        let sub_c = add_subcommand(App::new("t")).get_matches_from(arg_vec);
        let (_, sub_m) = sub_c.subcommand();
        let sub_m = sub_m.expect("no matches?");

        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(5 - 2 + 1, r.messages_output);
        assert_eq!(persisted_msgs, r.messages_processed);
        assert!(file.close().is_ok());

        // check that output file has now the expected (number of) msgs:
        let arg_vec = vec!["t", "convert", &output_file_path];
        let sub_c = add_subcommand(App::new("t")).get_matches_from(arg_vec);
        let (_, sub_m) = sub_c.subcommand();
        let sub_m = sub_m.expect("no matches?");
        let r = convert(&logger, sub_m, std::io::stdout()).unwrap();
        assert_eq!(5 - 2 + 1, r.messages_processed);
        assert!(output_file.close().is_ok());
    }

    // todo add tests for filter_file
}
