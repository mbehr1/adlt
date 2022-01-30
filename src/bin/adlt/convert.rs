use chrono::{Local, TimeZone};
use clap::{App, Arg, SubCommand};
use slog::{crit, debug, error, info, warn};
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufRead, BufReader, BufWriter, Seek};
use std::sync::mpsc::channel;

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
            /* .arg(
                Arg::with_name("hex")
                    .short("x")
                    .group("style")
                    .display_order(2)
                    .help("print DLT file; payload as hex"),
            )*/
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
                Arg::with_name("file")
                    .required(true)
                    .multiple(true)
                    .min_values(1)
                    .help("input DLT files to process"),
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
    let input_file_names: Vec<&str> = sub_m.values_of("file").unwrap().collect();

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

    let output_file = sub_m.value_of("output_file").map(|s| s.to_string());
    info!(log, "convert have {} input files", input_file_names.len(); "index_first"=>index_first, "index_last"=>index_last);
    debug!(log, "convert "; "input_file_names" => format!("{:?}",&input_file_names), "filter_lc_ids" => format!("{:?}",filter_lc_ids), "sort_by_time" => sort_by_time, "output_file" => &output_file);

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
    let mut messages_processed: adlt::dlt::DltMessageIndexType = 0;
    let mut messages_output: adlt::dlt::DltMessageIndexType = 0;
    let mut input_file_names_iter = input_file_names.iter();
    let mut last_data = false;

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

            for msg in t4_input {
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
                            // output_screen.write(&[' ' as u8])?;
                            writeln!(writer_screen, " [{}]", msg.payload_as_text()?)?;
                            // todo change to write directly to Writer
                            // output_screen.write(&['\n' as u8])?;
                            did_output = true;
                        }
                        _ => {
                            // todo...
                        }
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
        assert!(f.is_some());
        let reader: &mut BufReader<File> = f.as_mut().unwrap();
        match adlt::dlt::parse_dlt_with_storage_header(messages_processed, &mut *reader) {
            Ok((res, msg)) => {
                bytes_per_file += res as u64;
                messages_processed += 1;

                tx.send(msg).unwrap(); // todo handle error?

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
                    debug!(log, "finished processing a file"; "bytes_per_file"=>bytes_per_file, "messages_processed"=>messages_processed);
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
    drop(tx);
    let _lcs_w = t2.join().unwrap();

    if let Some(t) = t3 {
        match t.join() {
            Err(s) => error!(log, "t3 join got Error {:?}", s),
            Ok(s) => debug!(log, "t3 join was Ok {:?}", s),
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
    fn non_empty2() {
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
}
