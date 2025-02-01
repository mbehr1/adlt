// todos:
mod convert;
mod remote;

use clap::{Arg, Command};
// todo use rayon::prelude::*;
use std::io::{self};
// use std::sync::mpsc::channel;
// use std::time::Instant;
// extern crate slog;
//extern crate slog_term;
use slog::{o, Drain};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // io::Result<()> {
    let cmd_app = Command::new("automotive dlt tool")
        .version(clap::crate_version!())
        .author("Matthias Behr <mbehr+adlt@mcbehr.de>")
        .about("Tool to handle automotive diagnostic log- and trace- (DLT) files.")
        .arg(
            Arg::new("verbose")
                .global(true)
                .short('v')
                .action(clap::ArgAction::Count)
                .help("verbosity level"),
        );
    let cmd_app = convert::add_subcommand(cmd_app);
    let cmd_app = remote::add_subcommand(cmd_app);
    let matches = cmd_app.get_matches();

    // initialize logging
    // all log levels are
    // Critical, Error, Warning
    // Info, Debug, Trace
    // by default we do output: Critical, Error, Warning
    // -v +Info -vv +Debug -vvv +Trace
    // Debug is removed at build time in Release builds by default!
    // Trace is removed at build time in Debug builds by default
    let min_log_level = match matches.get_count("verbose") {
        0 => slog::Level::Warning,
        1 => slog::Level::Info,
        2 => slog::Level::Debug,
        3 => slog::Level::Trace,
        _ => slog::Level::Trace,
    };
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    // todo think whether async is useful as it makes the match from log and output more difficult
    let drain = slog_async::Async::new(drain)
        .build()
        .filter_level(min_log_level)
        .fuse();
    let log = slog::Logger::root(
        drain,
        o!("version"=>clap::crate_version!(), "log_level"=>format!("{}",min_log_level)),
    );

    match matches.subcommand() {
        Some(("convert", sub_m)) => {
            convert::convert(&log, sub_m, std::io::BufWriter::new(std::io::stdout()))
                .map_err(|e| e.into())
                .map(|_x| ())
        } // dont return anything here
        Some(("remote", sub_m)) => remote::remote(&log, sub_m, false),
        _ => Err(Box::new(io::Error::new(
            io::ErrorKind::Unsupported,
            "unknown subcommand",
        ))),
    }
    // return Ok(());
    /*
    let input_file_name = matches.value_of("file").unwrap();

    let f = File::open(input_file_name)?;
    const BUFREADER_CAPACITY: usize = 0x10000 * 50;
    let mut f = BufReader::with_capacity(BUFREADER_CAPACITY, f); // BufReader::new(f);
                                                                 // f.fill_buf().expect("fill_buf failed!");
    let mut bytes_processed: u64 = 0;
    let mut done = false;

    // flow of messages:
    // file -> storage_header extraction -> msg
    // -> filter stage 1 "load time, raw" e.g. pos/neg load filters (before transform-alike plugins)
    // -> filter stage 2 "transform" e.g. someip, non-verbose, rewrite or filetransfer plugin (can remove msgs as well)

    // lifecycle detection

    // -> filter stage 3, "load time, post transform & lifecycle detected"

    // view time filter
    // or rest queries with filters or reports

    let now = Instant::now();
    let mut msgs: Vec<adlt::dlt::DltMessage> = Vec::new(); // LinkedList::new(); // Vec<edlt::DltMessage> = Vec::new();
    let (tx, rx) = channel();

    let (tx2, rx2) = channel();

    let filter_stage1_thread = std::thread::spawn(move || {
        let mut f1 = adlt::filter::Filter::new(adlt::filter::FilterKind::Positive);
        f1.apid = Some(adlt::dlt::DltChar4::from_buf(b"LSMF"));
        adlt::filter::functions::filter_as_streams(&[f1], &rx, &tx2)
    });

    let mut last_data = false;
    while !done {
        match adlt::dlt::parse_dlt_with_storage_header(&mut f) {
            Ok((res, msg)) => {
                bytes_processed += res as u64;
                if false && msgs.len() % 1000 == 0 {
                    println!("msg={:?}", &msg);
                }
                // msgs.push(msg);
                tx.send(msg).unwrap();
                if !last_data && (f.buffer().len() < 0x10000) {
                    // read more data
                    // println!("Hello, seek={}", bytes_processed);
                    let pos = std::io::SeekFrom::Start(bytes_processed);
                    f.seek(pos).unwrap();
                    f.fill_buf().expect("fill_buf 2 failed!");
                    last_data = f.buffer().len() < 0x10000;
                }
            }
            Err(error) => match error.kind() {
                adlt::dlt::ErrorKind::InvalidData(_str) => {
                    bytes_processed += 1;
                    f.consume(1); // skip 1 byte and check for new valid storage_header
                    eprintln!("skipped 1 byte at {}", bytes_processed);
                }
                _ => {
                    done = true;
                    eprintln!("got Error {}", error);
                }
            },
        }
    }
    drop(tx); // signal end of the channel to filterThread

    let (passed, filtered) = filter_stage1_thread.join().unwrap().unwrap();
    println!(
        "edlt processed={}bytes got {} (passed={} filtered={}) msgs in {}ms",
        bytes_processed,
        passed + filtered,
        passed,
        filtered,
        now.elapsed().as_millis()
    );
    rx2.iter().for_each(|m| msgs.push(m));

    std::thread::sleep(std::time::Duration::from_millis(1000));

    // try a filter:
    let now = Instant::now();
    let mut lsmf_msgs: Vec<&adlt::dlt::DltMessage> = msgs
        .iter()
        .filter(|m| match m.apid() {
            None => false,
            Some(e) => *e == adlt::dlt::DltChar4::from_buf(b"LSMF"),
        })
        .collect();
    println!(
        "got filtered msgs={} after {}ms",
        lsmf_msgs.len(),
        now.elapsed().as_millis()
    );
    println!("msg={:?}", &lsmf_msgs[0]);

    // try a filter:
    println!("now parallel with {} threads", rayon::current_num_threads());
    let now = Instant::now();
    let mut lsmf_msgs2: Vec<&adlt::dlt::DltMessage> = msgs
        .par_iter()
        .filter(|m| match m.apid() {
            None => false,
            Some(e) => *e == adlt::dlt::DltChar4::from_buf(b"LSMF"),
        })
        .collect();
    println!(
        "got filtered msgs2={} after {}ms",
        lsmf_msgs2.len(),
        now.elapsed().as_millis()
    );
    println!("msg={:?}", &lsmf_msgs2[0]);

    let now = Instant::now();
    let lsmf_msgs3: Vec<&adlt::dlt::DltMessage> = msgs
        .iter()
        .filter(|m| match m.apid() {
            None => false,
            Some(e) => *e == adlt::dlt::DltChar4::from_buf(b"LSMF"),
        })
        .collect();
    println!(
        "got filtered msgs={} after {}ms",
        lsmf_msgs3.len(),
        now.elapsed().as_millis()
    );
    println!("msg={:?}", &lsmf_msgs3[0]);

    let now = Instant::now();
    lsmf_msgs.par_sort_by(|a, b| -> std::cmp::Ordering {
        if a.timestamp_dms < b.timestamp_dms {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });
    println!(
        "par sorted msgs={} after {}ms",
        lsmf_msgs.len(),
        now.elapsed().as_millis()
    );
    println!("msg={:?}", &lsmf_msgs[0]);

    let now = Instant::now();
    lsmf_msgs2.sort_by(|a, b| -> std::cmp::Ordering {
        if a.timestamp_dms < b.timestamp_dms {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });
    println!(
        "sorted msgs={} after {}ms",
        lsmf_msgs2.len(),
        now.elapsed().as_millis()
    );
    println!("msg={:?}", &lsmf_msgs2[0]);

    Ok(()) */
}
