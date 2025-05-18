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
}
