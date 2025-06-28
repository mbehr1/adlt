/**
 * TODOs:
 * [x] - support limit for file size. split files if limit is reached. autogenerate file names.
 * [ ] - support forwarding/serving messages via TCP incl. a ring buffer
 * [ ] - for forwarding: support filters
 * [ ] - for forwarding: support context level changes
 * [ ] - support filters for received messages
 */
use std::{
    io::{BufWriter, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use adlt::{
    dlt::DltChar4,
    utils::{buf_as_hex_to_io_write, IpDltMsgReceiver, RecvMode},
};
use clap::{Arg, ArgMatches, Command};
use slog::{debug, error, info};

/*
printf("Usage: dlt-receive [options] hostname/serial_device_name\n");
    printf("Receive DLT messages from DLT daemon and print or store the messages.\n");
    printf("Use filters to filter received messages.\n");
    printf("%s \n", version);
    printf("Options:\n");
  +  printf("  -a            Print DLT messages; payload as ASCII\n");
  +  printf("  -x            Print DLT messages; payload as hex\n");
    printf("  -m            Print DLT messages; payload as hex and ASCII\n");
  +  printf("  -s            Print DLT messages; only headers\n");
    printf("  -v            Verbose mode\n");
    printf("  -h            Usage\n");
    printf("  -S            Send message with serial header (Default: Without serial header)\n");
    printf("  -R            Enable resync serial header\n");
    printf("  -y            Serial device mode\n");
 +   printf("  -u            UDP multicast mode\n");
 +   printf("  -i addr       Host interface address\n");
    printf("  -b baudrate   Serial device baudrate (Default: 115200)\n");
    printf("  -e ecuid      Set ECU ID (Default: RECV)\n");
 +   printf("  -o filename   Output messages in new DLT file\n");
 +   printf("  -c limit      Restrict file size to <limit> bytes when output to file\n");
    printf("                When limit is reached, a new file is opened. Use K,M,G as\n");
    printf("                suffix to specify kilo-, mega-, giga-bytes respectively\n");
    printf("  -f filename   Enable filtering of messages with space separated list (<AppID> <ContextID>)\n");
    printf("  -j filename   Enable filtering of messages with filter defined in json file\n");
 +   printf("  -p port       Use the given port instead the default port\n");
    printf("                Cannot be used with serial devices\n");
 */
pub fn add_subcommand(app: Command) -> Command {
    app.subcommand(
        Command::new("receive")
            .about("Receive DLT messages via UDP/TCP or serial and show or save as file")
            .arg(
                Arg::new("hex")
                    .short('x')
                    .action(clap::ArgAction::SetTrue)
                    .group("style")
                    .display_order(2)
                    .help("Print DLT msgs: payload as hex"),
            )
            .arg(
                Arg::new("ascii")
                    .short('a')
                    .action(clap::ArgAction::SetTrue)
                    .group("style")
                    .display_order(1)
                    .help("Print DLT msgs: payload as ASCII"),
            )
            /* .arg(
                Arg::with_name("mixed")
                    .short("m")
                    .group("style")
                    .display_order(1)
                    .help("print DLT file; payload as ASCII and hex"),
            )*/
            .arg(
                Arg::new("headers")
                    .short('s')
                    .action(clap::ArgAction::SetTrue)
                    .group("style")
                    .display_order(1)
                    .help("Print DLT msgs: only headers"),
            )
            .arg(
                Arg::new("hostname")
                    .required(true)
                    .num_args(1)
                    .help("hostname/serial device name"),
            )
            .arg(
                Arg::new("output_file")
                    .short('o')
                    .num_args(1)
                    .help("save messages in a DLT file (overwrite existing file!) If name ends with .zip, the file is zipped."),
            )
            .arg(
                Arg::new("port")
                    .short('p')
                    .num_args(1)
                    .help("port to use")
                    .default_value("3490")
                    .value_parser(clap::value_parser!(u16)),
            )
            .arg(
                Arg::new("interface_address")
                    .short('i')
                    .num_args(1)
                    .help("interface address (ipv4) to use")
                    .value_parser(clap::value_parser!(std::net::Ipv4Addr)),
            )
            .arg(
                Arg::new("udp_multicast")
                    .long("udp_multicast")
                    .short('u')
                    .num_args(0)
                    .help("UDP multicast mode"),
            )
            .arg(Arg::new("file_size_limit")
                .short('c')
                .num_args(1)
                .help("Restrict file size to <limit> bytes when output to file. Use MB, MiB, GB, GIB as suffix to specify mega-, giga-bytes respectively (e.g. 200MB). If used a 3 digit index is added to the file name before the extension.")
                .value_parser(clap::value_parser!(size::Size))
            )
    )
}

#[derive(Clone, Copy)]
enum OutputStyle {
    Hex,
    Ascii,
    //Mixed,
    HeaderOnly,
    None,
}

struct StreamWriterWithBytesWritten<W: std::io::Write> {
    writer: W,
    bytes_written: std::rc::Rc<std::sync::atomic::AtomicUsize>,
}

impl<W: Write> Write for StreamWriterWithBytesWritten<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let bytes_written = self.writer.write(buf)?;
        self.bytes_written
            .fetch_add(bytes_written, std::sync::atomic::Ordering::SeqCst);
        Ok(bytes_written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

pub fn receive<W: std::io::Write + Send + 'static>(
    log: &slog::Logger,
    sub_m: &ArgMatches,
    mut writer_screen: W,
) -> Result<(), Box<dyn std::error::Error>> {
    let hostname = sub_m.get_one::<String>("hostname").unwrap(); // mand. arg. cannot fail
    let port = sub_m.get_one::<u16>("port").unwrap_or(&3490);
    let udp_multicast = sub_m.get_flag("udp_multicast");
    let output_style: OutputStyle = if sub_m.get_flag("hex") {
        OutputStyle::Hex
    } else if sub_m.get_flag("ascii") {
        OutputStyle::Ascii
    } else if sub_m.get_flag("headers") {
        OutputStyle::HeaderOnly
    } else {
        OutputStyle::None
    };

    let recv_addr = hostname.parse::<Ipv4Addr>()?;
    let recv_addr = SocketAddr::new(IpAddr::V4(recv_addr), *port);
    let recv_mode = if udp_multicast {
        if recv_addr.ip().is_multicast() {
            RecvMode::UdpMulticast
        } else {
            RecvMode::Udp
        }
    } else {
        RecvMode::Tcp
    };
    let interface = if let Some(addr) = sub_m.get_one::<Ipv4Addr>("interface_address") {
        socket2::InterfaceIndexOrAddress::Address(*addr)
    } else {
        // use default interface address
        socket2::InterfaceIndexOrAddress::Index(0) // 0 means default interface
    };

    let mut file_size_limit_idx =
        if let Some(limit) = sub_m.get_one::<size::Size>("file_size_limit") {
            if *limit < size::Size::from_str("1MB").unwrap() {
                // some sanity check
                error!(log, "File size limit must be at least 1MB");
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "File size limit too small",
                )));
            }
            Some((limit.bytes() as usize, 1u32))
        } else {
            None
        };

    let new_file_writer = |path: &str, limit_idx: &Option<(usize, u32)>| {
        let do_zip = path.ends_with(".zip");
        let path_to_use = if let Some((_limit, next_idx)) = limit_idx {
            // split path into path without extension and extension
            let (path_wo_ext, ext) = path.rsplit_once('.').unwrap_or((path, "dlt"));
            &format!("{}_{:03}.{}", path_wo_ext, next_idx, ext)
        } else {
            path
        };
        std::fs::File::create(path_to_use).and_then(|f: std::fs::File| {
            if do_zip {
                let fa = StreamWriterWithBytesWritten {
                    writer: BufWriter::new(f),
                    bytes_written: std::rc::Rc::new(std::sync::atomic::AtomicUsize::new(0)),
                };
                let bytes_written = std::rc::Rc::clone(&fa.bytes_written);
                let mut zip = zip::ZipWriter::new_stream(fa);
                let file_name = if let Some((_limit, next_idx)) = limit_idx {
                    &format!("adlt_receive_{:03}.dlt", next_idx)
                } else {
                    "adlt_receive.dlt"
                };
                zip.start_file(
                    file_name,
                    zip::write::SimpleFileOptions::default().large_file(true),
                )
                .map_err(std::io::Error::other)?;
                Ok((bytes_written, Box::new(zip) as Box<dyn std::io::Write>))
            } else {
                let fa = StreamWriterWithBytesWritten {
                    writer: BufWriter::new(f),
                    bytes_written: std::rc::Rc::new(std::sync::atomic::AtomicUsize::new(0)),
                };
                let bytes_written = std::rc::Rc::clone(&fa.bytes_written);
                Ok((bytes_written, Box::new(fa) as Box<dyn std::io::Write>))
            }
        })
    };

    let output_file_name = sub_m.get_one::<String>("output_file").map(|s| s.to_owned());
    let mut output_file: Option<(
        std::rc::Rc<std::sync::atomic::AtomicUsize>,
        Box<dyn std::io::Write>,
    )> = if let Some(s) = &output_file_name {
        let writer_result = new_file_writer(s, &file_size_limit_idx);
        writer_result.map(Some)?
    } else {
        None
    };
    info!(
        log,
        "receive from {}:{} via {} on host interface {:?}",
        hostname,
        port,
        match recv_mode {
            RecvMode::Udp => "UDP",
            RecvMode::UdpMulticast => "UDP Multicast",
            RecvMode::Tcp => "TCP",
        },
        interface
    );

    // create ip_receiver:
    let stop_receive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_recv_clone = stop_receive.clone();

    let mut ip_receiver = IpDltMsgReceiver::new(
        log.clone(),
        // stop_recv_clone,
        0,
        recv_mode,
        interface,
        recv_addr,
    )?;

    // install ctrl+c handler
    let log_c = log.clone();
    ctrlc::set_handler(move || {
        info!(log_c, "Ctrl+C received, stopping receiver...");
        stop_receive.store(true, std::sync::atomic::Ordering::SeqCst);
    })?;

    let adlt = DltChar4::from_buf(b"ADLT");
    let mut next_adlt_timestamp = 0;

    // spawn a thread to receive messages as eg. write/flush to zip file takes too much time
    // send messages via a channel (async) to the main thread

    let (tx, rx_from_recv_thread) = std::sync::mpsc::channel();
    let log_clone_for_recv_thread = log.clone();
    let recv_thread = std::thread::Builder::new()
        .name("recv_thread".to_string())
        .spawn(move || {
            let log = log_clone_for_recv_thread;
            while !stop_recv_clone.load(std::sync::atomic::Ordering::SeqCst) {
                match ip_receiver.recv_msg() {
                    Ok(msg_from_pair) => {
                        if let Err(e) = tx.send(msg_from_pair){
                         error!(log, "Failed to send message to processing thread: {}. Stopping receiver thread.", e);
                        break;
                        }
                    }
                    Err(e) => {
                        match e.kind() {
                            // match Resource temporarily unavailable
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                                // no message received, continue
                                continue;
                            }
                            _ => {
                                info!(log, "error receiving message: {}", e);
                                // TODO exit on specific errors! break; // exit on error
                            }
                        }
                    }
                }
            }
            info!(log, "receiver thread stopped.");
        })
        .unwrap();

    for (msg, _msg_from) in rx_from_recv_thread {
        // verify the consistency of the message TODO for test purposes only. define via parameter!
        if msg.ecu == adlt {
            if msg.timestamp_dms != next_adlt_timestamp {
                info!(
                    log,
                    "received ADLT message with unexpected timestamp: {} vs expected {}",
                    msg.timestamp_dms,
                    next_adlt_timestamp
                );
                break;
            }
            next_adlt_timestamp = msg.timestamp_dms + 1;
        }
        // process the received message
        //verbose!(log, "received message: {:?}", msg);

        match output_style {
            OutputStyle::HeaderOnly => {
                msg.header_as_text_to_write(&mut writer_screen)?;
                writer_screen.write_all(b"\n")?;
                //did_output = true;
            }
            OutputStyle::Ascii => {
                msg.header_as_text_to_write(&mut writer_screen)?;
                writeln!(writer_screen, " [{}]", msg.payload_as_text()?)?;
                //did_output = true;
            }
            OutputStyle::Hex => {
                msg.header_as_text_to_write(&mut writer_screen)?;
                writer_screen.write_all(b" [")?;
                buf_as_hex_to_io_write(&mut writer_screen, &msg.payload)?;
                writer_screen.write_all(b"]\n")?;
                //did_output = true;
            }
            _ => {
                // todo... mixed? (the dlt-convert output is not nicely readable...)
                // info!(log, "received message: {:?}", msg); // TODO only for debugging
            }
        }

        // if output to file:
        if let Some((bytes_written, file)) = output_file.as_mut() {
            // shall we split the file?
            if let Some((limit, next_idx)) = &mut file_size_limit_idx {
                // TODO change to see if with this msg plus an overhead for the zip file descriptors the limit is reached
                if bytes_written.load(std::sync::atomic::Ordering::SeqCst) >= *limit {
                    info!(
                        log,
                        "file size limit reached, closing file (idx: {}) and opening a new one",
                        next_idx
                    );
                    *next_idx += 1;
                    // close the current file and open a new one
                    if let Err(e) = file.flush() {
                        error!(log, "Error flushing file: {}", e);
                    }

                    match new_file_writer(output_file_name.as_ref().unwrap(), &file_size_limit_idx)
                    {
                        Ok((new_bytes_written, new_file)) => {
                            *file = new_file;
                            *bytes_written = new_bytes_written;
                        }
                        Err(e) => {
                            error!(log, "Error creating new file: {}", e);
                            break; // exit on error
                        }
                    }
                }
            }

            msg.to_write(file)?;
        }
        /* TODO how to flush the writer_screen frequently? */
    }

    writer_screen.flush()?;
    if let Some((_, mut writer)) = output_file {
        writer.flush()?;
        drop(writer); // close, happens anyhow autom...
    }
    match recv_thread.join() {
        Err(s) => error!(log, "recv_thread join got Error {:?}", s),
        Ok(s) => debug!(log, "recv_thread join was Ok {:?}", s),
    };

    Ok(())
}
