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
    printf("  -c limit      Restrict file size to <limit> bytes when output to file\n");
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
            ),
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

        // socket2::InterfaceIndexOrAddress::Address("127.0.0.1".parse::<Ipv4Addr>()?);
    };

    let output_file = sub_m.get_one::<String>("output_file").map(|s| s.to_owned());
    let mut output_file: Option<Box<dyn std::io::Write>> = if let Some(s) = output_file {
        let do_zip = s.ends_with(".zip");

        let writer_result: Result<Box<dyn std::io::Write>, std::io::Error> =
            std::fs::File::create(s).and_then(|f: std::fs::File| {
                if do_zip {
                    let mut zip = zip::ZipWriter::new(f);
                    zip.start_file(
                        "adlt_receive.dlt",
                        zip::write::SimpleFileOptions::default().large_file(true),
                    )
                    .map_err(std::io::Error::other)?;
                    Ok(Box::new(zip) as Box<dyn std::io::Write>)
                } else {
                    Ok(Box::new(BufWriter::new(f)) as Box<dyn std::io::Write>)
                }
            });
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
        if let Some(ref mut file) = output_file {
            msg.to_write(file)?;
        }
        /* TODO how to flush the writer_screen frequently? */
    }

    writer_screen.flush()?;
    if let Some(mut writer) = output_file {
        writer.flush()?;
        drop(writer); // close, happens anyhow autom...
    }
    match recv_thread.join() {
        Err(s) => error!(log, "recv_thread join got Error {:?}", s),
        Ok(s) => debug!(log, "recv_thread join was Ok {:?}", s),
    };

    Ok(())
}
