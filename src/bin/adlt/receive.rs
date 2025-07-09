/**
 * TODOs:
 * [x] - support limit for file size. split files if limit is reached. autogenerate file names.
 * [x] - support forwarding/serving messages via TCP
 * [ ] - support a ring buffer with old messages for tcp forwarding?
 * [ ] - for forwarding: support filters
 * [x] - for forwarding: support context level changes
 * [ ] - support filters for received messages
 */
use nohash_hasher::NoHashHasher;
use std::{
    hash::BuildHasherDefault,
    io::{BufWriter, Write},
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};

use adlt::{
    dlt::{
        parse_dlt_with_std_header, DltChar4, DltMessage, DltMessageIndexType, DltStandardHeader,
        SERVICE_ID_GET_LOG_INFO, SERVICE_ID_NAMES, SERVICE_ID_SET_DEFAULT_LOG_LEVEL,
        SERVICE_ID_SET_DEFAULT_TRACE_STATUS, SERVICE_ID_SET_LOG_LEVEL,
        SERVICE_ID_SET_TIMING_PACKETS, SERVICE_ID_SET_VERBOSE_MODE,
    },
    utils::{buf_as_hex_to_io_write, set_max_buffer_size, IpDltMsgReceiver, RecvMode},
};
use clap::{Arg, ArgMatches, Command};
use slog::{debug, error, info, warn};

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
 +  printf("  -e ecuid      Set ECU ID (Default: RECV)\n");
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
            .arg(Arg::new("forward_tcp")
                .long("forward_tcp")
                .short('t')
                .num_args(1)
                .help("Forward/serve received messages via TCP on the given port.")
                .value_parser(clap::value_parser!(u16))
            )
            .arg(Arg::new("ecu_id")
                .short('e')
                .num_args(1)
                .default_value("RECV")
                .value_parser(|s: &str|DltChar4::from_str(s).map_err(|_|"ecu contains non ascii characters"))
                .help("Set ECU ID for received messages if they have no extended header (default: RECV)")
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
    stop_receive_param: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<usize, Box<dyn std::error::Error>> {
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
    let ecu_id = sub_m
        .get_one::<DltChar4>("ecu_id")
        .map(|s| s.to_owned())
        .unwrap();

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

    let forward_tcp_port = sub_m.get_one::<u16>("forward_tcp");

    let new_file_writer = |path: &str, limit_idx: &Option<(usize, u32)>| {
        let do_zip = path.ends_with(".zip");
        let path_to_use = if let Some((_limit, next_idx)) = limit_idx {
            // split path into path without extension and extension
            let (path_wo_ext, ext) = path.rsplit_once('.').unwrap_or((path, "dlt"));
            &format!("{path_wo_ext}_{next_idx:03}.{ext}")
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
                    &format!("adlt_receive_{next_idx:03}.dlt")
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
    let stop_receive = if let Some(stop_receive_param) = &stop_receive_param {
        stop_receive_param.clone()
    } else {
        // create a new stop receive flag
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))
    };
    //let stop_receive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_recv_clone = stop_receive.clone();

    let mut ip_receiver = IpDltMsgReceiver::new(
        log.clone(),
        // stop_recv_clone,
        0,
        recv_mode,
        interface,
        recv_addr,
    )?;

    // channels used:
    // tx_for_recv_thread -> receiver thread will put messages into this channel/end (and they will end at rx_from_recv_thread)
    // forward_thread -> forward thread will receive messages from rx_from_recv_thread and put back to tx_for_forward_thread

    let (tx_for_recv_thread, rx_from_recv_thread) = std::sync::mpsc::channel();

    // forward_tcp thread?
    let (forward_tcp_thread, rx_from_forward_thread) = if let Some(port) = forward_tcp_port {
        let log = log.clone();
        info!(log, "Forwarding messages via TCP on port {}", port);
        let stop_forward = stop_receive.clone();
        let port = *port;

        let (tx_for_forward_thread, rx_from_forward_thread) = std::sync::mpsc::channel();

        let forward_thread = std::thread::Builder::new()
            .name("forward_tcp_thread".to_string())
            .spawn(move || -> std::io::Result<()> {
                forward_serve_via_tcp(
                    log,
                    stop_forward,
                    port,
                    ecu_id,
                    rx_from_recv_thread,
                    tx_for_forward_thread,
                )
            })
            .unwrap();
        (Some(forward_thread), rx_from_forward_thread)
    } else {
        (None, rx_from_recv_thread)
    };

    // install ctrl+c handler
    if stop_receive_param.is_none() {
        let log_c = log.clone();
        ctrlc::set_handler(move || {
            info!(log_c, "Ctrl+C received, stopping receiver...");
            stop_receive.store(true, std::sync::atomic::Ordering::SeqCst);
        })?;
    }

    let adlt = DltChar4::from_buf(b"ADLT");
    let mut next_adlt_timestamp = 0;

    // spawn a thread to receive messages as eg. write/flush to zip file takes too much time
    // send messages via a channel (async) to the main thread

    let log_clone_for_recv_thread = log.clone();
    let recv_thread = std::thread::Builder::new()
        .name("recv_thread".to_string())
        .spawn(move || {
            let log = log_clone_for_recv_thread;
            while !stop_recv_clone.load(std::sync::atomic::Ordering::SeqCst) {
                match ip_receiver.recv_msg() {
                    Ok(msg_from_pair) => {
                        if let Err(e) = tx_for_recv_thread.send(msg_from_pair){
                         error!(log, "Failed to send message to processing thread: {}. Stopping receiver thread.", e);
                        break;
                        }
                    }
                    Err(e) => {
                        match e.kind() {
                            // match Resource temporarily unavailable
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock | std::io::ErrorKind::InvalidData => {
                                // no message received, continue
                                continue;
                            }
                            _ => {
                                info!(log, "error receiving message: {} e.kind={} recv_mode={:?}", e, e.kind(), ip_receiver.recv_mode);
                                // TODO exit on specific errors! break; // exit on error
                                // break;
                            }
                        }
                    }
                }
            }
            info!(log, "receiver thread stopped.");
        })
        .unwrap();

    let mut nr_msg_received = 0usize;
    for (msg, _msg_from) in rx_from_forward_thread {
        // verify the consistency of the message TODO for test purposes only. define via parameter!
        nr_msg_received += 1;
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
    if let Some(thread) = forward_tcp_thread {
        match thread.join() {
            Err(s) => error!(log, "forward_tcp_thread join got Error {:?}", s),
            Ok(s) => debug!(log, "forward_tcp_thread join was Ok {:?}", s),
        };
    }

    Ok(nr_msg_received)
}

fn forward_serve_via_tcp(
    log: slog::Logger,
    stop_forward: std::sync::Arc<std::sync::atomic::AtomicBool>,
    port: u16,
    ecu_id: DltChar4,
    rx_for_forward_thread: std::sync::mpsc::Receiver<(DltMessage, SocketAddr)>,
    tx_for_forward_thread: std::sync::mpsc::Sender<(DltMessage, SocketAddr)>,
) -> std::io::Result<()> {
    // use libc::{c_int, setsockopt, SOL_SOCKET, SO_SNDLOWAT};
    use socket2::{Domain, SockAddr, Type};
    use std::sync::{Arc, Mutex};

    // list of connected clients (expected dlt-viewers)

    struct Viewer {
        stream: socket2::Socket,
        addr: SockAddr,
        default_log_level: Option<u8>, // default log level for this viewer (none if not set yet) (0 = off, 1 = fatal, 2 = error, 3=warning, 4 = info, 5=debug, 6 = verbose)
        apid_ctid_log_level_map: std::collections::HashMap<
            u64, // (apid, ctid) as u32le
            u8,
            BuildHasherDefault<NoHashHasher<u64>>,
        >, // map of (apid, ctid (as u32le)) to log level for this viewer
    }
    let viewers = Arc::new(Mutex::new(Vec::<Viewer>::new()));

    let listener = socket2::Socket::new(Domain::IPV4, Type::STREAM, None)
        .expect("Failed to create TCP socket");
    let address: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let address: SockAddr = address.into();

    listener.set_reuse_address(true).unwrap_or_else(|_| {
        panic!(
            "Failed to set reuse address on TCP socket for port {:?}",
            address.as_socket_ipv4()
        )
    });
    listener.bind(&address).unwrap_or_else(|_| {
        panic!(
            "Failed to bind TCP socket to port {:?}",
            address.as_socket_ipv4()
        )
    });
    info!(log, "TCP listener bound to port {}", port);
    listener.listen(10).expect("Failed to listen on TCP socket");
    // set the listener to non-blocking mode
    listener
        .set_nonblocking(true)
        .expect("Failed to set non-blocking mode");

    let log_clone = log.clone();
    let viewers_clone = viewers.clone();
    let stop_listener = stop_forward.clone();
    let listen_thread = std::thread::Builder::new()
        .name("forward_tcp_listen_thread".to_string())
        .spawn(move || {
            let log = log_clone;
            let viewers = viewers_clone;
            while !stop_forward.load(std::sync::atomic::Ordering::SeqCst) {
                match listener.accept() {
                    Ok((viewer, addr)) => {
                        info!(log, "Accepted connection from {:?}", addr.as_socket_ipv4());
                        // set the stream to non-blocking mode
                        if let Err(e) = viewer.set_nonblocking(true) {
                            error!(log, "Failed to set stream to non-blocking: {}", e);
                            continue;
                        }
                        match set_max_buffer_size(&viewer, true, 64 * 1024 * 1000) {
                            Ok(size) => {
                                info!(log, "Set send buffer size to {} bytes", size);
                            }
                            Err(e) => {
                                error!(
                                    log,
                                    "Failed to set send buffer size: {}! Current size = {}",
                                    e,
                                    viewer.send_buffer_size().unwrap_or(0)
                                );
                            }
                        }
                        // set SO_SNDLOWAT to 64kb to allow at least 1 message to be always fitting:
                        // using setsocketopt
                        // seems not supported on windows, so dont using that approach
                        /*let lowat: c_int = 64 * 1024; // 64kb
                        let ret = unsafe {
                            setsockopt(
                                viewer.as_raw_fd(),
                                SOL_SOCKET,
                                SO_SNDLOWAT,
                                &lowat as *const _ as *const libc::c_void,
                                std::mem::size_of_val(&lowat) as libc::socklen_t,
                            )
                        };
                        if ret != 0 {
                            error!(
                                log,
                                "Failed to set SO_SNDLOWAT on viewer socket: {}",
                                std::io::Error::last_os_error()
                            );
                            continue;
                        } else {
                            info!(log, "Set SO_SNDLOWAT to 64kb for viewer socket");
                        }*/

                        // spawn a thread to handle the connection
                        let stop_forward_clone = stop_forward.clone();
                        let log_clone = log.clone();
                        let viewers_clone = viewers.clone();
                        std::thread::spawn(move || {
                            let log = log_clone;
                            let viewers = viewers_clone;
                            // add the viewer to the list
                            viewers.lock().unwrap().push(Viewer {
                                stream: viewer.try_clone().expect("Failed to clone viewer stream"),
                                addr: addr.clone(),
                                default_log_level: None,
                                apid_ctid_log_level_map: std::collections::HashMap::with_capacity_and_hasher(
                                    512, // initial capacity for 512 entries (apid/ctid) pairs
                                    BuildHasherDefault::<NoHashHasher<u64>>::default(),
                                ),
                            });
                            let mut recvd_msg_index: DltMessageIndexType = 0;
                            while !stop_forward_clone.load(std::sync::atomic::Ordering::SeqCst) {
                                let mut buf = [MaybeUninit::uninit(); 64 * 1024]; // todo buffer size?
                                                                                  // todo change to ipdltmsgreceiver code

                                match viewer.recv(&mut buf) {
                                    Ok(rcvd_len) => {
                                        if rcvd_len > 0 {
                                            info!(
                                                log,
                                                "Got {} bytes from viewer {:?}",
                                                rcvd_len,
                                                addr.as_socket_ipv4()
                                            );
                                            let mut recvd_data = unsafe {
                                                // This creates a `&[u8]` slice from the `&[MaybeUninit<u8>]` slice.
                                                // It's safe because u8 and MaybeUninit<u8> have the same layout,
                                                // and we trust `recv_from` to have initialized these `size` bytes.
                                                std::slice::from_raw_parts(
                                                    buf.as_ptr() as *const u8,
                                                    rcvd_len,
                                                )
                                            };
                                            loop{
                                                let parse_res = parse_dlt_with_std_header(
                                                    recvd_data,
                                                    recvd_msg_index,
                                                    ecu_id,
                                                );
                                                match parse_res {
                                                    Ok((to_consume, msg)) => {
                                                        let remaining = recvd_data.len().saturating_sub(to_consume);
                                                        info!(log, "Parsed message: {:?}, remaining bytes = {}", msg, remaining);
                                                        recvd_msg_index += 1;
                                                        // todo parse as msg and process control msgs (setDefaultLogLevel, setLogLevel)
                                                        // default log level should be off

                                                        if msg.is_ctrl_request(){
                                                            let mut args = msg.into_iter();
                                                            let message_id_arg = args.next();
                                                            if let Some(a) = message_id_arg {
                                                                let message_id = if a.is_big_endian {
                                                                    // todo this fails if first arg is not a uint32! add check
                                                                    u32::from_be_bytes(a.payload_raw.get(0..4).unwrap().try_into().unwrap())
                                                                } else {
                                                                    u32::from_le_bytes(a.payload_raw.get(0..4).unwrap().try_into().unwrap())
                                                                };
                                                                let payload_arg = args.next();
                                                                let (payload, _is_big_endian) = match payload_arg {
                                                                    Some(a) => (a.payload_raw, a.is_big_endian),
                                                                    None => (&[] as &[u8], false),
                                                                };
                                                                info!(log, "Received control request message id {} ({}): {:?}", message_id, SERVICE_ID_NAMES.get(&message_id).unwrap_or(&"Unknown"),payload);
                                                                match message_id{
                                                                    SERVICE_ID_SET_LOG_LEVEL => {
                                                                        // set the log level for apid/ctid
                                                                        if payload.len() >= 9 {
                                                                            let apid = DltChar4::from_buf(&payload[0..4]);
                                                                            let ctid = DltChar4::from_buf(&payload[4..8]);
                                                                            let log_level = payload[8];
                                                                            info!(log, "Set log level for apid {} and ctid {} to {}", apid, ctid, log_level);
                                                                            // update the viewer's apid/ctid log level map
                                                                            let mut viewers_lock = viewers.lock().unwrap();
                                                                            if let Some(viewer) = viewers_lock.iter_mut().find(|v| v.addr == addr) {
                                                                                viewer.apid_ctid_log_level_map.insert(
                                                                                    ((apid.as_u32le() as u64) << 32) | (ctid.as_u32le() as u64),
                                                                                    log_level,
                                                                                );
                                                                            } else {
                                                                                warn!(log, "Viewer with addr {:?} not found in list", addr.as_socket_ipv4());
                                                                            }
                                                                        }else {
                                                                            warn!(log, "Invalid payload length for set log level message: {} bytes, expected at least 9 bytes", payload.len());
                                                                        }
                                                                    }
                                                                    SERVICE_ID_GET_LOG_INFO => {}
                                                                    SERVICE_ID_SET_DEFAULT_LOG_LEVEL => {
                                                                        let default_log_level = if !payload.is_empty(){
                                                                            payload[0]
                                                                        }else{
                                                                            0 // default to 0 (off)
                                                                        };
                                                                        info!(log, "Set default log level to {} for addr {:?}", default_log_level, addr.as_socket_ipv4());
                                                                        // 0 = off, 1 = fatal, 2 = error, 3=warning, 4 = info, 5=debug, 6 = verbose
                                                                        let mut viewers_lock = viewers.lock().unwrap();
                                                                        // update viewer with that addr:
                                                                        if let Some(viewer) = viewers_lock.iter_mut().find(|v| v.addr == addr) {
                                                                            viewer.default_log_level = Some(default_log_level);
                                                                        } else {
                                                                            warn!(log, "Viewer with addr {:?} not found in list", addr.as_socket_ipv4());
                                                                        }
                                                                    }
                                                                    SERVICE_ID_SET_DEFAULT_TRACE_STATUS|SERVICE_ID_SET_TIMING_PACKETS|SERVICE_ID_SET_VERBOSE_MODE=>{}
                                                                    _ => {
                                                                        warn!(log, "Unknown control request message id: {}", message_id);
                                                                    }
                                                                }
                                                                // todo process control request messages
                                                                // e.g. set log level, set default log level, etc.

                                                            };
                                                        }


                                                        if remaining>0 {
                                                            recvd_data = &recvd_data[recvd_data.len()-remaining..];
                                                        }else{
                                                            break;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                            log,
                                                            "Failed to parse DLT message from viewer {:?}: bytes missing={}",
                                                            addr.as_socket_ipv4(),
                                                            e
                                                        );
                                                        break; // todo: add to buffer!
                                                    }
                                                }
                                            }

                                            viewer
                                                .send(recvd_data)
                                                .expect("Failed to send ACK to viewer");
                                        } else {
                                            // no data available, continue
                                            std::thread::sleep(std::time::Duration::from_millis(
                                                50,
                                            ));
                                        }

                                        // break;
                                    }
                                    Err(e) => {
                                        if e.kind() != std::io::ErrorKind::WouldBlock {
                                            error!(log, "Error receiving data from viewer: {}", e);
                                            break;
                                        } else {
                                            // no data available, continue
                                            std::thread::sleep(std::time::Duration::from_millis(
                                                50,
                                            ));
                                        }
                                    }
                                }
                            }
                            // remove the viewer from the list
                            let mut viewers_lock = viewers.lock().unwrap();
                            viewers_lock.retain(|v| v.addr != addr);
                            // close the stream
                            if let Err(e) = viewer.shutdown(std::net::Shutdown::Both) {
                                error!(log, "Error shutting down viewer stream: {}", e);
                            }
                            info!(log, "TCP connection to {:?} closed.", addr.as_socket_ipv4());
                        });
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            error!(log, "Error accepting connection: {}", e);
                            std::thread::sleep(std::time::Duration::from_millis(250));
                        } else {
                            // no connection available, continue
                            // std::thread::sleep(std::time::Duration::from_millis(50));
                            // wait not needed here, as the channel recv_timeout will block for some time
                        }
                    }
                }
            }
            let _ = listener.shutdown(std::net::Shutdown::Both);
        })
        .unwrap();

    let mut send_buf = Vec::with_capacity(64 * 1024); // 64kb send buffer that we use for a message
                                                      // this is not to optimize for the case with multiple viewers but to avoid multiple write calls to the ip streams

    loop {
        // need to receive messages from the channel, forward them to the tcp clients and put it to the tx channel
        match rx_for_forward_thread.recv() {
            Ok((msg, addr)) => {
                //info!(log, "Forwarding message to {:?}", addr);
                let mut failed_viewers = Vec::new();
                send_buf.clear();

                for viewer in viewers.lock().unwrap().iter_mut() {
                    // send the message to all connected viewers (dlt-viewer doesn't expect the storage header)

                    // write_all doesn't help with non-blocking sockets! (TODO)
                    // so we use a really big send_buffer size (64mb target)
                    // if this is not enough the viewer/client is too slow and will be removed from the forwarders

                    // do we have a log level for the apid/ctid?
                    // else use default log level of the viewer

                    let log_level = if let Some(ext_header) = &msg.extended_header {
                        if let Some(level) = viewer.apid_ctid_log_level_map.get(
                            &((ext_header.apid.as_u32le() as u64) << 32
                                | ext_header.ctid.as_u32le() as u64),
                        ) {
                            *level
                        } else {
                            // use default log level of the viewer or >verbose if not set yet (TODO rethink initial value)
                            viewer.default_log_level.unwrap_or(7) // 0 = off, 1 = fatal, 2 = error, 3=warning, 4 = info, 5=debug, 6 = verbose
                        }
                    } else {
                        1 // fatal by default if no extended header is present
                    };

                    // todo add trace status support as well

                    let shall_forward =
                        // check if the message should be forwarded to this viewer
                        // if the default log level is set, only forward messages with a log level <= default_log_level

                        if let Some(msg_vmm) = msg.verb_mstp_mtin() {
                            let mstp = (msg_vmm >> 1) & 0x07u8;
                            let mtin = (msg_vmm >> 4) & 0x0fu8;
                            mstp == 0 && mtin <= log_level
                        } else {
                            true // no ext header, forward all messages
                        };

                    if !shall_forward {
                        // skip this viewer
                        continue;
                    }

                    if send_buf.is_empty() {
                        // prepare the send buffer with the DLT standard header and the message
                        if let Err(e) = DltStandardHeader::to_write(
                            &mut send_buf,
                            &msg.standard_header,
                            &msg.extended_header,
                            Some(msg.ecu),
                            None, // session_id = None, todo
                            if msg.standard_header.has_timestamp() {
                                Some(msg.timestamp_dms)
                            } else {
                                None
                            },
                            &msg.payload,
                        ) {
                            error!(
                                log,
                                "Error preparing message for viewer {:?}: {}",
                                viewer.addr.as_socket_ipv4(),
                                e
                            );
                            send_buf.clear(); // clear the buffer to avoid sending partial message
                            continue; // skip this viewer
                        }
                        debug_assert_eq!(
                            msg.standard_header.len as usize,
                            send_buf.len(),
                            "The send buffer length should match the standard header length"
                        );
                        /*assert_eq!(
                            0xff,
                            send_buf[msg.standard_header.len as usize - 1],
                            "The send buffer should end with 0xff for test msgs"
                        );*/
                        #[cfg(debug_assertions)]
                        match parse_dlt_with_std_header(&send_buf, 0, msg.ecu) {
                            Ok((to_consume, _)) => {
                                assert_eq!(to_consume, send_buf.len(), "The send buffer should be fully consumed by the DLT standard header parsing");
                            }
                            Err(e) => {
                                panic!("Error parsing DLT message with standard header: {e}");
                            }
                        }
                    }

                    /* TODO: is the write_all() sufficient for non-blocking sockets?
                    let mut written = 0;
                    while written < send_buf.len() {
                        match viewer.stream.write(&send_buf[written..]) {
                            Ok(0) => {
                                // no bytes written, connection closed
                                error!(
                                    log,
                                    "Viewer {:?} closed the connection",
                                    viewer.addr.as_socket_ipv4()
                                );
                                failed_viewers.push(viewer.addr.clone());
                                break; // exit the loop for this viewer
                            }
                            Ok(n) => {
                                written += n;
                                if written < send_buf.len() {
                                    info!(
                                        log,
                                        "Viewer {:?} wrote {}/{}/{} bytes, waiting to write more",
                                        viewer.addr.as_socket_ipv4(),
                                        n,
                                        written,
                                        send_buf.len()
                                    );
                                }
                            }
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    // would block, try again later
                                    info!(
                                        log,
                                        "Viewer {:?} would block, retrying to send message",
                                        viewer.addr.as_socket_ipv4()
                                    );
                                    std::thread::sleep(std::time::Duration::from_millis(50));
                                    continue; // retry sending
                                } else {
                                    error!(
                                        log,
                                        "Error sending message to viewer {:?}: {}",
                                        viewer.addr.as_socket_ipv4(),
                                        e
                                    );
                                    failed_viewers.push(viewer.addr.clone());
                                    break; // exit the loop for this viewer
                                }
                            }
                        }
                    }*/

                    match viewer.stream.write_all(&send_buf) {
                        Ok(()) => {
                            // info!(log, "Sent message to viewer {:?}", viewer.addr.as_socket_ipv4());
                        }
                        Err(e) => {
                            error!(
                                log,
                                "Error sending message to viewer {:?}: {}",
                                viewer.addr.as_socket_ipv4(),
                                e
                            );
                            // remove the viewer from the list
                            failed_viewers.push(viewer.addr.clone());
                            continue; // skip this viewer
                        }
                    }
                }

                if let Err(e) = tx_for_forward_thread.send((msg, addr)) {
                    error!(log, "Failed to forward message to main thread: {}", e);
                    break; // exit on error
                }

                // remove failed viewers
                if !failed_viewers.is_empty() {
                    let mut viewers_lock = viewers.lock().unwrap();
                    viewers_lock.retain(|v| !failed_viewers.contains(&v.addr));
                }
            }
            Err(std::sync::mpsc::RecvError) => {
                error!(
                    log,
                    "Error receiving message for forwarding: Disconnected channel"
                );
                break;
            }
        }
    }
    // set stop_forward to true to stop the listener thread
    // this might be stopped/set already as ctrl+c handler sets it
    // but to avoid a deadlock here we set it again
    stop_listener.store(true, std::sync::atomic::Ordering::SeqCst);

    match listen_thread.join() {
        Err(s) => error!(log, "listen_thread join got Error {:?}", s),
        Ok(s) => debug!(log, "listen_thread join was Ok {:?}", s),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use super::*;
    use crate::transmit::create_send_socket;
    use adlt::{
        dlt::{DltExtendedHeader, DLT_MIN_STD_HEADER_SIZE},
        dlt_args,
    };

    use portpicker::pick_unused_port;
    use slog::{o, Drain, Logger};
    use socket2::SockAddr;
    use tempfile::NamedTempFile;

    fn new_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, o!())
    }

    #[test]
    fn params_wrong_port() {
        let logger = new_logger();
        let arg_vec = vec!["t", "receive", "-p66666"];
        let sub_c = add_subcommand(Command::new("t")).try_get_matches_from(arg_vec);
        assert!(sub_c.is_err());
        let err = sub_c.unwrap_err();
        assert!(err.kind() == clap::error::ErrorKind::ValueValidation);
        assert_eq!(err.to_string(), "error: invalid value '66666' for '-p <port>': 66666 is not in 0..=65535\n\nFor more information, try '--help'.\n");
    }

    #[test]
    fn params_ok() {
        let arg_vec = vec!["t", "receive", "127.0.0.1", "-u"];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (c, sub_m) = sub_c.subcommand().unwrap();
        assert_eq!("receive", c);
        assert_eq!(
            sub_m.get_one::<String>("hostname").map(|s| s.to_string()),
            Some(String::from("127.0.0.1"))
        );
        //let r = receive(&logger, sub_m, std::io::stdout());
    }

    #[test]
    fn recv_udp() {
        const DLT_STD_HDR_VERSION: u8 = 0x1 << 5;

        // determine a free port:
        let port = pick_unused_port().expect("no ports free");
        let port_str = port.to_string();

        let forward_port = pick_unused_port().expect("no ports free");
        let forward_port_str = forward_port.to_string();

        let logger = new_logger();
        let file = NamedTempFile::with_suffix(".zip").unwrap();
        let file_path = file.path().to_str().unwrap();

        let arg_vec = vec![
            "t",
            "receive",
            "127.0.0.1",
            "-u",
            "-p",
            &port_str,
            "-o",
            file_path,
            "-t",
            &forward_port_str,
        ];
        let sub_c = add_subcommand(Command::new("t")).get_matches_from(arg_vec);
        let (_c, sub_m) = sub_c.subcommand().unwrap();
        // spawn on a thread to not block the test
        std::thread::scope(|s| {
            let stop_receive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop_receive_t = stop_receive.clone();

            let logger_t = logger.clone();
            let t = s.spawn(move || {
                let logger = logger_t;
                let r = receive(&logger, sub_m, std::io::stdout(), Some(stop_receive_t));
                assert!(r.is_ok());
                r.unwrap()
            });

            // send a test message to the UDP port
            // create send socket:
            let send_addr = std::net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port).into();
            let socket = create_send_socket(
                RecvMode::Udp,
                send_addr,
                socket2::InterfaceIndexOrAddress::Index(0),
            )
            .unwrap();

            let send_to_addr = SockAddr::from(send_addr);

            let mut nr_msgs_sent = 0usize;
            let ecu = DltChar4::from_buf(b"ADLT");
            let mut exth = Some(DltExtendedHeader {
                verb_mstp_mtin: 0x41,
                noar: 0, // will be set later
                apid: DltChar4::from_buf(b"TSTA"),
                ctid: DltChar4::from_buf(b"TSTC"),
            });

            // init a vec with ascending numbers:
            let payload_buf = (0..u16::MAX).map(|u| u as u8).collect::<Vec<u8>>();
            let std_hdr = adlt::dlt::DltStandardHeader {
                htyp: DLT_STD_HDR_VERSION, // dlt_args! uses machine endianess! | DLT_STD_HDR_BIG_ENDIAN,
                mcnt: (nr_msgs_sent % 256) as u8,
                len: 0, // set automatically by DltStandardHeader::to_write
            };

            // write the DLT message to the buffer
            // Todo move alloc out of loop
            let mut buf = Vec::with_capacity(u16::MAX as usize);
            let mut buf_writer = std::io::Cursor::new(&mut buf);

            let wanted_payload_len = std::cmp::min(
                nr_msgs_sent % u16::MAX as usize,
                u16::MAX as usize - (4 + 8 + 4 + 2 + DLT_MIN_STD_HEADER_SIZE + 18 + 28), // type info, usize(8), type info, payload len(2) + std/ext header size -> this leads to a max dlt message of 64k
                                                                                         // -28 as otherwise osx rejects the message as too large (error 40)
            );
            let (noar, payload) = dlt_args!(
                nr_msgs_sent,
                serde_bytes::Bytes::new(&payload_buf[0..(wanted_payload_len)])
            )
            .unwrap();
            if let Some(exth) = &mut exth {
                exth.noar = noar;
            }

            adlt::dlt::DltStandardHeader::to_write(
                &mut buf_writer,
                &std_hdr,
                &exth,
                Some(ecu),
                None,                      // session_id = None, todo
                Some(nr_msgs_sent as u32), // use message count as timestamp
                &payload,
            )
            .expect("Failed to write DLT message: {e}");

            // let full_msg_len = buf_writer.position() as usize;
            let buf = buf_writer.into_inner();

            // wait 100ms (to give the receiver time to start)
            std::thread::sleep(std::time::Duration::from_millis(100));

            socket.send_to(buf, &send_to_addr).unwrap();
            info!(
                logger,
                "Sent message to {:?}",
                send_to_addr.as_socket_ipv4(),
            );
            nr_msgs_sent += 1;

            // wait 100ms
            std::thread::sleep(std::time::Duration::from_millis(100));
            stop_receive.store(true, std::sync::atomic::Ordering::SeqCst);
            let r = t.join();
            assert!(r.is_ok());
            let nr_msg_received = r.unwrap();
            assert_eq!(nr_msg_received, nr_msgs_sent);
            info!(logger, "Received {} messages", nr_msg_received);
        });

        // check if the file exists and is not empty
        // TODO
    }
}
