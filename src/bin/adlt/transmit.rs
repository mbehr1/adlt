use clap::{Arg, ArgMatches, Command};
use slog::info;
use socket2::{Domain, InterfaceIndexOrAddress, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use adlt::{
    dlt::{DltChar4, DltExtendedHeader, DLT_MIN_STD_HEADER_SIZE},
    dlt_args,
    utils::RecvMode,
};

pub fn add_subcommand(app: Command) -> Command {
    app.subcommand(
        Command::new("transmit")
            .about("Send/transmit test dlt messages")
            .arg(
                Arg::new("hostname")
                    .required(true)
                    .num_args(1)
                    .help("hostname/serial device name"),
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

// TODO import???
const DLT_STD_HDR_VERSION: u8 = 0x1 << 5; // 3 bits (5,6,7) max.  [Dlt299]

pub fn transmit(
    log: &slog::Logger,
    matches: &ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    let hostname = matches.get_one::<String>("hostname").unwrap();
    let port = matches.get_one::<u16>("port").unwrap_or(&3490);
    let udp_multicast = matches.get_flag("udp_multicast");

    let send_addr = hostname.parse::<Ipv4Addr>()?;
    let send_addr = SocketAddr::new(IpAddr::V4(send_addr), *port);
    let send_mode = if udp_multicast {
        if send_addr.ip().is_multicast() {
            RecvMode::UdpMulticast
        } else {
            RecvMode::Udp
        }
    } else {
        RecvMode::Tcp
    };
    let interface = if let Some(addr) = matches.get_one::<Ipv4Addr>("interface_address") {
        socket2::InterfaceIndexOrAddress::Address(*addr)
    } else {
        // use default interface address
        socket2::InterfaceIndexOrAddress::Index(0) // 0 means default interface

        // socket2::InterfaceIndexOrAddress::Address("127.0.0.1".parse::<Ipv4Addr>()?);
    };

    info!(
        log,
        "transmitting test DLT messages to {}:{} via {} on host interface {:?}",
        hostname,
        port,
        match send_mode {
            RecvMode::Udp => "UDP",
            RecvMode::UdpMulticast => "UDP Multicast",
            RecvMode::Tcp => "TCP",
        },
        interface
    );

    // install ctrl+c handler
    let stop_receive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_recv_clone = stop_receive.clone();
    let log_c = log.clone();
    ctrlc::set_handler(move || {
        info!(log_c, "Ctrl+C received, stopping receiver...");
        stop_receive.store(true, std::sync::atomic::Ordering::SeqCst);
    })?;

    // create send socket:
    let socket = create_send_socket(send_mode, send_addr, interface)
        .map_err(|e| format!("Failed to create send socket: {e}"))?;

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

    while !stop_recv_clone.load(std::sync::atomic::Ordering::SeqCst) {
        // create a test DLT message (standard-header with ext header and payload size = nr_msgs_sent % u16::MAX)
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
        .map_err(|e| format!("Failed to write DLT message: {e}"))?;

        // let full_msg_len = buf_writer.position() as usize;
        let buf = buf_writer.into_inner();
        assert!(
            buf.len() <= u16::MAX as usize,
            "DLT message too large: {}",
            buf.len()
        );

        socket.send_to(buf, &send_to_addr).map_err(|e| {
            format!(
                "Failed to send_to DLT message #{} (len={}): {}",
                nr_msgs_sent,
                buf.len(),
                e
            )
        })?;
        nr_msgs_sent += 1;
        // sleep a bit to avoid flooding the network
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    println!(
        "Sent {nr_msgs_sent} test DLT messages to {hostname}:{port}"
    );

    Ok(())
}

fn create_send_socket(
    send_mode: RecvMode,
    send_addr: SocketAddr,
    interface: InterfaceIndexOrAddress,
) -> Result<socket2::Socket, std::io::Error> {
    let socket = match send_mode {
        RecvMode::Tcp => {
            // Initialize TCP receiver here if needed
            panic!("TCP receiver not implemented yet");
        }
        RecvMode::Udp => {
            // Initialize UDP receiver here if needed
            let ip_addr = send_addr.ip();
            if ip_addr.is_multicast() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Provided address is a multicast address",
                )); // todo auto enable multicast if not set?
            }
            let socket = match ip_addr {
                IpAddr::V4(_) => Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
                    .expect("ipv4 dgram socket"),
                IpAddr::V6(_) => {
                    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
                        .expect("ipv6 dgram socket");
                    socket.set_only_v6(true)?;
                    socket
                }
            };
            socket.set_reuse_address(true).expect("reuse addr error");
            // #[cfg(unix)] // this is currently restricted to Unix's in socket2
            // TODO check! socket.set_reuse_port(true).expect("reuse port Error");
            /*socket TODO bind to a port by parameter?
            .bind(&socket2::SockAddr::from(send_addr))
            .expect("bind error");*/
            socket
        }
        RecvMode::UdpMulticast => {
            let ip_addr = send_addr.ip();
            if !ip_addr.is_multicast() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Provided address is not a multicast address",
                ));
            }
            let socket = match ip_addr {
                IpAddr::V4(ref mdns_v4) => {
                    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
                        .expect("ipv4 dgram socket");
                    socket
                        .join_multicast_v4_n(mdns_v4, &interface)
                        .expect("join_multicast_v4_n");
                    socket
                }
                IpAddr::V6(ref mdns_v6) => match interface {
                    InterfaceIndexOrAddress::Index(index) => {
                        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
                            .expect("ipv6 dgram socket");
                        socket.set_only_v6(true)?;
                        socket
                            .join_multicast_v6(mdns_v6, index)
                            .expect("join_multicast_v6");
                        socket
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "IPv6 multicast requires an interface index",
                        ));
                    }
                },
            };
            socket.set_reuse_address(true).expect("reuse addr error");
            // #[cfg(unix)] // this is currently restricted to Unix's in socket2
            // TODO check! socket.set_reuse_port(true).expect("reuse port Error");
            /*socket
            .bind(&socket2::SockAddr::from(send_addr))
            .expect("bind error"); TODO see above */
            socket
        }
    };

    // set read timeout
    socket // TODO which timeout to choose?
        .set_write_timeout(Some(std::time::Duration::from_millis(500)))
        .expect("set write timeout error");

    socket
        .set_nonblocking(false)
        .expect("set non-blocking error");

    socket
        .set_send_buffer_size(u16::MAX as usize)
        .expect("set send buffer size error");

    println!(
        "Created send socket for {}://{}:{} with send_buffer_size={} bytes",
        match send_mode {
            RecvMode::Udp => "UDP",
            RecvMode::UdpMulticast => "UDP Multicast",
            RecvMode::Tcp => "TCP",
        },
        send_addr.ip(),
        send_addr.port(),
        socket.send_buffer_size().unwrap_or(0)
    );

    Ok(socket)
}
