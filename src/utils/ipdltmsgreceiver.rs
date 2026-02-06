/// TODOs:
/// [ ] - remove the .expect() calls and handle errors gracefully (non panic)
/// [ ] - handle fragmentation per sender
/// [ ] - set recv buffer size
/// [ ] - decide whether using a single socket for all addresses is sufficient or whether we need a socket per address
///
use slog::{debug, info, warn};
use socket2::{Domain, InterfaceIndexOrAddress, Protocol, SockAddr, Socket, Type};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
};

#[cfg(not(windows))]
use std::os::fd::OwnedFd;

#[cfg(feature = "pcap")]
use crate::utils::plp_packet::PlpPacket;
#[cfg(feature = "pcap")]
use pcap::{Active, Capture, Offline};
#[cfg(feature = "pcap")]
use pnet::packet::{
    ethernet::EthernetPacket, ip::IpNextHeaderProtocol, ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet, udp::UdpPacket, vlan::VlanPacket, Packet,
};
#[cfg(feature = "pcap")]
use std::collections::HashMap;
#[cfg(feature = "pcap")]
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(feature = "pcap")]
type Ipv4FragmentKey = (Ipv4Addr, Ipv4Addr, IpNextHeaderProtocol, u16);

use crate::dlt::{
    first_idx_of_serial_pattern, parse_dlt_with_serial_header, parse_dlt_with_std_header, DltChar4,
    DltMessage, DltMessageIndexType, Error, ErrorKind, DLT_SERIAL_HEADER_SIZE,
};

#[cfg(not(windows))]
fn open_serial_port_from_file(path: &str) -> Result<serial2::SerialPort, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let owned_fd: OwnedFd = file.into();
    Ok(serial2::SerialPort::from(owned_fd))
}

#[cfg(windows)]
fn open_serial_port_from_file(path: &str) -> Result<serial2::SerialPort, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "Opening serial device as file is not supported on Windows: {}",
            path
        ),
    ))
}

#[cfg(feature = "pcap")]
struct UdpPacketOwned {
    buffer: Vec<u8>,
}

#[cfg(feature = "pcap")]
impl UdpPacketOwned {
    fn new(data: Vec<u8>) -> Option<Self> {
        // Validate that the data is a valid UDP packet
        if UdpPacket::new(&data).is_some() {
            Some(Self { buffer: data })
        } else {
            None
        }
    }

    fn packet(&'_ self) -> UdpPacket<'_> {
        // This is only safe if constructed via new()
        UdpPacket::new(&self.buffer).unwrap()
    }

    fn payload(&self) -> &[u8] {
        let udp_header_length = UdpPacket::minimum_packet_size();
        &self.buffer[udp_header_length..]
    }
}

#[cfg(feature = "pcap")]
enum UdpPacketRef<'a> {
    Borrowed(UdpPacket<'a>),
    Owned(UdpPacketOwned),
}

#[cfg(feature = "pcap")]
impl<'a> UdpPacketRef<'a> {
    fn payload(&self) -> &[u8] {
        match self {
            UdpPacketRef::Borrowed(udp) => udp.payload(),
            UdpPacketRef::Owned(udp) => udp.payload(),
        }
    }

    fn get_destination(&self) -> u16 {
        match self {
            UdpPacketRef::Borrowed(udp) => udp.get_destination(),
            UdpPacketRef::Owned(udp) => udp.packet().get_destination(),
        }
    }
}

/// Set the maximum buffer size for a socket, trying to set it to the given size.
///
/// If the size is too large, it will try to halve the size until it succeeds or reaches a minimum size.
/// Returns the actual size set on the socket or an error if it fails to set the size.
///
/// size needs to be minimum 16kb, otherwise it will fail.
pub fn set_max_buffer_size(
    socket: &socket2::Socket,
    send: bool,
    size: usize,
) -> std::io::Result<usize> {
    let mut try_size = size;
    while try_size >= 16 * 1024 {
        // set the send buffer size to 64kb
        match if send {
            socket.set_send_buffer_size(try_size)
        } else {
            socket.set_recv_buffer_size(size)
        } {
            Ok(()) => {
                return Ok(try_size);
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::InvalidInput {
                    // the size is too large, try a smaller size
                    try_size /= 2;
                } else {
                    return Err(e);
                }
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("Failed to set send buffer size {try_size}/{size} bytes"),
    ))
}

pub fn create_send_socket(
    send_mode: RecvMode,
    send_addr: SocketAddr,
    interface: InterfaceIndexOrAddress,
) -> Result<socket2::Socket, std::io::Error> {
    let socket = match send_mode {
        RecvMode::Serial(_) => {
            panic!("Serial server not implemented yet");
        }
        #[cfg(feature = "pcap")]
        RecvMode::Pcap(_) => {
            panic!("PCAP server not implemented yet");
        }
        RecvMode::Tcp => {
            panic!("TCP server not implemented yet");
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
            socket
        }
    };

    // set read timeout
    socket // TODO which timeout to choose?
        .set_write_timeout(Some(std::time::Duration::from_millis(500)))
        .expect("set write timeout error");

    socket
        .set_nonblocking(false)
        .expect("set non-blocking(false) error");

    set_max_buffer_size(&socket, true, u16::MAX as usize).expect("set send buffer size error");

    println!(
        "Created send socket for {}://{}:{} with send_buffer_size={} bytes",
        send_mode,
        send_addr.ip(),
        send_addr.port(),
        socket.send_buffer_size().unwrap_or(0)
    );

    Ok(socket)
}

#[derive(PartialEq, Debug)]
pub enum PcapParam {
    InterfaceName(String),
    File(String),
}

#[derive(PartialEq, Debug)]
pub struct SerialParams {
    pub device_name: String,
    pub baudrate: u32,
}

#[derive(PartialEq, Debug)]
pub enum RecvMode {
    Tcp,
    Udp,
    UdpMulticast,
    Serial(SerialParams),
    #[cfg(feature = "pcap")]
    Pcap(PcapParam),
}

enum RecvMethod {
    Recv(Socket),
    RecvFrom(Socket),
    Serial(serial2::SerialPort),
    #[cfg(feature = "pcap")]
    PcapCaptureOffline(Capture<Offline>),
    #[cfg(feature = "pcap")]
    PcapCaptureActive(Capture<Active>),
}

#[cfg(feature = "pcap")]
struct PlpStats {
    last_plp_counter: u16,
    start_time: u64,
    nr_packets: u64,
    packets_lost: u64,
    last_dump_time: u64,
}

impl std::fmt::Display for RecvMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecvMode::Udp => write!(f, "UDP"),
            RecvMode::UdpMulticast => write!(f, "UDP Multicast"),
            RecvMode::Tcp => write!(f, "TCP"),
            RecvMode::Serial(_) => write!(f, "Serial"),
            #[cfg(feature = "pcap")]
            RecvMode::Pcap(_) => write!(f, "PCAP"),
        }
    }
}

enum ExpectedHeader {
    Serial, // expect DLT_SERIAL_HEADER
    Std,    // expect no header but directly the DLT standard header
}

pub struct IpDltMsgReceiver {
    log: slog::Logger,
    pub recv_mode: RecvMode,
    pub interface: InterfaceIndexOrAddress,
    pub addr: SocketAddr,
    recv_method: RecvMethod,
    expected_header: ExpectedHeader,
    storage_header_ecu: DltChar4,
    /// buffer for receiving fragmented messages (e.g. due to payloads > MTU)
    /// use a buffer per sock_addr that we received from (but this would require a socket per sock_addr)
    /// TODO consider different sockets per sock_addr
    /// we use a vec for now as we expect only a few sock_addrs/senders. so a hashmap would be overkill
    /// could sort/bin_search later
    recv_buffer_list: Vec<(SockAddr, Vec<u8>)>,
    recv_buffer: Vec<u8>,
    pub index: DltMessageIndexType,
    buffered_msgs: VecDeque<(DltMessage, SocketAddr)>,
    #[cfg(feature = "pcap")]
    plp_stats: Option<PlpStats>,
    #[cfg(feature = "pcap")]
    fragment_cache: HashMap<Ipv4FragmentKey, Vec<u8>>,
}

impl IpDltMsgReceiver {
    fn new_tcp_client_socket(addr: SocketAddr) -> Result<Socket, std::io::Error> {
        let ip_addr = addr.ip();
        let socket = match ip_addr {
            IpAddr::V4(_) => Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
                .expect("ipv4 tcp socket"),
            IpAddr::V6(_) => {
                let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
                    .expect("ipv6 tcp socket");
                socket.set_only_v6(true)?;
                socket
            }
        };
        socket.set_reuse_address(true).expect("reuse addr error");
        // connect will be done in recv_msg

        // set read timeout
        socket // TODO which timeout to choose?
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("set read timeout error");

        socket
            .set_nonblocking(false)
            .expect("set non-blocking error");

        // set the receive buffer size. dlt-viewer uses 26214400 (400* 65536) bytes
        set_max_buffer_size(&socket, false, 26214400).expect("set recv buffer size error");

        Ok(socket)
    }

    pub fn new(
        log: slog::Logger,
        // stop_receive: std::sync::Arc<std::sync::atomic::AtomicBool>,
        start_index: DltMessageIndexType,
        recv_mode: RecvMode,
        interface: InterfaceIndexOrAddress,
        addr: SocketAddr,
        storage_header_ecu: DltChar4,
    ) -> Result<Self, std::io::Error> {
        let recv_method = match recv_mode {
            RecvMode::Serial(ref params) => {
                let available_interfaces =
                    serial2::SerialPort::available_ports().unwrap_or_else(|_| vec![]);
                info!(
                    log,
                    "Available serial interfaces (#{}):",
                    available_interfaces.len()
                );
                available_interfaces.iter().for_each(|iface| {
                    info!(log, " {:?}", iface);
                });
                let mut serial_port = if params.baudrate == 0 {
                    open_serial_port_from_file(&params.device_name)?
                } else {
                    serial2::SerialPort::open(
                        &params.device_name,
                        |mut settings: serial2::Settings| {
                            settings.set_raw();
                            if params.baudrate > 0 {
                                settings.set_baud_rate(params.baudrate)?;
                            }
                            settings.set_char_size(serial2::CharSize::Bits8);
                            settings.set_parity(serial2::Parity::None);
                            settings.set_stop_bits(serial2::StopBits::One);
                            settings.set_flow_control(serial2::FlowControl::None);
                            Ok(settings)
                        },
                    )
                    .map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!("Failed to open serial port {}: {}", params.device_name, e),
                        )
                    })?
                };
                serial_port.discard_buffers()?;
                serial_port.set_read_timeout(std::time::Duration::from_millis(500))?; // TODO which timeout to choose to get a good accurate timing?
                RecvMethod::Serial(serial_port)
                // panic!("Serial server not implemented yet");
            }
            #[cfg(feature = "pcap")]
            RecvMode::Pcap(PcapParam::InterfaceName(ref interface_name)) => {
                let available_interfaces = pcap::Device::list().unwrap_or_else(|_| vec![]);
                info!(
                    log,
                    "Available interfaces (#{}):",
                    available_interfaces.len()
                );
                available_interfaces.iter().for_each(|iface| {
                    info!(log, " {} - {:?}", iface.name, iface.flags); // addresses?
                });

                let iface = available_interfaces
                    .into_iter()
                    .find(|iface| iface.name == *interface_name);

                if iface.is_none() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Interface {interface_name} not found"),
                    ));
                }
                let iface = iface.unwrap();
                info!(log, "Using interface: {:?}", iface.name);
                let cap = pcap::Capture::from_device(iface).map_err(|e| {
                    std::io::Error::other(format!("Failed to create pcap capture device: {}", e))
                })?;
                let cap = cap.buffer_size(4 * 1024 * 65536).timeout(500).promisc(true);
                RecvMethod::PcapCaptureActive(cap.open().map_err(|e| {
                    std::io::Error::other(format!("Failed to open pcap capture: {}", e))
                })?)
            }
            #[cfg(feature = "pcap")]
            RecvMode::Pcap(PcapParam::File(ref file_name)) => {
                let cap = Capture::from_file(file_name).map_err(|e| {
                    std::io::Error::other(format!("Failed to open pcap file: {}", e))
                })?;
                RecvMethod::PcapCaptureOffline(cap)
            }
            RecvMode::Tcp => {
                let socket = Self::new_tcp_client_socket(addr)?;
                info!(
                    log,
                    "created TCP receiver socket for Recv: {:?}/{:?} with receiver buffer size: {} and read timeout: {:?}",
                    socket.local_addr().map(|s|s.as_socket_ipv4()),
                    socket.local_addr().map(|s|s.as_socket_ipv6()),
                    socket.recv_buffer_size().unwrap_or(0),
                    socket.read_timeout()
                );
                RecvMethod::Recv(socket)
            }
            RecvMode::Udp => {
                // Initialize UDP receiver here if needed
                let ip_addr = addr.ip();
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
                socket
                    .bind(&socket2::SockAddr::from(addr))
                    .expect("bind error");

                // set read timeout
                socket // TODO which timeout to choose?
                    .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                    .expect("set read timeout error");

                socket
                    .set_nonblocking(false)
                    .expect("set non-blocking error");

                // set the receive buffer size. dlt-viewer uses 26214400 (400* 65536) bytes
                set_max_buffer_size(&socket, false, 26214400).expect("set recv buffer size error");
                info!(
                    log,
                    "created UDP receiver socket for RecvFrom: {:?}/{:?} with receiver buffer size: {} and read timeout: {:?}",
                    socket.local_addr().map(|s|s.as_socket_ipv4()),
                    socket.local_addr().map(|s|s.as_socket_ipv6()),
                    socket.recv_buffer_size().unwrap_or(0),
                    socket.read_timeout()
                );
                RecvMethod::RecvFrom(socket)
            }
            RecvMode::UdpMulticast => {
                let ip_addr = addr.ip();
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

                        // 1st bind to the interface address:
                        if let InterfaceIndexOrAddress::Address(if_addr) = interface {
                            let socket_addr =
                                SocketAddr::new(std::net::IpAddr::V4(if_addr), addr.port());
                            socket
                                .bind(&SockAddr::from(socket_addr))
                                .unwrap_or_else(|_| {
                                    panic!("bind multicast error. socket_addr={socket_addr:?}")
                                });
                        } else {
                            // TODO! (test)
                            // if no interface address is given, bind to "any"
                            let any_addr = SocketAddr::new(
                                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                                addr.port(),
                            );
                            socket.bind(&SockAddr::from(any_addr))?;
                        }
                        // 2nd join the multicast group
                        socket
                            .join_multicast_v4_n(mdns_v4, &interface)
                            .expect("join_multicast_v4_n");
                        socket
                    }
                    IpAddr::V6(ref mdns_v6) => match interface {
                        InterfaceIndexOrAddress::Index(index) => {
                            let socket =
                                Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
                                    .expect("ipv6 dgram socket");
                            socket.set_only_v6(true)?;
                            // Bind to [::]:port
                            let any_addr = SocketAddr::new(
                                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                                addr.port(),
                            );
                            socket.bind(&SockAddr::from(any_addr))?;
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

                // set read timeout
                socket // TODO which timeout to choose?
                    .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                    .expect("set read timeout error");

                socket
                    .set_nonblocking(false)
                    .expect("set non-blocking error");

                // set the receive buffer size. dlt-viewer uses 26214400 (400* 65536) bytes
                set_max_buffer_size(&socket, false, 26214400).expect("set recv buffer size error");
                info!(
                    log,
                    "created UDP multicast receiver socket for RecvFrom: {:?}/{:?} with receiver buffer size: {} and read timeout: {:?}",
                    socket.local_addr().map(|s|s.as_socket_ipv4()),
                    socket.local_addr().map(|s|s.as_socket_ipv6()),
                    socket.recv_buffer_size().unwrap_or(0),
                    socket.read_timeout()
                );
                RecvMethod::RecvFrom(socket)
            }
        };

        // so try the max then... (e.g. by looping down the size until it works)
        // hmm. on osx it silently fails and uses the default size of 8388608 bytes

        // allocate a buffer for the socket for receiving messages
        let data = if recv_mode == RecvMode::Tcp {
            Vec::<u8>::with_capacity(100usize * 0xffff) // this is the max len as part of DLTv1 standard header
        } else {
            Vec::<u8>::with_capacity(0x10000) // 64kb, this is the max len as part of DLTv1 standard header and UDP should not concat to more than that size
        };

        let expected_header = match recv_mode {
            RecvMode::Serial(_) => ExpectedHeader::Serial,
            _ => ExpectedHeader::Std,
        };

        Ok(IpDltMsgReceiver {
            log,
            recv_mode,
            interface,
            addr,
            recv_method,
            expected_header,
            storage_header_ecu,
            recv_buffer_list: Vec::with_capacity(256),
            recv_buffer: data,
            index: start_index,
            buffered_msgs: VecDeque::with_capacity(16), // buffer for messages that will be returned on next recv_msg call
            #[cfg(feature = "pcap")]
            plp_stats: None,
            #[cfg(feature = "pcap")]
            fragment_cache: HashMap::new(),
        })
    }

    pub fn recv_msg(&mut self) -> Result<(DltMessage, SocketAddr), std::io::Error> {
        if let Some((msg, addr)) = self.buffered_msgs.pop_front() {
            // if we have buffered messages, return the first one
            //info!(self.log, "recv_msg: returning buffered message: {:?}", msg);
            return Ok((msg, addr));
        }

        let recv_buffer = &mut self.recv_buffer.spare_capacity_mut();

        let (size, src_addr) = match &mut self.recv_method {
            RecvMethod::Serial(ref serial_port) => {
                // debug!(self.log, "recv_msg: receiving message via serial");
                // SAFETY: We're treating MaybeUninit<u8> as u8 for the read operation
                // The serial port will initialize the bytes it writes to
                let buffer_slice = unsafe {
                    std::slice::from_raw_parts_mut(
                        (*recv_buffer).as_mut_ptr() as *mut u8,
                        (*recv_buffer).len(),
                    )
                };
                match serial_port.read(buffer_slice) {
                    Ok(size) => {
                        debug!(self.log, "recv_msg: received {} bytes via serial", size);
                        if size > 0 {
                            // Serial does not provide src_addr, use a dummy addr
                            (size, SockAddr::from(self.addr))
                        } else {
                            info!(
                                self.log,
                                "recv_msg: received zero bytes via Serial, retrying"
                            );
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "Received zero bytes from serial",
                            ));
                        }
                    }
                    Err(e) => {
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::WouldBlock,
                                "No data available to read from serial",
                            ));
                        } else {
                            warn!(
                                self.log,
                                "recv_msg: error receiving message from serial: {} e.kind={}",
                                e,
                                e.kind()
                            );
                            return Err(e);
                        }
                    }
                }
            }
            RecvMethod::Recv(ref mut socket) => {
                // info!(self.log, "recv_msg: receiving message via TCP");
                match socket.recv(recv_buffer) {
                    Ok(size) => {
                        // info!(self.log, "recv_msg: received {} bytes via TCP", size);
                        if size > 0 {
                            // TCP does not provide src_addr, use the bound addr
                            (size, SockAddr::from(self.addr))
                        } else {
                            info!(
                                self.log,
                                "recv_msg: received zero bytes via TCP, shutdown socket"
                            );
                            // size 0 means the other side has closed the connection (called shutdown)
                            // and is now waiting for us to close the socket
                            // we ignore any errors from shutdown here
                            let _ = socket.shutdown(std::net::Shutdown::Both);
                            // TODO in case of an error the old socket is not dropped!
                            *socket = Self::new_tcp_client_socket(self.addr)?;

                            return Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "Received zero bytes, socket closed",
                            ));
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::WouldBlock,
                                "No data available to read",
                            ));
                        } else if e.kind() == std::io::ErrorKind::NotConnected {
                            info!(
                                self.log,
                                "recv_msg: socket not connected, trying to connect"
                            );
                            // connect the socket:
                            match socket.connect(&SockAddr::from(self.addr)) {
                                Ok(_) => {
                                    info!(
                                        self.log,
                                        "recv_msg: socket connected to {:?}", self.addr
                                    );
                                    return self.recv_msg(); // retry receiving after successful connecting
                                }
                                Err(e) => {
                                    std::thread::sleep(std::time::Duration::from_millis(50)); // TODO for test only!
                                    if e.kind() == std::io::ErrorKind::ConnectionRefused {
                                        info!(
                                            self.log,
                                            "recv_msg: connection refused, trying to reconnect"
                                        );
                                        *socket = Self::new_tcp_client_socket(self.addr)?;
                                    } else {
                                        info!(
                                            self.log,
                                            "recv_msg: error connecting socket: {} e.kind={}",
                                            e,
                                            e.kind()
                                        );
                                    }
                                    return Err(e);
                                }
                            }
                        } else {
                            warn!(
                                self.log,
                                "recv_msg: error receiving message: {} e.kind={}",
                                e,
                                e.kind()
                            );
                            std::thread::sleep(std::time::Duration::from_millis(50)); // TODO for test only!
                            return Err(e);
                        }
                    }
                }
            }
            RecvMethod::RecvFrom(ref socket) => {
                // info!(self.log, "recv_msg: receiving message via UDP");
                socket.recv_from(recv_buffer)?
            }
            #[cfg(feature = "pcap")]
            RecvMethod::PcapCaptureOffline(cap) => {
                match cap.next_packet() {
                    Ok(pkt) => {
                        match IpDltMsgReceiver::get_dlt_from_pcap_packet(
                            &self.log,
                            recv_buffer,
                            &pkt,
                            &mut self.fragment_cache,
                            &mut self.plp_stats,
                        ) {
                            Some(value) => value,
                            None => {
                                return Err(std::io::Error::other("Failed to get DLT from packet"))
                            }
                        }
                    }
                    Err(pcap::Error::NoMorePackets) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound, // used to indicate end of file
                            "No more packets in pcap file",
                        ));
                    }
                    Err(e) => {
                        return Err(std::io::Error::other(format!(
                            "Error reading packet from pcap: {}",
                            e
                        )));
                    }
                }
            }
            #[cfg(feature = "pcap")]
            RecvMethod::PcapCaptureActive(cap) => {
                match cap.next_packet() {
                    Ok(pkt) => {
                        match IpDltMsgReceiver::get_dlt_from_pcap_packet(
                            &self.log,
                            recv_buffer,
                            &pkt,
                            &mut self.fragment_cache,
                            &mut self.plp_stats,
                        ) {
                            Some(value) => value,
                            None => {
                                return Err(std::io::Error::other("Failed to get DLT from packet"))
                            }
                        }
                    }
                    Err(pcap::Error::NoMorePackets) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound, // used to indicate end of file
                            "No more packets in pcap file",
                        ));
                    }
                    Err(e) => {
                        return Err(std::io::Error::other(format!(
                            "Error reading packet from pcap: {}",
                            e
                        )));
                    }
                }
            }
        };

        if size == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Received zero bytes", // not expected for DLT messages
            ));
        }

        // do we have a fragmented messages for this src_addr?
        // Check if we have a buffer for this src_addr
        let src_addr_buffer = if let Some((_, existing_buffer)) = self
            .recv_buffer_list
            .iter_mut()
            .find(|(addr, _)| addr == &src_addr)
        {
            existing_buffer // .extend_from_slice(&recv_buffer[..size]);
        } else {
            // No existing buffer, create a new one
            let data = Vec::<u8>::with_capacity(u16::MAX.into()); // this is the max len as part of DLTv1 standard header
            self.recv_buffer_list.push((src_addr.clone(), data));
            &mut self.recv_buffer_list.last_mut().unwrap().1
        };

        // Safety: `recv_from` guarantees that `size` bytes are initialized in the buffer.
        // We are upholding the safety contract to only view these initialized bytes as `&[u8]`.

        let recvd_data = unsafe {
            // This creates a `&[u8]` slice from the `&[MaybeUninit<u8>]` slice.
            // It's safe because u8 and MaybeUninit<u8> have the same layout,
            // and we trust `recv_from` to have initialized these `size` bytes.
            std::slice::from_raw_parts(recv_buffer.as_ptr() as *const u8, size)
        };

        let data: &[u8] = if src_addr_buffer.is_empty() {
            recvd_data // no need to copy here, we do this only later if this is a start of a fragmented message
        } else {
            // If we have an existing buffer, extend it with the new data
            // TODO check that it's still <= u16::MAX (might be larger with tcp but not larger than 2x u16::MAX)
            // TODO add heuristic to check whether the newly recved data is a new msg (e.g. dlt v1 header pattern)
            src_addr_buffer.extend(recvd_data);
            &src_addr_buffer[..]
        };

        // Parse the DltMessage(s) from the buffer
        let data_len = data.len();

        let mut msg_to_ret = None;
        let mut did_consume = 0;
        loop {
            let rem_data = &data[did_consume..];
            match match self.expected_header {
                ExpectedHeader::Std => {
                    parse_dlt_with_std_header(rem_data, self.index, self.storage_header_ecu)
                }
                ExpectedHeader::Serial => parse_dlt_with_serial_header(
                    self.index,
                    rem_data,
                    self.storage_header_ecu,
                    true,
                ),
            } {
                Ok((to_consume, msg)) => {
                    debug_assert_eq!(
                        match self.expected_header {
                            ExpectedHeader::Std => msg.standard_header.len as usize,
                            ExpectedHeader::Serial => {
                                (msg.standard_header.len as usize) + DLT_SERIAL_HEADER_SIZE
                            }
                        },
                        to_consume,
                        "The DLT message length should match the consumed data length"
                    );
                    self.index += 1; // increment index for next message
                    did_consume += to_consume;
                    if msg_to_ret.is_none() {
                        msg_to_ret = Some(msg);
                    } else {
                        self.buffered_msgs
                            .push_back((msg, src_addr.as_socket().unwrap()));
                    }
                }
                Err(Error {
                    kind: ErrorKind::NotEnoughData(_missing),
                }) => {
                    break;
                }
                Err(e) => {
                    warn!(
                        self.log,
                        "recv_msg: error parsing DLT message: {} at index {} rem_data.len={}",
                        e,
                        self.index,
                        rem_data.len()
                    );

                    // now we prune data from start of the buffer to the first byte that could be a valid DLT standard header:
                    // we check at least the first byte to be htyp with DLT version 1 or 2

                    // remove from src_addr_buffer until we find a byte with 0x1<<5 or 0x2<<5 being set:
                    let idx_first_pos_header = match self.expected_header {
                        ExpectedHeader::Std => rem_data[1..]
                            .iter()
                            .position(|&b| (((b >> 5) & 0x07) == 1) || (((b >> 5) & 0x07) == 2)),
                        ExpectedHeader::Serial => first_idx_of_serial_pattern(&rem_data[1..]),
                    };
                    if let Some(idx) = idx_first_pos_header {
                        warn!(
                            self.log,
                            "recv_msg: found next possible header start at idx={idx}",
                        );
                        did_consume += 1 + idx;
                    } else {
                        warn!(
                            self.log,
                            "recv_msg: found no possible header start. draining {} bytes",
                            rem_data.len()
                        );
                        did_consume += rem_data.len();
                    }
                }
            }
            if did_consume >= data_len {
                break;
            }
        }
        if did_consume < data_len {
            if src_addr_buffer.is_empty() {
                src_addr_buffer.extend_from_slice(&recvd_data[did_consume..]);
            } else {
                debug_assert!(did_consume <= src_addr_buffer.len());
                let max_to_consume = std::cmp::min(did_consume, src_addr_buffer.len());
                src_addr_buffer.drain(..max_to_consume);
            }
        } else {
            src_addr_buffer.clear();
        }
        if let Some(msg) = msg_to_ret {
            Ok((msg, src_addr.as_socket().unwrap()))
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not enough data",
            ))
        }
    }

    #[cfg(feature = "pcap")]
    fn get_udp_from_ethernet_packet<'a>(
        log: &slog::Logger,
        ethernet_packet: &'a EthernetPacket,
        fragment_cache: &mut HashMap<Ipv4FragmentKey, Vec<u8>>,
    ) -> Option<(Ipv4Addr, UdpPacketRef<'a>)> {
        match ethernet_packet.get_ethertype().0 {
            0x0800 => {
                // Calculate IPv4 header length to find the UDP payload offset
                let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
                if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                    let addr = ipv4_packet.get_source();
                    let min = Ipv4Packet::minimum_packet_size();
                    // fragmented packet?
                    let is_fragmented = ipv4_packet.get_flags() & 0x1 != 0 || ipv4_packet.get_fragment_offset() != 0;
                    if is_fragmented {
                        let payload = IpDltMsgReceiver::handle_fragmented_ipv4_packet(log, &ipv4_packet, fragment_cache)?;
                        let udp_owned = UdpPacketOwned::new(payload)?;
                        Some((addr, UdpPacketRef::Owned(udp_owned)))
                    } else {
                        // Get the IPv4 header length to calculate offset
                        let max = ipv4_packet.packet().len();
                        let header_length = match ipv4_packet.get_header_length() as usize * 4 {
                            length if length < min => min,
                            length if length > max => max,
                            length => length,
                        };
                        let payload_len = (ipv4_packet.get_total_length() as usize).saturating_sub(header_length);
                        // Use the offset to get UDP payload directly from ethernet_packet's payload
                        UdpPacket::new(&ethernet_packet.payload()[header_length..header_length + payload_len]).map(|udp| (addr, UdpPacketRef::Borrowed(udp)))
                    }
                } else {
                    None
                }
            }
            0x8100 /* VLAN */ => {
                // Handle VLAN tagged packets
                let vlan_packet = VlanPacket::new(ethernet_packet.payload())?;
                if vlan_packet.get_ethertype().0 == 0x0800 { // todo handle another level of vlan?
                    let vlan_header_length = VlanPacket::minimum_packet_size();
                    let ipv4_packet = Ipv4Packet::new(vlan_packet.payload())?;
                    if ((ipv4_packet.get_total_length() as usize)+4).max(50) < vlan_packet.payload().len() || ipv4_packet.get_total_length() as usize > vlan_packet.payload().len() {
                        warn!(log, "get_udp_from_ethernet_packet: IPv4 total length {} does not match VLAN payload length {}, {:?}", ipv4_packet.get_total_length(), vlan_packet.payload().len(), ipv4_packet);
                        //panic!("get_udp_from_ethernet_packet: IPv4 total length {} does not match VLAN payload length {}", ipv4_packet.get_total_length(), vlan_packet.payload().len());
                    }
                    if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                        let addr = ipv4_packet.get_source();
                        let min = Ipv4Packet::minimum_packet_size();
                        // fragmented packet?
                        let is_fragmented = ipv4_packet.get_flags() & 0x1 != 0 || ipv4_packet.get_fragment_offset() != 0;
                        if is_fragmented {
                            let payload = IpDltMsgReceiver::handle_fragmented_ipv4_packet(log, &ipv4_packet, fragment_cache)?;
                            let udp_owned = UdpPacketOwned::new(payload)?;
                            Some((addr, UdpPacketRef::Owned(udp_owned)))
                        }else{
                            // Get the IPv4 header length to calculate offset
                            let max = ipv4_packet.packet().len();
                            let header_length = match ipv4_packet.get_header_length() as usize * 4 {
                                length if length < min => min,
                                length if length > max => max,
                                length => length,
                            };
                            let payload_len = (ipv4_packet.get_total_length() as usize).saturating_sub(header_length);
                            // Use the offset to get UDP payload directly from vlan_packet's payload
                            UdpPacket::new(&ethernet_packet.payload()[vlan_header_length + header_length..vlan_header_length + header_length + payload_len]).map(|udp| (addr, UdpPacketRef::Borrowed(udp)))
                        }
                    } else {
                        None
                    }
                } else if vlan_packet.get_ethertype().0 == 0x8100 {
                       let vlan_packet = VlanPacket::new(vlan_packet.payload())?;
                        if vlan_packet.get_ethertype().0 == 0x0800 { // handle another level of vlan
                            let ipv4_packet = Ipv4Packet::new(vlan_packet.payload())?;
                            if ((ipv4_packet.get_total_length() as usize)+4).max(50) < vlan_packet.payload().len() || ipv4_packet.get_total_length() as usize > vlan_packet.payload().len() {
                                warn!(log, "get_udp_from_ethernet_packet: IPv4 total length {} does not match VLAN payload length {}, {:?}", ipv4_packet.get_total_length(), vlan_packet.payload().len(), ipv4_packet);
                            }
                            if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                                let addr = ipv4_packet.get_source();
                                let min = Ipv4Packet::minimum_packet_size();
                                // fragmented packet?
                                let is_fragmented = ipv4_packet.get_flags() & 0x1 != 0 || ipv4_packet.get_fragment_offset() != 0;
                                if is_fragmented {
                                    let payload = IpDltMsgReceiver::handle_fragmented_ipv4_packet(log, &ipv4_packet, fragment_cache)?;
                                    let udp_owned = UdpPacketOwned::new(payload)?;
                                    Some((addr, UdpPacketRef::Owned(udp_owned)))
                                } else {
                                    // Get the IPv4 header length to calculate offset
                                    let max = ipv4_packet.packet().len();
                                    let header_length = match ipv4_packet.get_header_length() as usize * 4 {
                                        length if length < min => min,
                                        length if length > max => max,
                                        length => length,
                                    };
                                    let payload_len = (ipv4_packet.get_total_length() as usize).saturating_sub(header_length);
                                    // Use the offset to get UDP payload directly from vlan_packet's payload
                                    let wd_offset = VlanPacket::minimum_packet_size() + VlanPacket::minimum_packet_size() + header_length;
                                    UdpPacket::new(&ethernet_packet.payload()[wd_offset..wd_offset + payload_len]).map(|udp| (addr, UdpPacketRef::Borrowed(udp)))
                                }
                            } else {
                                None
                            }
                        } else {
                            // different ethertype -> ignoring
                            warn!(log, "get_udp_from_ethernet_packet: ignoring double VLAN tagged packet, {vlan_packet:?}");
                            None
                        }
                    }else{
                        None
                    }
            }
            _ => None,
        }
    }

    #[cfg(feature = "pcap")]
    fn handle_fragmented_ipv4_packet(
        log: &slog::Logger,
        ipv4_packet: &Ipv4Packet,
        fragment_cache: &mut HashMap<Ipv4FragmentKey, Vec<u8>>,
    ) -> Option<Vec<u8>> {
        let is_fragmented =
            ipv4_packet.get_flags() & 0x1 != 0 || ipv4_packet.get_fragment_offset() != 0;
        let is_last_fragment = is_fragmented && ipv4_packet.get_flags() & 0x1 == 0;

        assert!(is_fragmented);

        let cache_key: Ipv4FragmentKey = (
            ipv4_packet.get_source(),
            ipv4_packet.get_destination(),
            ipv4_packet.get_next_level_protocol(),
            ipv4_packet.get_identification(),
        );

        if is_last_fragment {
            // check whether we have the remaining payload:
            if let Some(mut existing_payload) = fragment_cache.remove(&cache_key) {
                // append the current payload
                existing_payload.extend_from_slice(ipv4_packet.payload());
                Some(existing_payload)
            } else {
                warn!(
                    log,
                    "handle_fragmented_ipv4_packet: received last fragment but no existing fragments found: {:?}",
                    ipv4_packet
                );
                None
            }
        } else {
            // we assume the fragments come in order! this is not according to the spec! (todo!)
            let entry = fragment_cache.entry(cache_key).or_default();
            if entry.len() != ipv4_packet.get_fragment_offset() as usize * 8 {
                // if it's the first packet we can keep the new one...
                if ipv4_packet.get_fragment_offset() == 0 {
                    debug!(
                        log,
                        "handle_fragmented_ipv4_packet: fragment offset mismatch on first fragment, expected {}, got {}, replacing fragment: {:?}",
                        entry.len(),
                        ipv4_packet.get_fragment_offset() as usize * 8,
                        ipv4_packet
                    );
                    entry.clear();
                    entry.extend_from_slice(ipv4_packet.payload());
                    return None;
                }

                warn!(
                    log,
                    "handle_fragmented_ipv4_packet: fragment offset mismatch, expected {}, got {}, ignoring fragment: {:?}",
                    entry.len(),
                    ipv4_packet.get_fragment_offset() as usize * 8,
                    ipv4_packet
                );
                // delete the existing entry as it's invalid now
                fragment_cache.remove(&cache_key);
                return None;
            }
            entry.extend_from_slice(ipv4_packet.payload());
            None
        }
    }

    #[cfg(feature = "pcap")]
    fn get_dlt_from_pcap_packet(
        log: &slog::Logger,
        recv_buffer: &mut &mut [std::mem::MaybeUninit<u8>],
        packet: &pcap::Packet, // rx: &mut Box<dyn DataLinkReceiver>,
        fragment_cache: &mut HashMap<Ipv4FragmentKey, Vec<u8>>,
        plp_stats: &mut Option<PlpStats>,
    ) -> Option<(usize, SockAddr)> {
        let packet = packet.data;
        let ethernet_packet = EthernetPacket::new(packet).unwrap();
        // info!(
        //     log,
        //     "recv_msg: received ethernet_packet with ethertype: {}",
        //     ethernet_packet.get_ethertype()
        // );
        match ethernet_packet.get_ethertype().0 {
            0x2090 /* PLP */| 0x99fe /* TECMP / ASAM CMP */ => {
                if let Some(plp_packet)=PlpPacket::new(ethernet_packet.payload()) {
                    // verify that counter is consecutive, warn on gaps
                    let counter = plp_packet.get_counter();
                    if let Some(ref mut plp_stats)=plp_stats {
                        plp_stats.nr_packets += 1;
                        let expected = plp_stats.last_plp_counter.wrapping_add(1);
                        if counter != expected {
                            let nr_lost = counter.wrapping_sub(expected);
                            plp_stats.packets_lost += nr_lost as u64;
                            let packet_timestamp = plp_packet.get_timestamp();
                            if packet_timestamp.saturating_sub(plp_stats.last_dump_time) > 1_000_000_000 {
                                plp_stats.last_dump_time = packet_timestamp;
                                let timestamp_secs = (packet_timestamp- plp_stats.start_time)/1_000_000_000;
                                let lost_per_sec = plp_stats.packets_lost
                                    / timestamp_secs.max(1);
                                warn!(log, "recv_msg: PLP packet counter gap: expected {}, got {}, lost: {}, total_lost: {}/{}s/{}, lost_per_sec: {}", expected, counter, nr_lost, plp_stats.packets_lost, timestamp_secs, plp_stats.nr_packets,lost_per_sec);
                            }
                        }
                        plp_stats.last_plp_counter = counter;
                    } else {
                        *plp_stats = Some(PlpStats{
                            last_plp_counter: counter,
                            start_time: plp_packet.get_timestamp(),
                            nr_packets:1,
                            packets_lost:0,
                            last_dump_time:0
                        });
                    }
                    if ethernet_packet.payload().len() != plp_packet.get_length() as usize + 28 {
                        // this would indicate that we cannot trust the length field?
                        warn!(log, "recv_msg: PLP length field {} does not match actual payload length {}", plp_packet.get_length(), ethernet_packet.payload().len());
                    }

                    // logging, ethernet frames?
                    if plp_packet.get_plp_type() == 0x03 &&  plp_packet.get_msg_type() == 0x80 {
                        // todo verify length? and check for another data packet following?
                        let ethernet_packet =EthernetPacket::new(plp_packet.payload()).unwrap();

                        //warn!(log, "recv_msg: got PLP ethernet packet {:?}, ethertype: {}:{:x}", plp_packet, ethernet_packet.get_ethertype(), ethernet_packet.get_ethertype().0);
                        if let Some((addr, udp_packet))=IpDltMsgReceiver::get_udp_from_ethernet_packet(log, &ethernet_packet, fragment_cache){
                            if udp_packet.get_destination() != 3490 {
                                // warn!(log, "recv_msg: ignoring UDP PLP ethernet packet not for port 3490: {:?}", udp_packet);
                                return None;
                            }
                            let payload = udp_packet.payload();
                            let len = payload.len().min(recv_buffer.len());
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    payload.as_ptr(),
                                    recv_buffer.as_mut_ptr() as *mut u8,
                                    len,
                                );
                            }
                            // todo use timestamp (except upper two bits) from plp packet
                            return Some((
                                len,
                                SockAddr::from(SocketAddrV4::new(addr, 3490)),
                            ));
                        } else{
                            match ethernet_packet.get_ethertype().0 {
                                0x88e5 /*macsec */ | 0x86dd /*ipv6 */ | 0x22f0 /* avb */ | 0x0800 /* ipv4 */ | 0x88f7 /* Ptp */ | 0x8100 /* vlan */ | 0x888e /* 802.1x frames? */ | 0x9101 /* ?? */=> {},
                                _ => {
                                    warn!(log, "recv_msg: ignoring non-udp/dlt PLP ethernet packet with ethertype: {} {:x} {:?}", ethernet_packet.get_ethertype(), ethernet_packet.get_ethertype().0, ethernet_packet);
                                }
                            }
                        }
                    }else{
                        match plp_packet.get_plp_type() {
                            0x00 => { /* ctrl message? */ }
                            0x01 => {
                                // status device
                            }
                            0x02 => {
                                // status bus
                            }
                            0x04 => {
                                // status config
                            }
                            _ => {
                                warn!(log, "recv_msg: ignoring PLP unknown type packet: {:?}", plp_packet);
                            }
                        }
                    }
                } else {
                    warn!(log, "recv_msg: ignoring invalid PLP packet: {:?}", ethernet_packet);
                }
            }
            // support ipv4/udp packets on port 3490 as well:
            _ => {
                if let Some((addr, udp_packet))=IpDltMsgReceiver::get_udp_from_ethernet_packet(log, &ethernet_packet, fragment_cache){
                    if udp_packet.get_destination() != 3490 {
                        // warn!(log, "recv_msg: ignoring UDP PLP ethernet packet not for port 3490: {:?}", udp_packet);
                        return None;
                    }
                    let payload = udp_packet.payload();
                    let len = payload.len().min(recv_buffer.len());
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            payload.as_ptr(),
                            recv_buffer.as_mut_ptr() as *mut u8,
                            len,
                        );
                    }
                    return Some((
                        len,
                        SockAddr::from(SocketAddrV4::new(addr, 3490)),
                    ));
                }else{
                    // this is not correct if we had a fragmented ipv4 packet! So removing the log for now.
                    /*debug!(
                        log,
                        "recv_msg: ignoring non-ip packet with ethertype: {} {:x} {:?}",
                        ethernet_packet.get_ethertype(), ethernet_packet.get_ethertype().0, ethernet_packet
                    );*/
                }
            }
        };
        None
    }
}

impl Drop for IpDltMsgReceiver {
    fn drop(&mut self) {
        match &mut self.recv_method {
            RecvMethod::Recv(ref socket) | RecvMethod::RecvFrom(ref socket) => {
                if self.recv_mode == RecvMode::UdpMulticast {
                    // Clean up UDP multicast receiver
                    match self.addr.ip() {
                        IpAddr::V4(ref mdns_v4) => {
                            socket
                                .leave_multicast_v4_n(mdns_v4, &self.interface)
                                .expect("leave_multicast_v4_n");
                        }
                        IpAddr::V6(ref mdns_v6) => {
                            if let socket2::InterfaceIndexOrAddress::Index(idx) = self.interface {
                                socket
                                    .leave_multicast_v6(mdns_v6, idx)
                                    .expect("leave_multicast_v6");
                            };
                        }
                    }
                }

                info!(
                    self.log,
                    "Dropping receiver socket: {:?} recv_mode: {:?}", socket, self.recv_mode
                );
            }
            RecvMethod::Serial(serial_port) => {
                info!(self.log, "Closing serial port: {:?}", serial_port);
            }
            #[cfg(feature = "pcap")]
            RecvMethod::PcapCaptureOffline(_) => {
                info!(self.log, "Dropping PCAP file");
            }
            #[cfg(feature = "pcap")]
            RecvMethod::PcapCaptureActive(ref mut cap) => {
                let stats = cap.stats();
                warn!(self.log, "Dropping PCAP capture: {:?}", stats);
            }
        }
    }
}

impl Iterator for IpDltMsgReceiver {
    type Item = (DltMessage, SocketAddr);
    fn next(&mut self) -> Option<Self::Item> {
        /*if let Some(msg) = self.receiver.recv().ok() {
          Some(msg)
        } else {*/
        None
        //}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlt::DltStandardHeader;
    #[cfg(not(windows))]
    use crate::dlt::{DLT_SERIAL_HEADER_PATTERN, DLT_SERIAL_HEADER_SIZE};
    use crate::dlt_args;
    use portpicker::pick_unused_port;
    use slog::{o, Drain, Logger};
    use std::io::IoSlice;
    use std::net::Ipv4Addr;
    #[cfg(not(windows))]
    use std::os::fd::{AsRawFd, FromRawFd};

    fn new_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, o!())
    }

    #[cfg(not(windows))]
    fn get_test_msg(arg: u32) -> (Vec<u8>, Vec<u8>) {
        let (noar, payload) = dlt_args!(arg).unwrap();
        let msg = DltMessage::get_testmsg_with_payload(cfg!(target_endian = "big"), noar, &payload);
        let mut buf = Vec::with_capacity(u16::MAX as usize);
        let mut buf_writer = std::io::Cursor::new(&mut buf);
        DltStandardHeader::to_write(
            &mut buf_writer,
            &msg.standard_header,
            &msg.extended_header,
            Some(msg.ecu),
            None,              // session_id = None, todo
            Some(noar as u32), // use message count as timestamp
            &payload,
        )
        .expect("Failed to write DLT message");
        (buf, payload)
    }

    // MARK: serial tests
    #[cfg(not(windows))] // the pipe is blocking (not supporting the timeout) on windows
    #[test]
    fn serial_recv_simple_dls_msg() {
        let logger = new_logger();
        // create a pipe and use the read end as serial port for the receiver
        let (read_end, mut write_end) = std::io::pipe().expect("create pipe");
        let read_end = std::mem::ManuallyDrop::new(read_end);
        let read_fd = read_end.as_raw_fd();

        let mut receiver = IpDltMsgReceiver {
            log: logger.clone(),
            recv_mode: RecvMode::Serial(SerialParams {
                device_name: "test".to_string(),
                baudrate: 0,
            }),
            recv_method: RecvMethod::Serial(unsafe { serial2::SerialPort::from_raw_fd(read_fd) }),
            expected_header: ExpectedHeader::Serial,
            interface: InterfaceIndexOrAddress::Index(0),
            addr: SocketAddr::new("127.0.0.1".parse().unwrap(), 0),
            recv_buffer: Vec::with_capacity(65536),
            storage_header_ecu: DltChar4::from_buf(b"EcuS"),
            buffered_msgs: std::collections::VecDeque::new(),
            recv_buffer_list: Vec::new(),
            #[cfg(feature = "pcap")]
            plp_stats: None,
            #[cfg(feature = "pcap")]
            fragment_cache: HashMap::new(),
            index: 0,
        };

        // 1. check default timeout:
        let r = receiver.recv_msg();
        assert!(r.is_err());
        assert_eq!(r.err().unwrap().kind(), std::io::ErrorKind::WouldBlock);

        // 2. write a simple valid DLT message with serial header:
        let (buf, payload) = get_test_msg(0);
        let dls_bytes = DLT_SERIAL_HEADER_PATTERN.to_le_bytes();
        let dls = std::io::IoSlice::new(&dls_bytes);
        use std::io::Write;
        let n = write_end
            .write_vectored(&mut [dls, std::io::IoSlice::new(&buf)])
            .expect("write to serial pipe");
        assert_eq!(n, DLT_SERIAL_HEADER_SIZE + buf.len());
        // now receive the message:
        let r = receiver.recv_msg();
        assert!(r.is_ok());
        let (rcvd_msg, _src_addr) = r.unwrap();
        assert_eq!(rcvd_msg.payload, payload);
        assert_eq!(rcvd_msg.ecu, DltChar4::from_buf(b"ECU1")); // the msg ext header contains "ECU1"
                                                               // 3. write a partial DLS message and then a complete one and expect the 2nd complete one to be received:
        let (buf, _payload) = get_test_msg(1);
        for partial_len in 1..buf.len() {
            let n = write_end
                .write_vectored(&mut [dls, std::io::IoSlice::new(&buf[..partial_len])])
                .expect("write partial to serial pipe");
            assert_eq!(n, DLT_SERIAL_HEADER_SIZE + partial_len);
            // now write a complete message:
            let (buf2, payload2) = get_test_msg(2);
            let n = write_end
                .write_vectored(&mut [dls, std::io::IoSlice::new(&buf2)])
                .expect("write complete to serial pipe");
            assert_eq!(n, DLT_SERIAL_HEADER_SIZE + buf2.len());
            // now receive the message:
            let r = receiver.recv_msg();
            assert!(r.is_ok());
            let (rcvd_msg, _src_addr) = r.unwrap();
            assert_eq!(rcvd_msg.payload, payload2);
            assert_eq!(rcvd_msg.ecu, DltChar4::from_buf(b"ECU1")); // the msg ext header contains "ECU1"
        }
    }

    #[cfg(not(windows))] // the pipe is blocking (not supporting the timeout) on windows
    #[test]
    fn serial_recv_real_example() {
        let logger = new_logger();
        // create a pipe and use the read end as serial port for the receiver
        let (read_end, mut write_end) = std::io::pipe().expect("create pipe");
        let read_end = std::mem::ManuallyDrop::new(read_end);
        let read_fd = read_end.as_raw_fd();

        let mut receiver = IpDltMsgReceiver {
            log: logger.clone(),
            recv_mode: RecvMode::Serial(SerialParams {
                device_name: "test".to_string(),
                baudrate: 0,
            }),
            recv_method: RecvMethod::Serial(unsafe { serial2::SerialPort::from_raw_fd(read_fd) }),
            expected_header: ExpectedHeader::Serial,
            interface: InterfaceIndexOrAddress::Index(0),
            addr: SocketAddr::new("127.0.0.1".parse().unwrap(), 0),
            recv_buffer: Vec::with_capacity(65536),
            storage_header_ecu: DltChar4::from_buf(b"EcuS"),
            buffered_msgs: std::collections::VecDeque::new(),
            recv_buffer_list: Vec::new(),
            #[cfg(feature = "pcap")]
            plp_stats: None,
            #[cfg(feature = "pcap")]
            fragment_cache: HashMap::new(),
            index: 0,
        };
        // example serial dlt capture with messages with mcnt 173..201 (and two leading bytes before the first msg)
        let hex = "0000444c530130ad001000a7fa083528000008000803444c530130ae001000a7faa83528000008030800444c530130af001000a7fc883528000008000802444c530130b0001000a7fe683528000008020709444c530130b1001000a7ff58c227000002100000444c530130b2001000a7ff58a62700004e000000444c530130b3001000a7ffa83528000007090801444c530130b4001000a8000c042b000032008700444c530130b5001000a8000c192b00001e000d00444c530130b6001000a8000c932a000001000000444c530130b7001000a8000c942a000001010000444c530130b8001000a8000c9c2a000000000100444c530130b9001000a800483528000008010800444c530130ba001000a800e83528000008000802444c530130bb001000a801883528000008020800444c530130bc001000a803683528000008000802444c530130bd001000a804083528000008020709444c530130be001000a804a83528000007090801444c530130bf001000a806883528000008010800444c530130c0001000a807283528000008000802444c530130c1001000a807c83528000008020800444c530130c2001000a808683528000008000802444c530130c3001000a809083528000008020800444c530130c4001000a80c824c2b00000dce9500444c530130c5002200a80c824d2b00001400476974205348413a203432333032323334623000444c530130c6001000a80c8c7129000019000000444c530130c7001000a80c8c6929000088130000444c530130c8001000a80cc83528000008000801444c530130c9001000a80e083528000008010800";
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex"))
            .collect();
        use std::io::Write;
        write_end
            .write_all(&bytes)
            .expect("write real example to serial pipe");

        for mcnt in 173..=201 {
            let (rcvd_msg, _src_addr) = receiver.recv_msg().expect(&format!("msg mcnt={}", mcnt));
            assert_eq!(rcvd_msg.mcnt(), mcnt, "Received msg: {:?}", rcvd_msg);
        }
        let r = receiver.recv_msg();
        assert!(r.is_err(), "Expecting no more messages, got: {:?}", r);
    }

    /// MARK: UDP tests
    #[test]
    fn test_create_send_socket_udp() {
        let port = pick_unused_port().expect("no ports free");
        let interface = InterfaceIndexOrAddress::Address("127.0.0.1".parse().unwrap());
        let socket = create_send_socket(
            RecvMode::Udp,
            SocketAddr::new("127.0.0.1".parse().unwrap(), port),
            interface,
        );
        assert!(socket.is_ok());
        drop(socket);

        let interface = InterfaceIndexOrAddress::Address("127.0.0.1".parse().unwrap());
        let socket = create_send_socket(
            RecvMode::UdpMulticast,
            SocketAddr::new("127.0.0.1".parse().unwrap(), port),
            interface,
        );
        assert!(socket.is_err());

        let interface = InterfaceIndexOrAddress::Address("127.0.0.1".parse().unwrap());
        let socket = create_send_socket(
            RecvMode::UdpMulticast,
            SocketAddr::new("224.0.0.1".parse().unwrap(), port),
            interface,
        );
        assert!(socket.is_ok());
        drop(socket);

        let interface = InterfaceIndexOrAddress::Address("127.0.0.1".parse().unwrap());
        let socket = create_send_socket(
            RecvMode::Udp,
            SocketAddr::new("224.0.0.1".parse().unwrap(), port),
            interface,
        );
        assert!(socket.is_err());
    }

    #[test]
    fn test_ip_dlt_msg_receiver_creation_udp_m() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), 12345);
        let interface = InterfaceIndexOrAddress::Address("127.0.0.1".parse().unwrap());
        let receiver = IpDltMsgReceiver::new(
            new_logger(),
            42,
            RecvMode::UdpMulticast,
            interface,
            addr,
            DltChar4::from_buf(b"EcuU"),
        );
        assert!(receiver.is_ok());
    }

    #[test]
    fn test_ip_dlt_msg_receiver_creation_udp() {
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), 12345);
        let interface = InterfaceIndexOrAddress::Address("127.0.0.1".parse().unwrap());
        let receiver = IpDltMsgReceiver::new(
            new_logger(),
            42,
            RecvMode::Udp,
            interface,
            addr,
            DltChar4::from_buf(b"EcuU"),
        );
        assert!(receiver.is_ok());
    }

    #[test]
    fn test_fragmented_udp_recv() {
        let port = pick_unused_port().expect("no ports free");
        let logger = new_logger();
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        let interface = InterfaceIndexOrAddress::Address("127.0.0.1".parse().unwrap());
        let receiver = IpDltMsgReceiver::new(
            logger.clone(),
            1,
            RecvMode::Udp,
            interface,
            addr,
            DltChar4::from_buf(b"EcuU"),
        );
        let mut receiver = receiver.unwrap();
        std::thread::scope(|s| {
            let stop_receive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop_receive_r = stop_receive.clone();

            let r = s.spawn(move || {
                let stop_receive = stop_receive_r;
                let mut rcvd_nr_msgs = 0;
                while !stop_receive.load(std::sync::atomic::Ordering::SeqCst) {
                    let result = receiver.recv_msg();
                    if let Ok((msg, src_addr)) = &result {
                        println!("Received message: {:?} from {:?}", msg, src_addr);
                        rcvd_nr_msgs += 1;
                    }
                    println!("No message received, got error: {:?}", result.err());
                }
                rcvd_nr_msgs
            });

            // send a test msg to the udp port:
            let send_addr = std::net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port).into();
            let socket = create_send_socket(
                RecvMode::Udp,
                send_addr,
                socket2::InterfaceIndexOrAddress::Index(0),
            )
            .unwrap();
            let send_to_addr = SockAddr::from(send_addr);
            let mut nr_msgs_sent = 0usize;
            let (noar, payload) = dlt_args!(nr_msgs_sent).unwrap();
            let msg =
                DltMessage::get_testmsg_with_payload(cfg!(target_endian = "big"), noar, &payload);

            let mut buf = Vec::with_capacity(u16::MAX as usize);
            let mut buf_writer = std::io::Cursor::new(&mut buf);
            DltStandardHeader::to_write(
                &mut buf_writer,
                &msg.standard_header,
                &msg.extended_header,
                Some(msg.ecu),
                None,                      // session_id = None, todo
                Some(nr_msgs_sent as u32), // use message count as timestamp
                &payload,
            )
            .expect("Failed to write DLT message: {e}");

            // let full_msg_len = buf_writer.position() as usize;
            let buf = buf_writer.into_inner();

            // two concacted full msgs and the first byte of 3rd msg
            socket
                .send_to_vectored(
                    &[
                        IoSlice::new(&buf[..]),
                        IoSlice::new(&buf[..]),
                        IoSlice::new(&buf[0..1]),
                    ],
                    &send_to_addr,
                )
                .unwrap();
            info!(
                logger,
                "Sent message to {:?}",
                send_to_addr.as_socket_ipv4(),
            );
            nr_msgs_sent += 2;

            // rest of the 3rd msg and start of 4th fragmented
            let buf_len = buf.len();
            socket
                .send_to_vectored(
                    &[IoSlice::new(&buf[1..]), IoSlice::new(&buf[0..buf_len - 1])],
                    &send_to_addr,
                )
                .unwrap();
            info!(
                logger,
                "Sent fragmented message to {:?}",
                send_to_addr.as_socket_ipv4(),
            );
            nr_msgs_sent += 1;
            // rest of 4th msg fragmented: (this is weird for udp, but we test it anyway)
            socket.send_to(&buf[buf_len - 1..], &send_to_addr).unwrap();
            info!(
                logger,
                "Sent 2nd fragmented message to {:?}",
                send_to_addr.as_socket_ipv4(),
            );
            nr_msgs_sent += 1;

            // now only a fragment (from an assumed empty buffer)
            socket.send_to(&buf[0..4], &send_to_addr).unwrap();
            socket.send_to(&buf[4..], &send_to_addr).unwrap();
            info!(
                logger,
                "Sent 3rd fragmented message to {:?}",
                send_to_addr.as_socket_ipv4(),
            );
            nr_msgs_sent += 1;

            // wait 100ms (to give the receiver time to start/process the messages)
            std::thread::sleep(std::time::Duration::from_millis(100));
            stop_receive.store(true, std::sync::atomic::Ordering::SeqCst);
            let r = r.join().unwrap();
            assert_eq!(
                r, nr_msgs_sent,
                "Expected to receive {nr_msgs_sent} messages, but got {r}"
            );
        });
    }

    #[test]
    fn test_corrupt_tcp_recv() {
        let port = pick_unused_port().expect("no ports free");
        let logger = new_logger();
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        let interface = InterfaceIndexOrAddress::Address("127.0.0.1".parse().unwrap());
        let receiver = IpDltMsgReceiver::new(
            logger.clone(),
            1,
            RecvMode::Tcp,
            interface,
            addr,
            DltChar4::from_buf(b"EcuT"),
        );
        let mut receiver = receiver.unwrap();
        std::thread::scope(|s| {
            let stop_receive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop_receive_r = stop_receive.clone();

            let r = s.spawn(move || {
                let stop_receive = stop_receive_r;
                let mut rcvd_nr_msgs = 0;
                while !stop_receive.load(std::sync::atomic::Ordering::SeqCst) {
                    let result = receiver.recv_msg();
                    if let Ok((msg, src_addr)) = &result {
                        println!("Received message: {:?} from {:?}", msg, src_addr);
                        rcvd_nr_msgs += 1;
                    }
                    println!("No message received, got error: {:?}", result.err());
                }
                rcvd_nr_msgs
            });

            // create a TCP listen port:
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
            listener.listen(1).expect("Failed to listen on TCP socket");
            // set the listener to non-blocking mode
            listener
                .set_nonblocking(true)
                .expect("Failed to set non-blocking mode");

            // wait 100ms (to give the receiver time to connect)
            std::thread::sleep(std::time::Duration::from_millis(100));
            let send_socket = match listener.accept() {
                Ok((send_socket, _)) => {
                    info!(
                        logger,
                        "TCP listener accepted connection from {:?}",
                        send_socket.peer_addr().unwrap()
                    );
                    // set the socket to non-blocking mode
                    send_socket
                        .set_nonblocking(true)
                        .expect("Failed to set non-blocking mode on accepted socket");
                    set_max_buffer_size(&send_socket, false, 64*1024*1000) // 64MB
                        .expect("Failed to set send buffer size on accepted send_socket");
                    send_socket
                }
                Err(e) => {
                    panic!("Failed to accept TCP connection: {}", e);
                }
            };
            let (noar, payload) = dlt_args!(0xdeafbeefu32).unwrap();
            let msg =
                DltMessage::get_testmsg_with_payload(cfg!(target_endian = "big"), noar, &payload);

            let mut buf = Vec::with_capacity(u16::MAX as usize);
            let mut buf_writer = std::io::Cursor::new(&mut buf);
            let mut nr_msgs_sent = 0usize;
            DltStandardHeader::to_write(
                &mut buf_writer,
                &msg.standard_header,
                &msg.extended_header,
                Some(msg.ecu),
                None, // session_id = None, todo
                Some(nr_msgs_sent as u32),
                &payload,
            )
            .expect("Failed to write DLT message: {e}");

            // let full_msg_len = buf_writer.position() as usize;
            let buf = buf_writer.into_inner();
            // let buf_len = buf.len();

            // send corrupt msgs (and one proper msg) to the tcp port:
            // a corrupt header with len 0...
            let std_hdr = DltStandardHeader {
                htyp: 0x1u8 << 5, // DLTv1 standard header type 1 << 5
                mcnt: (nr_msgs_sent % 256) as u8,
                len: 0,
            };
            let b2 = &u16::to_be_bytes(std_hdr.len);
            let b1 = &[std_hdr.htyp, std_hdr.mcnt, b2[0], b2[1]];
            // send as two sep. "packets"
            send_socket.send(b1).expect("msg header send failed");
            std::thread::sleep(std::time::Duration::from_millis(100));
            send_socket.send(&buf).expect("Failed to send DLT message");
            nr_msgs_sent += 1;

            // send as one pkg (to simulate a slower receiver)
            send_socket
                .send_vectored(&[IoSlice::new(b1), IoSlice::new(&buf[..])])
                .expect("Failed to send DLT message via vectored send");
            nr_msgs_sent += 1;
            std::thread::sleep(std::time::Duration::from_millis(100));
            // send a 3rd, corrupt and 4th message
            send_socket
                .send_vectored(&[IoSlice::new(buf), IoSlice::new(b1), IoSlice::new(buf)])
                .expect("Failed to send DLT message");
            nr_msgs_sent += 2;
            std::thread::sleep(std::time::Duration::from_millis(100));

            // send a 5th, proper message (TODO: this is currently needed as otherwise the last valid message is not returned
            // if prev data was drained
            send_socket
                .send_vectored(&[IoSlice::new(&buf[..])])
                .expect("Failed to send DLT message");
            nr_msgs_sent += 1;

            // wait 100ms (to give the receiver time to start/process the messages)
            std::thread::sleep(std::time::Duration::from_millis(100));
            stop_receive.store(true, std::sync::atomic::Ordering::SeqCst);
            let r = r.join().unwrap();
            assert_eq!(
                r, nr_msgs_sent,
                "Expected to receive {nr_msgs_sent} messages, but got {r}"
            );
        });
    }

    #[test]
    #[ignore]
    fn test_recv_msg() {
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), 12345);
        let interface = InterfaceIndexOrAddress::Address("127.0.0.1".parse().unwrap());
        let receiver = IpDltMsgReceiver::new(
            new_logger(),
            1,
            RecvMode::Udp,
            interface,
            addr,
            DltChar4::from_buf(b"EcuU"),
        );
        let mut receiver = receiver.unwrap();
        let mut nr_msgs = 0;
        loop {
            let result = receiver.recv_msg();
            if let Ok((msg, src_addr)) = &result {
                // If we got a message, we can break the loop
                println!("Received message: {:?} from {:?}", msg, src_addr);
                nr_msgs += 1;
                if nr_msgs >= 3 {
                    break; // stop after 10 messages
                } else {
                    continue;
                }
            }
            println!("No message received, got error: {:?}", result.err());
            break;
        }
        assert_eq!(
            nr_msgs, 3,
            "Expected to receive 3 messages, but got {}",
            nr_msgs
        );
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn test_get_dlt_from_pcap_packet_plp_udp() {
        use crate::utils::plp_packet::MutablePlpPacket;

        let logger = new_logger();

        // Create a test DLT message
        let (noar, payload) = dlt_args!(0xdeadbeef_u32).unwrap();
        let msg = DltMessage::get_testmsg_with_payload(cfg!(target_endian = "big"), noar, &payload);

        let mut dlt_buf = Vec::new();
        let mut buf_writer = std::io::Cursor::new(&mut dlt_buf);
        DltStandardHeader::to_write(
            &mut buf_writer,
            &msg.standard_header,
            &msg.extended_header,
            Some(msg.ecu),
            None,
            Some(1),
            &payload,
        )
        .unwrap();

        // Create UDP packet with DLT payload
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_port = 3490u16;
        let src_port = 12345u16;

        // Build UDP header (8 bytes)
        let udp_len = 8 + dlt_buf.len() as u16;
        let mut udp_packet = Vec::new();
        udp_packet.extend_from_slice(&src_port.to_be_bytes()); // src port
        udp_packet.extend_from_slice(&dst_port.to_be_bytes()); // dst port
        udp_packet.extend_from_slice(&udp_len.to_be_bytes()); // length
        udp_packet.extend_from_slice(&0u16.to_be_bytes()); // checksum (0 for simplicity)
        udp_packet.extend_from_slice(&dlt_buf); // DLT payload

        // Build IPv4 header (20 bytes minimum)
        let ip_total_len = 20 + udp_packet.len() as u16;
        let mut ipv4_packet = Vec::new();
        ipv4_packet.push(0x45); // version (4) + IHL (5)
        ipv4_packet.push(0x00); // DSCP + ECN
        ipv4_packet.extend_from_slice(&ip_total_len.to_be_bytes()); // total length
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes()); // identification
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
        ipv4_packet.push(64); // TTL
        ipv4_packet.push(17); // protocol (UDP)
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes()); // checksum
        ipv4_packet.extend_from_slice(&src_ip.octets()); // src IP
        ipv4_packet.extend_from_slice(&Ipv4Addr::new(192, 168, 1, 1).octets()); // dst IP
        ipv4_packet.extend_from_slice(&udp_packet);

        // Build inner ethernet frame for PLP
        let mut inner_ethernet = Vec::new();
        inner_ethernet.extend_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]); // dst MAC
        inner_ethernet.extend_from_slice(&[0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b]); // src MAC
        inner_ethernet.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype (IPv4)
        inner_ethernet.extend_from_slice(&ipv4_packet);

        //        plp_payload.extend_from_slice(&inner_ethernet);
        // Build PLP packet
        let mut plp = MutablePlpPacket::owned(vec![
            0xff;
            PlpPacket::minimum_packet_size()
                + inner_ethernet.len()
        ])
        .unwrap();
        //plp.set_probe_id(2345);
        plp.set_counter(1234);
        plp.set_version(3);
        plp.set_plp_type(3); // ethernet
        plp.set_msg_type(0x80);
        //plp.set_reserved(0);
        //plp.set_probe_flags(0);
        //plp.set_bus_spec_id(0);
        plp.set_timestamp(0);
        plp.set_length(inner_ethernet.len() as u16);
        //plp.set_data_flags(0);
        plp.set_payload(&inner_ethernet);

        let plp_payload = &plp.packet();

        // Build outer ethernet frame
        let mut ethernet_frame = Vec::new();
        ethernet_frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
        ethernet_frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src MAC
        ethernet_frame.extend_from_slice(&0x2090u16.to_be_bytes()); // ethertype (PLP)
        ethernet_frame.extend_from_slice(&plp_payload);

        // Create pcap packet
        let pcap_packet = pcap::Packet {
            header: &pcap::PacketHeader {
                ts: unsafe { std::mem::zeroed() },
                caplen: ethernet_frame.len() as u32,
                len: ethernet_frame.len() as u32,
            },
            data: &ethernet_frame,
        };

        let mut recv_buffer_raw = vec![std::mem::MaybeUninit::<u8>::uninit(); 65536];
        let mut recv_buffer = recv_buffer_raw.as_mut_slice();
        let mut plp_stats = None;

        let result = IpDltMsgReceiver::get_dlt_from_pcap_packet(
            &logger,
            &mut recv_buffer,
            &pcap_packet,
            &mut HashMap::new(),
            &mut plp_stats,
        );

        assert!(result.is_some());
        let (size, sock_addr) = result.unwrap();
        assert_eq!(size, dlt_buf.len());
        assert_eq!(sock_addr.as_socket_ipv4().unwrap().ip(), &src_ip);
        assert_eq!(sock_addr.as_socket_ipv4().unwrap().port(), 3490);

        // Verify PLP stats were updated
        assert!(plp_stats.is_some());
        let stats = plp_stats.unwrap();
        assert_eq!(stats.nr_packets, 1);
        assert_eq!(stats.last_plp_counter, 1234);
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn test_get_dlt_from_pcap_packet_vlan() {
        let logger = new_logger();

        // Create a test DLT message
        let (noar, payload) = dlt_args!(0xcafebabe_u32).unwrap();
        let msg = DltMessage::get_testmsg_with_payload(cfg!(target_endian = "big"), noar, &payload);

        let mut dlt_buf = Vec::new();
        let mut buf_writer = std::io::Cursor::new(&mut dlt_buf);
        DltStandardHeader::to_write(
            &mut buf_writer,
            &msg.standard_header,
            &msg.extended_header,
            Some(msg.ecu),
            None,
            Some(2),
            &payload,
        )
        .unwrap();

        // Create UDP packet
        let src_ip = Ipv4Addr::new(10, 0, 0, 50);
        let udp_len = 8 + dlt_buf.len() as u16;
        let mut udp_packet = Vec::new();
        udp_packet.extend_from_slice(&12345u16.to_be_bytes()); // src port
        udp_packet.extend_from_slice(&3490u16.to_be_bytes()); // dst port
        udp_packet.extend_from_slice(&udp_len.to_be_bytes()); // length
        udp_packet.extend_from_slice(&0u16.to_be_bytes()); // checksum
        udp_packet.extend_from_slice(&dlt_buf);

        // Create IPv4 packet
        let ip_total_len = 20 + udp_packet.len() as u16;
        let mut ipv4_packet = Vec::new();
        ipv4_packet.push(0x45);
        ipv4_packet.push(0x00);
        ipv4_packet.extend_from_slice(&ip_total_len.to_be_bytes());
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes());
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes());
        ipv4_packet.push(64);
        ipv4_packet.push(17); // UDP
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes());
        ipv4_packet.extend_from_slice(&src_ip.octets());
        ipv4_packet.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        ipv4_packet.extend_from_slice(&udp_packet);

        // Create VLAN tagged ethernet frame
        let mut ethernet_frame = Vec::new();
        ethernet_frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
        ethernet_frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src MAC
        ethernet_frame.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN ethertype
        ethernet_frame.extend_from_slice(&0x0064u16.to_be_bytes()); // VLAN tag (VLAN 100)
        ethernet_frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4 ethertype
        ethernet_frame.extend_from_slice(&ipv4_packet);

        let pcap_packet = pcap::Packet {
            header: &pcap::PacketHeader {
                ts: unsafe { std::mem::zeroed() },
                caplen: ethernet_frame.len() as u32,
                len: ethernet_frame.len() as u32,
            },
            data: &ethernet_frame,
        };

        let mut recv_buffer_raw = vec![std::mem::MaybeUninit::<u8>::uninit(); 65536];
        let mut recv_buffer = recv_buffer_raw.as_mut_slice();
        let mut plp_stats = None;

        let result = IpDltMsgReceiver::get_dlt_from_pcap_packet(
            &logger,
            &mut recv_buffer,
            &pcap_packet,
            &mut HashMap::new(),
            &mut plp_stats,
        );

        assert!(result.is_some());
        let (size, sock_addr) = result.unwrap();
        assert_eq!(size, dlt_buf.len());
        assert_eq!(sock_addr.as_socket_ipv4().unwrap().ip(), &src_ip);
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn test_get_dlt_from_pcap_packet_double_vlan_plp() {
        use crate::utils::plp_packet::MutablePlpPacket;

        let logger = new_logger();

        // Create a test DLT message
        let (noar, payload) = dlt_args!(0xbabecafe_u32).unwrap();
        let msg = DltMessage::get_testmsg_with_payload(cfg!(target_endian = "big"), noar, &payload);

        let mut dlt_buf = Vec::new();
        let mut buf_writer = std::io::Cursor::new(&mut dlt_buf);
        DltStandardHeader::to_write(
            &mut buf_writer,
            &msg.standard_header,
            &msg.extended_header,
            Some(msg.ecu),
            None,
            Some(3),
            &payload,
        )
        .unwrap();

        // Create UDP packet with DLT payload
        let src_ip = Ipv4Addr::new(172, 16, 0, 42);
        let dst_port = 3490u16;
        let src_port = 54321u16;

        // Build UDP header (8 bytes)
        let udp_len = 8 + dlt_buf.len() as u16;
        let mut udp_packet = Vec::new();
        udp_packet.extend_from_slice(&src_port.to_be_bytes()); // src port
        udp_packet.extend_from_slice(&dst_port.to_be_bytes()); // dst port
        udp_packet.extend_from_slice(&udp_len.to_be_bytes()); // length
        udp_packet.extend_from_slice(&0u16.to_be_bytes()); // checksum (0 for simplicity)
        udp_packet.extend_from_slice(&dlt_buf); // DLT payload

        // Build IPv4 header (20 bytes minimum)
        let ip_total_len = 20 + udp_packet.len() as u16;
        let mut ipv4_packet = Vec::new();
        ipv4_packet.push(0x45); // version (4) + IHL (5)
        ipv4_packet.push(0x00); // DSCP + ECN
        ipv4_packet.extend_from_slice(&ip_total_len.to_be_bytes()); // total length
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes()); // identification
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
        ipv4_packet.push(64); // TTL
        ipv4_packet.push(17); // protocol (UDP)
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes()); // checksum
        ipv4_packet.extend_from_slice(&src_ip.octets()); // src IP
        ipv4_packet.extend_from_slice(&Ipv4Addr::new(172, 16, 0, 1).octets()); // dst IP
        ipv4_packet.extend_from_slice(&udp_packet);

        // Build double VLAN tagged ethernet frame for PLP inner payload
        let mut inner_ethernet = Vec::new();
        inner_ethernet.extend_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]); // dst MAC
        inner_ethernet.extend_from_slice(&[0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b]); // src MAC
        inner_ethernet.extend_from_slice(&0x8100u16.to_be_bytes()); // First VLAN ethertype
        inner_ethernet.extend_from_slice(&0x00c8u16.to_be_bytes()); // VLAN tag (VLAN 200, priority 0)
        inner_ethernet.extend_from_slice(&0x8100u16.to_be_bytes()); // Second VLAN ethertype
        inner_ethernet.extend_from_slice(&0x012cu16.to_be_bytes()); // VLAN tag (VLAN 300, priority 0)
        inner_ethernet.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4 ethertype
        inner_ethernet.extend_from_slice(&ipv4_packet);

        // Build PLP packet
        let mut plp = MutablePlpPacket::owned(vec![
            0u8;
            PlpPacket::minimum_packet_size()
                + inner_ethernet.len()
        ])
        .unwrap();

        plp.set_counter(5678);
        plp.set_version(3);
        plp.set_plp_type(3); // ethernet
        plp.set_msg_type(0x80); // data
        plp.set_timestamp(3000000000);
        plp.set_length(inner_ethernet.len() as u16);
        plp.set_payload(&inner_ethernet);

        let plp_data = plp.packet();

        // Build outer ethernet frame (with PLP)
        let mut ethernet_frame = Vec::new();
        ethernet_frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
        ethernet_frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src MAC
        ethernet_frame.extend_from_slice(&0x2090u16.to_be_bytes()); // ethertype (PLP)
        ethernet_frame.extend_from_slice(plp_data);

        // Create pcap packet
        let pcap_packet = pcap::Packet {
            header: &pcap::PacketHeader {
                ts: unsafe { std::mem::zeroed() },
                caplen: ethernet_frame.len() as u32,
                len: ethernet_frame.len() as u32,
            },
            data: &ethernet_frame,
        };

        let mut recv_buffer_raw = vec![std::mem::MaybeUninit::<u8>::uninit(); 65536];
        let mut recv_buffer = recv_buffer_raw.as_mut_slice();
        let mut plp_stats = None;

        let result = IpDltMsgReceiver::get_dlt_from_pcap_packet(
            &logger,
            &mut recv_buffer,
            &pcap_packet,
            &mut HashMap::new(),
            &mut plp_stats,
        );

        assert!(result.is_some());
        let (size, sock_addr) = result.unwrap();
        assert_eq!(size, dlt_buf.len());
        assert_eq!(sock_addr.as_socket_ipv4().unwrap().ip(), &src_ip);
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn test_get_dlt_from_pcap_packet_wrong_port() {
        let logger = new_logger();

        // Create UDP packet to wrong port (not 3490)
        let mut udp_packet = Vec::new();
        udp_packet.extend_from_slice(&12345u16.to_be_bytes()); // src port
        udp_packet.extend_from_slice(&3491u16.to_be_bytes()); // dst port (wrong!)
        udp_packet.extend_from_slice(&8u16.to_be_bytes()); // length
        udp_packet.extend_from_slice(&0u16.to_be_bytes()); // checksum

        // Create IPv4 packet
        let ip_total_len = 20 + udp_packet.len() as u16;
        let mut ipv4_packet = Vec::new();
        ipv4_packet.push(0x45);
        ipv4_packet.push(0x00);
        ipv4_packet.extend_from_slice(&ip_total_len.to_be_bytes());
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes());
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes());
        ipv4_packet.push(64);
        ipv4_packet.push(17); // UDP
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes());
        ipv4_packet.extend_from_slice(&Ipv4Addr::new(192, 168, 1, 100).octets());
        ipv4_packet.extend_from_slice(&Ipv4Addr::new(192, 168, 1, 1).octets());
        ipv4_packet.extend_from_slice(&udp_packet);

        // Create ethernet frame
        let mut ethernet_frame = Vec::new();
        ethernet_frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        ethernet_frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        ethernet_frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        ethernet_frame.extend_from_slice(&ipv4_packet);

        let pcap_packet = pcap::Packet {
            header: &pcap::PacketHeader {
                ts: unsafe { std::mem::zeroed() },
                caplen: ethernet_frame.len() as u32,
                len: ethernet_frame.len() as u32,
            },
            data: &ethernet_frame,
        };

        let mut recv_buffer_raw = vec![std::mem::MaybeUninit::<u8>::uninit(); 65536];
        let mut recv_buffer = recv_buffer_raw.as_mut_slice();
        let mut plp_stats = None;

        let result = IpDltMsgReceiver::get_dlt_from_pcap_packet(
            &logger,
            &mut recv_buffer,
            &pcap_packet,
            &mut HashMap::new(),
            &mut plp_stats,
        );

        // Should return None because it's not port 3490
        assert!(result.is_none());
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn test_get_dlt_from_pcap_packet_non_udp() {
        let logger = new_logger();

        // Create TCP packet (protocol 6, not UDP 17)
        let mut tcp_packet = Vec::new();
        tcp_packet.extend_from_slice(&[0u8; 20]); // minimal TCP header

        let ip_total_len = 20 + tcp_packet.len() as u16;
        let mut ipv4_packet = Vec::new();
        ipv4_packet.push(0x45);
        ipv4_packet.push(0x00);
        ipv4_packet.extend_from_slice(&ip_total_len.to_be_bytes());
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes());
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes());
        ipv4_packet.push(64);
        ipv4_packet.push(6); // TCP protocol
        ipv4_packet.extend_from_slice(&0u16.to_be_bytes());
        ipv4_packet.extend_from_slice(&Ipv4Addr::new(192, 168, 1, 100).octets());
        ipv4_packet.extend_from_slice(&Ipv4Addr::new(192, 168, 1, 1).octets());
        ipv4_packet.extend_from_slice(&tcp_packet);

        let mut ethernet_frame = Vec::new();
        ethernet_frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        ethernet_frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        ethernet_frame.extend_from_slice(&0x0800u16.to_be_bytes());
        ethernet_frame.extend_from_slice(&ipv4_packet);

        let pcap_packet = pcap::Packet {
            header: &pcap::PacketHeader {
                ts: unsafe { std::mem::zeroed() },
                caplen: ethernet_frame.len() as u32,
                len: ethernet_frame.len() as u32,
            },
            data: &ethernet_frame,
        };

        let mut recv_buffer_raw = vec![std::mem::MaybeUninit::<u8>::uninit(); 65536];
        let mut recv_buffer = recv_buffer_raw.as_mut_slice();
        let mut plp_stats = None;

        let result = IpDltMsgReceiver::get_dlt_from_pcap_packet(
            &logger,
            &mut recv_buffer,
            &pcap_packet,
            &mut HashMap::new(),
            &mut plp_stats,
        );

        // Should return None because it's TCP, not UDP
        assert!(result.is_none());
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn test_get_dlt_from_pcap_packet_plp_counter_gap() {
        use crate::utils::plp_packet::MutablePlpPacket;

        let logger = new_logger();

        // Create a minimal PLP packet with specific counter
        let mut plp = MutablePlpPacket::owned(vec![0u8; PlpPacket::minimum_packet_size()]).unwrap();
        plp.set_plp_type(42); // invalid one (should lead to a WARN!)
        plp.set_counter(4);
        plp.set_timestamp(2000000000);
        plp.set_length(0);

        let plp_payload = plp.packet();

        let mut ethernet_frame = Vec::new();
        ethernet_frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        ethernet_frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        ethernet_frame.extend_from_slice(&0x2090u16.to_be_bytes()); // PLP ethertype
        ethernet_frame.extend_from_slice(&plp_payload);

        let pcap_packet = pcap::Packet {
            header: &pcap::PacketHeader {
                ts: unsafe { std::mem::zeroed() },
                caplen: ethernet_frame.len() as u32,
                len: ethernet_frame.len() as u32,
            },
            data: &ethernet_frame,
        };

        let mut recv_buffer_raw = vec![std::mem::MaybeUninit::<u8>::uninit(); 65536];
        let mut recv_buffer = recv_buffer_raw.as_mut_slice();

        // Initialize PLP stats with previous counter
        let mut plp_stats = Some(PlpStats {
            last_plp_counter: 0xfffeu16, // simulate wrap-around
            start_time: 1000000000,
            nr_packets: 5,
            packets_lost: 0,
            last_dump_time: 0,
        });

        let result = IpDltMsgReceiver::get_dlt_from_pcap_packet(
            &logger,
            &mut recv_buffer,
            &pcap_packet,
            &mut HashMap::new(),
            &mut plp_stats,
        );

        // Should return None because it's not a data packet
        assert!(result.is_none());

        // But PLP stats should be updated with gap detection
        let stats = plp_stats.unwrap();
        assert_eq!(stats.last_plp_counter, 4);
        assert_eq!(stats.nr_packets, 6);
        assert_eq!(stats.packets_lost, 5); // gap of 5 packets (0xffff, 0, 1,2,3)
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn test_get_dlt_from_pcap_packet_fragmented_ipv4() {
        let logger = new_logger();

        // Create a test DLT message
        let (noar, payload) = dlt_args!(0x1234abcd_u32).unwrap();
        let msg = DltMessage::get_testmsg_with_payload(cfg!(target_endian = "big"), noar, &payload);

        let mut dlt_buf = Vec::new();
        let mut buf_writer = std::io::Cursor::new(&mut dlt_buf);
        DltStandardHeader::to_write(
            &mut buf_writer,
            &msg.standard_header,
            &msg.extended_header,
            Some(msg.ecu),
            None,
            Some(100),
            &payload,
        )
        .unwrap();

        let src_ip = Ipv4Addr::new(192, 168, 10, 50);
        let dst_port = 3490u16;
        let src_port = 33333u16;

        // Build UDP header + DLT payload
        let udp_len = 8 + dlt_buf.len() as u16;
        let mut udp_packet = Vec::new();
        udp_packet.extend_from_slice(&src_port.to_be_bytes());
        udp_packet.extend_from_slice(&dst_port.to_be_bytes());
        udp_packet.extend_from_slice(&udp_len.to_be_bytes());
        udp_packet.extend_from_slice(&0u16.to_be_bytes());
        udp_packet.extend_from_slice(&dlt_buf);

        // Split the UDP packet into two fragments
        let fragment_size = 20; // First fragment gets 20 bytes of UDP data
        let first_fragment_data = &udp_packet[..fragment_size];
        let second_fragment_data = &udp_packet[fragment_size..];

        // Build first IPv4 fragment
        let identification = 0x1234u16;
        let ip_total_len_1 = 20 + first_fragment_data.len() as u16;
        let mut ipv4_fragment1 = Vec::new();
        ipv4_fragment1.push(0x45);
        ipv4_fragment1.push(0x00);
        ipv4_fragment1.extend_from_slice(&ip_total_len_1.to_be_bytes());
        ipv4_fragment1.extend_from_slice(&identification.to_be_bytes());
        ipv4_fragment1.extend_from_slice(&0x2000u16.to_be_bytes()); // More fragments flag set, offset 0
        ipv4_fragment1.push(64);
        ipv4_fragment1.push(17); // UDP
        ipv4_fragment1.extend_from_slice(&0u16.to_be_bytes());
        ipv4_fragment1.extend_from_slice(&src_ip.octets());
        ipv4_fragment1.extend_from_slice(&Ipv4Addr::new(192, 168, 10, 1).octets());
        ipv4_fragment1.extend_from_slice(first_fragment_data);

        // Build second IPv4 fragment (last fragment)
        let ip_total_len_2 = 20 + second_fragment_data.len() as u16;
        let fragment_offset = (fragment_size / 8) as u16; // Offset in 8-byte units
        let mut ipv4_fragment2 = Vec::new();
        ipv4_fragment2.push(0x45);
        ipv4_fragment2.push(0x00);
        ipv4_fragment2.extend_from_slice(&ip_total_len_2.to_be_bytes());
        ipv4_fragment2.extend_from_slice(&identification.to_be_bytes());
        ipv4_fragment2.extend_from_slice(&fragment_offset.to_be_bytes()); // No more fragments, offset set
        ipv4_fragment2.push(64);
        ipv4_fragment2.push(17); // UDP
        ipv4_fragment2.extend_from_slice(&0u16.to_be_bytes());
        ipv4_fragment2.extend_from_slice(&src_ip.octets());
        ipv4_fragment2.extend_from_slice(&Ipv4Addr::new(192, 168, 10, 1).octets());
        ipv4_fragment2.extend_from_slice(second_fragment_data);

        // Create ethernet frames for both fragments
        let mut ethernet_frame1 = Vec::new();
        ethernet_frame1.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        ethernet_frame1.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        ethernet_frame1.extend_from_slice(&0x0800u16.to_be_bytes());
        ethernet_frame1.extend_from_slice(&ipv4_fragment1);

        let mut ethernet_frame2 = Vec::new();
        ethernet_frame2.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        ethernet_frame2.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        ethernet_frame2.extend_from_slice(&0x0800u16.to_be_bytes());
        ethernet_frame2.extend_from_slice(&ipv4_fragment2);

        let mut recv_buffer_raw = vec![std::mem::MaybeUninit::<u8>::uninit(); 65536];
        let mut recv_buffer = recv_buffer_raw.as_mut_slice();
        let mut plp_stats = None;
        let mut fragment_cache = HashMap::new();

        // Process first fragment - should return None (incomplete)
        let pcap_packet1 = pcap::Packet {
            header: &pcap::PacketHeader {
                ts: unsafe { std::mem::zeroed() },
                caplen: ethernet_frame1.len() as u32,
                len: ethernet_frame1.len() as u32,
            },
            data: &ethernet_frame1,
        };

        let result1 = IpDltMsgReceiver::get_dlt_from_pcap_packet(
            &logger,
            &mut recv_buffer,
            &pcap_packet1,
            &mut fragment_cache,
            &mut plp_stats,
        );
        assert!(result1.is_none(), "First fragment should return None");
        assert_eq!(
            fragment_cache.len(),
            1,
            "Fragment cache should have one entry"
        );

        // Process second fragment - should return complete packet
        let pcap_packet2 = pcap::Packet {
            header: &pcap::PacketHeader {
                ts: unsafe { std::mem::zeroed() },
                caplen: ethernet_frame2.len() as u32,
                len: ethernet_frame2.len() as u32,
            },
            data: &ethernet_frame2,
        };

        let result2 = IpDltMsgReceiver::get_dlt_from_pcap_packet(
            &logger,
            &mut recv_buffer,
            &pcap_packet2,
            &mut fragment_cache,
            &mut plp_stats,
        );

        assert!(
            result2.is_some(),
            "Second fragment should complete the packet"
        );
        let (size, sock_addr) = result2.unwrap();
        assert_eq!(size, dlt_buf.len());
        assert_eq!(sock_addr.as_socket_ipv4().unwrap().ip(), &src_ip);
        assert_eq!(sock_addr.as_socket_ipv4().unwrap().port(), 3490);
        assert_eq!(
            fragment_cache.len(),
            0,
            "Fragment cache should be empty after completion"
        );
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn test_get_dlt_from_pcap_packet_fragmented_vlan() {
        let logger = new_logger();

        // Create a test DLT message
        let (noar, payload) = dlt_args!(0x5678dcba_u32).unwrap();
        let msg = DltMessage::get_testmsg_with_payload(cfg!(target_endian = "big"), noar, &payload);

        let mut dlt_buf = Vec::new();
        let mut buf_writer = std::io::Cursor::new(&mut dlt_buf);
        DltStandardHeader::to_write(
            &mut buf_writer,
            &msg.standard_header,
            &msg.extended_header,
            Some(msg.ecu),
            None,
            Some(200),
            &payload,
        )
        .unwrap();

        let src_ip = Ipv4Addr::new(10, 20, 30, 40);
        let dst_port = 3490u16;
        let src_port = 44444u16;

        // Build UDP header + DLT payload
        let udp_len = 8 + dlt_buf.len() as u16;
        let mut udp_packet = Vec::new();
        udp_packet.extend_from_slice(&src_port.to_be_bytes());
        udp_packet.extend_from_slice(&dst_port.to_be_bytes());
        udp_packet.extend_from_slice(&udp_len.to_be_bytes());
        udp_packet.extend_from_slice(&0u16.to_be_bytes());
        udp_packet.extend_from_slice(&dlt_buf);

        // Split into three fragments to test multiple fragment reassembly
        let frag1_size = 16;
        let frag2_size = 16;
        let frag1_data = &udp_packet[..frag1_size];
        let frag2_data = &udp_packet[frag1_size..frag1_size + frag2_size];
        let frag3_data = &udp_packet[frag1_size + frag2_size..];

        let identification = 0x5678u16;

        // Build three IPv4 fragments
        let create_fragment = |data: &[u8], offset_bytes: usize, more_fragments: bool| {
            let ip_total_len = 20 + data.len() as u16;
            let mut ipv4_frag = Vec::new();
            ipv4_frag.push(0x45);
            ipv4_frag.push(0x00);
            ipv4_frag.extend_from_slice(&ip_total_len.to_be_bytes());
            ipv4_frag.extend_from_slice(&identification.to_be_bytes());
            let flags_offset = if more_fragments {
                0x2000 | ((offset_bytes / 8) as u16)
            } else {
                (offset_bytes / 8) as u16
            };
            ipv4_frag.extend_from_slice(&flags_offset.to_be_bytes());
            ipv4_frag.push(64);
            ipv4_frag.push(17); // UDP
            ipv4_frag.extend_from_slice(&0u16.to_be_bytes());
            ipv4_frag.extend_from_slice(&src_ip.octets());
            ipv4_frag.extend_from_slice(&Ipv4Addr::new(10, 20, 30, 1).octets());
            ipv4_frag.extend_from_slice(data);
            ipv4_frag
        };

        let ipv4_frag1 = create_fragment(frag1_data, 0, true);
        let ipv4_frag2 = create_fragment(frag2_data, frag1_size, true);
        let ipv4_frag3 = create_fragment(frag3_data, frag1_size + frag2_size, false);

        // Wrap in VLAN ethernet frames
        let create_vlan_ethernet = |ipv4_data: &[u8]| {
            let mut eth = Vec::new();
            eth.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
            eth.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
            eth.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN
            eth.extend_from_slice(&0x0032u16.to_be_bytes()); // VLAN ID 50
            eth.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
            eth.extend_from_slice(ipv4_data);
            eth
        };

        let eth_frame1 = create_vlan_ethernet(&ipv4_frag1);
        let eth_frame2 = create_vlan_ethernet(&ipv4_frag2);
        let eth_frame3 = create_vlan_ethernet(&ipv4_frag3);

        let mut recv_buffer_raw = vec![std::mem::MaybeUninit::<u8>::uninit(); 65536];
        let mut recv_buffer = recv_buffer_raw.as_mut_slice();
        let mut plp_stats = None;
        let mut fragment_cache = HashMap::new();

        // Process fragments
        for (i, eth_frame) in [&eth_frame1, &eth_frame2, &eth_frame3].iter().enumerate() {
            let pcap_packet = pcap::Packet {
                header: &pcap::PacketHeader {
                    ts: unsafe { std::mem::zeroed() },
                    caplen: eth_frame.len() as u32,
                    len: eth_frame.len() as u32,
                },
                data: eth_frame,
            };

            let result = IpDltMsgReceiver::get_dlt_from_pcap_packet(
                &logger,
                &mut recv_buffer,
                &pcap_packet,
                &mut fragment_cache,
                &mut plp_stats,
            );

            if i < 2 {
                assert!(result.is_none(), "Fragment {} should return None", i + 1);
            } else {
                assert!(result.is_some(), "Last fragment should complete the packet");
                let (size, sock_addr) = result.unwrap();
                assert_eq!(size, dlt_buf.len());
                assert_eq!(sock_addr.as_socket_ipv4().unwrap().ip(), &src_ip);
            }
        }

        assert_eq!(fragment_cache.len(), 0, "Fragment cache should be empty");
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn test_fragmentation_out_of_order() {
        let logger = new_logger();

        // Test that out-of-order fragments are rejected
        // TODO this is only for the current implementation which does not handle out-of-order fragments
        // We want to be able to handle fragmentation!
        let src_ip = Ipv4Addr::new(172, 16, 0, 100);
        let identification = 0xabcdu16;

        // Create second fragment first (offset != 0, more fragments = false)
        let mut ipv4_frag2 = Vec::new();
        ipv4_frag2.push(0x45);
        ipv4_frag2.push(0x00);
        ipv4_frag2.extend_from_slice(&40u16.to_be_bytes()); // total length
        ipv4_frag2.extend_from_slice(&identification.to_be_bytes());
        ipv4_frag2.extend_from_slice(&0x0002u16.to_be_bytes()); // offset=2 (16 bytes), no more fragments
        ipv4_frag2.push(64);
        ipv4_frag2.push(17); // UDP
        ipv4_frag2.extend_from_slice(&0u16.to_be_bytes());
        ipv4_frag2.extend_from_slice(&src_ip.octets());
        ipv4_frag2.extend_from_slice(&Ipv4Addr::new(172, 16, 0, 1).octets());
        ipv4_frag2.extend_from_slice(&[0u8; 20]); // dummy data

        let mut ethernet_frame = Vec::new();
        ethernet_frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        ethernet_frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        ethernet_frame.extend_from_slice(&0x0800u16.to_be_bytes());
        ethernet_frame.extend_from_slice(&ipv4_frag2);

        let pcap_packet = pcap::Packet {
            header: &pcap::PacketHeader {
                ts: unsafe { std::mem::zeroed() },
                caplen: ethernet_frame.len() as u32,
                len: ethernet_frame.len() as u32,
            },
            data: &ethernet_frame,
        };

        let mut recv_buffer_raw = vec![std::mem::MaybeUninit::<u8>::uninit(); 65536];
        let mut recv_buffer = recv_buffer_raw.as_mut_slice();
        let mut plp_stats = None;
        let mut fragment_cache = HashMap::new();

        // Should return None and not cache anything (out of order)
        let result = IpDltMsgReceiver::get_dlt_from_pcap_packet(
            &logger,
            &mut recv_buffer,
            &pcap_packet,
            &mut fragment_cache,
            &mut plp_stats,
        );

        assert!(result.is_none());
        // Cache should be empty because we received last fragment without first
        assert_eq!(fragment_cache.len(), 0);
    }

    // TODO add tests for fragmentation handling in TCP receiver
}
