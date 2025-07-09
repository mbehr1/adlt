/// TODOs:
/// [ ] - remove the .expect() calls and handle errors gracefully (non panic)
/// [ ] - handle fragmentation per sender
/// [ ] - set recv buffer size
/// [ ] - decide whether using a single socket for all addresses is sufficient or whether we need a socket per address
///
use slog::{info, warn};
use socket2::{Domain, InterfaceIndexOrAddress, Protocol, SockAddr, Socket, Type};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
};

use crate::dlt::{
    parse_dlt_with_std_header, DltChar4, DltMessage, DltMessageIndexType, Error, ErrorKind,
};

pub fn set_max_buffer_size(
    socket: &socket2::Socket,
    send: bool,
    size: usize,
) -> std::io::Result<usize> {
    let mut try_size = size;
    while try_size > 64 * 1024 {
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

#[derive(PartialEq, Debug)]
pub enum RecvMode {
    Tcp,
    Udp,
    UdpMulticast,
}

pub struct IpDltMsgReceiver {
    log: slog::Logger,
    pub recv_mode: RecvMode,
    pub interface: InterfaceIndexOrAddress,
    pub addr: SocketAddr,
    socket: Socket,
    /// buffer for receiving fragmented messages (e.g. due to payloads > MTU)
    /// use a buffer per sock_addr that we received from (but this would require a socket per sock_addr)
    /// TODO consider different sockets per sock_addr
    /// we use a vec for now as we expect only a few sock_addrs/senders. so a hashmap would be overkill
    /// could sort/bin_search later
    recv_buffer_list: Vec<(SockAddr, Vec<u8>)>,
    recv_buffer: Vec<u8>,
    pub index: DltMessageIndexType,
    buffered_msgs: VecDeque<(DltMessage, SocketAddr)>,
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
    ) -> Result<Self, std::io::Error> {
        let socket = match recv_mode {
            RecvMode::Tcp => Self::new_tcp_client_socket(addr)?,
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

                socket
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

                socket
            }
        };

        // so try the max then... (e.g. by looping down the size until it works)
        // hmm. on osx it silently fails and uses the default size of 8388608 bytes

        info!(
            log,
            "created receiver socket: {:?}/{:?} with receiver buffer size: {} and read timeout: {:?}",
            socket.local_addr().unwrap().as_socket_ipv4(),
            socket.local_addr().unwrap().as_socket_ipv6(),
            socket.recv_buffer_size().unwrap_or(0),
            socket.read_timeout()
        );

        // allocate a buffer for the socket for receiving messages
        let data = if recv_mode == RecvMode::Tcp {
            Vec::<u8>::with_capacity(100usize * 0xffff) // this is the max len as part of DLTv1 standard header
        } else {
            Vec::<u8>::with_capacity(0x10000) // 64kb, this is the max len as part of DLTv1 standard header and UDP should not concat to more than that size
        };

        Ok(IpDltMsgReceiver {
            log,
            recv_mode,
            interface,
            addr,
            socket,
            recv_buffer_list: Vec::with_capacity(256),
            recv_buffer: data,
            index: start_index,
            buffered_msgs: VecDeque::with_capacity(16), // buffer for messages that will be returned on next recv_msg call
        })
    }

    pub fn recv_msg(&mut self) -> Result<(DltMessage, SocketAddr), std::io::Error> {
        if let Some((msg, addr)) = self.buffered_msgs.pop_front() {
            // if we have buffered messages, return the first one
            //info!(self.log, "recv_msg: returning buffered message: {:?}", msg);
            return Ok((msg, addr));
        }

        let recv_buffer = &mut self.recv_buffer.spare_capacity_mut();

        let (size, src_addr) = if self.recv_mode == RecvMode::Tcp {
            // info!(self.log, "recv_msg: receiving message via TCP");
            match self.socket.recv(recv_buffer) {
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
                        let _ = self.socket.shutdown(std::net::Shutdown::Both);
                        // TODO in case of an error the old socket is not dropped!
                        self.socket = Self::new_tcp_client_socket(self.addr)?;

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
                        match self.socket.connect(&SockAddr::from(self.addr)) {
                            Ok(_) => {
                                info!(self.log, "recv_msg: socket connected to {:?}", self.addr);
                                return self.recv_msg(); // retry receiving after successful connecting
                            }
                            Err(e) => {
                                std::thread::sleep(std::time::Duration::from_millis(50)); // TODO for test only!
                                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                                    info!(
                                        self.log,
                                        "recv_msg: connection refused, trying to reconnect"
                                    );
                                    self.socket = Self::new_tcp_client_socket(self.addr)?;
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
        } else {
            self.socket.recv_from(recv_buffer)?
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

        // Parse the DltMessage from the buffer
        let data_len = data.len();

        match parse_dlt_with_std_header(data, self.index, DltChar4::from_buf(b"RECV")) {
            Ok((mut to_consume, msg)) => {
                debug_assert_eq!(
                    msg.standard_header.len as usize, to_consume,
                    "The DLT message length should match the consumed data length"
                );
                /* todo add test-pattern checks
                // check that msg payload is counting from 1 to 0xff continously except for the last byte:
                if msg.payload.len() > 4 + 8 + 6 {
                    for i in 4 + 8 + 6..msg.payload.len() - 1 {
                        assert_eq!(
                        msg.payload[i],
                        (i -(4+8+6)) as u8,
                        "The DLT message payload should be counting from 0 to 0xff, but got {} at index {} for msg {:?}",
                        msg.payload[i],
                        i, msg
                    );
                    }
                }
                assert_eq!(
                    0xff,
                    data[msg.standard_header.len as usize - 1],
                    "The msg buffer should end with 0xff for test msgs {:?} {:?} with payload.len: {} index: {}, src_addr_buffer.len: {}, {:?} {:?}",
                    msg.standard_header,
                    msg.extended_header,
                    msg.payload.len(),
                    self.index,
                    src_addr_buffer.len(),
                    data,
                    src_addr_buffer
                );*/
                let remaining = data_len - to_consume;
                self.index += 1; // increment index for next message
                if remaining > 0 {
                    // keep the remaining bytes in the buffer -> needed for TCP (and UDP might bundle few msgs into one dgram as well!
                    // Currently dlt-daemon does not bundle msgs via UDP (dgram) but via TCP (stream) it is expected

                    // parse the remaining bytes as a new message and put them into a queue
                    // once NotEnoughData is returned, keep that buffer part
                    while to_consume < data_len {
                        let rem_data = &data[to_consume..];
                        match parse_dlt_with_std_header(
                            rem_data,
                            self.index,
                            DltChar4::from_buf(b"RECV"),
                        ) {
                            Ok((new_to_consume, new_msg)) => {
                                debug_assert_eq!(
                                    new_msg.standard_header.len as usize, new_to_consume,
                                    "The inner DLT message length should match the consumed data length"
                                );
                                /*
                                // check that msg payload is counting from 1 to 0xff continously except for the last byte:
                                if new_msg.payload.len() > 4 + 8 + 6 {
                                    for i in 4 + 8 + 6..new_msg.payload.len() - 1 {
                                        assert_eq!(
                                            new_msg.payload[i],
                                            (i -(4+8+6)) as u8,
                                            "The inner DLT message payload should be counting from 0 to 0xff, but got {} at index {} for msg {:?}",
                                            new_msg.payload[i],
                                            i, new_msg
                                        );
                                    }
                                }
                                assert_eq!(
                                        0xff,
                                        rem_data[new_msg.standard_header.len as usize - 1],
                                        "The inner send buffer should end with 0xff for test msgs {:?} {:?} with payload.len: {}",
                                        new_msg.standard_header,
                                        new_msg.extended_header,
                                        new_msg.payload.len()
                                );*/

                                self.index += 1; // increment index for next message
                                to_consume += new_to_consume;
                                self.buffered_msgs
                                    .push_back((new_msg, src_addr.as_socket().unwrap()));
                            }
                            Err(Error {
                                kind: ErrorKind::NotEnoughData(_),
                            }) => {
                                // todo: use that number for next read to get the buffers aligned again
                                // otherwise it can happen that constantly 2 read calls are needed
                                // to get a message (well, only if the messages are so large that the fragment
                                // plus the new dont fit into the 64kb)
                                break;
                            }
                            Err(e) => {
                                warn!(
                                    self.log,
                                    "recv_msg inner: error parsing DLT message: {} at index {}, buffered msgs: {}, data_len:{}, to_consume:{}, rem_data.len:{} outer msg: {:?}",
                                    e,
                                    self.index, self.buffered_msgs.len(),data_len, to_consume, rem_data.len(),
                                     &msg
                                );

                                // invalid message, so we cannot really trust the remaining data
                                to_consume = data_len; // consume all remaining data
                                                       //src_addr_buffer.clear(); // clear the buffer for this src_addr

                                // TODO we might have to search for the next valid message start (DLTv1 header pattern)
                            }
                        }
                    }
                }
                if src_addr_buffer.is_empty() {
                    let to_keep = &recvd_data[to_consume..];
                    if !to_keep.is_empty() {
                        src_addr_buffer.extend_from_slice(to_keep);
                    }
                } else {
                    src_addr_buffer.drain(..to_consume);
                }
                Ok((msg, src_addr.as_socket().unwrap()))
            }
            Err(Error {
                kind: ErrorKind::NotEnoughData(missing),
            }) => {
                // this is not a valid DLT message, so we need to handle it as a fragmented message
                // or an invalid message
                let recvd_data_len = recvd_data.len();
                if src_addr_buffer.is_empty() {
                    src_addr_buffer.extend_from_slice(recvd_data);
                } // else we already extended the buffer above
                  //src_addr_buffer.extend_from_slice(recvd_data);
                  // it's expected for a tcp stream to receive fragments
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("not enough data (missing {missing} recvd={recvd_data_len}), storing fragment"),
                ))
            }
            Err(e) => {
                warn!(
                    self.log,
                    "recv_msg: error parsing DLT message: {} at index {}", e, self.index
                );
                src_addr_buffer.clear(); // invalid, clear (if any)

                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "stdh.len too small",
                ))
            }
        }
    }
}

impl Drop for IpDltMsgReceiver {
    fn drop(&mut self) {
        // Clean up resources if necessary
        match self.recv_mode {
            RecvMode::Tcp => {
                // Clean up TCP receiver
            }
            RecvMode::Udp => {
                // Clean up UDP receiver
            }
            RecvMode::UdpMulticast => {
                // Clean up UDP multicast receiver
                match self.addr.ip() {
                    IpAddr::V4(ref mdns_v4) => {
                        self.socket
                            .leave_multicast_v4_n(mdns_v4, &self.interface)
                            .expect("leave_multicast_v4_n");
                    }
                    IpAddr::V6(ref mdns_v6) => {
                        if let socket2::InterfaceIndexOrAddress::Index(idx) = self.interface {
                            self.socket
                                .leave_multicast_v6(mdns_v6, idx)
                                .expect("leave_multicast_v6");
                        };
                    }
                }
            }
        }
        info!(self.log, "Droping receiver socket: {:?}", self.socket);
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
    use slog::{o, Drain, Logger};
    use std::net::Ipv4Addr;

    fn new_logger() -> Logger {
        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, o!())
    }

    #[test]
    fn test_ip_dlt_msg_receiver_creation_udp_m() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), 12345);
        let interface = InterfaceIndexOrAddress::Address("127.0.0.1".parse().unwrap());
        let receiver =
            IpDltMsgReceiver::new(new_logger(), 42, RecvMode::UdpMulticast, interface, addr);
        assert!(receiver.is_ok());
    }

    #[test]
    fn test_ip_dlt_msg_receiver_creation_udp() {
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), 12345);
        let interface = InterfaceIndexOrAddress::Address("127.0.0.1".parse().unwrap());
        let receiver = IpDltMsgReceiver::new(new_logger(), 42, RecvMode::Udp, interface, addr);
        assert!(receiver.is_ok());
    }

    #[test]
    #[ignore]
    fn test_recv_msg() {
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), 12345);
        let interface = InterfaceIndexOrAddress::Address("127.0.0.1".parse().unwrap());
        let receiver = IpDltMsgReceiver::new(new_logger(), 1, RecvMode::Udp, interface, addr);
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
}
