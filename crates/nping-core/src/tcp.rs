//! TCP ping implementations.
//!
//! - **TcpConnect**: Measures TCP handshake time via `TcpStream::connect`.
//!   Works unprivileged on all platforms.
//! - **TcpSyn**: Raw SYN ping via raw sockets. Requires root/admin.

use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::config::PingConfig;
use crate::error::{NpingError, Result};
use crate::result::{PingResult, PingStatus};
use crate::timing;

/// Runs a TCP connect ping loop.
///
/// For each iteration, opens a TCP connection to `target:port`, measures the
/// time for the three-way handshake to complete, then closes the connection.
/// This is the unprivileged cross-platform TCP ping method.
pub async fn run_tcp_connect(
    config: &PingConfig,
    target_ip: IpAddr,
    tx: mpsc::Sender<PingResult>,
) -> Result<()> {
    let port = config.port.ok_or_else(|| {
        NpingError::Other("TCP ping requires a port (--port)".into())
    })?;

    let addr = SocketAddr::new(target_ip, port);
    let mut seq: u64 = 0;

    loop {
        if let Some(count) = config.count {
            if seq >= count {
                break;
            }
        }

        let icmp_seq = seq as u16;
        let start = timing::now();

        let result = match tokio::time::timeout(config.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => {
                // Connection succeeded — handshake complete.
                let rtt = start.elapsed();
                PingResult {
                    seq: icmp_seq,
                    target: target_ip,
                    rtt: Some(rtt),
                    ttl: None, // not available from userspace TCP
                    packet_size: 0,
                    timestamp: SystemTime::now(),
                    status: PingStatus::Success,
                }
                // _stream is dropped here, sending FIN/RST to close.
            }
            Ok(Err(e)) => {
                let rtt = start.elapsed();
                // Connection refused means the host is reachable but port is closed.
                // We still record the RTT since we got a response (RST).
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    PingResult {
                        seq: icmp_seq,
                        target: target_ip,
                        rtt: Some(rtt),
                        ttl: None,
                        packet_size: 0,
                        timestamp: SystemTime::now(),
                        status: PingStatus::Success, // host responded (with RST)
                    }
                } else {
                    PingResult {
                        seq: icmp_seq,
                        target: target_ip,
                        rtt: None,
                        ttl: None,
                        packet_size: 0,
                        timestamp: SystemTime::now(),
                        status: PingStatus::Unreachable,
                    }
                }
            }
            Err(_elapsed) => PingResult {
                seq: icmp_seq,
                target: target_ip,
                rtt: None,
                ttl: None,
                packet_size: 0,
                timestamp: SystemTime::now(),
                status: PingStatus::Timeout,
            },
        };

        if tx.send(result).await.is_err() {
            break;
        }

        seq += 1;

        let elapsed = start.elapsed();
        if let Some(remaining) = config.interval.checked_sub(elapsed) {
            tokio::time::sleep(remaining).await;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Raw TCP SYN ping implementation (Unix only, requires root)
// ---------------------------------------------------------------------------

/// Runs a raw TCP SYN ping loop.
///
/// Sends hand-crafted TCP SYN packets via a raw socket and listens for
/// SYN-ACK or RST responses to measure host liveness and RTT.
///
/// Requires root/CAP_NET_RAW on Unix. IPv6 targets fall back to TCP connect
/// with a warning.
pub async fn run_tcp_syn(
    config: &PingConfig,
    target_ip: IpAddr,
    tx: mpsc::Sender<PingResult>,
) -> Result<()> {
    // IPv6 raw TCP SYN is not yet implemented; fall back gracefully.
    if target_ip.is_ipv6() {
        eprintln!(
            "warning: raw TCP SYN ping not yet implemented for IPv6, \
             falling back to TCP connect timing"
        );
        return run_tcp_connect(config, target_ip, tx).await;
    }

    // Only available on Unix.
    #[cfg(unix)]
    {
        unix_tcp_syn::run_tcp_syn_v4(config, target_ip, tx).await
    }

    #[cfg(not(unix))]
    {
        eprintln!(
            "warning: raw TCP SYN ping not supported on this platform, \
             falling back to TCP connect timing"
        );
        run_tcp_connect(config, target_ip, tx).await
    }
}

#[cfg(unix)]
mod unix_tcp_syn {
    use super::*;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::mem::MaybeUninit;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::io::unix::AsyncFd;

    /// TCP header size in bytes (no options).
    const TCP_HEADER_LEN: usize = 20;

    /// Minimum IPv4 header size.
    const IPV4_HEADER_LEN: usize = 20;

    // TCP flags
    const TCP_FLAG_SYN: u8 = 0x02;
    const TCP_FLAG_RST: u8 = 0x04;
    const TCP_FLAG_ACK: u8 = 0x10;

    /// Generate a pseudo-random u16 from time + pid, similar to icmp.rs.
    fn pseudo_random_u16() -> u16 {
        let time_seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u16;
        (std::process::id() as u16) ^ time_seed
    }

    /// Generate a pseudo-random u32 for the TCP sequence number.
    fn pseudo_random_u32() -> u32 {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let mut seed = nanos ^ (std::process::id() as u64).wrapping_mul(2654435761);
        seed ^= seed >> 17;
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed as u32
    }

    /// Build a TCP SYN packet (TCP header only, no IP header).
    ///
    /// Returns the raw bytes of the TCP header with SYN flag set and a valid
    /// checksum computed over the IPv4 pseudo-header.
    fn build_tcp_syn_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; TCP_HEADER_LEN];

        // Source port (bytes 0-1)
        pkt[0..2].copy_from_slice(&src_port.to_be_bytes());
        // Destination port (bytes 2-3)
        pkt[2..4].copy_from_slice(&dst_port.to_be_bytes());
        // Sequence number (bytes 4-7)
        pkt[4..8].copy_from_slice(&seq_num.to_be_bytes());
        // Acknowledgment number (bytes 8-11) — 0 for SYN
        // Data offset (byte 12, upper 4 bits): 5 words = 20 bytes, no options
        pkt[12] = (5u8) << 4;
        // Flags (byte 13): SYN
        pkt[13] = TCP_FLAG_SYN;
        // Window size (bytes 14-15): 64240 is a common default
        pkt[14..16].copy_from_slice(&64240u16.to_be_bytes());
        // Checksum (bytes 16-17): computed below
        // Urgent pointer (bytes 18-19): 0

        // Compute TCP checksum over pseudo-header + TCP segment
        let checksum = tcp_checksum(src_ip, dst_ip, &pkt);
        pkt[16..18].copy_from_slice(&checksum.to_be_bytes());

        pkt
    }

    /// Compute the TCP checksum per RFC 793.
    ///
    /// Uses the IPv4 pseudo-header (src_ip, dst_ip, zero, protocol=6, tcp_len)
    /// followed by the TCP segment (header + data).
    fn tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Pseudo-header
        let src = src_ip.octets();
        let dst = dst_ip.octets();
        sum += u16::from_be_bytes([src[0], src[1]]) as u32;
        sum += u16::from_be_bytes([src[2], src[3]]) as u32;
        sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
        sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
        sum += 6u32; // protocol TCP
        sum += tcp_segment.len() as u32;

        // TCP segment in 16-bit words
        let mut i = 0;
        while i + 1 < tcp_segment.len() {
            sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
            i += 2;
        }
        // If odd length, pad with zero byte
        if i < tcp_segment.len() {
            sum += (tcp_segment[i] as u32) << 8;
        }

        // Fold 32-bit sum into 16-bit
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Try to determine the local source IP for reaching `dst`.
    ///
    /// Connects a UDP socket (which does not send data) to pick the route,
    /// then reads back the local address.
    fn get_local_ip_for(dst: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        sock.connect(SocketAddrV4::new(dst, 80))?;
        match sock.local_addr()? {
            SocketAddr::V4(a) => Ok(*a.ip()),
            _ => Ok(Ipv4Addr::UNSPECIFIED),
        }
    }

    /// Parse a received raw packet to extract the TCP header fields we care about.
    ///
    /// Raw IPPROTO_TCP sockets receive packets WITH the IP header on both
    /// macOS and Linux.
    ///
    /// Returns `(src_ip, src_port, dst_port, flags, ttl)` or None if malformed.
    fn parse_tcp_response(data: &[u8]) -> Option<(Ipv4Addr, u16, u16, u8, u8)> {
        if data.len() < IPV4_HEADER_LEN {
            return None;
        }

        // Verify IPv4
        let version = data[0] >> 4;
        if version != 4 {
            return None;
        }

        let ihl = (data[0] & 0x0F) as usize * 4;
        if data.len() < ihl + TCP_HEADER_LEN {
            return None;
        }

        // Verify protocol is TCP (6)
        if data[9] != 6 {
            return None;
        }

        let ttl = data[8];
        let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);

        let tcp = &data[ihl..];
        let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        let flags = tcp[13];

        Some((src_ip, src_port, dst_port, flags, ttl))
    }

    /// Create a send-only raw socket with IP_HDRINCL for transmitting crafted
    /// IP+TCP packets. Uses IPPROTO_RAW which is inherently send-only.
    fn create_send_socket(config: &PingConfig) -> Result<Socket> {
        // IPPROTO_RAW is send-only and always implies IP_HDRINCL.
        let socket = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(libc::IPPROTO_RAW)),
        )
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::EPERM)
                || e.raw_os_error() == Some(libc::EACCES)
            {
                NpingError::PermissionDenied(
                    "could not create raw send socket — try running with sudo".into(),
                )
            } else {
                NpingError::SocketCreate(e)
            }
        })?;

        // IP_HDRINCL is implied by IPPROTO_RAW on most systems, but set it
        // explicitly for safety.
        socket
            .set_header_included_v4(true)
            .map_err(NpingError::SocketCreate)?;

        if let Some(ttl) = config.ttl {
            socket
                .set_ttl(ttl as u32)
                .map_err(NpingError::SocketCreate)?;
        }

        if let Some(tos) = config.tos {
            socket
                .set_tos(tos as u32)
                .map_err(NpingError::SocketCreate)?;
        }

        socket
            .set_nonblocking(true)
            .map_err(NpingError::SocketCreate)?;

        Ok(socket)
    }

    /// Create a receive-only raw socket (IPPROTO_TCP) for capturing TCP
    /// response packets (SYN-ACK, RST). This socket does NOT have IP_HDRINCL
    /// so it receives all TCP traffic with IP headers intact.
    fn create_recv_socket() -> Result<Socket> {
        let socket =
            Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).map_err(|e| {
                if e.raw_os_error() == Some(libc::EPERM)
                    || e.raw_os_error() == Some(libc::EACCES)
                {
                    NpingError::PermissionDenied(
                        "could not create raw recv socket — try running with sudo".into(),
                    )
                } else {
                    NpingError::SocketCreate(e)
                }
            })?;

        // Do NOT set IP_HDRINCL on the receive socket — we want the kernel
        // to deliver packets normally.

        socket
            .set_nonblocking(true)
            .map_err(NpingError::SocketCreate)?;

        Ok(socket)
    }

    /// Core IPv4 raw TCP SYN ping loop.
    ///
    /// Uses two separate raw sockets:
    /// - Send socket: IPPROTO_RAW + IP_HDRINCL (send-only)
    /// - Recv socket: IPPROTO_TCP (receives all TCP packets including SYN-ACK/RST)
    ///
    /// This split is necessary because:
    /// 1. IPPROTO_RAW sockets cannot receive any packets (they are send-only).
    /// 2. A single IPPROTO_TCP socket with IP_HDRINCL set can have issues
    ///    receiving on macOS where the kernel may consume TCP responses before
    ///    they reach the raw socket.
    pub(super) async fn run_tcp_syn_v4(
        config: &PingConfig,
        target_ip: IpAddr,
        tx: mpsc::Sender<PingResult>,
    ) -> Result<()> {
        let port = config.port.ok_or_else(|| {
            NpingError::Other("TCP SYN ping requires a port (--port)".into())
        })?;

        let dst_ipv4 = match target_ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return Err(NpingError::Other(
                    "run_tcp_syn_v4 called with IPv6 address".into(),
                ));
            }
        };

        let src_ip = get_local_ip_for(dst_ipv4).map_err(|e| {
            NpingError::Other(format!("failed to determine local IP: {e}"))
        })?;

        // Pick a random ephemeral source port (49152–65535).
        let src_port = 49152 + (pseudo_random_u16() % 16384);

        // Create separate send and receive sockets.
        let send_socket = create_send_socket(config)?;
        let recv_socket = create_recv_socket()?;

        let send_fd = AsyncFd::new(send_socket).map_err(NpingError::SocketCreate)?;
        let recv_fd = AsyncFd::new(recv_socket).map_err(NpingError::SocketCreate)?;

        let mut seq: u64 = 0;

        loop {
            if let Some(count) = config.count {
                if seq >= count {
                    break;
                }
            }

            let icmp_seq = seq as u16;
            let tcp_seq_num = pseudo_random_u32();

            // Build TCP SYN
            let tcp_pkt =
                build_tcp_syn_packet(src_ip, dst_ipv4, src_port, port, tcp_seq_num);

            // Build full IP + TCP packet for IP_HDRINCL send socket.
            // On macOS, IP total length must be in HOST byte order when
            // IP_HDRINCL is set; on Linux it must be network byte order.
            let ip_tcp_pkt = build_ipv4_packet(
                src_ip,
                dst_ipv4,
                config.ttl.unwrap_or(64),
                config.tos.unwrap_or(0),
                &tcp_pkt,
            );

            let dest_addr =
                socket2::SockAddr::from(SocketAddr::V4(SocketAddrV4::new(dst_ipv4, port)));

            let start = timing::now();

            // Send the SYN packet via the send socket.
            let send_res = send_raw(&send_fd, &ip_tcp_pkt, &dest_addr, target_ip).await;

            let result = match send_res {
                Ok(()) => {
                    // Wait for matching response on the recv socket.
                    match recv_syn_response(
                        &recv_fd,
                        dst_ipv4,
                        src_port,
                        port,
                        config.timeout,
                    )
                    .await
                    {
                        Ok(Some((flags, ttl))) => {
                            let rtt = start.elapsed();
                            let is_syn_ack =
                                (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) != 0;
                            let is_rst = (flags & TCP_FLAG_RST) != 0;

                            if is_syn_ack || is_rst {
                                let port_status = if is_syn_ack {
                                    "open"
                                } else {
                                    "closed"
                                };
                                eprintln!(
                                    "  port {port} {port_status} (flags=0x{flags:02x})"
                                );
                                PingResult {
                                    seq: icmp_seq,
                                    target: target_ip,
                                    rtt: Some(rtt),
                                    ttl: Some(ttl),
                                    packet_size: TCP_HEADER_LEN,
                                    timestamp: SystemTime::now(),
                                    status: PingStatus::Success,
                                }
                            } else {
                                // Unexpected TCP flags — still got a response.
                                PingResult {
                                    seq: icmp_seq,
                                    target: target_ip,
                                    rtt: Some(rtt),
                                    ttl: Some(ttl),
                                    packet_size: TCP_HEADER_LEN,
                                    timestamp: SystemTime::now(),
                                    status: PingStatus::Success,
                                }
                            }
                        }
                        Ok(None) => {
                            // Timeout — no response.
                            PingResult {
                                seq: icmp_seq,
                                target: target_ip,
                                rtt: None,
                                ttl: None,
                                packet_size: 0,
                                timestamp: SystemTime::now(),
                                status: PingStatus::Timeout,
                            }
                        }
                        Err(_) => PingResult {
                            seq: icmp_seq,
                            target: target_ip,
                            rtt: None,
                            ttl: None,
                            packet_size: 0,
                            timestamp: SystemTime::now(),
                            status: PingStatus::Timeout,
                        },
                    }
                }
                Err(e) => {
                    eprintln!("  send error: {e}");
                    PingResult {
                        seq: icmp_seq,
                        target: target_ip,
                        rtt: None,
                        ttl: None,
                        packet_size: 0,
                        timestamp: SystemTime::now(),
                        status: PingStatus::Error,
                    }
                }
            };

            if tx.send(result).await.is_err() {
                break;
            }

            seq += 1;

            let elapsed = start.elapsed();
            if let Some(remaining) = config.interval.checked_sub(elapsed) {
                tokio::time::sleep(remaining).await;
            }
        }

        Ok(())
    }

    /// Build a raw IPv4 packet wrapping the given TCP segment.
    ///
    /// On macOS with IP_HDRINCL, the kernel expects the IP total length in
    /// **host byte order**. On Linux, it expects network byte order. We handle
    /// this with a compile-time cfg.
    fn build_ipv4_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        ttl: u8,
        tos: u8,
        tcp_segment: &[u8],
    ) -> Vec<u8> {
        let total_len = (IPV4_HEADER_LEN + tcp_segment.len()) as u16;
        let mut pkt = vec![0u8; IPV4_HEADER_LEN + tcp_segment.len()];

        // Version (4) + IHL (5) = 0x45
        pkt[0] = 0x45;
        // TOS
        pkt[1] = tos;

        // Total length — macOS wants host byte order, Linux wants network order
        #[cfg(target_os = "macos")]
        {
            pkt[2..4].copy_from_slice(&total_len.to_ne_bytes());
        }
        #[cfg(not(target_os = "macos"))]
        {
            pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        }

        // Identification — use a pseudo-random value
        let ident = pseudo_random_u16();
        pkt[4..6].copy_from_slice(&ident.to_be_bytes());
        // Flags + Fragment offset: Don't Fragment (0x4000)
        pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        // TTL
        pkt[8] = ttl;
        // Protocol: TCP = 6
        pkt[9] = 6;
        // Header checksum (bytes 10-11): computed below
        // Source IP
        pkt[12..16].copy_from_slice(&src_ip.octets());
        // Destination IP
        pkt[16..20].copy_from_slice(&dst_ip.octets());

        // IP header checksum
        let cksum = ip_checksum(&pkt[..IPV4_HEADER_LEN]);
        pkt[10..12].copy_from_slice(&cksum.to_be_bytes());

        // Copy TCP segment
        pkt[IPV4_HEADER_LEN..].copy_from_slice(tcp_segment);

        pkt
    }

    /// Standard Internet checksum (RFC 1071) over a byte slice.
    fn ip_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Send raw bytes via the AsyncFd-wrapped send socket.
    async fn send_raw(
        async_fd: &AsyncFd<Socket>,
        packet: &[u8],
        dest: &socket2::SockAddr,
        target: IpAddr,
    ) -> Result<()> {
        loop {
            let mut guard =
                async_fd.writable().await.map_err(|e| NpingError::Send {
                    target,
                    source: e,
                })?;

            match guard.try_io(|fd| {
                fd.get_ref()
                    .send_to(packet, dest)
                    .map(|_| ())
            }) {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => {
                    return Err(if e.raw_os_error() == Some(libc::EPERM)
                        || e.raw_os_error() == Some(libc::EACCES)
                    {
                        NpingError::PermissionDenied(
                            "permission denied sending raw TCP packet — try running with sudo"
                                .into(),
                        )
                    } else {
                        NpingError::Send {
                            target,
                            source: e,
                        }
                    });
                }
                Err(_would_block) => continue,
            }
        }
    }

    /// Wait for a TCP response (SYN-ACK or RST) from the target that matches
    /// our source/destination port pair.
    ///
    /// Uses the recv socket (IPPROTO_TCP, no IP_HDRINCL) which receives all
    /// inbound TCP packets with IP headers.
    ///
    /// Returns `Ok(Some((flags, ttl)))` on match, `Ok(None)` on timeout.
    async fn recv_syn_response(
        recv_fd: &AsyncFd<Socket>,
        target_ipv4: Ipv4Addr,
        our_src_port: u16,
        our_dst_port: u16,
        timeout: std::time::Duration,
    ) -> Result<Option<(u8, u8)>> {
        let recv_fut = async {
            loop {
                let mut guard =
                    recv_fd.readable().await.map_err(NpingError::Recv)?;

                let mut buf = [MaybeUninit::<u8>::uninit(); 1500];

                match guard.try_io(|fd| fd.get_ref().recv_from(&mut buf)) {
                    Ok(Ok((n, _addr))) => {
                        let data: Vec<u8> = buf[..n]
                            .iter()
                            .map(|b| unsafe { b.assume_init() })
                            .collect();

                        if let Some((src_ip, src_port, dst_port, flags, ttl)) =
                            parse_tcp_response(&data)
                        {
                            // Match: response from our target, ports match
                            if src_ip == target_ipv4
                                && src_port == our_dst_port
                                && dst_port == our_src_port
                            {
                                return Ok(Some((flags, ttl)));
                            }
                        }
                        // Not our packet — keep listening.
                        continue;
                    }
                    Ok(Err(e)) => {
                        // ENOBUFS or similar transient errors — retry
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            continue;
                        }
                        return Err(NpingError::Recv(e));
                    }
                    Err(_would_block) => continue,
                }
            }
        };

        match tokio::time::timeout(timeout, recv_fut).await {
            Ok(result) => result,
            Err(_elapsed) => Ok(None),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn tcp_checksum_basic() {
            // Verify checksum computation with a known SYN packet.
            let src = Ipv4Addr::new(192, 168, 1, 100);
            let dst = Ipv4Addr::new(93, 184, 216, 34);
            let pkt = build_tcp_syn_packet(src, dst, 12345, 80, 0x01020304);

            // Re-compute checksum over the finished packet — should be 0 or 0xFFFF.
            let verify = tcp_checksum(src, dst, &pkt);
            assert!(
                verify == 0x0000 || verify == 0xFFFF,
                "checksum verification failed: got {verify:#06x}"
            );
        }

        #[test]
        fn build_syn_packet_has_correct_flags() {
            let src = Ipv4Addr::new(10, 0, 0, 1);
            let dst = Ipv4Addr::new(10, 0, 0, 2);
            let pkt = build_tcp_syn_packet(src, dst, 50000, 443, 0xDEADBEEF);

            assert_eq!(pkt.len(), TCP_HEADER_LEN);
            // Source port
            assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), 50000);
            // Destination port
            assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 443);
            // Sequence number
            assert_eq!(
                u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]),
                0xDEADBEEF
            );
            // Data offset: 5 << 4 = 80
            assert_eq!(pkt[12], 0x50);
            // Flags: SYN only
            assert_eq!(pkt[13], TCP_FLAG_SYN);
            // Window size
            assert_eq!(u16::from_be_bytes([pkt[14], pkt[15]]), 64240);
        }

        #[test]
        fn build_ipv4_packet_structure() {
            let src = Ipv4Addr::new(10, 0, 0, 1);
            let dst = Ipv4Addr::new(10, 0, 0, 2);
            let tcp_data = vec![0u8; TCP_HEADER_LEN];
            let pkt = build_ipv4_packet(src, dst, 64, 0, &tcp_data);

            assert_eq!(pkt.len(), IPV4_HEADER_LEN + TCP_HEADER_LEN);
            // Version + IHL
            assert_eq!(pkt[0], 0x45);
            // TTL
            assert_eq!(pkt[8], 64);
            // Protocol TCP
            assert_eq!(pkt[9], 6);
            // Source IP
            assert_eq!(&pkt[12..16], &[10, 0, 0, 1]);
            // Dest IP
            assert_eq!(&pkt[16..20], &[10, 0, 0, 2]);
        }

        #[test]
        fn parse_tcp_response_valid() {
            // Construct a minimal IP+TCP packet (use big-endian len for test)
            let src = Ipv4Addr::new(93, 184, 216, 34);
            let dst = Ipv4Addr::new(192, 168, 1, 100);
            let tcp_data = build_tcp_syn_packet(src, dst, 80, 12345, 0);

            // Build a test packet with network-byte-order length for parsing
            let total_len = (IPV4_HEADER_LEN + tcp_data.len()) as u16;
            let mut pkt = vec![0u8; IPV4_HEADER_LEN + tcp_data.len()];
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
            pkt[8] = 55; // TTL
            pkt[9] = 6; // TCP
            pkt[12..16].copy_from_slice(&src.octets());
            pkt[16..20].copy_from_slice(&dst.octets());
            pkt[IPV4_HEADER_LEN..].copy_from_slice(&tcp_data);

            let parsed = parse_tcp_response(&pkt);
            assert!(parsed.is_some());
            let (s_ip, s_port, d_port, flags, ttl) = parsed.unwrap();
            assert_eq!(s_ip, src);
            assert_eq!(s_port, 80);
            assert_eq!(d_port, 12345);
            assert_eq!(flags, TCP_FLAG_SYN);
            assert_eq!(ttl, 55);
        }

        #[test]
        fn parse_tcp_response_too_short() {
            assert!(parse_tcp_response(&[0u8; 10]).is_none());
        }

        #[test]
        fn ip_checksum_zeros() {
            // Checksum of all zeros should be 0xFFFF
            let data = [0u8; 20];
            assert_eq!(ip_checksum(&data), 0xFFFF);
        }
    }
}
