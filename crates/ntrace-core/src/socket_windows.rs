//! Windows traceroute socket implementation.
//!
//! Uses a raw ICMP socket (`SOCK_RAW + IPPROTO_ICMP`) via `socket2` to
//! send ICMP echo requests with controlled TTL and receive all ICMP
//! responses (Echo Reply, Time Exceeded, Destination Unreachable).
//!
//! This approach supports all traceroute methods (ICMP, UDP, TCP) because
//! the raw ICMP socket receives all inbound ICMP packets, including error
//! responses triggered by UDP/TCP probes.
//!
//! **Requires Administrator privileges** — same as Linux requiring
//! `sudo` or `CAP_NET_RAW`.
//!
//! Async I/O is handled via `tokio::task::spawn_blocking` since
//! `tokio::io::unix::AsyncFd` is not available on Windows.

use crate::socket::{RecvResult, TraceSocketTrait};
use crate::{NtraceError, Result};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

/// Raw ICMP socket for traceroute on Windows.
///
/// Uses `SOCK_RAW + IPPROTO_ICMP` which can both send ICMP echo requests
/// and receive all ICMP response types (Time Exceeded, Dest Unreachable,
/// Echo Reply). This enables ICMP, UDP, and TCP traceroute methods.
pub struct TraceSocket {
    socket: Arc<Socket>,
}

impl TraceSocket {
    /// Create a new raw ICMP socket.
    ///
    /// **Requires Administrator privileges.** If you get "Permission denied",
    /// run the application as Administrator.
    pub fn new() -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .map_err(|e| {
                if e.raw_os_error() == Some(10013) {
                    // WSAEACCES = 10013
                    NtraceError::SocketCreate(
                        "Raw ICMP socket requires Administrator privileges. \
                         Run as Administrator or use an elevated terminal."
                            .into(),
                    )
                } else {
                    NtraceError::SocketCreate(format!("Raw ICMP socket: {}", e))
                }
            })?;

        // Set a short default timeout for recv — we'll use our own timeout logic
        // but this prevents spawn_blocking from hanging indefinitely.
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| NtraceError::SocketCreate(format!("set_read_timeout: {}", e)))?;

        // Bind to INADDR_ANY to receive ICMP responses
        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        socket
            .bind(&bind_addr.into())
            .map_err(|e| NtraceError::SocketCreate(format!("bind: {}", e)))?;

        Ok(Self {
            socket: Arc::new(socket),
        })
    }
}

impl TraceSocketTrait for TraceSocket {
    /// Send an ICMP echo request probe with the specified TTL.
    async fn send_probe(&self, packet: &[u8], target: IpAddr, ttl: u8) -> Result<()> {
        // Set TTL for this probe
        self.socket
            .set_ttl(ttl as u32)
            .map_err(|e| NtraceError::Send(format!("set_ttl({}): {}", ttl, e)))?;

        let sock_addr = SockAddr::from(SocketAddr::new(target, 0));

        self.socket
            .send_to(packet, &sock_addr)
            .map_err(|e| NtraceError::Send(format!("send_to: {}", e)))?;

        Ok(())
    }

    /// Receive an ICMP packet with the given timeout.
    ///
    /// Uses `tokio::task::spawn_blocking` with a polling loop since
    /// `AsyncFd` is not available on Windows. The socket has a 100ms
    /// read timeout, and we loop until we get a packet or the overall
    /// timeout expires.
    async fn recv_icmp(&self, timeout: Duration) -> Result<Option<RecvResult>> {
        let socket = self.socket.clone();

        tokio::task::spawn_blocking(move || {
            let deadline = std::time::Instant::now() + timeout;

            loop {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Ok(None);
                }

                // Set recv timeout to min(remaining, 100ms) to allow periodic
                // deadline checks without busy-waiting.
                let recv_timeout = remaining.min(Duration::from_millis(100));
                let _ = socket.set_read_timeout(Some(recv_timeout));

                let mut buf = [MaybeUninit::<u8>::uninit(); 1500];

                match socket.recv_from(&mut buf) {
                    Ok((n, addr)) => {
                        // SAFETY: recv_from initialized `n` bytes.
                        let data: Vec<u8> = buf[..n]
                            .iter()
                            .map(|b| unsafe { b.assume_init() })
                            .collect();

                        let source = addr
                            .as_socket()
                            .map(|sa| sa.ip())
                            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

                        // On Windows, raw ICMP sockets include the IP header.
                        // Strip it to get the ICMP data.
                        let icmp_data = strip_ip_header(&data);

                        return Ok(Some(RecvResult {
                            bytes_received: icmp_data.len(),
                            source,
                            icmp_data,
                        }));
                    }
                    Err(e) => {
                        // Timeout or WSAETIMEDOUT (10060) or WSAEWOULDBLOCK (10035)
                        let raw = e.raw_os_error().unwrap_or(0);
                        if raw == 10060 || raw == 10035
                            || e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut
                        {
                            // Timeout on this recv — loop and check deadline
                            continue;
                        }
                        return Err(NtraceError::Recv(format!("recv_from: {}", e)));
                    }
                }
            }
        })
        .await
        .map_err(|e| NtraceError::Recv(format!("blocking task panicked: {e}")))?
    }
}

/// Strip the IP header from received data to get the raw ICMP payload.
///
/// On Windows with raw ICMP sockets, received packets include the IP header.
/// We check for an IPv4 header and strip it based on the IHL field.
fn strip_ip_header(data: &[u8]) -> Vec<u8> {
    if data.len() < 20 {
        return data.to_vec();
    }

    let version = (data[0] >> 4) & 0xF;
    if version == 4 {
        let ihl = (data[0] & 0x0F) as usize;
        let header_len = ihl * 4;
        if header_len <= data.len() {
            return data[header_len..].to_vec();
        }
    }

    data.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ip_header_normal() {
        // Fake IPv4 header (IHL = 5 -> 20 bytes) + 8-byte ICMP stub.
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[8] = 64; // TTL
        pkt[20] = 11; // ICMP Time Exceeded type
        pkt[21] = 0x00; // code 0

        let icmp = strip_ip_header(&pkt);
        assert_eq!(icmp.len(), 8);
        assert_eq!(icmp[0], 11); // Time Exceeded type
    }

    #[test]
    fn strip_ip_header_passthrough() {
        // Data that starts with ICMP directly
        let pkt = vec![11, 0, 0, 0, 0, 0, 0, 0];
        let icmp = strip_ip_header(&pkt);
        assert_eq!(icmp, pkt);
    }

    #[test]
    fn strip_ip_header_short() {
        let pkt = vec![0x45, 0x00];
        let icmp = strip_ip_header(&pkt);
        assert_eq!(icmp, pkt); // too short, returned as-is
    }

    #[test]
    fn strip_ip_header_empty() {
        let icmp = strip_ip_header(&[]);
        assert!(icmp.is_empty());
    }
}
