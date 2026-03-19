//! Unix traceroute socket implementation.
//!
//! macOS: SOCK_DGRAM + IPPROTO_ICMPV4 — receives all ICMP types including Time Exceeded
//! Linux: SOCK_RAW + IPPROTO_ICMPV4 — required for receiving Time Exceeded (DGRAM only delivers Echo Reply)

use crate::socket::{RecvResult, TraceSocketTrait};
use crate::{NtraceError, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::io::unix::AsyncFd;

/// Raw ICMP socket for traceroute on Unix platforms.
pub struct TraceSocket {
    inner: AsyncFd<Socket>,
}

impl TraceSocket {
    /// Create a new non-blocking ICMP socket suitable for traceroute.
    ///
    /// On macOS, uses SOCK_DGRAM which receives all ICMP types.
    /// On Linux, uses SOCK_RAW because DGRAM only delivers Echo Reply
    /// matching our identifier, not Time Exceeded from intermediate routers.
    pub fn new() -> Result<Self> {
        #[cfg(target_os = "macos")]
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
            .map_err(|e| NtraceError::SocketCreate(format!("DGRAM ICMP socket: {}", e)))?;

        #[cfg(target_os = "linux")]
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .map_err(|e| {
                NtraceError::SocketCreate(format!(
                    "RAW ICMP socket: {} (try running with sudo or CAP_NET_RAW)",
                    e
                ))
            })?;

        // For other Unix platforms, try RAW first
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .map_err(|e| NtraceError::SocketCreate(format!("RAW ICMP socket: {}", e)))?;

        socket
            .set_nonblocking(true)
            .map_err(|e| NtraceError::SocketCreate(format!("set_nonblocking: {}", e)))?;

        // Bind to INADDR_ANY to receive ICMP responses
        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        socket
            .bind(&bind_addr.into())
            .map_err(|e| NtraceError::SocketCreate(format!("bind: {}", e)))?;

        let inner = AsyncFd::new(socket)
            .map_err(|e| NtraceError::SocketCreate(format!("AsyncFd: {}", e)))?;

        Ok(Self { inner })
    }
}

impl TraceSocketTrait for TraceSocket {
    async fn send_probe(&self, packet: &[u8], target: IpAddr, ttl: u8) -> Result<()> {
        // Set TTL for this probe
        self.inner
            .get_ref()
            .set_ttl(ttl as u32)
            .map_err(|e| NtraceError::Send(format!("set_ttl({}): {}", ttl, e)))?;

        let sock_addr = SockAddr::from(SocketAddr::new(target, 0));

        loop {
            let mut guard = self
                .inner
                .writable()
                .await
                .map_err(|e| NtraceError::Send(format!("writable: {}", e)))?;

            match guard.try_io(|fd| {
                fd.get_ref()
                    .send_to(packet, &sock_addr)
                    .map(|_bytes_sent| ())
            }) {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => return Err(NtraceError::Send(format!("send_to: {}", e))),
                // WouldBlock — readiness was a false positive; retry.
                Err(_would_block) => continue,
            }
        }
    }

    async fn recv_icmp(&self, timeout: Duration) -> Result<Option<RecvResult>> {
        let recv_fut = async {
            loop {
                let mut guard = self
                    .inner
                    .readable()
                    .await
                    .map_err(|e| NtraceError::Recv(format!("readable: {}", e)))?;

                // 1500 bytes is enough for any ICMP reply (+ IP header on macOS).
                let mut buf = [MaybeUninit::<u8>::uninit(); 1500];

                match guard.try_io(|fd| fd.get_ref().recv_from(&mut buf)) {
                    Ok(Ok((n, addr))) => {
                        // SAFETY: recv_from initialised `n` bytes of `buf`.
                        let data: Vec<u8> = buf[..n]
                            .iter()
                            .map(|b| unsafe { b.assume_init() })
                            .collect();

                        let source = addr
                            .as_socket()
                            .map(|sa| sa.ip())
                            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

                        let icmp_data = parse_platform_reply(&data);

                        return Ok(Some(RecvResult {
                            bytes_received: icmp_data.len(),
                            source,
                            icmp_data,
                        }));
                    }
                    Ok(Err(e)) => return Err(NtraceError::Recv(format!("recv_from: {}", e))),
                    // WouldBlock — false positive; wait for readiness again.
                    Err(_would_block) => continue,
                }
            }
        };

        match tokio::time::timeout(timeout, recv_fut).await {
            Ok(result) => result,
            Err(_elapsed) => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Platform-specific reply parsing
// ---------------------------------------------------------------------------

/// Parse the platform-specific reply format.
///
/// On macOS, DGRAM ICMP sockets prepend the IP header to received data.
/// We need to strip it to get the raw ICMP data.
/// On Linux with RAW sockets, the IP header is also included.
fn parse_platform_reply(data: &[u8]) -> Vec<u8> {
    if data.len() < 20 {
        return data.to_vec();
    }

    // Check if this starts with an IP header (version 4)
    let version = (data[0] >> 4) & 0xF;
    if version == 4 {
        let ihl = (data[0] & 0x0F) as usize;
        let header_len = ihl * 4;
        if header_len <= data.len() {
            return data[header_len..].to_vec();
        }
    }

    // No IP header prefix — return as-is
    data.to_vec()
}

// ---------------------------------------------------------------------------
// `socket2::Socket` already implements `AsRawFd` on Unix, so `AsyncFd`
// accepts it directly. No additional trait impls are needed.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ip_header() {
        // Fake IPv4 header (IHL = 5 -> 20 bytes) + 8-byte ICMP stub.
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[8] = 64; // TTL
        pkt[20] = 11; // ICMP Time Exceeded type
        pkt[21] = 0x00; // code 0

        let icmp = parse_platform_reply(&pkt);
        assert_eq!(icmp.len(), 8);
        assert_eq!(icmp[0], 11); // Time Exceeded type
    }

    #[test]
    fn no_ip_header_passthrough() {
        // Data that starts with ICMP directly (e.g., already stripped)
        let pkt = vec![11, 0, 0, 0, 0, 0, 0, 0];
        let icmp = parse_platform_reply(&pkt);
        assert_eq!(icmp, pkt);
    }

    #[test]
    fn short_data_does_not_panic() {
        let pkt = vec![0x45, 0x00];
        let icmp = parse_platform_reply(&pkt);
        assert_eq!(icmp, pkt); // too short, returned as-is
    }

    #[test]
    fn empty_data_does_not_panic() {
        let icmp = parse_platform_reply(&[]);
        assert!(icmp.is_empty());
    }
}
