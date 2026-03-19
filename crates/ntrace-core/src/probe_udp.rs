//! UDP probe sender for traceroute.
//!
//! UDP traceroute works by sending UDP packets to target:port with controlled TTL.
//! Intermediate hops reply with ICMP Time Exceeded (received on our ICMP socket).
//! The destination replies with ICMP Port Unreachable (type 3, code 3).
//!
//! Probe identification for UDP is via src_port + dst_port extracted from the
//! ICMP error's quoted original packet.

use crate::{NtraceError, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

/// UDP probe sender — sends UDP packets with controlled TTL.
/// ICMP responses (Time Exceeded, Port Unreachable) are received on the separate ICMP socket.
pub struct UdpProbeSender {
    #[cfg(unix)]
    inner: tokio::io::unix::AsyncFd<Socket>,
    #[cfg(windows)]
    inner: Socket,
    local_port: u16,
}

impl UdpProbeSender {
    /// Create a new UDP probe sender bound to a random port.
    pub fn new() -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| NtraceError::SocketCreate(format!("UDP socket: {}", e)))?;

        socket
            .set_nonblocking(true)
            .map_err(|e| NtraceError::SocketCreate(format!("set_nonblocking: {}", e)))?;

        // Bind to any port
        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        socket
            .bind(&bind_addr.into())
            .map_err(|e| NtraceError::SocketCreate(format!("bind: {}", e)))?;

        // Get the assigned local port
        let local_addr = socket
            .local_addr()
            .map_err(|e| NtraceError::SocketCreate(format!("local_addr: {}", e)))?;
        let local_port = local_addr
            .as_socket_ipv4()
            .map(|a| a.port())
            .unwrap_or(0);

        #[cfg(unix)]
        let inner = tokio::io::unix::AsyncFd::new(socket)
            .map_err(|e| NtraceError::SocketCreate(format!("AsyncFd: {}", e)))?;
        #[cfg(windows)]
        let inner = socket;

        Ok(Self { inner, local_port })
    }

    /// Get the local port this sender is bound to.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Send a UDP probe to the target with the specified TTL and destination port.
    pub async fn send_probe(
        &self,
        target: IpAddr,
        port: u16,
        ttl: u8,
        payload: &[u8],
    ) -> Result<()> {
        let addr = SocketAddr::new(target, port);
        let addr: socket2::SockAddr = addr.into();

        #[cfg(unix)]
        {
            self.inner
                .get_ref()
                .set_ttl(ttl as u32)
                .map_err(|e| NtraceError::Send(format!("set_ttl({}): {}", ttl, e)))?;

            loop {
                let mut guard = self
                    .inner
                    .writable()
                    .await
                    .map_err(|e| NtraceError::Send(format!("writable: {}", e)))?;

                match guard.try_io(|inner| inner.get_ref().send_to(payload, &addr)) {
                    Ok(Ok(_)) => return Ok(()),
                    Ok(Err(e)) => return Err(NtraceError::Send(format!("UDP send_to: {}", e))),
                    Err(_would_block) => continue,
                }
            }
        }

        #[cfg(windows)]
        {
            self.inner
                .set_ttl(ttl as u32)
                .map_err(|e| NtraceError::Send(format!("set_ttl({}): {}", ttl, e)))?;

            // On Windows, the socket is non-blocking but UDP sends are typically immediate.
            // Use send_to directly — for a datagram socket this rarely blocks.
            self.inner
                .send_to(payload, &addr)
                .map_err(|e| NtraceError::Send(format!("UDP send_to: {}", e)))?;
            Ok(())
        }
    }
}
