//! TCP probe sender for traceroute.
//!
//! TCP traceroute works by:
//! 1. Creating a TCP socket, setting TTL, and attempting connect() to target:port
//! 2. Intermediate hops send ICMP Time Exceeded (received on ICMP socket)
//! 3. The destination either:
//!    - Completes the connection (SYN-ACK) — connect() succeeds
//!    - Sends RST — connect() gets ConnectionRefused
//!
//! We don't need raw TCP — just use normal socket2 TCP with TTL set.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Outcome of a TCP probe that reached the destination
#[derive(Debug, Clone)]
pub enum TcpProbeOutcome {
    /// TCP SYN-ACK received (port open)
    Connected { rtt: Duration },
    /// TCP RST received (port closed)
    Refused { rtt: Duration },
    /// Connection timed out (intermediate hop will send ICMP Time Exceeded)
    Timeout,
    /// Error during probe
    Error(String),
}

/// Send a TCP SYN probe by attempting a connect() with a controlled TTL.
///
/// If the TTL expires before reaching the destination, an ICMP Time Exceeded
/// will be received on the separate ICMP socket — that's handled by the engine.
///
/// If the destination is reached, connect() either succeeds (SYN-ACK) or
/// returns ConnectionRefused (RST).
pub async fn send_tcp_probe(
    target: IpAddr,
    port: u16,
    ttl: u8,
    timeout: Duration,
) -> TcpProbeOutcome {
    let start = Instant::now();

    // Create a socket2 TCP socket to set TTL before connecting
    let socket = match socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    ) {
        Ok(s) => s,
        Err(e) => return TcpProbeOutcome::Error(format!("socket create: {}", e)),
    };

    if let Err(e) = socket.set_ttl(ttl as u32) {
        return TcpProbeOutcome::Error(format!("set_ttl: {}", e));
    }

    if let Err(e) = socket.set_nonblocking(true) {
        return TcpProbeOutcome::Error(format!("set_nonblocking: {}", e));
    }

    let addr = SocketAddr::new(target, port);
    let addr: socket2::SockAddr = addr.into();

    // Attempt connect — on non-blocking socket this returns immediately with WouldBlock
    match socket.connect(&addr) {
        Ok(()) => {
            // Immediate connection (unlikely but possible on localhost)
            return TcpProbeOutcome::Connected {
                rtt: start.elapsed(),
            };
        }
        Err(e) => {
            let kind = e.kind();
            if kind == std::io::ErrorKind::ConnectionRefused {
                return TcpProbeOutcome::Refused {
                    rtt: start.elapsed(),
                };
            }
            if kind == std::io::ErrorKind::WouldBlock {
                // Connection in progress — wait for completion below
            } else {
                // On macOS, connect() on non-blocking returns EINPROGRESS
                // On Linux, also EINPROGRESS
                // EINPROGRESS = 36 on macOS, 115 on Linux
                let raw_err = e.raw_os_error().unwrap_or(0);
                if raw_err != 36 && raw_err != 115 {
                    return TcpProbeOutcome::Error(format!("connect: {}", e));
                }
            }
        }
    }

    // Wait for connection to complete or timeout
    let result = tokio::time::timeout(timeout, async {
        // Convert to tokio AsyncFd for polling
        let async_fd = match tokio::io::unix::AsyncFd::new(socket) {
            Ok(fd) => fd,
            Err(e) => return TcpProbeOutcome::Error(format!("AsyncFd: {}", e)),
        };

        // Wait for the socket to become writable (connect completed)
        match async_fd.writable().await {
            Ok(_guard) => {
                // Check if the connection actually succeeded via SO_ERROR
                match async_fd.get_ref().take_error() {
                    Ok(None) => {
                        // No error — connection succeeded
                        TcpProbeOutcome::Connected {
                            rtt: start.elapsed(),
                        }
                    }
                    Ok(Some(e)) => {
                        let e: std::io::Error = e;
                        if e.kind() == std::io::ErrorKind::ConnectionRefused {
                            TcpProbeOutcome::Refused {
                                rtt: start.elapsed(),
                            }
                        } else {
                            // Other error — likely the probe was intercepted or TTL expired
                            // The ICMP Time Exceeded will be received on the ICMP socket
                            TcpProbeOutcome::Timeout
                        }
                    }
                    Err(e) => TcpProbeOutcome::Error(format!("take_error: {}", e)),
                }
            }
            Err(e) => TcpProbeOutcome::Error(format!("writable: {}", e)),
        }
    })
    .await;

    match result {
        Ok(outcome) => outcome,
        Err(_timeout) => TcpProbeOutcome::Timeout,
    }
}
