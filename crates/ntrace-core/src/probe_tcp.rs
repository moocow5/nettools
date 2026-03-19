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
            if !is_in_progress(&e) {
                return TcpProbeOutcome::Error(format!("connect: {}", e));
            }
            // Connection in progress — wait for completion below
        }
    }

    // Wait for connection to complete or timeout.
    // Use platform-specific async polling.
    let result = tokio::time::timeout(timeout, wait_for_connect(socket, start)).await;

    match result {
        Ok(outcome) => outcome,
        Err(_timeout) => TcpProbeOutcome::Timeout,
    }
}

/// Check if a connect() error indicates the operation is in progress.
fn is_in_progress(e: &std::io::Error) -> bool {
    if e.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    let raw = e.raw_os_error().unwrap_or(0);
    // EINPROGRESS: macOS=36, Linux=115, Windows WSAEWOULDBLOCK=10035
    raw == 36 || raw == 115 || raw == 10035
}

/// Unix: use AsyncFd to wait for the socket to become writable.
#[cfg(unix)]
async fn wait_for_connect(socket: socket2::Socket, start: Instant) -> TcpProbeOutcome {
    let async_fd = match tokio::io::unix::AsyncFd::new(socket) {
        Ok(fd) => fd,
        Err(e) => return TcpProbeOutcome::Error(format!("AsyncFd: {}", e)),
    };

    match async_fd.writable().await {
        Ok(_guard) => check_connect_result(async_fd.get_ref(), start),
        Err(e) => TcpProbeOutcome::Error(format!("writable: {}", e)),
    }
}

/// Windows: use spawn_blocking with poll to wait for the socket to become writable.
#[cfg(windows)]
async fn wait_for_connect(socket: socket2::Socket, start: Instant) -> TcpProbeOutcome {
    use std::sync::Arc;
    let socket = Arc::new(socket);
    let sock = socket.clone();

    tokio::task::spawn_blocking(move || {
        // Poll the socket for writability using socket2's poll API.
        // The socket becomes writable when connect() completes (success or error).
        let deadline = start + Duration::from_secs(10);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return TcpProbeOutcome::Timeout;
            }

            // Use a short poll timeout and loop
            let poll_timeout = remaining.min(Duration::from_millis(50));

            // Check if the socket is writable (connect completed) using take_error
            match sock.take_error() {
                Ok(None) => {
                    // Try a zero-length send to check if the socket is connected.
                    // On a connected socket this succeeds; on a pending one it returns WouldBlock.
                    match sock.send(&[]) {
                        Ok(_) => {
                            return TcpProbeOutcome::Connected {
                                rtt: start.elapsed(),
                            };
                        }
                        Err(e) => {
                            let raw = e.raw_os_error().unwrap_or(0);
                            if raw == 10035 {
                                // WSAEWOULDBLOCK — still connecting
                                std::thread::sleep(poll_timeout);
                                continue;
                            }
                            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                                return TcpProbeOutcome::Refused {
                                    rtt: start.elapsed(),
                                };
                            }
                            // WSAENOTCONN (10057) means connect hasn't completed
                            if raw == 10057 {
                                std::thread::sleep(poll_timeout);
                                continue;
                            }
                            // Other error — likely ICMP error caused the connect to fail
                            return TcpProbeOutcome::Timeout;
                        }
                    }
                }
                Ok(Some(e)) => {
                    if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        return TcpProbeOutcome::Refused {
                            rtt: start.elapsed(),
                        };
                    }
                    return TcpProbeOutcome::Timeout;
                }
                Err(e) => return TcpProbeOutcome::Error(format!("take_error: {}", e)),
            }
        }
    })
    .await
    .unwrap_or(TcpProbeOutcome::Error("blocking task panicked".into()))
}

/// Check the connect result via SO_ERROR.
fn check_connect_result(socket: &socket2::Socket, start: Instant) -> TcpProbeOutcome {
    match socket.take_error() {
        Ok(None) => TcpProbeOutcome::Connected {
            rtt: start.elapsed(),
        },
        Ok(Some(e)) => {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                TcpProbeOutcome::Refused {
                    rtt: start.elapsed(),
                }
            } else {
                // Other error — likely the probe was intercepted or TTL expired.
                // The ICMP Time Exceeded will be received on the ICMP socket.
                TcpProbeOutcome::Timeout
            }
        }
        Err(e) => TcpProbeOutcome::Error(format!("take_error: {}", e)),
    }
}
