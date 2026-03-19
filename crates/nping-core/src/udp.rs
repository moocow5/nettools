//! UDP ping implementation.
//!
//! Sends a UDP packet to the target port and measures response time.
//! A response can be:
//! - A UDP reply (e.g., DNS response on port 53)
//! - An ICMP "port unreachable" message (most common for non-listening ports)
//! - Timeout (packet dropped, filtered, or no ICMP response)
//!
//! Works cross-platform using `tokio::net::UdpSocket`.

use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::config::PingConfig;
use crate::error::{NpingError, Result};
use crate::result::{PingResult, PingStatus};
use crate::timing;

/// Runs a UDP ping loop.
///
/// For each iteration, sends a UDP packet to `target:port` and waits for
/// either a UDP reply or a timeout. ICMP port-unreachable errors surface
/// as connection errors on connected UDP sockets.
pub async fn run_udp_ping(
    config: &PingConfig,
    target_ip: IpAddr,
    tx: mpsc::Sender<PingResult>,
) -> Result<()> {
    let port = config.port.ok_or_else(|| {
        NpingError::Other("UDP ping requires a port (--port)".into())
    })?;

    let target_addr = SocketAddr::new(target_ip, port);

    // Bind to an ephemeral port. Use 0.0.0.0 for IPv4 or [::] for IPv6.
    let bind_addr: SocketAddr = match target_ip {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };

    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(NpingError::SocketCreate)?;

    // Connect the socket so that ICMP errors are delivered to us via recv.
    socket
        .connect(target_addr)
        .await
        .map_err(|e| NpingError::Send {
            target: target_ip,
            source: e,
        })?;

    let mut seq: u64 = 0;

    // Build a small payload with a sequence marker.
    let base_payload = vec![0u8; config.packet_size.min(1400)];

    loop {
        if let Some(count) = config.count {
            if seq >= count {
                break;
            }
        }

        let icmp_seq = seq as u16;
        let start = timing::now();

        // Build payload with sequence number embedded.
        let mut payload = base_payload.clone();
        if payload.len() >= 2 {
            let seq_bytes = icmp_seq.to_be_bytes();
            payload[0] = seq_bytes[0];
            payload[1] = seq_bytes[1];
        }

        // Send the UDP packet.
        let send_result = socket.send(&payload).await;

        let result = match send_result {
            Ok(bytes_sent) => {
                // Wait for a reply or ICMP error.
                let mut recv_buf = [0u8; 1500];
                match tokio::time::timeout(config.timeout, socket.recv(&mut recv_buf)).await {
                    Ok(Ok(n)) => {
                        // Got a UDP reply.
                        let rtt = start.elapsed();
                        PingResult {
                            seq: icmp_seq,
                            target: target_ip,
                            rtt: Some(rtt),
                            ttl: None,
                            packet_size: n,
                            timestamp: SystemTime::now(),
                            status: PingStatus::Success,
                        }
                    }
                    Ok(Err(e)) => {
                        // ICMP port-unreachable or other error.
                        let rtt = start.elapsed();
                        if e.kind() == std::io::ErrorKind::ConnectionRefused {
                            // ICMP port unreachable — host is reachable, port closed.
                            PingResult {
                                seq: icmp_seq,
                                target: target_ip,
                                rtt: Some(rtt),
                                ttl: None,
                                packet_size: bytes_sent,
                                timestamp: SystemTime::now(),
                                status: PingStatus::Success,
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
                }
            }
            Err(_) => PingResult {
                seq: icmp_seq,
                target: target_ip,
                rtt: None,
                ttl: None,
                packet_size: 0,
                timestamp: SystemTime::now(),
                status: PingStatus::Error,
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
