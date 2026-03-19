use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nping_core::packet::{parse_echo_reply, ICMP_ECHO_REPLY};
use nping_core::socket::PingSocket;
use nping_core::IcmpSocket;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

/// Result of pinging a single host.
#[derive(Debug, Clone)]
pub struct PingSweepResult {
    pub ip: IpAddr,
    pub alive: bool,
    pub ttl: Option<u8>,
    pub rtt_ms: Option<f64>,
}

/// Perform an ICMP ping sweep across all given IPs.
pub async fn ping_sweep(
    ips: &[IpAddr],
    timeout: Duration,
    concurrency: usize,
) -> Vec<PingSweepResult> {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(ips.len());

    for &ip in ips {
        let sem = semaphore.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            ping_one(ip, timeout).await
        });
        handles.push(handle);
    }

    let mut results = Vec::with_capacity(ips.len());
    for handle in handles {
        match handle.await {
            Ok(result) => results.push(result),
            Err(e) => warn!("ping task panicked: {}", e),
        }
    }
    results
}

async fn ping_one(ip: IpAddr, timeout: Duration) -> PingSweepResult {
    let socket = match IcmpSocket::new() {
        Ok(s) => s,
        Err(e) => {
            debug!("failed to create socket for {}: {}", ip, e);
            return PingSweepResult {
                ip,
                alive: false,
                ttl: None,
                rtt_ms: None,
            };
        }
    };

    // Build ICMP echo request
    let identifier = (std::process::id() as u16) ^ (ip_to_u16(ip));
    let sequence = 1u16;
    let packet = build_echo_request(identifier, sequence);

    let start = std::time::Instant::now();
    if let Err(e) = socket.send_ping(&packet, ip).await {
        debug!("send to {} failed: {}", ip, e);
        return PingSweepResult {
            ip,
            alive: false,
            ttl: None,
            rtt_ms: None,
        };
    }

    let deadline = Instant::now() + timeout;

    loop {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => d,
            _ => {
                // Timeout expired while waiting for a matching reply.
                return PingSweepResult {
                    ip,
                    alive: false,
                    ttl: None,
                    rtt_ms: None,
                };
            }
        };

        match socket.recv_ping(remaining).await {
            Ok(Some(recv)) => {
                // Verify source IP matches the target we pinged.
                if recv.source != ip {
                    debug!(
                        "ignoring reply from {} (expected {})",
                        recv.source, ip
                    );
                    continue;
                }

                // Parse the ICMP header and verify type, identifier, and sequence.
                match parse_echo_reply(&recv.icmp_data) {
                    Ok(reply)
                        if reply.type_field == ICMP_ECHO_REPLY
                            && reply.identifier == identifier
                            && reply.sequence == sequence =>
                    {
                        let rtt = start.elapsed().as_secs_f64() * 1000.0;
                        return PingSweepResult {
                            ip,
                            alive: true,
                            ttl: recv.ttl,
                            rtt_ms: Some(rtt),
                        };
                    }
                    Ok(reply) => {
                        debug!(
                            "ignoring non-matching ICMP reply from {}: type={} id={} seq={} (expected type={} id={} seq={})",
                            recv.source,
                            reply.type_field,
                            reply.identifier,
                            reply.sequence,
                            ICMP_ECHO_REPLY,
                            identifier,
                            sequence,
                        );
                        continue;
                    }
                    Err(e) => {
                        debug!("failed to parse ICMP reply from {}: {}", recv.source, e);
                        continue;
                    }
                }
            }
            Ok(None) => {
                // Timeout — no reply received within the remaining window.
                return PingSweepResult {
                    ip,
                    alive: false,
                    ttl: None,
                    rtt_ms: None,
                };
            }
            Err(e) => {
                debug!("recv error while waiting for reply from {}: {}", ip, e);
                return PingSweepResult {
                    ip,
                    alive: false,
                    ttl: None,
                    rtt_ms: None,
                };
            }
        }
    }
}

fn ip_to_u16(ip: IpAddr) -> u16 {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            ((o[2] as u16) << 8) | (o[3] as u16)
        }
        IpAddr::V6(_) => 0,
    }
}

fn build_echo_request(identifier: u16, sequence: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 64];
    packet[0] = 8; // Echo Request
    packet[1] = 0; // Code
    // checksum at [2..4] — fill after
    packet[4] = (identifier >> 8) as u8;
    packet[5] = (identifier & 0xFF) as u8;
    packet[6] = (sequence >> 8) as u8;
    packet[7] = (sequence & 0xFF) as u8;
    // Fill payload with pattern
    for i in 8..64 {
        packet[i] = (i & 0xFF) as u8;
    }
    // Compute checksum
    let checksum = icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xFF) as u8;
    packet
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i < data.len() - 1 {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if data.len() % 2 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}
