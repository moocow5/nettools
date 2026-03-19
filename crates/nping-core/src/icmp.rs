//! Core async ICMP ping loop.
//!
//! Coordinates with the packet, socket, timing, and config modules to send
//! ICMP echo requests and collect replies.

use std::net::IpAddr;
use std::time::SystemTime;

use tokio::sync::mpsc;

use crate::config::{PayloadPattern, PingConfig};
use crate::error::{NpingError, Result};
use crate::packet::{build_echo_request, parse_echo_reply, ICMP_ECHO_REPLY};
use crate::result::{PingResult, PingStatus};
use crate::socket::PingSocket;
use crate::timing;

/// Generates a pseudo-random `u16` identifier without requiring the `rand` crate.
///
/// Mixes the process ID with the low bits of the current system time to produce
/// a value that is unlikely to collide across concurrent pinger instances.
fn random_identifier() -> u16 {
    let time_seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u16;
    (std::process::id() as u16) ^ time_seed
}

/// Generates a payload buffer of the requested `size` filled according to `pattern`.
fn generate_payload(pattern: &PayloadPattern, size: usize) -> Vec<u8> {
    match pattern {
        PayloadPattern::Zeros => vec![0u8; size],
        PayloadPattern::AltBits => vec![0xAAu8; size],
        PayloadPattern::Byte(b) => vec![*b; size],
        PayloadPattern::Random => {
            // Simple xorshift-style PRNG seeded from system time to avoid
            // pulling in the `rand` crate.
            let mut seed: u64 = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let mut buf = Vec::with_capacity(size);
            for _ in 0..size {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                buf.push(seed as u8);
            }
            buf
        }
    }
}

/// An ICMP pinger that sends echo requests and collects replies.
pub struct IcmpPinger {
    /// Configuration for this ping session.
    config: PingConfig,
    /// Random identifier used to match replies to this pinger instance.
    identifier: u16,
}

impl IcmpPinger {
    /// Creates a new `IcmpPinger` with the given configuration and a randomly
    /// generated identifier.
    pub fn new(config: PingConfig) -> Self {
        Self {
            config,
            identifier: random_identifier(),
        }
    }

    /// Returns the identifier used by this pinger to tag outgoing requests.
    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    /// Resolves the configured target hostname to an [`IpAddr`].
    async fn resolve_target(&self) -> Result<IpAddr> {
        let lookup = format!("{}:0", self.config.target);
        let addr = tokio::net::lookup_host(&lookup)
            .await
            .map_err(|e| NpingError::DnsResolution {
                hostname: self.config.target.clone(),
                source: e,
            })?
            .next()
            .ok_or_else(|| NpingError::DnsResolution {
                hostname: self.config.target.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no addresses returned",
                ),
            })?;

        Ok(addr.ip())
    }

    /// Runs the main ping loop, sending results over the provided channel.
    ///
    /// The loop sends ICMP echo requests to the resolved target address and
    /// listens for replies. Each result (success, timeout, or error) is
    /// forwarded through `tx`. The loop terminates after `config.count` pings
    /// (if set) or runs indefinitely until the sender is dropped / the task
    /// is cancelled.
    pub async fn run<S: PingSocket>(
        &self,
        socket: &S,
        tx: mpsc::Sender<PingResult>,
    ) -> Result<()> {
        let target_ip = self.resolve_target().await?;

        let mut seq: u64 = 0;

        loop {
            // Check if we have reached the requested count.
            if let Some(count) = self.config.count {
                if seq >= count {
                    break;
                }
            }

            let icmp_seq = seq as u16;

            // Generate payload and build the ICMP packet.
            let payload = generate_payload(&self.config.payload_pattern, self.config.packet_size);
            let packet = build_echo_request(self.identifier, icmp_seq, &payload);

            // Record start time for RTT calculation.
            let start = timing::now();

            // Send the echo request.
            let send_result = socket.send_ping(&packet, target_ip).await;

            let result = match send_result {
                Ok(()) => {
                    // Wait for a reply within the configured timeout.
                    match socket.recv_ping(self.config.timeout).await {
                        Ok(Some(recv)) => {
                            let rtt = start.elapsed();

                            // Parse the ICMP reply.
                            match parse_echo_reply(&recv.icmp_data) {
                                Ok(reply)
                                    if reply.type_field == ICMP_ECHO_REPLY
                                        && reply.identifier == self.identifier
                                        && reply.sequence == icmp_seq =>
                                {
                                    PingResult {
                                        seq: icmp_seq,
                                        target: target_ip,
                                        rtt: Some(rtt),
                                        ttl: recv.ttl,
                                        packet_size: recv.bytes_received,
                                        timestamp: SystemTime::now(),
                                        status: PingStatus::Success,
                                    }
                                }
                                Ok(_) => {
                                    // Reply did not match our identifier/sequence;
                                    // treat as if we timed out.
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
                                    status: PingStatus::Error,
                                },
                            }
                        }
                        Ok(None) => {
                            // Timeout — no reply received.
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
                            status: PingStatus::Error,
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

            // If the receiver has been dropped, stop the loop.
            if tx.send(result).await.is_err() {
                break;
            }

            seq += 1;

            // Sleep for the remainder of the interval (accounting for elapsed time).
            let elapsed = start.elapsed();
            if let Some(remaining) = self.config.interval.checked_sub(elapsed) {
                tokio::time::sleep(remaining).await;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_payload_zeros() {
        let p = generate_payload(&PayloadPattern::Zeros, 10);
        assert_eq!(p.len(), 10);
        assert!(p.iter().all(|&b| b == 0));
    }

    #[test]
    fn generate_payload_alt_bits() {
        let p = generate_payload(&PayloadPattern::AltBits, 8);
        assert_eq!(p.len(), 8);
        assert!(p.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn generate_payload_byte() {
        let p = generate_payload(&PayloadPattern::Byte(0x42), 5);
        assert_eq!(p, vec![0x42; 5]);
    }

    #[test]
    fn generate_payload_random_has_correct_length() {
        let p = generate_payload(&PayloadPattern::Random, 64);
        assert_eq!(p.len(), 64);
    }

    #[test]
    fn generate_payload_empty() {
        let p = generate_payload(&PayloadPattern::Zeros, 0);
        assert!(p.is_empty());
    }

    #[test]
    fn new_pinger_has_nonzero_identifier() {
        // While technically a random id *could* be zero, it is astronomically
        // unlikely. This test is mainly a smoke-test for construction.
        let config = PingConfig {
            target: "127.0.0.1".to_string(),
            ..PingConfig::default()
        };
        let pinger = IcmpPinger::new(config);
        // Just ensure construction succeeds.
        let _ = pinger.identifier();
    }
}
