use serde::Serialize;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// Status of an individual ping attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PingStatus {
    Success,
    Timeout,
    Unreachable,
    Error,
}

/// Result of a single ping packet.
#[derive(Debug, Clone, Serialize)]
pub struct PingResult {
    /// Sequence number.
    pub seq: u16,
    /// Target IP address.
    pub target: IpAddr,
    /// Round-trip time (None if timed out or error).
    pub rtt: Option<Duration>,
    /// TTL from the reply packet.
    pub ttl: Option<u8>,
    /// Size of the reply payload in bytes.
    pub packet_size: usize,
    /// Wall-clock timestamp when this result was recorded.
    pub timestamp: SystemTime,
    /// Status of this ping attempt.
    pub status: PingStatus,
}

impl PingResult {
    /// RTT in microseconds, or None.
    pub fn rtt_us(&self) -> Option<f64> {
        self.rtt.map(|d| d.as_secs_f64() * 1_000_000.0)
    }

    /// RTT in milliseconds, or None.
    pub fn rtt_ms(&self) -> Option<f64> {
        self.rtt.map(|d| d.as_secs_f64() * 1_000.0)
    }
}

/// A complete ping session with all results.
#[derive(Debug, Clone)]
pub struct PingSession {
    pub target: IpAddr,
    pub hostname: Option<String>,
    pub results: Vec<PingResult>,
    pub started_at: SystemTime,
}
