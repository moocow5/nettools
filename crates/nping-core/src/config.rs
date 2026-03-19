use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Ping protocol mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PingMode {
    #[default]
    Icmp,
    Tcp,
    TcpConnect,
    Udp,
}

impl std::fmt::Display for PingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PingMode::Icmp => write!(f, "icmp"),
            PingMode::Tcp => write!(f, "tcp"),
            PingMode::TcpConnect => write!(f, "tcp-connect"),
            PingMode::Udp => write!(f, "udp"),
        }
    }
}

/// Payload fill pattern for ping packets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadPattern {
    /// Fill with zeros.
    Zeros,
    /// Fill with 0xAA bytes.
    AltBits,
    /// Fill with random data.
    Random,
    /// Fill with a specific byte.
    Byte(u8),
}

impl Default for PayloadPattern {
    fn default() -> Self {
        PayloadPattern::Zeros
    }
}

/// Configuration for a ping operation.
#[derive(Debug, Clone)]
pub struct PingConfig {
    /// Target hostname or IP address.
    pub target: String,
    /// Ping protocol mode.
    pub mode: PingMode,
    /// Port for TCP/UDP modes.
    pub port: Option<u16>,
    /// Number of pings to send (None = infinite).
    pub count: Option<u64>,
    /// Interval between pings.
    pub interval: Duration,
    /// Timeout for each ping.
    pub timeout: Duration,
    /// ICMP payload size in bytes.
    pub packet_size: usize,
    /// IP TTL (Time To Live).
    pub ttl: Option<u8>,
    /// IP ToS (Type of Service) / DSCP value.
    pub tos: Option<u8>,
    /// Payload fill pattern.
    pub payload_pattern: PayloadPattern,
}

impl Default for PingConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            mode: PingMode::Icmp,
            port: None,
            count: None,
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            packet_size: 56, // standard ping payload size
            ttl: None,
            tos: None,
            payload_pattern: PayloadPattern::default(),
        }
    }
}
