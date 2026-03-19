use std::time::Duration;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeMethod {
    Icmp,
    Udp,
    TcpSyn,
}

impl Default for ProbeMethod {
    fn default() -> Self {
        Self::Icmp
    }
}

impl std::fmt::Display for ProbeMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Icmp => write!(f, "icmp"),
            Self::Udp => write!(f, "udp"),
            Self::TcpSyn => write!(f, "tcp"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TraceConfig {
    pub target: String,
    pub method: ProbeMethod,
    pub first_ttl: u8,
    pub max_ttl: u8,
    pub probes_per_hop: u8,
    pub timeout: Duration,
    pub send_interval: Duration,
    pub port: u16,
    pub packet_size: usize,
    pub concurrent: bool,
    pub max_inflight: usize,
    pub paris_mode: bool,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            method: ProbeMethod::default(),
            first_ttl: 1,
            max_ttl: 30,
            probes_per_hop: 3,
            timeout: Duration::from_secs(2),
            send_interval: Duration::from_millis(50),
            port: 33434,
            packet_size: 60,
            concurrent: false,
            max_inflight: 16,
            paris_mode: false,
        }
    }
}
