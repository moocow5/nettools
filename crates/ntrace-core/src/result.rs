use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeStatus {
    /// Destination reached (Echo Reply or TCP SYN-ACK)
    Reply,
    /// Intermediate hop (ICMP Time Exceeded)
    TimeExceeded,
    /// Destination unreachable (ICMP Type 3)
    Unreachable,
    /// No response within timeout
    Timeout,
    /// Error sending or receiving
    Error,
}

impl std::fmt::Display for ProbeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reply => write!(f, "reply"),
            Self::TimeExceeded => write!(f, "time_exceeded"),
            Self::Unreachable => write!(f, "unreachable"),
            Self::Timeout => write!(f, "timeout"),
            Self::Error => write!(f, "error"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// TTL value used for this probe
    pub ttl: u8,
    /// Probe number within this TTL (0-indexed)
    pub probe_num: u8,
    /// IP address that responded (router or destination)
    pub source: Option<IpAddr>,
    /// Round-trip time
    pub rtt: Option<Duration>,
    /// Probe status
    pub status: ProbeStatus,
    /// ICMP type of the response (0=Echo Reply, 11=Time Exceeded, 3=Unreachable)
    pub icmp_type: u8,
    /// ICMP code of the response
    pub icmp_code: u8,
    /// When this probe was sent
    pub timestamp: SystemTime,
}

impl ProbeResult {
    /// RTT in milliseconds
    pub fn rtt_ms(&self) -> Option<f64> {
        self.rtt.map(|d| d.as_secs_f64() * 1000.0)
    }

    /// RTT in microseconds
    pub fn rtt_us(&self) -> Option<f64> {
        self.rtt.map(|d| d.as_secs_f64() * 1_000_000.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopResult {
    /// TTL for this hop
    pub ttl: u8,
    /// All probe results for this hop
    pub probes: Vec<ProbeResult>,
    /// Most common responding IP address at this hop
    pub addr: Option<IpAddr>,
}

impl HopResult {
    /// Compute the most common responding IP from probes
    pub fn compute_addr(probes: &[ProbeResult]) -> Option<IpAddr> {
        use std::collections::HashMap;
        let mut counts: HashMap<IpAddr, usize> = HashMap::new();
        for p in probes {
            if let Some(ip) = p.source {
                *counts.entry(ip).or_insert(0) += 1;
            }
        }
        counts.into_iter().max_by_key(|(_, c)| *c).map(|(ip, _)| ip)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResult {
    /// Resolved target IP
    pub target: IpAddr,
    /// Original hostname (if DNS resolved)
    pub hostname: Option<String>,
    /// Per-hop results, ordered by TTL
    pub hops: Vec<HopResult>,
    /// Whether the trace reached the destination
    pub reached_destination: bool,
    /// When the trace started
    pub started_at: SystemTime,
    /// When the trace completed
    pub completed_at: SystemTime,
}
