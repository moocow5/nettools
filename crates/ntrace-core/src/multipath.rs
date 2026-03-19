//! Multipath detection: identifies load-balanced hops in traceroute results.
//!
//! When multiple distinct IPs respond at the same TTL across different probes,
//! it indicates the presence of a load balancer at that hop.

use crate::result::ProbeResult;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Detection result for a single hop
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipathHop {
    /// TTL of this hop
    pub ttl: u8,
    /// All distinct IPs observed at this TTL
    pub addresses: Vec<IpAddr>,
    /// Whether this hop appears to be load-balanced
    pub is_load_balanced: bool,
    /// Number of probes that received responses
    pub responses: usize,
    /// Number of probes that timed out
    pub timeouts: usize,
}

/// Overall multipath analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipathAnalysis {
    /// Per-hop multipath results
    pub hops: Vec<MultipathHop>,
    /// Total number of load-balanced hops detected
    pub load_balanced_count: usize,
}

/// Analyze probe results to detect multipath routing / load balancing.
///
/// Groups probes by TTL and checks if multiple distinct IPs responded
/// at the same TTL, which indicates per-packet or per-flow load balancing.
pub fn detect_multipath(probes: &[ProbeResult]) -> MultipathAnalysis {
    // Group probes by TTL
    let mut by_ttl: HashMap<u8, Vec<&ProbeResult>> = HashMap::new();
    for probe in probes {
        by_ttl.entry(probe.ttl).or_default().push(probe);
    }

    let mut hops: Vec<MultipathHop> = Vec::new();
    let mut load_balanced_count = 0;

    let mut ttls: Vec<u8> = by_ttl.keys().copied().collect();
    ttls.sort();

    for ttl in ttls {
        let ttl_probes = &by_ttl[&ttl];
        let mut ips: HashSet<IpAddr> = HashSet::new();
        let mut timeouts = 0;
        let mut responses = 0;

        for probe in ttl_probes {
            if let Some(ip) = probe.source {
                ips.insert(ip);
                responses += 1;
            } else {
                timeouts += 1;
            }
        }

        let addresses: Vec<IpAddr> = ips.into_iter().collect();
        let is_load_balanced = addresses.len() > 1;

        if is_load_balanced {
            load_balanced_count += 1;
        }

        hops.push(MultipathHop {
            ttl,
            addresses,
            is_load_balanced,
            responses,
            timeouts,
        });
    }

    MultipathAnalysis {
        hops,
        load_balanced_count,
    }
}

/// Detect flow-based vs packet-based load balancing.
///
/// If Paris-mode probes (constant flow ID) see multiple IPs at a hop,
/// it's per-packet load balancing. If normal probes see multiple IPs
/// but Paris probes see only one, it's per-flow load balancing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadBalancerType {
    /// Per-flow: routes based on flow hash (5-tuple)
    PerFlow,
    /// Per-packet: round-robin or random
    PerPacket,
    /// Unknown: not enough data to determine
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{ProbeResult, ProbeStatus};
    use std::time::{Duration, SystemTime};

    fn make_probe(ttl: u8, probe_num: u8, source: Option<IpAddr>) -> ProbeResult {
        ProbeResult {
            ttl,
            probe_num,
            source,
            rtt: source.map(|_| Duration::from_millis(10)),
            status: if source.is_some() {
                ProbeStatus::TimeExceeded
            } else {
                ProbeStatus::Timeout
            },
            icmp_type: 11,
            icmp_code: 0,
            timestamp: SystemTime::now(),
        }
    }

    #[test]
    fn test_no_multipath() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let probes = vec![
            make_probe(1, 0, Some(ip1)),
            make_probe(1, 1, Some(ip1)),
            make_probe(1, 2, Some(ip1)),
            make_probe(2, 0, Some(ip2)),
            make_probe(2, 1, Some(ip2)),
        ];

        let analysis = detect_multipath(&probes);
        assert_eq!(analysis.load_balanced_count, 0);
        assert!(!analysis.hops[0].is_load_balanced);
        assert!(!analysis.hops[1].is_load_balanced);
    }

    #[test]
    fn test_multipath_detected() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();
        let probes = vec![
            make_probe(1, 0, Some(ip1)),
            make_probe(1, 1, Some(ip2)),
            make_probe(1, 2, Some(ip1)),
            make_probe(2, 0, Some(ip3)),
            make_probe(2, 1, Some(ip3)),
        ];

        let analysis = detect_multipath(&probes);
        assert_eq!(analysis.load_balanced_count, 1);
        assert!(analysis.hops[0].is_load_balanced);
        assert_eq!(analysis.hops[0].addresses.len(), 2);
        assert!(!analysis.hops[1].is_load_balanced);
    }

    #[test]
    fn test_all_timeouts() {
        let probes = vec![make_probe(1, 0, None), make_probe(1, 1, None)];

        let analysis = detect_multipath(&probes);
        assert_eq!(analysis.load_balanced_count, 0);
        assert_eq!(analysis.hops[0].timeouts, 2);
        assert_eq!(analysis.hops[0].responses, 0);
    }

    #[test]
    fn test_empty_input() {
        let analysis = detect_multipath(&[]);
        assert_eq!(analysis.load_balanced_count, 0);
        assert!(analysis.hops.is_empty());
    }
}
