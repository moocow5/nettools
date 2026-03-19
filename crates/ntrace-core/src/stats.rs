//! Per-hop statistics for traceroute.

use crate::result::ProbeResult;
use serde::{Serialize, Deserialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopStats {
    pub ttl: u8,
    pub addr: Option<IpAddr>,
    pub sent: u64,
    pub received: u64,
    pub loss_pct: f64,
    pub min_rtt_ms: Option<f64>,
    pub max_rtt_ms: Option<f64>,
    pub avg_rtt_ms: Option<f64>,
    pub stddev_rtt_ms: Option<f64>,
    pub last_rtt_ms: Option<f64>,
}

impl HopStats {
    /// Compute statistics from a slice of probe results for a single hop.
    pub fn from_probes(ttl: u8, probes: &[ProbeResult]) -> Self {
        let sent = probes.len() as u64;
        let received = probes.iter().filter(|p| p.rtt.is_some()).count() as u64;
        let loss_pct = if sent > 0 {
            ((sent - received) as f64 / sent as f64) * 100.0
        } else {
            0.0
        };

        let rtts: Vec<f64> = probes
            .iter()
            .filter_map(|p| p.rtt_ms())
            .collect();

        let min_rtt_ms = rtts.iter().copied().reduce(f64::min);
        let max_rtt_ms = rtts.iter().copied().reduce(f64::max);
        let avg_rtt_ms = if !rtts.is_empty() {
            Some(rtts.iter().sum::<f64>() / rtts.len() as f64)
        } else {
            None
        };
        let stddev_rtt_ms = if rtts.len() > 1 {
            let avg = avg_rtt_ms.unwrap();
            let variance = rtts.iter().map(|r| (r - avg).powi(2)).sum::<f64>() / rtts.len() as f64;
            Some(variance.sqrt())
        } else {
            None
        };
        let last_rtt_ms = rtts.last().copied();

        // Most common responding IP
        let addr = crate::result::HopResult::compute_addr(probes);

        Self {
            ttl,
            addr,
            sent,
            received,
            loss_pct,
            min_rtt_ms,
            max_rtt_ms,
            avg_rtt_ms,
            stddev_rtt_ms,
            last_rtt_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{ProbeResult, ProbeStatus};
    use std::time::{Duration, SystemTime};
    use std::net::IpAddr;

    fn make_probe(ttl: u8, rtt_ms: Option<f64>, source: Option<IpAddr>) -> ProbeResult {
        ProbeResult {
            ttl,
            probe_num: 0,
            source,
            rtt: rtt_ms.map(|ms| Duration::from_secs_f64(ms / 1000.0)),
            status: if rtt_ms.is_some() { ProbeStatus::TimeExceeded } else { ProbeStatus::Timeout },
            icmp_type: if rtt_ms.is_some() { 11 } else { 0 },
            icmp_code: 0,
            timestamp: SystemTime::now(),
        }
    }

    #[test]
    fn test_basic_stats() {
        let ip = "10.0.0.1".parse().unwrap();
        let probes = vec![
            make_probe(1, Some(10.0), Some(ip)),
            make_probe(1, Some(20.0), Some(ip)),
            make_probe(1, Some(15.0), Some(ip)),
        ];

        let stats = HopStats::from_probes(1, &probes);
        assert_eq!(stats.ttl, 1);
        assert_eq!(stats.sent, 3);
        assert_eq!(stats.received, 3);
        assert_eq!(stats.loss_pct, 0.0);
        assert_eq!(stats.min_rtt_ms, Some(10.0));
        assert_eq!(stats.max_rtt_ms, Some(20.0));
        assert!((stats.avg_rtt_ms.unwrap() - 15.0).abs() < 0.01);
        assert_eq!(stats.addr, Some(ip));
    }

    #[test]
    fn test_with_timeouts() {
        let ip = "10.0.0.1".parse().unwrap();
        let probes = vec![
            make_probe(2, Some(10.0), Some(ip)),
            make_probe(2, None, None),
            make_probe(2, Some(20.0), Some(ip)),
        ];

        let stats = HopStats::from_probes(2, &probes);
        assert_eq!(stats.sent, 3);
        assert_eq!(stats.received, 2);
        assert!((stats.loss_pct - 33.333).abs() < 0.1);
    }

    #[test]
    fn test_all_timeouts() {
        let probes = vec![
            make_probe(3, None, None),
            make_probe(3, None, None),
        ];

        let stats = HopStats::from_probes(3, &probes);
        assert_eq!(stats.sent, 2);
        assert_eq!(stats.received, 0);
        assert_eq!(stats.loss_pct, 100.0);
        assert_eq!(stats.min_rtt_ms, None);
        assert_eq!(stats.addr, None);
    }

    #[test]
    fn test_empty_probes() {
        let stats = HopStats::from_probes(1, &[]);
        assert_eq!(stats.sent, 0);
        assert_eq!(stats.loss_pct, 0.0);
    }
}
