use serde::Serialize;

use crate::result::{PingResult, PingStatus};

/// Aggregate statistics computed from a sequence of ping results.
#[derive(Debug, Clone, Serialize)]
pub struct PingStats {
    /// Number of packets transmitted.
    pub transmitted: u64,
    /// Number of successful replies received.
    pub received: u64,
    /// Number of packets lost (timeout, unreachable, or error).
    pub lost: u64,
    /// Packet loss as a percentage (0.0 – 100.0).
    pub loss_pct: f64,
    /// Minimum round-trip time in milliseconds.
    pub min_rtt_ms: Option<f64>,
    /// Maximum round-trip time in milliseconds.
    pub max_rtt_ms: Option<f64>,
    /// Mean round-trip time in milliseconds.
    pub avg_rtt_ms: Option<f64>,
    /// Population standard deviation of round-trip times in milliseconds.
    pub stddev_rtt_ms: Option<f64>,
    /// Mean jitter in milliseconds (RFC 3550 style: mean absolute difference
    /// between consecutive RTTs).
    pub jitter_ms: Option<f64>,
    /// Estimated Mean Opinion Score (1.0 – 4.5) derived from the E-model.
    pub mos: Option<f64>,
}

impl PingStats {
    /// Compute aggregate statistics from a slice of [`PingResult`]s.
    ///
    /// If no results are provided the counters are all zero and every
    /// `Option` field is `None`.
    pub fn from_results(results: &[PingResult]) -> Self {
        let transmitted = results.len() as u64;

        // Collect RTTs (in ms) from successful pings.
        let rtts: Vec<f64> = results
            .iter()
            .filter(|r| r.status == PingStatus::Success)
            .filter_map(|r| r.rtt_ms())
            .collect();

        let received = rtts.len() as u64;
        let lost = transmitted.saturating_sub(received);
        let loss_pct = if transmitted == 0 {
            0.0
        } else {
            (lost as f64 / transmitted as f64) * 100.0
        };

        if rtts.is_empty() {
            return Self {
                transmitted,
                received,
                lost,
                loss_pct,
                min_rtt_ms: None,
                max_rtt_ms: None,
                avg_rtt_ms: None,
                stddev_rtt_ms: None,
                jitter_ms: None,
                mos: None,
            };
        }

        let min_rtt = rtts.iter().copied().fold(f64::INFINITY, f64::min);
        let max_rtt = rtts.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let sum: f64 = rtts.iter().sum();
        let avg_rtt = sum / rtts.len() as f64;

        // Population standard deviation.
        let variance =
            rtts.iter().map(|&r| (r - avg_rtt).powi(2)).sum::<f64>() / rtts.len() as f64;
        let stddev = variance.sqrt();

        // Jitter: mean absolute difference between consecutive RTTs (RFC 3550).
        let jitter = if rtts.len() >= 2 {
            let total_diff: f64 = rtts
                .windows(2)
                .map(|w| (w[1] - w[0]).abs())
                .sum();
            Some(total_diff / (rtts.len() - 1) as f64)
        } else {
            None
        };

        // MOS via E-model simplified formula.
        let mos = Self::compute_mos(avg_rtt, jitter, loss_pct);

        Self {
            transmitted,
            received,
            lost,
            loss_pct,
            min_rtt_ms: Some(min_rtt),
            max_rtt_ms: Some(max_rtt),
            avg_rtt_ms: Some(avg_rtt),
            stddev_rtt_ms: Some(stddev),
            jitter_ms: jitter,
            mos,
        }
    }

    /// Compute Mean Opinion Score using a simplified E-model.
    ///
    /// `avg_rtt` and `jitter` are in milliseconds; `loss_pct` is 0–100.
    ///
    /// R = 93.2 - (effective_latency / 40) - 2.5 * loss_pct
    ///   where effective_latency = avg_rtt + jitter * 2
    ///
    /// MOS = 1 + 0.035*R + R*(R-60)*(100-R)*7e-6, clamped to [1.0, 4.5]
    fn compute_mos(avg_rtt: f64, jitter: Option<f64>, loss_pct: f64) -> Option<f64> {
        let j = jitter.unwrap_or(0.0);
        let effective_latency = avg_rtt + j * 2.0;
        let r = 93.2 - (effective_latency / 40.0) - 2.5 * loss_pct;

        // The polynomial MOS formula is only valid for R in [0, 100].
        if r < 0.0 {
            return Some(1.0);
        }
        let r = r.min(100.0);
        let mos = 1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7.0e-6;
        Some(mos.clamp(1.0, 4.5))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{PingResult, PingStatus};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, SystemTime};

    /// Helper: build a successful PingResult with the given RTT in milliseconds.
    fn success(seq: u16, rtt_ms: f64) -> PingResult {
        PingResult {
            seq,
            target: IpAddr::V4(Ipv4Addr::LOCALHOST),
            rtt: Some(Duration::from_secs_f64(rtt_ms / 1000.0)),
            ttl: Some(64),
            packet_size: 64,
            timestamp: SystemTime::now(),
            status: PingStatus::Success,
        }
    }

    /// Helper: build a timed-out PingResult.
    fn timeout(seq: u16) -> PingResult {
        PingResult {
            seq,
            target: IpAddr::V4(Ipv4Addr::LOCALHOST),
            rtt: None,
            ttl: None,
            packet_size: 0,
            timestamp: SystemTime::now(),
            status: PingStatus::Timeout,
        }
    }

    #[test]
    fn empty_results() {
        let stats = PingStats::from_results(&[]);
        assert_eq!(stats.transmitted, 0);
        assert_eq!(stats.received, 0);
        assert_eq!(stats.lost, 0);
        assert_eq!(stats.loss_pct, 0.0);
        assert!(stats.min_rtt_ms.is_none());
        assert!(stats.max_rtt_ms.is_none());
        assert!(stats.avg_rtt_ms.is_none());
        assert!(stats.stddev_rtt_ms.is_none());
        assert!(stats.jitter_ms.is_none());
        assert!(stats.mos.is_none());
    }

    #[test]
    fn all_timeouts() {
        let results = vec![timeout(0), timeout(1), timeout(2)];
        let stats = PingStats::from_results(&results);

        assert_eq!(stats.transmitted, 3);
        assert_eq!(stats.received, 0);
        assert_eq!(stats.lost, 3);
        assert!((stats.loss_pct - 100.0).abs() < f64::EPSILON);
        assert!(stats.min_rtt_ms.is_none());
        assert!(stats.avg_rtt_ms.is_none());
        assert!(stats.jitter_ms.is_none());
        assert!(stats.mos.is_none());
    }

    #[test]
    fn single_packet() {
        let results = vec![success(0, 10.0)];
        let stats = PingStats::from_results(&results);

        assert_eq!(stats.transmitted, 1);
        assert_eq!(stats.received, 1);
        assert_eq!(stats.lost, 0);
        assert!((stats.loss_pct).abs() < f64::EPSILON);

        assert!((stats.min_rtt_ms.unwrap() - 10.0).abs() < 1e-6);
        assert!((stats.max_rtt_ms.unwrap() - 10.0).abs() < 1e-6);
        assert!((stats.avg_rtt_ms.unwrap() - 10.0).abs() < 1e-6);
        assert!((stats.stddev_rtt_ms.unwrap()).abs() < 1e-6);
        // Only one RTT means no consecutive pair, so jitter is None.
        assert!(stats.jitter_ms.is_none());
        // MOS should still be computed (jitter defaults to 0).
        assert!(stats.mos.is_some());
    }

    #[test]
    fn known_values() {
        // RTTs: 10, 20, 30, 40 ms
        let results = vec![
            success(0, 10.0),
            success(1, 20.0),
            success(2, 30.0),
            success(3, 40.0),
        ];
        let stats = PingStats::from_results(&results);

        assert_eq!(stats.transmitted, 4);
        assert_eq!(stats.received, 4);
        assert_eq!(stats.lost, 0);
        assert!((stats.loss_pct).abs() < f64::EPSILON);

        assert!((stats.min_rtt_ms.unwrap() - 10.0).abs() < 1e-6);
        assert!((stats.max_rtt_ms.unwrap() - 40.0).abs() < 1e-6);
        assert!((stats.avg_rtt_ms.unwrap() - 25.0).abs() < 1e-6);

        // stddev = sqrt(((−15)²+(−5)²+(5)²+(15)²)/4) = sqrt(500/4) = sqrt(125) ≈ 11.180
        let expected_stddev = (125.0_f64).sqrt();
        assert!((stats.stddev_rtt_ms.unwrap() - expected_stddev).abs() < 1e-3);

        // Jitter: |20−10| + |30−20| + |40−30| = 30; 30/3 = 10.0
        assert!((stats.jitter_ms.unwrap() - 10.0).abs() < 1e-6);
    }

    #[test]
    fn mixed_success_and_loss() {
        let results = vec![
            success(0, 15.0),
            timeout(1),
            success(2, 25.0),
            timeout(3),
        ];
        let stats = PingStats::from_results(&results);

        assert_eq!(stats.transmitted, 4);
        assert_eq!(stats.received, 2);
        assert_eq!(stats.lost, 2);
        assert!((stats.loss_pct - 50.0).abs() < f64::EPSILON);

        assert!((stats.min_rtt_ms.unwrap() - 15.0).abs() < 1e-6);
        assert!((stats.max_rtt_ms.unwrap() - 25.0).abs() < 1e-6);
        assert!((stats.avg_rtt_ms.unwrap() - 20.0).abs() < 1e-6);

        // Jitter between the two successful RTTs: |25−15| / 1 = 10.0
        assert!((stats.jitter_ms.unwrap() - 10.0).abs() < 1e-6);
    }

    #[test]
    fn mos_perfect_conditions() {
        // Very low RTT, zero loss => MOS should be near 4.5 (clamped maximum).
        let results = vec![
            success(0, 1.0),
            success(1, 1.0),
            success(2, 1.0),
        ];
        let stats = PingStats::from_results(&results);
        let mos = stats.mos.unwrap();
        assert!(mos >= 4.3, "MOS under perfect conditions should be high, got {mos}");
        assert!(mos <= 4.5, "MOS must not exceed 4.5, got {mos}");
    }

    #[test]
    fn mos_degraded_conditions() {
        // High RTT and high loss => MOS should be low.
        let results: Vec<PingResult> = (0..10)
            .map(|i| {
                if i < 3 {
                    success(i, 300.0)
                } else {
                    timeout(i)
                }
            })
            .collect();
        let stats = PingStats::from_results(&results);
        let mos = stats.mos.unwrap();
        assert!(mos >= 1.0, "MOS must not go below 1.0, got {mos}");
        assert!(mos < 2.5, "MOS under degraded conditions should be low, got {mos}");
    }

    #[test]
    fn mos_clamped_to_floor() {
        // Extreme loss should clamp MOS to 1.0.
        let results: Vec<PingResult> = (0..100)
            .map(|i| {
                if i == 0 {
                    success(i, 2000.0)
                } else {
                    timeout(i)
                }
            })
            .collect();
        let stats = PingStats::from_results(&results);
        let mos = stats.mos.unwrap();
        assert!((mos - 1.0).abs() < f64::EPSILON, "MOS should be clamped to 1.0, got {mos}");
    }
}
