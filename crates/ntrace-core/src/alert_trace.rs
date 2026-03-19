//! Path change alerting and hop-level threshold alerts for traceroute.
//!
//! Follows the pattern from nping-core's `alert.rs` but adapted for
//! traceroute-specific metrics: per-hop latency, per-hop loss, and path changes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::stats::HopStats;

/// Default cooldown between repeated alerts for the same metric.
fn default_cooldown_secs() -> u64 {
    60
}

/// Configuration for traceroute alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceAlertConfig {
    /// Maximum acceptable average latency (ms) at any single hop.
    pub max_hop_latency_ms: Option<f64>,
    /// Maximum acceptable packet loss percentage at any single hop.
    pub max_hop_loss_pct: Option<f64>,
    /// Whether to alert on path changes (hop IP address changes).
    #[serde(default = "default_true")]
    pub alert_on_path_change: bool,
    /// Cooldown period in seconds between repeated alerts for the same metric+TTL.
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u64,
}

fn default_true() -> bool {
    true
}

impl Default for TraceAlertConfig {
    fn default() -> Self {
        Self {
            max_hop_latency_ms: None,
            max_hop_loss_pct: None,
            alert_on_path_change: true,
            cooldown_secs: default_cooldown_secs(),
        }
    }
}

impl TraceAlertConfig {
    /// Get the cooldown as a [`Duration`].
    pub fn cooldown(&self) -> Duration {
        Duration::from_secs(self.cooldown_secs)
    }
}

/// A fired traceroute alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TraceAlert {
    /// The IP address at a hop changed between rounds.
    PathChanged {
        ttl: u8,
        old_addr: Option<IpAddr>,
        new_addr: Option<IpAddr>,
        message: String,
    },
    /// Average latency at a hop exceeded the configured threshold.
    HopLatencyHigh {
        ttl: u8,
        avg_ms: f64,
        threshold: f64,
        message: String,
    },
    /// Packet loss at a hop exceeded the configured threshold.
    HopLossHigh {
        ttl: u8,
        loss_pct: f64,
        threshold: f64,
        message: String,
    },
    /// A new IP appeared at a TTL that was previously unresponsive.
    NewHopAppeared {
        ttl: u8,
        addr: IpAddr,
        message: String,
    },
    /// A previously responsive hop stopped responding.
    HopDisappeared {
        ttl: u8,
        addr: IpAddr,
        message: String,
    },
}

impl std::fmt::Display for TraceAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathChanged { message, .. } => write!(f, "{}", message),
            Self::HopLatencyHigh { message, .. } => write!(f, "{}", message),
            Self::HopLossHigh { message, .. } => write!(f, "{}", message),
            Self::NewHopAppeared { message, .. } => write!(f, "{}", message),
            Self::HopDisappeared { message, .. } => write!(f, "{}", message),
        }
    }
}

/// Alert state machine with per-metric cooldown tracking.
///
/// Tracks when each alert (keyed by metric name + TTL) was last fired,
/// and suppresses duplicate alerts within the cooldown window.
pub struct TraceAlertState {
    config: TraceAlertConfig,
    last_fired: HashMap<String, Instant>,
}

impl TraceAlertState {
    /// Create a new alert state from configuration.
    pub fn new(config: TraceAlertConfig) -> Self {
        Self {
            config,
            last_fired: HashMap::new(),
        }
    }

    /// Check hop stats and return any alerts that should fire.
    ///
    /// Evaluates the hop's average latency and loss against configured
    /// thresholds, respecting the cooldown period.
    pub fn check(&mut self, ttl: u8, stats: &HopStats) -> Vec<TraceAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        // Check latency threshold
        if let (Some(threshold), Some(avg)) = (self.config.max_hop_latency_ms, stats.avg_rtt_ms) {
            let key = format!("latency:{}", ttl);
            if avg > threshold && !self.in_cooldown(&key, now) {
                self.last_fired.insert(key, now);
                alerts.push(TraceAlert::HopLatencyHigh {
                    ttl,
                    avg_ms: avg,
                    threshold,
                    message: format!(
                        "Hop {} average latency {:.2}ms exceeds threshold {:.2}ms",
                        ttl, avg, threshold
                    ),
                });
            }
        }

        // Check loss threshold
        if let Some(threshold) = self.config.max_hop_loss_pct {
            let loss = stats.loss_pct;
            let key = format!("loss:{}", ttl);
            if loss > threshold && !self.in_cooldown(&key, now) {
                self.last_fired.insert(key, now);
                alerts.push(TraceAlert::HopLossHigh {
                    ttl,
                    loss_pct: loss,
                    threshold,
                    message: format!(
                        "Hop {} packet loss {:.1}% exceeds threshold {:.1}%",
                        ttl, loss, threshold
                    ),
                });
            }
        }

        alerts
    }

    /// Check for a path change and return an alert if appropriate.
    ///
    /// A path change means the IP at a given TTL changed between rounds.
    /// This also detects hops appearing or disappearing.
    pub fn check_path_change(
        &mut self,
        ttl: u8,
        old_addr: Option<IpAddr>,
        new_addr: Option<IpAddr>,
    ) -> Option<TraceAlert> {
        if !self.config.alert_on_path_change {
            return None;
        }

        if old_addr == new_addr {
            return None;
        }

        let now = Instant::now();
        let key = format!("path:{}", ttl);
        if self.in_cooldown(&key, now) {
            return None;
        }
        self.last_fired.insert(key, now);

        match (old_addr, new_addr) {
            (None, Some(addr)) => Some(TraceAlert::NewHopAppeared {
                ttl,
                addr,
                message: format!("Hop {}: new responder appeared at {}", ttl, addr),
            }),
            (Some(addr), None) => Some(TraceAlert::HopDisappeared {
                ttl,
                addr,
                message: format!("Hop {}: responder {} disappeared", ttl, addr),
            }),
            (Some(old), Some(new)) => Some(TraceAlert::PathChanged {
                ttl,
                old_addr: Some(old),
                new_addr: Some(new),
                message: format!("Hop {}: path changed from {} to {}", ttl, old, new),
            }),
            (None, None) => None, // Both None, no change
        }
    }

    /// Returns `true` if the given metric key is still within its cooldown window.
    fn in_cooldown(&self, key: &str, now: Instant) -> bool {
        self.last_fired
            .get(key)
            .map(|&last| now.duration_since(last) < self.config.cooldown())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{ProbeResult, ProbeStatus};
    use std::time::SystemTime;

    fn make_probe(ttl: u8, rtt_ms: Option<f64>, source: Option<IpAddr>) -> ProbeResult {
        ProbeResult {
            ttl,
            probe_num: 0,
            source,
            rtt: rtt_ms.map(|ms| Duration::from_secs_f64(ms / 1000.0)),
            status: if rtt_ms.is_some() {
                ProbeStatus::TimeExceeded
            } else {
                ProbeStatus::Timeout
            },
            icmp_type: if rtt_ms.is_some() { 11 } else { 0 },
            icmp_code: 0,
            timestamp: SystemTime::now(),
        }
    }

    #[test]
    fn test_latency_alert_fires() {
        let config = TraceAlertConfig {
            max_hop_latency_ms: Some(50.0),
            max_hop_loss_pct: None,
            alert_on_path_change: false,
            cooldown_secs: 60,
        };

        let mut state = TraceAlertState::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // High latency probes
        let probes = vec![
            make_probe(3, Some(80.0), Some(ip)),
            make_probe(3, Some(90.0), Some(ip)),
            make_probe(3, Some(100.0), Some(ip)),
        ];
        let stats = HopStats::from_probes(3, &probes);

        let alerts = state.check(3, &stats);
        assert_eq!(alerts.len(), 1);
        match &alerts[0] {
            TraceAlert::HopLatencyHigh {
                ttl,
                avg_ms,
                threshold,
                ..
            } => {
                assert_eq!(*ttl, 3);
                assert!(*avg_ms > 50.0);
                assert_eq!(*threshold, 50.0);
            }
            other => panic!("Expected HopLatencyHigh, got {:?}", other),
        }
    }

    #[test]
    fn test_latency_alert_does_not_fire_below_threshold() {
        let config = TraceAlertConfig {
            max_hop_latency_ms: Some(100.0),
            max_hop_loss_pct: None,
            alert_on_path_change: false,
            cooldown_secs: 60,
        };

        let mut state = TraceAlertState::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let probes = vec![
            make_probe(3, Some(10.0), Some(ip)),
            make_probe(3, Some(20.0), Some(ip)),
        ];
        let stats = HopStats::from_probes(3, &probes);

        let alerts = state.check(3, &stats);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_loss_alert_fires() {
        let config = TraceAlertConfig {
            max_hop_latency_ms: None,
            max_hop_loss_pct: Some(20.0),
            alert_on_path_change: false,
            cooldown_secs: 60,
        };

        let mut state = TraceAlertState::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // 50% loss
        let probes = vec![
            make_probe(5, Some(10.0), Some(ip)),
            make_probe(5, None, None),
            make_probe(5, Some(20.0), Some(ip)),
            make_probe(5, None, None),
        ];
        let stats = HopStats::from_probes(5, &probes);

        let alerts = state.check(5, &stats);
        assert_eq!(alerts.len(), 1);
        match &alerts[0] {
            TraceAlert::HopLossHigh {
                ttl,
                loss_pct,
                threshold,
                ..
            } => {
                assert_eq!(*ttl, 5);
                assert!(*loss_pct > 20.0);
                assert_eq!(*threshold, 20.0);
            }
            other => panic!("Expected HopLossHigh, got {:?}", other),
        }
    }

    #[test]
    fn test_cooldown_prevents_duplicate_alerts() {
        let config = TraceAlertConfig {
            max_hop_latency_ms: Some(50.0),
            max_hop_loss_pct: None,
            alert_on_path_change: false,
            cooldown_secs: 60,
        };

        let mut state = TraceAlertState::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let probes = vec![
            make_probe(3, Some(80.0), Some(ip)),
            make_probe(3, Some(90.0), Some(ip)),
        ];
        let stats = HopStats::from_probes(3, &probes);

        // First check should fire
        let alerts = state.check(3, &stats);
        assert_eq!(alerts.len(), 1);

        // Second check within cooldown should NOT fire
        let alerts = state.check(3, &stats);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_path_change_alert() {
        let config = TraceAlertConfig {
            max_hop_latency_ms: None,
            max_hop_loss_pct: None,
            alert_on_path_change: true,
            cooldown_secs: 60,
        };

        let mut state = TraceAlertState::new(config);

        let old: IpAddr = "10.0.0.1".parse().unwrap();
        let new: IpAddr = "10.0.0.2".parse().unwrap();

        let alert = state.check_path_change(3, Some(old), Some(new));
        assert!(alert.is_some());

        match alert.unwrap() {
            TraceAlert::PathChanged {
                ttl,
                old_addr,
                new_addr,
                ..
            } => {
                assert_eq!(ttl, 3);
                assert_eq!(old_addr, Some(old));
                assert_eq!(new_addr, Some(new));
            }
            other => panic!("Expected PathChanged, got {:?}", other),
        }
    }

    #[test]
    fn test_path_change_no_alert_same_addr() {
        let config = TraceAlertConfig {
            max_hop_latency_ms: None,
            max_hop_loss_pct: None,
            alert_on_path_change: true,
            cooldown_secs: 60,
        };

        let mut state = TraceAlertState::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let alert = state.check_path_change(3, Some(ip), Some(ip));
        assert!(alert.is_none());
    }

    #[test]
    fn test_new_hop_appeared() {
        let config = TraceAlertConfig::default();
        let mut state = TraceAlertState::new(config);

        let new: IpAddr = "10.0.0.1".parse().unwrap();
        let alert = state.check_path_change(4, None, Some(new));
        assert!(alert.is_some());

        match alert.unwrap() {
            TraceAlert::NewHopAppeared { ttl, addr, .. } => {
                assert_eq!(ttl, 4);
                assert_eq!(addr, new);
            }
            other => panic!("Expected NewHopAppeared, got {:?}", other),
        }
    }

    #[test]
    fn test_hop_disappeared() {
        let config = TraceAlertConfig::default();
        let mut state = TraceAlertState::new(config);

        let old: IpAddr = "10.0.0.1".parse().unwrap();
        let alert = state.check_path_change(4, Some(old), None);
        assert!(alert.is_some());

        match alert.unwrap() {
            TraceAlert::HopDisappeared { ttl, addr, .. } => {
                assert_eq!(ttl, 4);
                assert_eq!(addr, old);
            }
            other => panic!("Expected HopDisappeared, got {:?}", other),
        }
    }

    #[test]
    fn test_path_change_disabled() {
        let config = TraceAlertConfig {
            alert_on_path_change: false,
            ..Default::default()
        };
        let mut state = TraceAlertState::new(config);

        let old: IpAddr = "10.0.0.1".parse().unwrap();
        let new: IpAddr = "10.0.0.2".parse().unwrap();

        let alert = state.check_path_change(3, Some(old), Some(new));
        assert!(alert.is_none());
    }

    #[test]
    fn test_path_change_cooldown() {
        let config = TraceAlertConfig {
            alert_on_path_change: true,
            cooldown_secs: 60,
            ..Default::default()
        };
        let mut state = TraceAlertState::new(config);

        let old: IpAddr = "10.0.0.1".parse().unwrap();
        let new: IpAddr = "10.0.0.2".parse().unwrap();

        // First should fire
        let alert = state.check_path_change(3, Some(old), Some(new));
        assert!(alert.is_some());

        // Second within cooldown should not
        let alert = state.check_path_change(3, Some(new), Some(old));
        assert!(alert.is_none());
    }

    #[test]
    fn test_display_impl() {
        let alert = TraceAlert::HopLatencyHigh {
            ttl: 3,
            avg_ms: 150.0,
            threshold: 50.0,
            message: "Hop 3 average latency 150.00ms exceeds threshold 50.00ms".to_string(),
        };
        let s = format!("{}", alert);
        assert!(s.contains("150.00ms"));
        assert!(s.contains("50.00ms"));
    }

    #[test]
    fn test_different_ttls_independent_cooldown() {
        let config = TraceAlertConfig {
            max_hop_latency_ms: Some(50.0),
            max_hop_loss_pct: None,
            alert_on_path_change: false,
            cooldown_secs: 60,
        };

        let mut state = TraceAlertState::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let probes_ttl3 = vec![make_probe(3, Some(80.0), Some(ip))];
        let stats_ttl3 = HopStats::from_probes(3, &probes_ttl3);

        let probes_ttl5 = vec![make_probe(5, Some(80.0), Some(ip))];
        let stats_ttl5 = HopStats::from_probes(5, &probes_ttl5);

        // Both should fire since they are different TTLs
        let alerts3 = state.check(3, &stats_ttl3);
        assert_eq!(alerts3.len(), 1);

        let alerts5 = state.check(5, &stats_ttl5);
        assert_eq!(alerts5.len(), 1);

        // But repeated checks on the same TTL should be suppressed
        let alerts3_again = state.check(3, &stats_ttl3);
        assert!(alerts3_again.is_empty());
    }
}
