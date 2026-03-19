use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::stats::PingStats;

/// Alert thresholds configuration, parsed from TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct AlertConfig {
    /// Maximum acceptable average latency in milliseconds.
    pub max_latency_ms: Option<f64>,
    /// Maximum acceptable jitter in milliseconds.
    pub max_jitter_ms: Option<f64>,
    /// Maximum acceptable packet loss percentage (0.0–100.0).
    pub max_loss_pct: Option<f64>,
    /// Cooldown period between repeated alerts for the same metric (e.g. "60s").
    #[serde(default = "default_cooldown")]
    pub cooldown: String,
}

fn default_cooldown() -> String {
    "60s".into()
}

/// A single alert that has been triggered.
#[derive(Debug, Clone, Serialize)]
pub struct FiredAlert {
    /// Which metric triggered: "latency", "jitter", or "loss".
    pub metric: String,
    /// The observed value that exceeded the threshold.
    pub value: f64,
    /// The configured threshold that was exceeded.
    pub threshold: f64,
    /// Human-readable description of the alert.
    pub message: String,
}

/// Tracks per-metric cooldown state so the same alert is not fired repeatedly.
pub struct AlertState {
    last_fired: HashMap<String, Instant>,
    cooldown: Duration,
}

impl AlertState {
    /// Create a new `AlertState` with the given cooldown duration.
    pub fn new(cooldown: Duration) -> Self {
        Self {
            last_fired: HashMap::new(),
            cooldown,
        }
    }

    /// Check the given stats against the alert config thresholds.
    ///
    /// Returns a list of newly fired alerts. An alert is suppressed if the same
    /// metric fired within the cooldown window.
    pub fn check(&mut self, config: &AlertConfig, stats: &PingStats) -> Vec<FiredAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        // Check average latency
        if let (Some(threshold), Some(value)) = (config.max_latency_ms, stats.avg_rtt_ms) {
            if value > threshold && !self.in_cooldown("latency", now) {
                self.last_fired.insert("latency".into(), now);
                alerts.push(FiredAlert {
                    metric: "latency".into(),
                    value,
                    threshold,
                    message: format!(
                        "Average latency {:.2}ms exceeds threshold {:.2}ms",
                        value, threshold
                    ),
                });
            }
        }

        // Check jitter
        if let (Some(threshold), Some(value)) = (config.max_jitter_ms, stats.jitter_ms) {
            if value > threshold && !self.in_cooldown("jitter", now) {
                self.last_fired.insert("jitter".into(), now);
                alerts.push(FiredAlert {
                    metric: "jitter".into(),
                    value,
                    threshold,
                    message: format!(
                        "Jitter {:.2}ms exceeds threshold {:.2}ms",
                        value, threshold
                    ),
                });
            }
        }

        // Check packet loss
        if let Some(threshold) = config.max_loss_pct {
            let value = stats.loss_pct;
            if value > threshold && !self.in_cooldown("loss", now) {
                self.last_fired.insert("loss".into(), now);
                alerts.push(FiredAlert {
                    metric: "loss".into(),
                    value,
                    threshold,
                    message: format!(
                        "Packet loss {:.1}% exceeds threshold {:.1}%",
                        value, threshold
                    ),
                });
            }
        }

        alerts
    }

    /// Returns `true` if the given metric is still within its cooldown window.
    fn in_cooldown(&self, metric: &str, now: Instant) -> bool {
        self.last_fired
            .get(metric)
            .map(|&last| now.duration_since(last) < self.cooldown)
            .unwrap_or(false)
    }
}

/// Parse a duration string like "60s", "500ms", "2m" into a [`Duration`].
///
/// Supported suffixes: `ms` (milliseconds), `s` (seconds), `m` (minutes).
/// Defaults to seconds if no suffix is recognized.
pub fn parse_duration(s: &str) -> Duration {
    let s = s.trim();
    if let Some(ms) = s.strip_suffix("ms") {
        if let Ok(n) = ms.trim().parse::<u64>() {
            return Duration::from_millis(n);
        }
    }
    if let Some(secs) = s.strip_suffix('s') {
        if let Ok(n) = secs.trim().parse::<u64>() {
            return Duration::from_secs(n);
        }
    }
    if let Some(mins) = s.strip_suffix('m') {
        if let Ok(n) = mins.trim().parse::<u64>() {
            return Duration::from_secs(n * 60);
        }
    }
    // Fallback: try parsing as raw seconds
    s.parse::<u64>()
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_variants() {
        assert_eq!(parse_duration("500ms"), Duration::from_millis(500));
        assert_eq!(parse_duration("30s"), Duration::from_secs(30));
        assert_eq!(parse_duration("2m"), Duration::from_secs(120));
        assert_eq!(parse_duration("10"), Duration::from_secs(10));
        assert_eq!(parse_duration("bogus"), Duration::from_secs(60));
    }

    #[test]
    fn test_cooldown_suppresses_repeat_alerts() {
        let config = AlertConfig {
            max_latency_ms: Some(100.0),
            max_jitter_ms: None,
            max_loss_pct: None,
            cooldown: "60s".into(),
        };

        let mut state = AlertState::new(Duration::from_secs(60));

        // Simulate stats with high latency
        let stats = PingStats {
            transmitted: 10,
            received: 10,
            lost: 0,
            loss_pct: 0.0,
            min_rtt_ms: Some(50.0),
            max_rtt_ms: Some(200.0),
            avg_rtt_ms: Some(150.0),
            stddev_rtt_ms: Some(20.0),
            jitter_ms: Some(5.0),
            mos: Some(4.0),
        };

        // First check should fire
        let fired = state.check(&config, &stats);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].metric, "latency");

        // Second check within cooldown should NOT fire
        let fired = state.check(&config, &stats);
        assert!(fired.is_empty());
    }
}
