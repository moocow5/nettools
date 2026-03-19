use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, Mutex};

use crate::alert::{parse_duration, AlertConfig, AlertState, FiredAlert};
use crate::config::{PayloadPattern, PingConfig, PingMode};
use crate::result::PingResult;
use crate::stats::PingStats;
use crate::IcmpSocket;

/// Top-level monitor configuration, typically deserialized from TOML.
///
/// ```toml
/// [[target]]
/// host = "8.8.8.8"
/// label = "Google DNS"
/// mode = "icmp"
/// interval = "1s"
///
/// [target.alert]
/// max_latency_ms = 100.0
/// max_loss_pct = 5.0
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct MonitorConfig {
    pub target: Vec<TargetConfig>,
}

/// Configuration for a single monitored target.
#[derive(Debug, Clone, Deserialize)]
pub struct TargetConfig {
    /// Hostname or IP address to ping.
    pub host: String,
    /// Optional human-readable label for display.
    #[serde(default)]
    pub label: Option<String>,
    /// Ping mode: "icmp", "tcp-connect", or "udp".
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Port number (required for tcp-connect and udp modes).
    #[serde(default)]
    pub port: Option<u16>,
    /// Interval between pings (e.g. "1s", "500ms").
    #[serde(default = "default_interval")]
    pub interval: String,
    /// Optional alert thresholds for this target.
    #[serde(default)]
    pub alert: Option<AlertConfig>,
}

fn default_mode() -> String {
    "icmp".into()
}

fn default_interval() -> String {
    "1s".into()
}

/// Events emitted by the monitor via its broadcast channel.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum MonitorEvent {
    /// A single ping result was received.
    PingResult {
        target_id: usize,
        result: PingResult,
    },
    /// Aggregated rolling-window statistics were updated.
    StatsUpdate {
        target_id: usize,
        stats: TargetStats,
    },
    /// An alert threshold was exceeded.
    AlertFired {
        target_id: usize,
        alert: FiredAlert,
    },
}

/// Rolling-window statistics for a monitored target.
#[derive(Debug, Clone, Serialize)]
pub struct TargetStats {
    pub host: String,
    pub label: Option<String>,
    pub mode: String,
    pub stats: PingStats,
    pub is_up: bool,
    pub last_rtt_ms: Option<f64>,
}

/// Maximum number of results kept in the rolling window per target.
const ROLLING_WINDOW_SIZE: usize = 100;

/// Capacity of the broadcast channel for monitor events.
const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Multi-target ping monitor.
///
/// Orchestrates concurrent ping tasks for multiple targets, computes rolling
/// statistics, and fires alerts when thresholds are breached.
pub struct Monitor {
    targets: Vec<TargetConfig>,
    event_tx: broadcast::Sender<MonitorEvent>,
    target_stats: Arc<Mutex<HashMap<usize, TargetStats>>>,
}

impl Monitor {
    /// Create a new monitor from the given configuration.
    pub fn new(config: MonitorConfig) -> Self {
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            targets: config.target,
            event_tx,
            target_stats: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Number of configured targets.
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    /// Subscribe to the stream of monitor events.
    pub fn subscribe(&self) -> broadcast::Receiver<MonitorEvent> {
        self.event_tx.subscribe()
    }

    /// Get a shared handle to the current per-target statistics.
    pub fn target_stats(&self) -> Arc<Mutex<HashMap<usize, TargetStats>>> {
        Arc::clone(&self.target_stats)
    }

    /// Run the monitor until a shutdown signal is received.
    ///
    /// Spawns one task per target. Each task pings its target in a loop,
    /// updates rolling statistics, and checks alert thresholds.
    pub async fn run(&self, mut shutdown: mpsc::Receiver<()>) -> crate::Result<()> {
        let mut handles = Vec::new();

        for (id, target) in self.targets.iter().enumerate() {
            let target = target.clone();
            let event_tx = self.event_tx.clone();
            let stats_map = Arc::clone(&self.target_stats);

            let handle = tokio::spawn(async move {
                if let Err(e) = run_target(id, target, event_tx, stats_map).await {
                    tracing::warn!(target_id = id, error = %e, "target monitor task failed");
                }
            });

            handles.push(handle);
        }

        tracing::info!(
            target_count = self.targets.len(),
            "monitor started for all targets"
        );

        // Wait for shutdown signal, then abort all target tasks.
        tokio::select! {
            _ = shutdown.recv() => {
                tracing::info!("shutdown signal received, stopping monitor");
                for handle in &handles {
                    handle.abort();
                }
            }
        }

        // Wait for all tasks to finish (they will return Cancelled).
        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }
}

/// Run the ping loop for a single target.
async fn run_target(
    target_id: usize,
    target: TargetConfig,
    event_tx: broadcast::Sender<MonitorEvent>,
    stats_map: Arc<Mutex<HashMap<usize, TargetStats>>>,
) -> crate::Result<()> {
    let ping_config = build_ping_config(&target)?;
    let interval = parse_duration(&target.interval);

    // Set up alert state if thresholds are configured.
    let mut alert_state = target.alert.as_ref().map(|ac| {
        let cooldown = parse_duration(&ac.cooldown);
        AlertState::new(cooldown)
    });

    let mut window: VecDeque<PingResult> = VecDeque::with_capacity(ROLLING_WINDOW_SIZE);

    tracing::info!(
        target_id,
        host = %target.host,
        mode = %target.mode,
        interval_ms = interval.as_millis() as u64,
        "starting target monitor"
    );

    loop {
        // Create a fresh socket and channel for each ping cycle.
        let socket = IcmpSocket::new()?;
        if let Some(ttl) = ping_config.ttl {
            socket.set_ttl(ttl)?;
        }
        if let Some(tos) = ping_config.tos {
            socket.set_tos(tos)?;
        }

        let (result_tx, mut result_rx) = mpsc::channel::<PingResult>(16);

        // Build a single-shot config (count = Some(1)) so pinger::run returns
        // after one probe, giving us control over the loop timing.
        let mut single_config = ping_config.clone();
        single_config.count = Some(1);

        // Spawn the pinger in a background task.
        let cfg = single_config.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::pinger::run(&cfg, &socket, result_tx).await {
                tracing::warn!("pinger probe failed: {e}");
            }
        });

        // Collect the single result.
        if let Some(result) = result_rx.recv().await {
            // Maintain rolling window.
            if window.len() >= ROLLING_WINDOW_SIZE {
                window.pop_front();
            }
            window.push_back(result.clone());

            // Broadcast the raw result.
            let _ = event_tx.send(MonitorEvent::PingResult {
                target_id,
                result: result.clone(),
            });

            // Compute rolling stats.
            let results_vec: Vec<PingResult> = window.iter().cloned().collect();
            let ping_stats = PingStats::from_results(&results_vec);

            let last_rtt_ms = result.rtt_ms();
            let is_up = last_rtt_ms.is_some();

            let target_stats = TargetStats {
                host: target.host.clone(),
                label: target.label.clone(),
                mode: target.mode.clone(),
                stats: ping_stats.clone(),
                is_up,
                last_rtt_ms,
            };

            // Update shared stats map.
            {
                let mut map = stats_map.lock().await;
                map.insert(target_id, target_stats.clone());
            }

            // Broadcast stats update.
            let _ = event_tx.send(MonitorEvent::StatsUpdate {
                target_id,
                stats: target_stats,
            });

            // Check alerts.
            if let (Some(ref alert_config), Some(ref mut state)) =
                (&target.alert, &mut alert_state)
            {
                let fired = state.check(alert_config, &ping_stats);
                for alert in fired {
                    tracing::warn!(
                        target_id,
                        host = %target.host,
                        metric = %alert.metric,
                        value = alert.value,
                        threshold = alert.threshold,
                        "alert fired"
                    );
                    let _ = event_tx.send(MonitorEvent::AlertFired {
                        target_id,
                        alert,
                    });
                }
            }
        }

        tokio::time::sleep(interval).await;
    }
}

/// Convert a [`TargetConfig`] into a [`PingConfig`] suitable for the pinger.
fn build_ping_config(target: &TargetConfig) -> crate::Result<PingConfig> {
    let mode = match target.mode.as_str() {
        "icmp" => PingMode::Icmp,
        "tcp-connect" | "tcp" => PingMode::TcpConnect,
        "udp" => PingMode::Udp,
        other => {
            tracing::warn!(mode = other, "unknown ping mode, defaulting to ICMP");
            PingMode::Icmp
        }
    };

    let interval = parse_duration(&target.interval);

    Ok(PingConfig {
        target: target.host.clone(),
        mode,
        port: target.port,
        count: None, // infinite — the monitor loop controls iteration
        interval,
        timeout: Duration::from_secs(5),
        packet_size: 64,
        ttl: None,
        tos: None,
        payload_pattern: PayloadPattern::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ping_config_icmp() {
        let tc = TargetConfig {
            host: "8.8.8.8".into(),
            label: Some("Google DNS".into()),
            mode: "icmp".into(),
            port: None,
            interval: "500ms".into(),
            alert: None,
        };
        let cfg = build_ping_config(&tc).unwrap();
        assert_eq!(cfg.target, "8.8.8.8");
        assert!(matches!(cfg.mode, PingMode::Icmp));
        assert_eq!(cfg.interval, Duration::from_millis(500));
        assert!(cfg.count.is_none());
    }

    #[test]
    fn test_build_ping_config_tcp() {
        let tc = TargetConfig {
            host: "example.com".into(),
            label: None,
            mode: "tcp-connect".into(),
            port: Some(443),
            interval: "2s".into(),
            alert: None,
        };
        let cfg = build_ping_config(&tc).unwrap();
        assert!(matches!(cfg.mode, PingMode::TcpConnect));
        assert_eq!(cfg.port, Some(443));
        assert_eq!(cfg.interval, Duration::from_secs(2));
    }

    #[test]
    fn test_deserialize_monitor_config() {
        let toml_str = r#"
[[target]]
host = "8.8.8.8"
label = "Google DNS"
mode = "icmp"
interval = "1s"

[target.alert]
max_latency_ms = 100.0
max_loss_pct = 5.0

[[target]]
host = "example.com"
mode = "tcp-connect"
port = 443
interval = "2s"
"#;
        let config: MonitorConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.target.len(), 2);
        assert_eq!(config.target[0].host, "8.8.8.8");
        assert!(config.target[0].alert.is_some());
        assert_eq!(config.target[1].port, Some(443));
    }
}
