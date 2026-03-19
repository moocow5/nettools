//! MTR (My Traceroute) engine: continuous traceroute with rolling statistics.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

use crate::config::TraceConfig;
use crate::enrich::Enricher;
use crate::engine::run_trace;
use crate::result::ProbeResult;
use crate::socket::TraceSocketTrait;
use crate::stats::HopStats;

/// Configuration for the MTR engine.
#[derive(Debug, Clone)]
pub struct MtrConfig {
    /// Underlying traceroute configuration.
    pub trace: TraceConfig,
    /// Interval between rounds.
    pub interval: Duration,
    /// Maximum number of probes to keep per hop for rolling stats.
    pub rolling_window: usize,
    /// Whether to perform reverse DNS lookups.
    pub resolve_dns: bool,
    /// Whether to perform ASN lookups.
    pub lookup_asn: bool,
    /// Whether to perform GeoIP lookups (requires `enrichment` feature).
    pub lookup_geo: bool,
    /// Maximum number of rounds (None = unlimited).
    pub max_rounds: Option<u64>,
}

impl Default for MtrConfig {
    fn default() -> Self {
        Self {
            trace: TraceConfig::default(),
            interval: Duration::from_secs(1),
            rolling_window: 100,
            resolve_dns: true,
            lookup_asn: false,
            lookup_geo: false,
            max_rounds: None,
        }
    }
}

/// Events emitted by the MTR engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MtrEvent {
    /// A single probe result from a round.
    ProbeResult {
        round: u64,
        result: crate::result::ProbeResult,
    },
    /// Updated statistics for a hop (emitted once per hop per round).
    HopUpdate {
        ttl: u8,
        stats: HopStats,
        hostname: Option<String>,
        asn: Option<u32>,
        asn_name: Option<String>,
    },
    /// Detected a path change at a given TTL.
    PathChange {
        ttl: u8,
        old_addr: Option<IpAddr>,
        new_addr: Option<IpAddr>,
    },
    /// A full round of probing has completed.
    RoundComplete {
        round: u64,
        reached_destination: bool,
        max_ttl_seen: u8,
    },
}

/// The MTR engine: runs continuous traceroute rounds and broadcasts events.
pub struct MtrEngine {
    config: MtrConfig,
    event_tx: broadcast::Sender<MtrEvent>,
}

impl MtrEngine {
    /// Create a new MTR engine with the given configuration.
    /// Returns the engine instance. Use `subscribe()` to get event receivers.
    pub fn new(config: MtrConfig) -> Self {
        let (event_tx, _) = broadcast::channel(1024);
        Self { config, event_tx }
    }

    /// Subscribe to the event stream.
    pub fn subscribe(&self) -> broadcast::Receiver<MtrEvent> {
        self.event_tx.subscribe()
    }

    /// Run the MTR engine until shutdown is signalled or max_rounds is reached.
    pub async fn run<S: TraceSocketTrait>(
        &self,
        socket: S,
        mut shutdown: mpsc::Receiver<()>,
    ) -> crate::Result<()> {
        let mut round: u64 = 0;
        let mut enricher = Enricher::new();

        // Per-hop rolling window of probe results
        let mut hop_probes: HashMap<u8, Vec<ProbeResult>> = HashMap::new();
        // Last known address per TTL for path change detection
        let mut last_addr: HashMap<u8, Option<IpAddr>> = HashMap::new();

        loop {
            round += 1;

            // Check max_rounds
            if let Some(max) = self.config.max_rounds {
                if round > max {
                    break;
                }
            }

            // Run a single traceroute round
            let (probe_tx, mut probe_rx) = mpsc::channel::<ProbeResult>(256);
            let trace_result = run_trace(&self.config.trace, &socket, probe_tx).await?;

            // Drain all probe results from the channel
            let mut round_probes: Vec<ProbeResult> = Vec::new();
            while let Ok(probe) = probe_rx.try_recv() {
                round_probes.push(probe);
            }

            // Broadcast individual probe results
            for probe in &round_probes {
                let _ = self.event_tx.send(MtrEvent::ProbeResult {
                    round,
                    result: probe.clone(),
                });
            }

            // Group probes by TTL
            let mut ttl_groups: HashMap<u8, Vec<ProbeResult>> = HashMap::new();
            for probe in round_probes {
                ttl_groups.entry(probe.ttl).or_default().push(probe);
            }

            let mut max_ttl_seen: u8 = 0;

            // Process each TTL
            for (ttl, probes) in &ttl_groups {
                if *ttl > max_ttl_seen {
                    max_ttl_seen = *ttl;
                }

                // Detect path changes
                let current_addr = crate::result::HopResult::compute_addr(probes);
                let prev_addr = last_addr.get(ttl).copied().flatten();
                if last_addr.contains_key(ttl) && current_addr != prev_addr {
                    let _ = self.event_tx.send(MtrEvent::PathChange {
                        ttl: *ttl,
                        old_addr: prev_addr,
                        new_addr: current_addr,
                    });
                }
                last_addr.insert(*ttl, current_addr);

                // Add to rolling window
                let window = hop_probes.entry(*ttl).or_default();
                window.extend(probes.iter().cloned());
                // Trim to rolling window size
                let max_size = self.config.rolling_window;
                if window.len() > max_size {
                    let drain_count = window.len() - max_size;
                    window.drain(..drain_count);
                }

                // Compute stats from the rolling window
                let stats = HopStats::from_probes(*ttl, window);

                // Enrich if needed
                let mut hostname = None;
                let mut asn = None;
                let mut asn_name = None;

                if let Some(ip) = current_addr {
                    if self.config.resolve_dns {
                        hostname = enricher.lookup_dns(ip).await;
                    }
                    if self.config.lookup_asn {
                        if let Some(asn_info) = enricher.lookup_asn(ip).await {
                            asn = Some(asn_info.asn);
                            asn_name = asn_info.name.clone();
                        }
                    }
                }

                let _ = self.event_tx.send(MtrEvent::HopUpdate {
                    ttl: *ttl,
                    stats,
                    hostname,
                    asn,
                    asn_name,
                });
            }

            // Broadcast round complete
            let _ = self.event_tx.send(MtrEvent::RoundComplete {
                round,
                reached_destination: trace_result.reached_destination,
                max_ttl_seen,
            });

            // Wait for next interval or shutdown
            tokio::select! {
                _ = tokio::time::sleep(self.config.interval) => {}
                _ = shutdown.recv() => {
                    break;
                }
            }
        }

        Ok(())
    }
}
