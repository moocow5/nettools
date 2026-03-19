use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use ntrace_core::mtr::MtrEvent;
use ntrace_core::stats::HopStats;

/// Per-hop enriched data stored in the dashboard state.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HopData {
    pub stats: HopStats,
    pub hostname: Option<String>,
    pub asn: Option<u32>,
    pub asn_name: Option<String>,
}

/// Traceroute state for the unified dashboard.
pub struct TraceState {
    /// Current per-hop stats (keyed by TTL).
    pub hops: RwLock<HashMap<u8, HopData>>,
    /// Highest TTL seen so far.
    pub max_ttl: RwLock<u8>,
    /// Current round number.
    pub round: RwLock<u64>,
    /// Target host string.
    pub target: RwLock<String>,
    /// Broadcast sender for SSE — re-broadcasts MtrEvents to web clients.
    pub sse_tx: broadcast::Sender<MtrEvent>,
}

impl TraceState {
    pub fn new(target: String) -> Arc<Self> {
        let (sse_tx, _) = broadcast::channel(1024);
        Arc::new(Self {
            hops: RwLock::new(HashMap::new()),
            max_ttl: RwLock::new(0),
            round: RwLock::new(0),
            target: RwLock::new(target),
            sse_tx,
        })
    }

    pub fn new_empty() -> Arc<Self> {
        let (sse_tx, _) = broadcast::channel(1024);
        Arc::new(Self {
            hops: RwLock::new(HashMap::new()),
            max_ttl: RwLock::new(0),
            round: RwLock::new(0),
            target: RwLock::new(String::new()),
            sse_tx,
        })
    }
}

/// Relay events from the MtrEngine broadcast into the TraceState and re-broadcast to SSE clients.
pub async fn relay_events(
    mut rx: broadcast::Receiver<MtrEvent>,
    state: Arc<TraceState>,
) {
    loop {
        match rx.recv().await {
            Ok(event) => {
                match &event {
                    MtrEvent::HopUpdate {
                        ttl,
                        stats,
                        hostname,
                        asn,
                        asn_name,
                    } => {
                        let mut hops = state.hops.write().await;
                        hops.insert(
                            *ttl,
                            HopData {
                                stats: stats.clone(),
                                hostname: hostname.clone(),
                                asn: *asn,
                                asn_name: asn_name.clone(),
                            },
                        );
                    }
                    MtrEvent::RoundComplete {
                        round,
                        max_ttl_seen,
                        ..
                    } => {
                        let mut r = state.round.write().await;
                        *r = *round;
                        let mut m = state.max_ttl.write().await;
                        if *max_ttl_seen > *m {
                            *m = *max_ttl_seen;
                        }
                    }
                    MtrEvent::ProbeResult { .. } | MtrEvent::PathChange { .. } => {}
                }
                let _ = state.sse_tx.send(event);
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!("trace web state relay lagged by {n} messages");
            }
            Err(broadcast::error::RecvError::Closed) => {
                tracing::info!("engine broadcast closed, stopping trace web state relay");
                break;
            }
        }
    }
}
