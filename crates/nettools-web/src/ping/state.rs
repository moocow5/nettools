use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use nping_core::db::Database;
use nping_core::monitor::{MonitorEvent, TargetConfig, TargetStats};
use nping_core::result::PingResult;

/// Maximum number of recent results kept per target for the history API.
const HISTORY_SIZE: usize = 300;

/// Ping monitoring state for the unified dashboard.
pub struct PingState {
    /// Current per-target stats (keyed by target_id).
    pub stats: RwLock<HashMap<usize, TargetStats>>,
    /// Recent ping results per target for history/sparkline.
    pub history: RwLock<HashMap<usize, Vec<PingResult>>>,
    /// Target configurations (set once at startup).
    pub targets: RwLock<Vec<TargetConfig>>,
    /// Broadcast sender for SSE — we re-broadcast monitor events to web clients.
    pub sse_tx: broadcast::Sender<MonitorEvent>,
    /// Optional SQLite database for historical data queries.
    pub db: Option<Arc<Database>>,
}

impl PingState {
    pub fn new(targets: Vec<TargetConfig>, db: Option<Arc<Database>>) -> Arc<Self> {
        let (sse_tx, _) = broadcast::channel(1024);
        Arc::new(Self {
            stats: RwLock::new(HashMap::new()),
            history: RwLock::new(HashMap::new()),
            targets: RwLock::new(targets),
            sse_tx,
            db,
        })
    }

    pub fn new_empty() -> Arc<Self> {
        let (sse_tx, _) = broadcast::channel(1024);
        Arc::new(Self {
            stats: RwLock::new(HashMap::new()),
            history: RwLock::new(HashMap::new()),
            targets: RwLock::new(Vec::new()),
            sse_tx,
            db: None,
        })
    }
}

/// Relay events from the monitor broadcast into the PingState and re-broadcast to SSE clients.
pub async fn relay_events(
    mut rx: broadcast::Receiver<MonitorEvent>,
    state: Arc<PingState>,
) {
    loop {
        match rx.recv().await {
            Ok(event) => {
                match &event {
                    MonitorEvent::PingResult { target_id, result } => {
                        let mut history = state.history.write().await;
                        let entry = history.entry(*target_id).or_insert_with(Vec::new);
                        if entry.len() >= HISTORY_SIZE {
                            entry.remove(0);
                        }
                        entry.push(result.clone());
                    }
                    MonitorEvent::StatsUpdate { target_id, stats } => {
                        let mut s = state.stats.write().await;
                        s.insert(*target_id, stats.clone());
                    }
                    MonitorEvent::AlertFired { .. } => {}
                }
                let _ = state.sse_tx.send(event);
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!("ping web state relay lagged by {n} messages");
            }
            Err(broadcast::error::RecvError::Closed) => {
                tracing::info!("monitor broadcast closed, stopping ping web state relay");
                break;
            }
        }
    }
}
