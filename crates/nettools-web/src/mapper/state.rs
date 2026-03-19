use std::sync::Arc;

use tokio::sync::{broadcast, RwLock};

use nmapper_core::result::{ScanEvent, ScanResult};
use nmapper_core::trap::TrapEvent;

/// Inner state holding scan data and the SSE broadcast channel.
pub struct MapperInnerState {
    pub scan_result: RwLock<Option<ScanResult>>,
    pub previous_result: RwLock<Option<ScanResult>>,
    pub event_tx: broadcast::Sender<ScanEvent>,
    pub trap_tx: broadcast::Sender<TrapEvent>,
    pub recent_traps: RwLock<Vec<TrapEvent>>,
}

const MAX_RECENT_TRAPS: usize = 200;

/// Mapper state for the unified dashboard.
#[derive(Clone)]
pub struct MapperState(pub(crate) Arc<MapperInnerState>);

impl MapperState {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(2048);
        let (trap_tx, _) = broadcast::channel(512);
        Self(Arc::new(MapperInnerState {
            scan_result: RwLock::new(None),
            previous_result: RwLock::new(None),
            event_tx,
            trap_tx,
            recent_traps: RwLock::new(Vec::new()),
        }))
    }

    pub async fn update_result(&self, result: ScanResult) {
        let mut prev = self.0.previous_result.write().await;
        let mut curr = self.0.scan_result.write().await;
        *prev = curr.take();
        *curr = Some(result);
    }

    pub async fn get_result(&self) -> Option<ScanResult> {
        self.0.scan_result.read().await.clone()
    }

    pub async fn get_previous_result(&self) -> Option<ScanResult> {
        self.0.previous_result.read().await.clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ScanEvent> {
        self.0.event_tx.subscribe()
    }

    pub fn event_tx(&self) -> &broadcast::Sender<ScanEvent> {
        &self.0.event_tx
    }

    pub fn trap_tx(&self) -> &broadcast::Sender<TrapEvent> {
        &self.0.trap_tx
    }

    pub fn subscribe_traps(&self) -> broadcast::Receiver<TrapEvent> {
        self.0.trap_tx.subscribe()
    }

    pub async fn add_trap(&self, trap: TrapEvent) {
        let mut traps = self.0.recent_traps.write().await;
        traps.push(trap);
        if traps.len() > MAX_RECENT_TRAPS {
            let excess = traps.len() - MAX_RECENT_TRAPS;
            traps.drain(0..excess);
        }
    }

    pub async fn get_recent_traps(&self) -> Vec<TrapEvent> {
        self.0.recent_traps.read().await.clone()
    }
}

impl Default for MapperState {
    fn default() -> Self {
        Self::new()
    }
}
