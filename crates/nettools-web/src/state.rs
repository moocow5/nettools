use std::sync::Arc;

use tokio::sync::RwLock;

use crate::ping::state::PingState;
use crate::trace::state::TraceState;
use crate::mapper::state::MapperState;

/// Tracks the status of an active job (ping, trace, or scan).
#[derive(Debug, Clone, serde::Serialize)]
pub struct JobStatus {
    pub running: bool,
    pub message: String,
}

impl Default for JobStatus {
    fn default() -> Self {
        Self {
            running: false,
            message: String::new(),
        }
    }
}

/// Unified application state composing all three tool states.
pub struct UnifiedState {
    pub ping: Arc<PingState>,
    pub trace: Arc<TraceState>,
    pub mapper: MapperState,
    /// Track whether an on-demand ping job is running.
    pub ping_job: RwLock<JobStatus>,
    /// Track whether an on-demand trace job is running.
    pub trace_job: RwLock<JobStatus>,
    /// Track whether an on-demand scan job is running.
    pub scan_job: RwLock<JobStatus>,
    /// Shutdown signal for the active ping job.
    pub ping_shutdown: RwLock<Option<tokio::sync::mpsc::Sender<()>>>,
    /// Shutdown signal for the active trace job.
    pub trace_shutdown: RwLock<Option<tokio::sync::mpsc::Sender<()>>>,
    /// Shutdown signal for the active scan job.
    pub scan_shutdown: RwLock<Option<tokio::sync::mpsc::Sender<()>>>,
    /// Path to the ping database file.
    pub ping_db_path: String,
    /// Path to the mapper database file.
    pub mapper_db_path: String,
}

impl UnifiedState {
    /// Create a new unified state with empty/default sub-states.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ping: PingState::new_empty(),
            trace: TraceState::new_empty(),
            mapper: MapperState::new(),
            ping_job: RwLock::new(JobStatus::default()),
            trace_job: RwLock::new(JobStatus::default()),
            scan_job: RwLock::new(JobStatus::default()),
            ping_shutdown: RwLock::new(None),
            trace_shutdown: RwLock::new(None),
            scan_shutdown: RwLock::new(None),
            ping_db_path: "nping.db".into(),
            mapper_db_path: "nmapper.db".into(),
        })
    }

    /// Create with pre-configured ping state.
    pub fn with_ping(
        ping: Arc<PingState>,
        trace: Arc<TraceState>,
        mapper: MapperState,
    ) -> Arc<Self> {
        Arc::new(Self {
            ping,
            trace,
            mapper,
            ping_job: RwLock::new(JobStatus::default()),
            trace_job: RwLock::new(JobStatus::default()),
            scan_job: RwLock::new(JobStatus::default()),
            ping_shutdown: RwLock::new(None),
            trace_shutdown: RwLock::new(None),
            scan_shutdown: RwLock::new(None),
            ping_db_path: "nping.db".into(),
            mapper_db_path: "nmapper.db".into(),
        })
    }

    /// Create with database paths configured.
    pub fn with_db_paths(
        ping: Arc<PingState>,
        trace: Arc<TraceState>,
        mapper: MapperState,
        ping_db_path: String,
        mapper_db_path: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            ping,
            trace,
            mapper,
            ping_job: RwLock::new(JobStatus::default()),
            trace_job: RwLock::new(JobStatus::default()),
            scan_job: RwLock::new(JobStatus::default()),
            ping_shutdown: RwLock::new(None),
            trace_shutdown: RwLock::new(None),
            scan_shutdown: RwLock::new(None),
            ping_db_path,
            mapper_db_path,
        })
    }
}
