pub mod state;

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use ntrace_core::config::{ProbeMethod, TraceConfig};
use ntrace_core::mtr::{MtrConfig, MtrEngine, MtrEvent};

use crate::state::{JobStatus, UnifiedState};
use state::HopData;

// ---------------------------------------------------------------------------
// REST API types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HopEntry {
    ttl: u8,
    addr: Option<String>,
    hostname: Option<String>,
    asn: Option<u32>,
    asn_name: Option<String>,
    loss_pct: f64,
    sent: u64,
    last_rtt_ms: Option<f64>,
    avg_rtt_ms: Option<f64>,
    min_rtt_ms: Option<f64>,
    max_rtt_ms: Option<f64>,
    stddev_rtt_ms: Option<f64>,
}

impl From<(u8, &HopData)> for HopEntry {
    fn from((ttl, hop): (u8, &HopData)) -> Self {
        Self {
            ttl,
            addr: hop.stats.addr.map(|a| a.to_string()),
            hostname: hop.hostname.clone(),
            asn: hop.asn,
            asn_name: hop.asn_name.clone(),
            loss_pct: hop.stats.loss_pct,
            sent: hop.stats.sent,
            last_rtt_ms: hop.stats.last_rtt_ms,
            avg_rtt_ms: hop.stats.avg_rtt_ms,
            min_rtt_ms: hop.stats.min_rtt_ms,
            max_rtt_ms: hop.stats.max_rtt_ms,
            stddev_rtt_ms: hop.stats.stddev_rtt_ms,
        }
    }
}

#[derive(Serialize)]
struct TraceInfoJson {
    target: String,
    round: u64,
    max_ttl: u8,
    hops: Vec<HopEntry>,
}

/// Parameters for starting an on-demand trace/MTR.
#[derive(Deserialize)]
pub struct StartTraceRequest {
    pub target: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default = "default_first_ttl")]
    pub first_ttl: u8,
    #[serde(default = "default_max_ttl")]
    pub max_ttl: u8,
    #[serde(default = "default_queries")]
    pub queries: u8,
    #[serde(default = "default_trace_timeout")]
    pub timeout: String,
    #[serde(default = "default_send_wait")]
    pub send_wait: String,
    #[serde(default = "default_packet_size")]
    pub packet_size: usize,
    pub port: Option<u16>,
    #[serde(default = "default_trace_interval")]
    pub interval: String,
    pub count: Option<u64>,
    #[serde(default)]
    pub no_dns: bool,
    #[serde(default)]
    pub asn: bool,
}

fn default_method() -> String { "icmp".into() }
fn default_first_ttl() -> u8 { 1 }
fn default_max_ttl() -> u8 { 30 }
fn default_queries() -> u8 { 1 }
fn default_trace_timeout() -> String { "2s".into() }
fn default_send_wait() -> String { "50ms".into() }
fn default_packet_size() -> usize { 60 }
fn default_trace_interval() -> String { "1s".into() }

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes(_state: Arc<UnifiedState>) -> Router<Arc<UnifiedState>> {
    Router::new()
        .route("/hops", get(get_hops))
        .route("/info", get(get_info))
        .route("/events", get(sse_handler))
        .route("/start", post(start_trace))
        .route("/stop", post(stop_trace))
        .route("/status", get(get_job_status))
        .route("/export", get(export_trace))
}

async fn get_hops(State(state): State<Arc<UnifiedState>>) -> Json<Vec<HopEntry>> {
    let hops = state.trace.hops.read().await;
    let max_ttl = *state.trace.max_ttl.read().await;
    let mut entries: Vec<HopEntry> = Vec::new();
    for ttl in 1..=max_ttl {
        if let Some(hop) = hops.get(&ttl) {
            entries.push(HopEntry::from((ttl, hop)));
        }
    }
    Json(entries)
}

async fn get_info(State(state): State<Arc<UnifiedState>>) -> Json<TraceInfoJson> {
    let hops = state.trace.hops.read().await;
    let round = *state.trace.round.read().await;
    let max_ttl = *state.trace.max_ttl.read().await;
    let target = state.trace.target.read().await.clone();
    let mut entries: Vec<HopEntry> = Vec::new();
    for ttl in 1..=max_ttl {
        if let Some(hop) = hops.get(&ttl) {
            entries.push(HopEntry::from((ttl, hop)));
        }
    }
    Json(TraceInfoJson { target, round, max_ttl, hops: entries })
}

async fn sse_handler(
    State(state): State<Arc<UnifiedState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.trace.sse_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let (event_type, data) = match &event {
                MtrEvent::ProbeResult { round, result } => (
                    "probe_result",
                    serde_json::json!({ "round": round, "result": result }),
                ),
                MtrEvent::HopUpdate { ttl, stats, hostname, asn, asn_name } => (
                    "hop_update",
                    serde_json::json!({ "ttl": ttl, "stats": stats, "hostname": hostname, "asn": asn, "asn_name": asn_name }),
                ),
                MtrEvent::PathChange { ttl, old_addr, new_addr } => (
                    "path_change",
                    serde_json::json!({ "ttl": ttl, "old_addr": old_addr, "new_addr": new_addr }),
                ),
                MtrEvent::RoundComplete { round, reached_destination, max_ttl_seen } => (
                    "round_complete",
                    serde_json::json!({ "round": round, "reached_destination": reached_destination, "max_ttl_seen": max_ttl_seen }),
                ),
            };
            Some(Ok(Event::default().event(event_type).data(data.to_string())))
        }
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ---------------------------------------------------------------------------
// On-demand trace/MTR execution
// ---------------------------------------------------------------------------

fn parse_dur(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if let Some(ms_str) = s.strip_suffix("ms") {
        let ms: f64 = ms_str.trim().parse().map_err(|_| format!("invalid duration: {s}"))?;
        Ok(Duration::from_secs_f64(ms / 1000.0))
    } else if let Some(sec_str) = s.strip_suffix('s') {
        let secs: f64 = sec_str.trim().parse().map_err(|_| format!("invalid duration: {s}"))?;
        Ok(Duration::from_secs_f64(secs))
    } else {
        let secs: f64 = s.parse().map_err(|_| format!("invalid duration: {s}"))?;
        Ok(Duration::from_secs_f64(secs))
    }
}

fn parse_method_str(s: &str) -> Result<ProbeMethod, String> {
    match s.to_lowercase().as_str() {
        "icmp" => Ok(ProbeMethod::Icmp),
        "udp" => Ok(ProbeMethod::Udp),
        "tcp" | "tcp-syn" => Ok(ProbeMethod::TcpSyn),
        _ => Err(format!("unknown method: {s}")),
    }
}

async fn start_trace(
    State(state): State<Arc<UnifiedState>>,
    Json(req): Json<StartTraceRequest>,
) -> Response {
    {
        let job = state.trace_job.read().await;
        if job.running {
            return (StatusCode::CONFLICT, Json(serde_json::json!({"error": "Trace is already running. Stop it first."}))).into_response();
        }
    }

    let method = match parse_method_str(&req.method) {
        Ok(m) => m,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    };
    let timeout = match parse_dur(&req.timeout) {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    };
    let send_wait = match parse_dur(&req.send_wait) {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    };
    let interval = match parse_dur(&req.interval) {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    };

    let default_port = match method {
        ProbeMethod::Udp => 33434,
        ProbeMethod::TcpSyn => 80,
        ProbeMethod::Icmp => 0,
    };

    let trace_config = TraceConfig {
        target: req.target.clone(),
        method,
        first_ttl: req.first_ttl,
        max_ttl: req.max_ttl,
        probes_per_hop: req.queries,
        timeout,
        send_interval: send_wait,
        port: req.port.unwrap_or(default_port),
        packet_size: req.packet_size,
        concurrent: false,
        max_inflight: 16,
        paris_mode: false,
    };

    let mtr_config = MtrConfig {
        trace: trace_config,
        interval,
        rolling_window: 100,
        resolve_dns: !req.no_dns,
        lookup_asn: req.asn,
        lookup_geo: false,
        max_rounds: req.count,
    };

    // Clear previous trace state
    { state.trace.hops.write().await.clear(); }
    { *state.trace.max_ttl.write().await = 0; }
    { *state.trace.round.write().await = 0; }
    { *state.trace.target.write().await = req.target.clone(); }

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    { *state.trace_shutdown.write().await = Some(shutdown_tx); }
    {
        let mut job = state.trace_job.write().await;
        job.running = true;
        job.message = format!("Tracing route to {}", req.target);
    }

    let state_clone = state.clone();
    let target = req.target.clone();

    tokio::spawn(async move {
        let engine = MtrEngine::new(mtr_config);
        let event_rx = engine.subscribe();

        let relay_state = Arc::clone(&state_clone.trace);
        let relay_handle = tokio::spawn(async move {
            state::relay_events(event_rx, relay_state).await;
        });

        let socket = match ntrace_core::TraceSocket::new() {
            Ok(s) => s,
            Err(e) => {
                let mut job = state_clone.trace_job.write().await;
                job.running = false;
                job.message = format!("Socket error: {e}");
                return;
            }
        };

        // Create a shutdown channel for the MTR engine
        let (engine_shutdown_tx, engine_shutdown_rx) = mpsc::channel::<()>(1);

        let engine_handle = tokio::spawn(async move {
            let _ = engine.run(socket, engine_shutdown_rx).await;
        });

        tokio::select! {
            _ = engine_handle => {}
            _ = shutdown_rx.recv() => {
                // Signal the engine to stop
                let _ = engine_shutdown_tx.send(()).await;
            }
        }

        relay_handle.abort();
        let mut job = state_clone.trace_job.write().await;
        job.running = false;
        job.message = format!("Trace to {} complete", target);
        *state_clone.trace_shutdown.write().await = None;
    });

    (StatusCode::OK, Json(serde_json::json!({"status": "started", "target": req.target}))).into_response()
}

async fn stop_trace(State(state): State<Arc<UnifiedState>>) -> Response {
    let shutdown = state.trace_shutdown.write().await.take();
    if let Some(tx) = shutdown {
        let _ = tx.send(()).await;
        (StatusCode::OK, Json(serde_json::json!({"status": "stopped"}))).into_response()
    } else {
        (StatusCode::OK, Json(serde_json::json!({"status": "not_running"}))).into_response()
    }
}

async fn get_job_status(State(state): State<Arc<UnifiedState>>) -> Json<JobStatus> {
    Json(state.trace_job.read().await.clone())
}

async fn export_trace(State(state): State<Arc<UnifiedState>>) -> Response {
    let hops = state.trace.hops.read().await;
    let max_ttl = *state.trace.max_ttl.read().await;
    let target = state.trace.target.read().await.clone();
    let round = *state.trace.round.read().await;
    let mut entries: Vec<HopEntry> = Vec::new();
    for ttl in 1..=max_ttl {
        if let Some(hop) = hops.get(&ttl) {
            entries.push(HopEntry::from((ttl, hop)));
        }
    }
    Json(serde_json::json!({ "target": target, "round": round, "max_ttl": max_ttl, "hops": entries })).into_response()
}
