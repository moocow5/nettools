pub mod state;

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use nping_core::config::{PayloadPattern, PingConfig, PingMode};
use nping_core::monitor::MonitorEvent;
use nping_core::result::{PingResult, PingStatus};

use crate::state::{JobStatus, UnifiedState};

// ---------------------------------------------------------------------------
// REST API types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct TargetInfo {
    id: usize,
    host: String,
    label: Option<String>,
    mode: String,
    port: Option<u16>,
    interval: String,
}

#[derive(Serialize)]
struct TargetDetail {
    #[serde(flatten)]
    info: TargetInfo,
    stats: Option<nping_core::monitor::TargetStats>,
}

#[derive(Serialize)]
struct HistoryEntry {
    seq: u16,
    rtt_ms: Option<f64>,
    status: String,
    timestamp_ms: u64,
}

#[derive(Deserialize)]
struct DbHistoryParams {
    from: Option<i64>,
    to: Option<i64>,
    limit: Option<usize>,
}

/// Parameters for starting an on-demand ping.
#[derive(Deserialize)]
pub struct StartPingRequest {
    pub target: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    pub port: Option<u16>,
    pub count: Option<u64>,
    #[serde(default = "default_interval")]
    pub interval: String,
    #[serde(default = "default_timeout")]
    pub timeout: String,
    #[serde(default = "default_size")]
    pub size: usize,
    pub ttl: Option<u8>,
    pub tos: Option<u8>,
    pub pattern: Option<String>,
}

fn default_mode() -> String { "icmp".into() }
fn default_interval() -> String { "1s".into() }
fn default_timeout() -> String { "2s".into() }
fn default_size() -> usize { 56 }

/// JSON representation of a ping result for the API.
#[derive(Serialize)]
struct PingResultJson {
    seq: u16,
    target: String,
    rtt_ms: Option<f64>,
    ttl: Option<u8>,
    packet_size: usize,
    status: String,
    timestamp_ms: u64,
}

impl From<&PingResult> for PingResultJson {
    fn from(r: &PingResult) -> Self {
        Self {
            seq: r.seq,
            target: r.target.to_string(),
            rtt_ms: r.rtt_ms(),
            ttl: r.ttl,
            packet_size: r.packet_size,
            status: format!("{:?}", r.status),
            timestamp_ms: r
                .timestamp
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }
}

/// Export parameters for ping data.
#[derive(Deserialize)]
struct PingExportParams {
    target: Option<String>,
    format: Option<String>,
    from: Option<String>,
    to: Option<String>,
    limit: Option<usize>,
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes(_state: Arc<UnifiedState>) -> Router<Arc<UnifiedState>> {
    Router::new()
        .route("/targets", get(list_targets))
        .route("/targets/{id}", get(get_target))
        .route("/targets/{id}/history", get(get_history))
        .route("/targets/{id}/db-history", get(get_db_history))
        .route("/events", get(sse_handler))
        .route("/start", post(start_ping))
        .route("/stop", post(stop_ping))
        .route("/status", get(get_job_status))
        .route("/results", get(get_results))
        .route("/export", get(export_ping))
        .route("/export/hosts", get(list_export_hosts))
}

async fn list_targets(State(state): State<Arc<UnifiedState>>) -> Json<Vec<TargetDetail>> {
    let targets = state.ping.targets.read().await;
    let stats = state.ping.stats.read().await;

    let result: Vec<TargetDetail> = targets
        .iter()
        .enumerate()
        .map(|(id, t)| TargetDetail {
            info: TargetInfo {
                id,
                host: t.host.clone(),
                label: t.label.clone(),
                mode: t.mode.clone(),
                port: t.port,
                interval: t.interval.clone(),
            },
            stats: stats.get(&id).cloned(),
        })
        .collect();

    Json(result)
}

async fn get_target(
    Path(id): Path<usize>,
    State(state): State<Arc<UnifiedState>>,
) -> Result<Json<TargetDetail>, StatusCode> {
    let targets = state.ping.targets.read().await;
    let target = targets.get(id).ok_or(StatusCode::NOT_FOUND)?;
    let stats = state.ping.stats.read().await;

    Ok(Json(TargetDetail {
        info: TargetInfo {
            id,
            host: target.host.clone(),
            label: target.label.clone(),
            mode: target.mode.clone(),
            port: target.port,
            interval: target.interval.clone(),
        },
        stats: stats.get(&id).cloned(),
    }))
}

async fn get_history(
    Path(id): Path<usize>,
    State(state): State<Arc<UnifiedState>>,
) -> Result<Json<Vec<HistoryEntry>>, StatusCode> {
    let targets = state.ping.targets.read().await;
    if id >= targets.len() {
        return Err(StatusCode::NOT_FOUND);
    }

    let history = state.ping.history.read().await;
    let entries = history
        .get(&id)
        .map(|results| {
            results
                .iter()
                .map(|r| {
                    let timestamp_ms = r
                        .timestamp
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    HistoryEntry {
                        seq: r.seq,
                        rtt_ms: r.rtt_ms(),
                        status: format!("{:?}", r.status),
                        timestamp_ms,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Json(entries))
}

async fn get_db_history(
    Path(id): Path<usize>,
    Query(params): Query<DbHistoryParams>,
    State(state): State<Arc<UnifiedState>>,
) -> Result<Json<Vec<nping_core::db::ExportRow>>, StatusCode> {
    let db = state.ping.db.as_ref().ok_or(StatusCode::NOT_IMPLEMENTED)?;

    let targets = state.ping.targets.read().await;
    let target = targets.get(id).ok_or(StatusCode::NOT_FOUND)?;
    let host = target.host.clone();
    drop(targets);

    let rows = db
        .query_results(&host, params.from, params.to, params.limit)
        .await
        .map_err(|e| {
            tracing::error!("db query failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(rows))
}

async fn sse_handler(
    State(state): State<Arc<UnifiedState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.ping.sse_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| {
        match result {
            Ok(event) => {
                let event_type = match &event {
                    MonitorEvent::PingResult { .. } => "ping_result",
                    MonitorEvent::StatsUpdate { .. } => "stats_update",
                    MonitorEvent::AlertFired { .. } => "alert_fired",
                };
                match serde_json::to_string(&event) {
                    Ok(data) => Some(Ok(Event::default().event(event_type).data(data))),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ---------------------------------------------------------------------------
// On-demand ping execution
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

fn parse_pattern(s: &str) -> Result<PayloadPattern, String> {
    match s {
        "zeros" | "0" => Ok(PayloadPattern::Zeros),
        "alt" | "aa" => Ok(PayloadPattern::AltBits),
        "random" | "rand" => Ok(PayloadPattern::Random),
        _ => {
            let s = s.strip_prefix("0x").unwrap_or(s);
            let byte = u8::from_str_radix(s, 16)
                .map_err(|_| "invalid pattern".to_string())?;
            Ok(PayloadPattern::Byte(byte))
        }
    }
}

async fn start_ping(
    State(state): State<Arc<UnifiedState>>,
    Json(req): Json<StartPingRequest>,
) -> Response {
    // Check if already running
    {
        let job = state.ping_job.read().await;
        if job.running {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "Ping is already running. Stop it first."})),
            ).into_response();
        }
    }

    let mode = match req.mode.as_str() {
        "icmp" => PingMode::Icmp,
        "tcp" => PingMode::Tcp,
        "tcp-connect" => PingMode::TcpConnect,
        "udp" => PingMode::Udp,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid mode. Use: icmp, tcp, tcp-connect, udp"})),
            ).into_response();
        }
    };

    if matches!(mode, PingMode::Tcp | PingMode::TcpConnect | PingMode::Udp) && req.port.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Port is required for TCP/UDP modes"})),
        ).into_response();
    }

    let interval = match parse_dur(&req.interval) {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    };

    let timeout = match parse_dur(&req.timeout) {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    };

    let payload_pattern = match &req.pattern {
        Some(p) => match parse_pattern(p) {
            Ok(pat) => pat,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
        },
        None => PayloadPattern::default(),
    };

    let config = PingConfig {
        target: req.target.clone(),
        mode,
        port: req.port,
        count: req.count,
        interval,
        timeout,
        packet_size: req.size,
        ttl: req.ttl,
        tos: req.tos,
        payload_pattern,
    };

    // Clear previous ping state
    {
        let mut targets = state.ping.targets.write().await;
        targets.clear();
        targets.push(nping_core::monitor::TargetConfig {
            host: req.target.clone(),
            label: Some(req.target.clone()),
            mode: req.mode.clone(),
            port: req.port,
            interval: req.interval.clone(),
            alert: None,
        });
    }
    {
        let mut stats = state.ping.stats.write().await;
        stats.clear();
    }
    {
        let mut history = state.ping.history.write().await;
        history.clear();
    }

    // Create shutdown channel
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    {
        let mut lock = state.ping_shutdown.write().await;
        *lock = Some(shutdown_tx);
    }

    // Mark job as running
    {
        let mut job = state.ping_job.write().await;
        job.running = true;
        job.message = format!("Pinging {}", req.target);
    }

    let state_clone = state.clone();
    let target = req.target.clone();

    // Spawn the ping task
    tokio::spawn(async move {
        let socket = match nping_core::IcmpSocket::new() {
            Ok(s) => s,
            Err(e) => {
                let mut job = state_clone.ping_job.write().await;
                job.running = false;
                job.message = format!("Socket error: {e}");
                return;
            }
        };

        if let Some(ttl) = config.ttl {
            let _ = socket.set_ttl(ttl);
        }
        if let Some(tos) = config.tos {
            let _ = socket.set_tos(tos);
        }

        let (tx, mut rx) = mpsc::channel::<PingResult>(128);
        let config_clone = config.clone();

        let pinger = tokio::spawn(async move {
            let _ = nping_core::pinger::run(&config_clone, &socket, tx).await;
        });

        let mut seq_counter: u64 = 0;
        let target_id: usize = 0;

        loop {
            tokio::select! {
                result = rx.recv() => {
                    match result {
                        Some(ping_result) => {
                            seq_counter += 1;

                            // Store in history
                            {
                                let mut history = state_clone.ping.history.write().await;
                                let entry = history.entry(target_id).or_insert_with(Vec::new);
                                if entry.len() >= 300 {
                                    entry.remove(0);
                                }
                                entry.push(ping_result.clone());
                            }

                            // Compute stats
                            {
                                let history = state_clone.ping.history.read().await;
                                if let Some(results) = history.get(&target_id) {
                                    let stats = nping_core::stats::PingStats::from_results(results);
                                    let is_up = matches!(ping_result.status, PingStatus::Success);
                                    let target_stats = nping_core::monitor::TargetStats {
                                        host: target.clone(),
                                        label: Some(target.clone()),
                                        mode: "icmp".into(),
                                        stats,
                                        is_up,
                                        last_rtt_ms: ping_result.rtt_ms(),
                                    };
                                    let mut s = state_clone.ping.stats.write().await;
                                    s.insert(target_id, target_stats.clone());

                                    // Broadcast to SSE
                                    let _ = state_clone.ping.sse_tx.send(
                                        MonitorEvent::PingResult {
                                            target_id,
                                            result: ping_result.clone(),
                                        },
                                    );
                                    let _ = state_clone.ping.sse_tx.send(
                                        MonitorEvent::StatsUpdate {
                                            target_id,
                                            stats: target_stats,
                                        },
                                    );
                                }
                            }
                        }
                        None => break,
                    }
                }
                _ = shutdown_rx.recv() => {
                    pinger.abort();
                    break;
                }
            }
        }

        let mut job = state_clone.ping_job.write().await;
        job.running = false;
        job.message = format!("Completed: {} pings to {}", seq_counter, target);

        let mut lock = state_clone.ping_shutdown.write().await;
        *lock = None;
    });

    (StatusCode::OK, Json(serde_json::json!({"status": "started", "target": req.target}))).into_response()
}

async fn stop_ping(State(state): State<Arc<UnifiedState>>) -> Response {
    let shutdown = {
        let mut lock = state.ping_shutdown.write().await;
        lock.take()
    };
    if let Some(tx) = shutdown {
        let _ = tx.send(()).await;
        (StatusCode::OK, Json(serde_json::json!({"status": "stopped"}))).into_response()
    } else {
        (StatusCode::OK, Json(serde_json::json!({"status": "not_running"}))).into_response()
    }
}

async fn get_job_status(State(state): State<Arc<UnifiedState>>) -> Json<JobStatus> {
    Json(state.ping_job.read().await.clone())
}

async fn get_results(State(state): State<Arc<UnifiedState>>) -> Json<Vec<PingResultJson>> {
    let history = state.ping.history.read().await;
    let results: Vec<PingResultJson> = history
        .get(&0)
        .map(|r| r.iter().map(PingResultJson::from).collect())
        .unwrap_or_default();
    Json(results)
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

async fn list_export_hosts(State(state): State<Arc<UnifiedState>>) -> Response {
    let db_path = &state.ping_db_path;
    match nping_core::db::Database::open(db_path) {
        Ok(db) => {
            if db.migrate().await.is_err() {
                return Json(Vec::<String>::new()).into_response();
            }
            match db.list_hosts().await {
                Ok(hosts) => Json(hosts).into_response(),
                Err(_) => Json(Vec::<String>::new()).into_response(),
            }
        }
        Err(_) => Json(Vec::<String>::new()).into_response(),
    }
}

fn parse_datetime_ms(s: &str) -> Result<i64, String> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.timestamp_millis());
    }
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(ndt.and_utc().timestamp_millis());
    }
    if let Ok(nd) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let ndt = nd.and_hms_opt(0, 0, 0).unwrap();
        return Ok(ndt.and_utc().timestamp_millis());
    }
    Err(format!("invalid date format: {s}"))
}

async fn export_ping(
    Query(params): Query<PingExportParams>,
    State(state): State<Arc<UnifiedState>>,
) -> Response {
    let format = params.format.as_deref().unwrap_or("json");

    if let Some(ref target) = params.target {
        let db_path = &state.ping_db_path;
        let db = match nping_core::db::Database::open(db_path) {
            Ok(db) => db,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Database error: {e}")})),
                ).into_response();
            }
        };
        if db.migrate().await.is_err() {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Migration failed"}))).into_response();
        }

        let from_ms = params.from.as_ref().and_then(|s| parse_datetime_ms(s).ok());
        let to_ms = params.to.as_ref().and_then(|s| parse_datetime_ms(s).ok());

        let rows = match db.query_results(target, from_ms, to_ms, params.limit).await {
            Ok(r) => r,
            Err(e) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{e}")}))).into_response();
            }
        };

        match format {
            "csv" => {
                let mut csv_data = String::from("timestamp,host,mode,seq,rtt_ms,rtt_us,ttl,packet_size,status\n");
                for row in &rows {
                    let ts = chrono::DateTime::from_timestamp_millis(row.timestamp_ms as i64)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_else(|| row.timestamp_ms.to_string());
                    csv_data.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{}\n",
                        ts, row.host, row.mode, row.seq,
                        row.rtt_ms().map(|v| format!("{:.3}", v)).unwrap_or_default(),
                        row.rtt_us.map(|v| format!("{:.1}", v)).unwrap_or_default(),
                        row.ttl.map(|t| t.to_string()).unwrap_or_default(),
                        row.packet_size, row.status,
                    ));
                }
                (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "text/csv")],
                    csv_data,
                ).into_response()
            }
            _ => Json(rows).into_response(),
        }
    } else {
        // Export in-memory results
        let history = state.ping.history.read().await;
        let results: Vec<PingResultJson> = history
            .get(&0)
            .map(|r| r.iter().map(PingResultJson::from).collect())
            .unwrap_or_default();
        match format {
            "csv" => {
                let mut csv_data = String::from("seq,target,rtt_ms,ttl,packet_size,status,timestamp_ms\n");
                for r in &results {
                    csv_data.push_str(&format!(
                        "{},{},{},{},{},{},{}\n",
                        r.seq, r.target,
                        r.rtt_ms.map(|v| format!("{:.3}", v)).unwrap_or_default(),
                        r.ttl.map(|t| t.to_string()).unwrap_or_default(),
                        r.packet_size, r.status, r.timestamp_ms,
                    ));
                }
                (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "text/csv")], csv_data).into_response()
            }
            _ => Json(results).into_response(),
        }
    }
}
