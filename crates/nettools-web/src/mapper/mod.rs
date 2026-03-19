pub mod state;

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use nmapper_core::config::{ScanConfig, ScanTarget, SnmpConfig, DEFAULT_PORTS};
use nmapper_core::diff;
use nmapper_core::result::ScanEvent;
use nmapper_core::topology::TopologyGraph;

use crate::state::{JobStatus, UnifiedState};

// ---------------------------------------------------------------------------
// REST API types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct DeviceJson {
    ip: String,
    mac: Option<String>,
    vendor: Option<String>,
    hostname: Option<String>,
    device_type: String,
    os_guess: Option<String>,
    ttl: Option<u8>,
    open_ports: Vec<PortJson>,
    subnet: Option<String>,
    discovered_at: String,
}

#[derive(Serialize)]
struct PortJson {
    port: u16,
    status: String,
    service: Option<String>,
}

#[derive(Serialize)]
struct TopologyNodeJson {
    ip: String,
    device_type: String,
    label: String,
    tier: u8,
    subnet: Option<String>,
}

#[derive(Serialize)]
struct TopologyEdgeJson {
    source: String,
    target: String,
    link_type: String,
}

#[derive(Serialize)]
struct TopologyJson {
    nodes: Vec<TopologyNodeJson>,
    edges: Vec<TopologyEdgeJson>,
}

#[derive(Serialize)]
struct ScanInfoJson {
    scan_id: String,
    started_at: String,
    completed_at: String,
    subnet_count: usize,
    device_count: usize,
    subnets: Vec<String>,
}

/// Parameters for starting a network scan.
#[derive(Deserialize)]
pub struct StartScanRequest {
    pub targets: Vec<String>,
    pub ports: Option<Vec<u16>>,
    #[serde(default = "default_ping_timeout")]
    pub ping_timeout: u64,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default)]
    pub no_arp: bool,
    #[serde(default)]
    pub no_rdns: bool,
    pub snmp_community: Option<String>,
    pub snmp_v3_user: Option<String>,
    pub snmp_v3_auth_proto: Option<String>,
    pub snmp_v3_auth_pass: Option<String>,
    pub snmp_v3_priv_proto: Option<String>,
    pub snmp_v3_priv_pass: Option<String>,
}

fn default_ping_timeout() -> u64 { 1000 }
fn default_concurrency() -> usize { 64 }

/// Export query parameters.
#[derive(Deserialize)]
struct ExportParams {
    format: Option<String>,
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes(_state: Arc<UnifiedState>) -> Router<Arc<UnifiedState>> {
    Router::new()
        .route("/devices", get(get_devices))
        .route("/topology", get(get_topology))
        .route("/scan-info", get(get_scan_info))
        .route("/diff", get(get_diff))
        .route("/traps", get(get_traps))
        .route("/events", get(sse_handler))
        .route("/trap-events", get(trap_sse_handler))
        .route("/start", post(start_scan))
        .route("/stop", post(stop_scan))
        .route("/status", get(get_job_status))
        .route("/export", get(export_scan))
}

async fn get_devices(State(state): State<Arc<UnifiedState>>) -> Response {
    let result = state.mapper.get_result().await;
    match result {
        Some(scan) => {
            let devices: Vec<DeviceJson> = scan.devices.iter().map(|d| DeviceJson {
                ip: d.ip.to_string(),
                mac: d.mac.clone(),
                vendor: d.vendor.clone(),
                hostname: d.hostname.clone(),
                device_type: d.device_type.to_string(),
                os_guess: d.os_guess.clone(),
                ttl: d.ttl,
                open_ports: d.ports.iter()
                    .filter(|p| p.status == nmapper_core::result::PortStatus::Open)
                    .map(|p| PortJson { port: p.port, status: format!("{:?}", p.status), service: p.service.clone() })
                    .collect(),
                subnet: d.subnet.clone(),
                discovered_at: d.discovered_at.to_rfc3339(),
            }).collect();
            Json(devices).into_response()
        }
        None => Json(Vec::<DeviceJson>::new()).into_response(),
    }
}

async fn get_topology(State(state): State<Arc<UnifiedState>>) -> Response {
    let result = state.mapper.get_result().await;
    match result {
        Some(scan) => {
            let graph = TopologyGraph::from_scan(&scan.devices, &scan.links);
            let topo = TopologyJson {
                nodes: graph.nodes.iter().map(|n| TopologyNodeJson {
                    ip: n.ip.to_string(),
                    device_type: n.device_type.to_string(),
                    label: n.label.clone(),
                    tier: n.tier,
                    subnet: n.subnet.clone(),
                }).collect(),
                edges: graph.edges.iter().map(|e| TopologyEdgeJson {
                    source: e.source_ip.to_string(),
                    target: e.target_ip.to_string(),
                    link_type: e.link_type.clone(),
                }).collect(),
            };
            Json(topo).into_response()
        }
        None => Json(TopologyJson { nodes: vec![], edges: vec![] }).into_response(),
    }
}

async fn get_scan_info(State(state): State<Arc<UnifiedState>>) -> Response {
    let result = state.mapper.get_result().await;
    match result {
        Some(scan) => {
            let info = ScanInfoJson {
                scan_id: scan.scan_id.clone(),
                started_at: scan.started_at.to_rfc3339(),
                completed_at: scan.completed_at.to_rfc3339(),
                subnet_count: scan.subnets_scanned.len(),
                device_count: scan.devices.len(),
                subnets: scan.subnets_scanned.clone(),
            };
            Json(info).into_response()
        }
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn get_diff(State(state): State<Arc<UnifiedState>>) -> Response {
    let current = state.mapper.get_result().await;
    let previous = state.mapper.get_previous_result().await;
    match (previous, current) {
        (Some(old), Some(new)) => {
            let scan_diff = diff::compare_scans(&old, &new);
            Json(scan_diff).into_response()
        }
        _ => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn get_traps(State(state): State<Arc<UnifiedState>>) -> Response {
    let traps = state.mapper.get_recent_traps().await;
    Json(traps).into_response()
}

async fn sse_handler(
    State(state): State<Arc<UnifiedState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.mapper.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let event_type = match &event {
                ScanEvent::PhaseStarted { .. } => "phase_started",
                ScanEvent::HostDiscovered { .. } => "host_discovered",
                ScanEvent::HostScanned { .. } => "host_scanned",
                ScanEvent::Progress { .. } => "progress",
                ScanEvent::PhaseCompleted { .. } => "phase_completed",
                ScanEvent::ScanCompleted { .. } => "scan_completed",
            };
            match serde_json::to_string(&event) {
                Ok(data) => Some(Ok(Event::default().event(event_type).data(data))),
                Err(_) => None,
            }
        }
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn trap_sse_handler(
    State(state): State<Arc<UnifiedState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.mapper.subscribe_traps();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(trap) => match serde_json::to_string(&trap) {
            Ok(data) => Some(Ok(Event::default().event("trap").data(data))),
            Err(_) => None,
        },
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ---------------------------------------------------------------------------
// On-demand scan execution
// ---------------------------------------------------------------------------

async fn start_scan(
    State(state): State<Arc<UnifiedState>>,
    Json(req): Json<StartScanRequest>,
) -> Response {
    {
        let job = state.scan_job.read().await;
        if job.running {
            return (StatusCode::CONFLICT, Json(serde_json::json!({"error": "Scan is already running. Stop it first."}))).into_response();
        }
    }

    if req.targets.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "No targets specified"}))).into_response();
    }

    let targets: Vec<ScanTarget> = match req.targets.iter().map(|t| ScanTarget::parse(t)).collect::<Result<Vec<_>, _>>() {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("Invalid target: {e}")}))).into_response(),
    };

    let snmp_config = SnmpConfig::from_flags(
        req.snmp_community.clone(),
        req.snmp_v3_user.clone(),
        req.snmp_v3_auth_proto.clone(),
        req.snmp_v3_auth_pass.clone(),
        req.snmp_v3_priv_proto.clone(),
        req.snmp_v3_priv_pass.clone(),
    );

    let config = ScanConfig {
        targets,
        ping_timeout: Duration::from_millis(req.ping_timeout),
        ping_concurrency: req.concurrency,
        ports: req.ports.unwrap_or_else(|| DEFAULT_PORTS.to_vec()),
        port_timeout: Duration::from_millis(500),
        port_concurrency: 128,
        arp_lookup: !req.no_arp,
        rdns: !req.no_rdns,
        snmp_community: req.snmp_community,
        snmp_config,
    };

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    { *state.scan_shutdown.write().await = Some(shutdown_tx); }
    {
        let mut job = state.scan_job.write().await;
        job.running = true;
        job.message = format!("Scanning {} target(s)", req.targets.len());
    }

    let state_clone = state.clone();
    let target_desc = req.targets.join(", ");
    let mapper_db_path = state.mapper_db_path.clone();

    tokio::spawn(async move {
        let event_tx = state_clone.mapper.event_tx().clone();

        let scan_handle = tokio::spawn(async move {
            nmapper_core::engine::run_scan(&config, &event_tx).await
        });

        let result = tokio::select! {
            res = scan_handle => {
                match res {
                    Ok(Ok(r)) => Some(r),
                    Ok(Err(e)) => {
                        tracing::error!("scan error: {e}");
                        None
                    }
                    Err(e) => {
                        tracing::error!("scan task error: {e}");
                        None
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                None
            }
        };

        if let Some(scan_result) = result {
            // Store in mapper state
            state_clone.mapper.update_result(scan_result.clone()).await;

            // Persist to database
            match nmapper_core::db::Database::open(&mapper_db_path) {
                Ok(db) => {
                    if db.migrate().await.is_ok() {
                        if let Err(e) = db.insert_scan(&scan_result).await {
                            tracing::error!("failed to persist scan: {e}");
                        }
                    }
                }
                Err(e) => tracing::error!("failed to open mapper db: {e}"),
            }

            let mut job = state_clone.scan_job.write().await;
            job.running = false;
            job.message = format!("Scan complete: {} devices found on {}", scan_result.devices.len(), target_desc);
        } else {
            let mut job = state_clone.scan_job.write().await;
            job.running = false;
            job.message = "Scan stopped or failed".into();
        }

        *state_clone.scan_shutdown.write().await = None;
    });

    (StatusCode::OK, Json(serde_json::json!({"status": "started"}))).into_response()
}

async fn stop_scan(State(state): State<Arc<UnifiedState>>) -> Response {
    let shutdown = state.scan_shutdown.write().await.take();
    if let Some(tx) = shutdown {
        let _ = tx.send(()).await;
        (StatusCode::OK, Json(serde_json::json!({"status": "stopped"}))).into_response()
    } else {
        (StatusCode::OK, Json(serde_json::json!({"status": "not_running"}))).into_response()
    }
}

async fn get_job_status(State(state): State<Arc<UnifiedState>>) -> Json<JobStatus> {
    Json(state.scan_job.read().await.clone())
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

async fn export_scan(
    Query(params): Query<ExportParams>,
    State(state): State<Arc<UnifiedState>>,
) -> Response {
    let format = params.format.as_deref().unwrap_or("json");
    let result = state.mapper.get_result().await;

    match result {
        Some(scan) => {
            match format {
                "csv" => {
                    let csv = nmapper_core::export::csv_export::export_csv(&scan);
                    (
                        StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, "text/csv")],
                        csv,
                    ).into_response()
                }
                "svg" => {
                    let graph = TopologyGraph::from_scan(&scan.devices, &scan.links);
                    let layout = nmapper_core::layout::compute_layout(&graph);
                    let svg = nmapper_core::export::svg::export_svg(&layout, &scan.devices);
                    (
                        StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, "image/svg+xml")],
                        svg,
                    ).into_response()
                }
                "vsdx" | "visio" => {
                    let graph = TopologyGraph::from_scan(&scan.devices, &scan.links);
                    let layout = nmapper_core::layout::compute_layout(&graph);
                    match nmapper_core::export::vsdx::export_vsdx_bytes(&layout, &scan.devices) {
                        Ok(bytes) => (
                            StatusCode::OK,
                            [
                                (axum::http::header::CONTENT_TYPE, "application/vnd.ms-visio.drawing"),
                                (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=\"network-topology.vsdx\""),
                            ],
                            bytes,
                        ).into_response(),
                        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{e}")}))).into_response(),
                    }
                }
                _ => {
                    match nmapper_core::export::json_export::export_json(&scan) {
                        Ok(json) => (
                            StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/json")],
                            json,
                        ).into_response(),
                        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{e}")}))).into_response(),
                    }
                }
            }
        }
        None => (StatusCode::NO_CONTENT, Json(serde_json::json!({"error": "No scan data available"}))).into_response(),
    }
}
