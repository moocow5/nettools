pub mod ping;
pub mod trace;
pub mod mapper;
pub mod state;
mod static_files;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use axum::response::Json;
use tower_http::cors::{Any, CorsLayer};
use serde::Serialize;

use state::UnifiedState;

/// Configuration for the unified web dashboard server.
pub struct DashboardConfig {
    pub bind_addr: SocketAddr,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 9090)),
        }
    }
}

// Re-export state types for convenience.
pub use ping::state::PingState;
pub use trace::state::TraceState;
pub use mapper::state::MapperState;
pub use state::UnifiedState as AppState;

/// Status response showing which tools are currently active.
#[derive(Serialize)]
struct StatusResponse {
    ping_active: bool,
    ping_running: bool,
    trace_active: bool,
    trace_running: bool,
    mapper_has_data: bool,
    scan_running: bool,
}

async fn status_handler(
    axum::extract::State(state): axum::extract::State<Arc<UnifiedState>>,
) -> Json<StatusResponse> {
    let ping_targets = state.ping.targets.read().await;
    let trace_target = state.trace.target.read().await;
    let mapper_result = state.mapper.get_result().await;
    let ping_job = state.ping_job.read().await;
    let trace_job = state.trace_job.read().await;
    let scan_job = state.scan_job.read().await;

    Json(StatusResponse {
        ping_active: !ping_targets.is_empty(),
        ping_running: ping_job.running,
        trace_active: !trace_target.is_empty(),
        trace_running: trace_job.running,
        mapper_has_data: mapper_result.is_some(),
        scan_running: scan_job.running,
    })
}

/// Build the unified axum router with all routes namespaced by tool.
pub fn build_router(state: Arc<UnifiedState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .nest("/api/ping", ping::routes(state.clone()))
        .nest("/api/trace", trace::routes(state.clone()))
        .nest("/api/mapper", mapper::routes(state.clone()))
        .route("/api/status", get(status_handler))
        .merge(static_files::routes())
        .layer(cors)
        .with_state(state)
}

/// Start the unified web dashboard server.
pub async fn serve(config: DashboardConfig, state: Arc<UnifiedState>) -> std::io::Result<()> {
    let app = build_router(state);

    tracing::info!("nettools dashboard listening on http://{}", config.bind_addr);

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
