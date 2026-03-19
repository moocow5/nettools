//! Unified dashboard command — launches nettools-web serving all three tools.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Args;
use tokio::sync::mpsc;

use nping_core::db::{self, Database};
use nping_core::monitor::Monitor;
use nettools_web::{DashboardConfig, PingState, AppState};

use crate::cmd_monitor::parse_targets_file;

#[derive(Args)]
pub struct DashboardArgs {
    /// Path to the targets TOML configuration file (for ping monitoring)
    pub targets: Option<String>,

    /// Address to bind the web server to
    #[arg(short = 'b', long, default_value = "127.0.0.1:9090")]
    pub bind: String,

    /// Override ping interval for all targets (e.g., "1s", "500ms")
    #[arg(short = 'i', long)]
    pub interval: Option<String>,

    /// SQLite database file for ping data
    #[arg(long, default_value = "nping.db")]
    pub ping_db: String,

    /// SQLite database file for nmapper data
    #[arg(long, default_value = "nmapper.db")]
    pub mapper_db: String,
}

pub async fn run(args: DashboardArgs) -> Result<(), String> {
    let bind_addr: SocketAddr = args
        .bind
        .parse()
        .map_err(|e| format!("invalid bind address: {e}"))?;

    // Build the unified state, optionally with ping monitoring.
    let unified_state = if let Some(ref targets_path) = args.targets {
        // Parse targets file and set up ping monitoring
        let mut config = parse_targets_file(targets_path)?;

        if let Some(ref interval) = args.interval {
            for t in &mut config.target {
                t.interval = interval.clone();
            }
        }

        let targets_snapshot = config.target.clone();

        let database = Database::open(&args.ping_db)
            .map_err(|e| format!("failed to open database {}: {e}", args.ping_db))?;
        database
            .migrate()
            .await
            .map_err(|e| format!("db migration failed: {e}"))?;
        let db = Arc::new(database);

        eprintln!("Storing ping results in {}", args.ping_db);

        let monitor = Monitor::new(config);
        let event_rx = monitor.subscribe();
        let db_event_rx = monitor.subscribe();

        let (_shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

        let target_info: Vec<(usize, String, String)> = targets_snapshot
            .iter()
            .enumerate()
            .map(|(id, t)| (id, t.host.clone(), t.mode.clone()))
            .collect();

        let _db_handle = db::spawn_db_writer(Arc::clone(&db), db_event_rx, target_info);

        let ping_state = PingState::new(targets_snapshot, Some(Arc::clone(&db)));

        // Spawn relay to feed monitor events into PingState SSE
        let relay_state = Arc::clone(&ping_state);
        tokio::spawn(async move {
            nettools_web::ping::state::relay_events(event_rx, relay_state).await;
        });

        eprintln!(
            "monitoring {} target(s)",
            monitor.target_count()
        );

        // Spawn the monitor
        tokio::spawn(async move {
            if let Err(e) = monitor.run(shutdown_rx).await {
                tracing::error!("monitor failed: {e}");
            }
        });

        // Build unified state with the configured ping state
        let trace_state = nettools_web::TraceState::new_empty();
        let mapper_state = nettools_web::mapper::state::MapperState::new();

        // Try to load latest scan from mapper db
        match nmapper_core::db::Database::open(&args.mapper_db) {
            Ok(mdb) => {
                if let Ok(()) = mdb.migrate().await {
                    if let Ok(scans) = mdb.list_scans().await {
                        if let Some(latest) = scans.first() {
                            if let Ok(Some(result)) = mdb.load_scan(&latest.scan_id).await {
                                eprintln!(
                                    "Loaded scan {} ({} devices) from mapper database",
                                    latest.scan_id, result.devices.len()
                                );
                                mapper_state.update_result(result).await;
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }

        AppState::with_db_paths(ping_state, trace_state, mapper_state, args.ping_db.clone(), args.mapper_db.clone())
    } else {
        // No targets file — start with empty ping state
        let ping_state = PingState::new_empty();
        let trace_state = nettools_web::TraceState::new_empty();
        let mapper_state = nettools_web::mapper::state::MapperState::new();
        let state = AppState::with_db_paths(ping_state, trace_state, mapper_state, args.ping_db.clone(), args.mapper_db.clone());

        // Try to load latest scan from mapper db
        match nmapper_core::db::Database::open(&args.mapper_db) {
            Ok(mdb) => {
                if let Ok(()) = mdb.migrate().await {
                    if let Ok(scans) = mdb.list_scans().await {
                        if let Some(latest) = scans.first() {
                            if let Ok(Some(result)) = mdb.load_scan(&latest.scan_id).await {
                                eprintln!(
                                    "Loaded scan {} ({} devices) from mapper database",
                                    latest.scan_id, result.devices.len()
                                );
                                state.mapper.update_result(result).await;
                            }
                        }
                    }
                }
            }
            Err(_) => {
                eprintln!("No existing mapper database found, starting with empty state");
            }
        }

        state
    };

    let config = DashboardConfig { bind_addr };
    eprintln!("nettools dashboard starting on http://{}", bind_addr);

    nettools_web::serve(config, unified_state)
        .await
        .map_err(|e| format!("web server error: {e}"))?;

    Ok(())
}
