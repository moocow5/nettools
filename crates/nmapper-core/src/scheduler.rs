use std::time::Duration;

use tokio::sync::broadcast;
use tracing::{error, info};

use crate::config::{ScanConfig, ScanTarget, SnmpConfig, DEFAULT_PORTS};
use crate::db::Database;
use crate::engine::run_scan;
use crate::result::ScanEvent;

/// Configuration for scheduled scans.
#[derive(Debug, Clone)]
pub struct ScheduleConfig {
    /// Target strings (CIDRs, ranges, IPs).
    pub targets: Vec<String>,
    /// How often to scan.
    pub interval: Duration,
    /// Where to store results.
    pub db_path: String,
    /// Ports to scan.
    pub ports: Vec<u16>,
    /// SNMP community string (legacy v2c).
    pub snmp_community: Option<String>,
    /// Unified SNMP config (v2c or v3) — preferred over snmp_community.
    pub snmp_config: Option<SnmpConfig>,
    /// ICMP ping timeout.
    pub ping_timeout: Duration,
    /// Maximum concurrent pings.
    pub ping_concurrency: usize,
    /// Whether to look up ARP cache.
    pub arp_lookup: bool,
    /// Whether to do reverse DNS lookups.
    pub rdns: bool,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            interval: Duration::from_secs(3600),
            db_path: "nmapper.db".to_string(),
            ports: DEFAULT_PORTS.to_vec(),
            snmp_community: None,
            snmp_config: None,
            ping_timeout: Duration::from_secs(1),
            ping_concurrency: 64,
            arp_lookup: true,
            rdns: true,
        }
    }
}

/// Parse target strings into `ScanTarget` values, logging and skipping invalid ones.
fn parse_targets(raw: &[String]) -> Vec<ScanTarget> {
    let mut targets = Vec::new();
    for s in raw {
        match ScanTarget::parse(s) {
            Ok(t) => targets.push(t),
            Err(e) => error!("skipping invalid target '{}': {}", s, e),
        }
    }
    targets
}

/// Build a `ScanConfig` from a `ScheduleConfig` and parsed targets.
fn build_scan_config(sched: &ScheduleConfig, targets: Vec<ScanTarget>) -> ScanConfig {
    ScanConfig {
        targets,
        ping_timeout: sched.ping_timeout,
        ping_concurrency: sched.ping_concurrency,
        ports: sched.ports.clone(),
        snmp_community: sched.snmp_community.clone(),
        snmp_config: sched.snmp_config.clone(),
        arp_lookup: sched.arp_lookup,
        rdns: sched.rdns,
        ..ScanConfig::default()
    }
}

/// Run scans on a recurring schedule.
///
/// Opens the database, then loops forever: parse targets, run a scan, insert
/// the results into the DB, then sleep for `config.interval`.  Errors within a
/// single cycle are logged but do not stop the scheduler.
pub async fn run_scheduled(
    config: ScheduleConfig,
    tx: broadcast::Sender<ScanEvent>,
) -> crate::Result<()> {
    let db = Database::open(&config.db_path).map_err(crate::NmapperError::Database)?;
    db.migrate().await.map_err(crate::NmapperError::Database)?;

    loop {
        let targets = parse_targets(&config.targets);
        if targets.is_empty() {
            error!("no valid targets; sleeping until next cycle");
        } else {
            let scan_config = build_scan_config(&config, targets);

            match run_scan(&scan_config, &tx).await {
                Ok(result) => {
                    info!(
                        "scan {} completed: {} devices found",
                        result.scan_id,
                        result.devices.len()
                    );
                    if let Err(e) = db.insert_scan(&result).await {
                        error!("failed to store scan results: {}", e);
                    }
                }
                Err(e) => {
                    error!("scan failed: {}", e);
                }
            }
        }

        info!("next scan in {} seconds", config.interval.as_secs());
        tokio::time::sleep(config.interval).await;
    }
}

/// Run a single scan cycle and return the scan ID.
pub async fn run_once(
    config: &ScheduleConfig,
    tx: &broadcast::Sender<ScanEvent>,
) -> crate::Result<String> {
    let db = Database::open(&config.db_path).map_err(crate::NmapperError::Database)?;
    db.migrate().await.map_err(crate::NmapperError::Database)?;

    let targets = parse_targets(&config.targets);
    if targets.is_empty() {
        return Err(crate::NmapperError::Other(
            "no valid targets provided".into(),
        ));
    }

    let scan_config = build_scan_config(config, targets);
    let result = run_scan(&scan_config, tx).await?;
    let scan_id = result.scan_id.clone();

    db.insert_scan(&result)
        .await
        .map_err(crate::NmapperError::Database)?;

    info!("scan {} completed and stored", scan_id);
    Ok(scan_id)
}
