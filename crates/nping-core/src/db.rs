//! SQLite persistence layer for ping results and alerts.
//!
//! Uses `rusqlite` with the bundled SQLite build for zero external dependencies.
//! Supports batch inserts for high-throughput monitoring.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use tokio::sync::Mutex;

use crate::alert::FiredAlert;
use crate::monitor::MonitorEvent;
use crate::result::{PingResult, PingStatus};

/// Batch insert threshold — flush after this many pending results.
const BATCH_SIZE: usize = 100;
/// Maximum time between flushes.
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// A database handle for nping data.
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Open (or create) a SQLite database at the given path.
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        Ok(db)
    }

    /// Open an in-memory database (useful for tests).
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        Ok(db)
    }

    /// Run schema migrations. Idempotent — safe to call on every startup.
    pub async fn migrate(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute_batch(SCHEMA)?;
        Ok(())
    }

    /// Get a shared handle to the connection (for the web API).
    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    /// Insert a single ping result.
    pub async fn insert_result(
        &self,
        target_id: usize,
        host: &str,
        mode: &str,
        result: &PingResult,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().await;
        let timestamp_ms = system_time_to_ms(result.timestamp);
        let rtt_us = result.rtt_us();
        let status = status_str(result.status);

        conn.execute(
            "INSERT INTO ping_results (target_id, host, mode, seq, rtt_us, ttl, packet_size, status, timestamp_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                target_id as i64,
                host,
                mode,
                result.seq as i64,
                rtt_us,
                result.ttl.map(|t| t as i64),
                result.packet_size as i64,
                status,
                timestamp_ms as i64,
            ],
        )?;
        Ok(())
    }

    /// Insert a batch of ping results in a single transaction.
    pub async fn insert_results_batch(
        &self,
        batch: &[(usize, String, String, PingResult)],
    ) -> rusqlite::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().await;
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO ping_results (target_id, host, mode, seq, rtt_us, ttl, packet_size, status, timestamp_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for (target_id, host, mode, result) in batch {
                let timestamp_ms = system_time_to_ms(result.timestamp);
                let rtt_us = result.rtt_us();
                let status = status_str(result.status);
                stmt.execute(params![
                    *target_id as i64,
                    host,
                    mode,
                    result.seq as i64,
                    rtt_us,
                    result.ttl.map(|t| t as i64),
                    result.packet_size as i64,
                    status,
                    timestamp_ms as i64,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Insert a fired alert record.
    pub async fn insert_alert(
        &self,
        target_id: usize,
        host: &str,
        alert: &FiredAlert,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().await;
        let now_ms = system_time_to_ms(SystemTime::now());
        conn.execute(
            "INSERT INTO alerts (target_id, host, metric, value, threshold, message, timestamp_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                target_id as i64,
                host,
                alert.metric,
                alert.value,
                alert.threshold,
                alert.message,
                now_ms as i64,
            ],
        )?;
        Ok(())
    }

    /// Query ping results for a target within a time range.
    /// Returns rows as (seq, rtt_us, ttl, packet_size, status, timestamp_ms).
    pub async fn query_results(
        &self,
        host: &str,
        from_ms: Option<i64>,
        to_ms: Option<i64>,
        limit: Option<usize>,
    ) -> rusqlite::Result<Vec<ExportRow>> {
        let conn = self.conn.lock().await;
        let mut sql = String::from(
            "SELECT target_id, host, mode, seq, rtt_us, ttl, packet_size, status, timestamp_ms
             FROM ping_results WHERE host = ?1",
        );
        let mut param_idx = 2;
        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(host.to_string())];

        if let Some(from) = from_ms {
            sql.push_str(&format!(" AND timestamp_ms >= ?{param_idx}"));
            params_vec.push(Box::new(from));
            param_idx += 1;
        }
        if let Some(to) = to_ms {
            sql.push_str(&format!(" AND timestamp_ms <= ?{param_idx}"));
            params_vec.push(Box::new(to));
            param_idx += 1;
        }
        sql.push_str(" ORDER BY timestamp_ms ASC");
        if let Some(lim) = limit {
            sql.push_str(&format!(" LIMIT ?{param_idx}"));
            params_vec.push(Box::new(lim as i64));
        }

        let mut stmt = conn.prepare(&sql)?;
        let params_refs: Vec<&dyn rusqlite::types::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                Ok(ExportRow {
                    target_id: row.get::<_, i64>(0)? as usize,
                    host: row.get(1)?,
                    mode: row.get(2)?,
                    seq: row.get::<_, i64>(3)? as u16,
                    rtt_us: row.get(4)?,
                    ttl: row.get::<_, Option<i64>>(5)?.map(|t| t as u8),
                    packet_size: row.get::<_, i64>(6)? as usize,
                    status: row.get(7)?,
                    timestamp_ms: row.get::<_, i64>(8)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// List distinct hosts in the database.
    pub async fn list_hosts(&self) -> rusqlite::Result<Vec<String>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare("SELECT DISTINCT host FROM ping_results ORDER BY host")?;
        let rows = stmt
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(rows)
    }
}

/// A row from the ping_results table, suitable for export.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExportRow {
    pub target_id: usize,
    pub host: String,
    pub mode: String,
    pub seq: u16,
    pub rtt_us: Option<f64>,
    pub ttl: Option<u8>,
    pub packet_size: usize,
    pub status: String,
    pub timestamp_ms: u64,
}

impl ExportRow {
    pub fn rtt_ms(&self) -> Option<f64> {
        self.rtt_us.map(|us| us / 1000.0)
    }
}

// ---------------------------------------------------------------------------
// Background DB writer task
// ---------------------------------------------------------------------------

/// Spawn a background task that listens to monitor events and writes them to the database.
///
/// Returns an mpsc sender that the caller should drop to stop the writer.
pub fn spawn_db_writer(
    db: Arc<Database>,
    mut event_rx: tokio::sync::broadcast::Receiver<MonitorEvent>,
    targets: Vec<(usize, String, String)>, // (id, host, mode)
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut batch: Vec<(usize, String, String, PingResult)> = Vec::with_capacity(BATCH_SIZE);
        let mut flush_timer = tokio::time::interval(FLUSH_INTERVAL);
        flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                event = event_rx.recv() => {
                    match event {
                        Ok(MonitorEvent::PingResult { target_id, result }) => {
                            if let Some((_, host, mode)) = targets.iter().find(|(id, _, _)| *id == target_id) {
                                batch.push((target_id, host.clone(), mode.clone(), result));
                            }
                            if batch.len() >= BATCH_SIZE {
                                flush_batch(&db, &mut batch).await;
                            }
                        }
                        Ok(MonitorEvent::AlertFired { target_id, alert }) => {
                            if let Some((_, host, _)) = targets.iter().find(|(id, _, _)| *id == target_id) {
                                if let Err(e) = db.insert_alert(target_id, host, &alert).await {
                                    tracing::warn!("failed to insert alert: {e}");
                                }
                            }
                        }
                        Ok(MonitorEvent::StatsUpdate { .. }) => {
                            // Stats are computed on-the-fly, not persisted.
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("db writer lagged by {n} events");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            // Monitor shut down — flush remaining and exit.
                            flush_batch(&db, &mut batch).await;
                            break;
                        }
                    }
                }
                _ = flush_timer.tick() => {
                    flush_batch(&db, &mut batch).await;
                }
            }
        }
    })
}

async fn flush_batch(
    db: &Database,
    batch: &mut Vec<(usize, String, String, PingResult)>,
) {
    if batch.is_empty() {
        return;
    }
    if let Err(e) = db.insert_results_batch(batch).await {
        tracing::warn!("failed to flush batch to db: {e}");
    }
    batch.clear();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn system_time_to_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn status_str(s: PingStatus) -> &'static str {
    match s {
        PingStatus::Success => "success",
        PingStatus::Timeout => "timeout",
        PingStatus::Unreachable => "unreachable",
        PingStatus::Error => "error",
    }
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS ping_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    host        TEXT    NOT NULL,
    mode        TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    rtt_us      REAL,
    ttl         INTEGER,
    packet_size INTEGER NOT NULL,
    status      TEXT    NOT NULL,
    timestamp_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_results_host_ts ON ping_results (host, timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_results_target_ts ON ping_results (target_id, timestamp_ms);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id    INTEGER NOT NULL,
    host         TEXT    NOT NULL,
    metric       TEXT    NOT NULL,
    value        REAL    NOT NULL,
    threshold    REAL    NOT NULL,
    message      TEXT    NOT NULL,
    timestamp_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_host_ts ON alerts (host, timestamp_ms);
";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{PingResult, PingStatus};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_result(seq: u16, rtt_ms: Option<f64>) -> PingResult {
        PingResult {
            seq,
            target: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            rtt: rtt_ms.map(|ms| Duration::from_secs_f64(ms / 1000.0)),
            ttl: Some(64),
            packet_size: 64,
            timestamp: SystemTime::now(),
            status: if rtt_ms.is_some() {
                PingStatus::Success
            } else {
                PingStatus::Timeout
            },
        }
    }

    #[tokio::test]
    async fn test_migrate_and_insert() {
        let db = Database::open_in_memory().unwrap();
        db.migrate().await.unwrap();

        let result = make_result(1, Some(10.5));
        db.insert_result(0, "8.8.8.8", "icmp", &result)
            .await
            .unwrap();

        let rows = db.query_results("8.8.8.8", None, None, None).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].host, "8.8.8.8");
        assert_eq!(rows[0].seq, 1);
        assert!(rows[0].rtt_us.is_some());
    }

    #[tokio::test]
    async fn test_batch_insert() {
        let db = Database::open_in_memory().unwrap();
        db.migrate().await.unwrap();

        let batch: Vec<(usize, String, String, PingResult)> = (0..50)
            .map(|i| {
                (
                    0,
                    "1.1.1.1".to_string(),
                    "icmp".to_string(),
                    make_result(i, Some(5.0 + i as f64)),
                )
            })
            .collect();

        db.insert_results_batch(&batch).await.unwrap();

        let rows = db.query_results("1.1.1.1", None, None, None).await.unwrap();
        assert_eq!(rows.len(), 50);
    }

    #[tokio::test]
    async fn test_insert_alert() {
        let db = Database::open_in_memory().unwrap();
        db.migrate().await.unwrap();

        let alert = FiredAlert {
            metric: "latency".into(),
            value: 150.0,
            threshold: 100.0,
            message: "Average latency 150.00ms exceeds threshold 100.00ms".into(),
        };
        db.insert_alert(0, "8.8.8.8", &alert).await.unwrap();
    }

    #[tokio::test]
    async fn test_list_hosts() {
        let db = Database::open_in_memory().unwrap();
        db.migrate().await.unwrap();

        db.insert_result(0, "8.8.8.8", "icmp", &make_result(0, Some(10.0)))
            .await
            .unwrap();
        db.insert_result(1, "1.1.1.1", "icmp", &make_result(0, Some(5.0)))
            .await
            .unwrap();

        let hosts = db.list_hosts().await.unwrap();
        assert_eq!(hosts, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[tokio::test]
    async fn test_query_with_limit() {
        let db = Database::open_in_memory().unwrap();
        db.migrate().await.unwrap();

        for i in 0..20 {
            db.insert_result(0, "8.8.8.8", "icmp", &make_result(i, Some(10.0)))
                .await
                .unwrap();
        }

        let rows = db
            .query_results("8.8.8.8", None, None, Some(5))
            .await
            .unwrap();
        assert_eq!(rows.len(), 5);
    }
}
