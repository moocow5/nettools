//! SQLite persistence layer for traceroute results.
//!
//! Uses `rusqlite` with the bundled SQLite build for zero external dependencies.
//! Supports batch inserts for high-throughput continuous tracing.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use tokio::sync::Mutex;

use crate::mtr::MtrEvent;
use crate::result::ProbeResult;

/// Batch insert threshold — flush after this many pending results.
const BATCH_SIZE: usize = 100;
/// Maximum time between flushes.
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// A row from the trace_runs table.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TraceRunRow {
    pub trace_id: String,
    pub target: String,
    pub method: String,
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub reached_dest: bool,
}

/// A row from the trace_hops table.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TraceHopRow {
    pub ttl: u8,
    pub probe_num: u8,
    pub source_ip: Option<String>,
    pub rtt_us: Option<f64>,
    pub status: String,
    pub hostname: Option<String>,
    pub asn: Option<u32>,
    pub asn_name: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub timestamp_ms: u64,
}

/// A database handle for ntrace data.
pub struct TraceDatabase {
    conn: Arc<Mutex<Connection>>,
}

impl TraceDatabase {
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

    /// Get a shared handle to the connection.
    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    /// Insert a new trace run record.
    pub async fn insert_run(
        &self,
        trace_id: &str,
        target: &str,
        method: &str,
        started_at: u64,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO trace_runs (trace_id, target, method, started_at) VALUES (?1, ?2, ?3, ?4)",
            params![trace_id, target, method, started_at as i64],
        )?;
        Ok(())
    }

    /// Mark a trace run as completed.
    pub async fn complete_run(
        &self,
        trace_id: &str,
        completed_at: u64,
        reached: bool,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE trace_runs SET completed_at = ?1, reached_dest = ?2 WHERE trace_id = ?3",
            params![completed_at as i64, reached as i64, trace_id],
        )?;
        Ok(())
    }

    /// Insert a batch of hop results in a single transaction.
    ///
    /// Each tuple contains: (ProbeResult, hostname, asn, asn_name, country, city)
    pub async fn insert_hops_batch(
        &self,
        trace_id: &str,
        hops: &[(
            ProbeResult,
            Option<&str>,
            Option<u32>,
            Option<&str>,
            Option<&str>,
            Option<&str>,
        )],
    ) -> rusqlite::Result<()> {
        if hops.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().await;
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO trace_hops (trace_id, ttl, probe_num, source_ip, rtt_us, status, icmp_type, icmp_code, hostname, asn, asn_name, country, city, timestamp_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            )?;
            for (probe, hostname, asn, asn_name, country, city) in hops {
                let source_ip = probe.source.map(|ip| ip.to_string());
                let rtt_us = probe.rtt_us();
                let status = probe.status.to_string();
                let timestamp_ms = system_time_to_ms(probe.timestamp);
                stmt.execute(params![
                    trace_id,
                    probe.ttl as i64,
                    probe.probe_num as i64,
                    source_ip,
                    rtt_us,
                    status,
                    probe.icmp_type as i64,
                    probe.icmp_code as i64,
                    hostname,
                    asn.map(|a| a as i64),
                    asn_name,
                    country,
                    city,
                    timestamp_ms as i64,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Query trace runs, optionally filtered by target. Ordered by most recent first.
    pub async fn query_runs(
        &self,
        target: Option<&str>,
        limit: usize,
    ) -> rusqlite::Result<Vec<TraceRunRow>> {
        let conn = self.conn.lock().await;
        let (sql, params_vec): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match target {
            Some(t) => (
                "SELECT trace_id, target, method, started_at, completed_at, reached_dest \
                 FROM trace_runs WHERE target = ?1 ORDER BY started_at DESC LIMIT ?2"
                    .to_string(),
                vec![Box::new(t.to_string()), Box::new(limit as i64)],
            ),
            None => (
                "SELECT trace_id, target, method, started_at, completed_at, reached_dest \
                 FROM trace_runs ORDER BY started_at DESC LIMIT ?1"
                    .to_string(),
                vec![Box::new(limit as i64)],
            ),
        };
        let mut stmt = conn.prepare(&sql)?;
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                Ok(TraceRunRow {
                    trace_id: row.get(0)?,
                    target: row.get(1)?,
                    method: row.get(2)?,
                    started_at: row.get::<_, i64>(3)? as u64,
                    completed_at: row.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                    reached_dest: row.get::<_, i64>(5)? != 0,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Query all hops for a given trace_id, ordered by TTL and probe_num.
    pub async fn query_hops(&self, trace_id: &str) -> rusqlite::Result<Vec<TraceHopRow>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT ttl, probe_num, source_ip, rtt_us, status, hostname, asn, asn_name, country, city, timestamp_ms \
             FROM trace_hops WHERE trace_id = ?1 ORDER BY ttl, probe_num",
        )?;
        let rows = stmt
            .query_map(params![trace_id], |row| {
                Ok(TraceHopRow {
                    ttl: row.get::<_, i64>(0)? as u8,
                    probe_num: row.get::<_, i64>(1)? as u8,
                    source_ip: row.get(2)?,
                    rtt_us: row.get(3)?,
                    status: row.get(4)?,
                    hostname: row.get(5)?,
                    asn: row.get::<_, Option<i64>>(6)?.map(|v| v as u32),
                    asn_name: row.get(7)?,
                    country: row.get(8)?,
                    city: row.get(9)?,
                    timestamp_ms: row.get::<_, i64>(10)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// List distinct targets in the database.
    pub async fn list_targets(&self) -> rusqlite::Result<Vec<String>> {
        let conn = self.conn.lock().await;
        let mut stmt =
            conn.prepare("SELECT DISTINCT target FROM trace_runs ORDER BY target")?;
        let rows = stmt
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(rows)
    }
}

// ---------------------------------------------------------------------------
// Background DB writer task
// ---------------------------------------------------------------------------

/// Buffered hop data for batch insertion.
struct BufferedHop {
    probe: ProbeResult,
    hostname: Option<String>,
    asn: Option<u32>,
    asn_name: Option<String>,
}

/// Spawn a background task that listens to MTR events and writes them to the database.
pub fn spawn_trace_db_writer(
    db: Arc<TraceDatabase>,
    mut event_rx: tokio::sync::broadcast::Receiver<MtrEvent>,
    trace_id: String,
    target: String,
    method: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let started_at = system_time_to_ms(SystemTime::now());
        if let Err(e) = db.insert_run(&trace_id, &target, &method, started_at).await {
            tracing::warn!("failed to insert trace run: {e}");
        }

        let mut batch: Vec<BufferedHop> = Vec::with_capacity(BATCH_SIZE);
        let mut flush_timer = tokio::time::interval(FLUSH_INTERVAL);
        flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                event = event_rx.recv() => {
                    match event {
                        Ok(MtrEvent::ProbeResult { result, .. }) => {
                            batch.push(BufferedHop {
                                probe: result,
                                hostname: None,
                                asn: None,
                                asn_name: None,
                            });
                            if batch.len() >= BATCH_SIZE {
                                flush_hop_batch(&db, &trace_id, &mut batch).await;
                            }
                        }
                        Ok(MtrEvent::HopUpdate { .. }) => {
                            // Stats updates are not persisted as individual hops.
                        }
                        Ok(MtrEvent::RoundComplete { reached_destination, .. }) => {
                            // Flush pending hops on round complete
                            flush_hop_batch(&db, &trace_id, &mut batch).await;
                            let now = system_time_to_ms(SystemTime::now());
                            if let Err(e) = db.complete_run(&trace_id, now, reached_destination).await {
                                tracing::warn!("failed to complete trace run: {e}");
                            }
                        }
                        Ok(MtrEvent::PathChange { .. }) => {
                            // Path changes are informational, not persisted.
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("trace db writer lagged by {n} events");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            flush_hop_batch(&db, &trace_id, &mut batch).await;
                            break;
                        }
                    }
                }
                _ = flush_timer.tick() => {
                    flush_hop_batch(&db, &trace_id, &mut batch).await;
                }
            }
        }
    })
}

async fn flush_hop_batch(
    db: &TraceDatabase,
    trace_id: &str,
    batch: &mut Vec<BufferedHop>,
) {
    if batch.is_empty() {
        return;
    }
    let hops: Vec<(
        ProbeResult,
        Option<&str>,
        Option<u32>,
        Option<&str>,
        Option<&str>,
        Option<&str>,
    )> = batch
        .iter()
        .map(|h| {
            (
                h.probe.clone(),
                h.hostname.as_deref(),
                h.asn,
                h.asn_name.as_deref(),
                None, // country
                None, // city
            )
        })
        .collect();
    if let Err(e) = db.insert_hops_batch(trace_id, &hops).await {
        tracing::warn!("failed to flush hop batch to db: {e}");
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

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS trace_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_id TEXT NOT NULL UNIQUE,
    target TEXT NOT NULL,
    method TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    reached_dest INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_runs_target ON trace_runs (target, started_at);

CREATE TABLE IF NOT EXISTS trace_hops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_id TEXT NOT NULL,
    ttl INTEGER NOT NULL,
    probe_num INTEGER NOT NULL,
    source_ip TEXT,
    rtt_us REAL,
    status TEXT NOT NULL,
    icmp_type INTEGER,
    icmp_code INTEGER,
    hostname TEXT,
    asn INTEGER,
    asn_name TEXT,
    country TEXT,
    city TEXT,
    timestamp_ms INTEGER NOT NULL,
    FOREIGN KEY (trace_id) REFERENCES trace_runs(trace_id)
);
CREATE INDEX IF NOT EXISTS idx_hops_trace ON trace_hops (trace_id, ttl);
CREATE INDEX IF NOT EXISTS idx_hops_target ON trace_hops (trace_id, timestamp_ms);
";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{ProbeResult, ProbeStatus};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_probe(ttl: u8, probe_num: u8, rtt_ms: Option<f64>, source: Option<IpAddr>) -> ProbeResult {
        ProbeResult {
            ttl,
            probe_num,
            source,
            rtt: rtt_ms.map(|ms| Duration::from_secs_f64(ms / 1000.0)),
            status: if rtt_ms.is_some() {
                ProbeStatus::TimeExceeded
            } else {
                ProbeStatus::Timeout
            },
            icmp_type: if rtt_ms.is_some() { 11 } else { 0 },
            icmp_code: 0,
            timestamp: SystemTime::now(),
        }
    }

    #[tokio::test]
    async fn test_migrate_and_insert() {
        let db = TraceDatabase::open_in_memory().unwrap();
        db.migrate().await.unwrap();

        db.insert_run("trace-001", "8.8.8.8", "icmp", 1700000000000)
            .await
            .unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let probe = make_probe(1, 0, Some(10.5), Some(ip));
        let hops = vec![(probe, Some("router.local"), Some(64496u32), Some("Example AS"), None, None)];
        db.insert_hops_batch("trace-001", &hops).await.unwrap();

        db.complete_run("trace-001", 1700000060000, true)
            .await
            .unwrap();

        let runs = db.query_runs(Some("8.8.8.8"), 10).await.unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].trace_id, "trace-001");
        assert_eq!(runs[0].target, "8.8.8.8");
        assert!(runs[0].reached_dest);
        assert_eq!(runs[0].completed_at, Some(1700000060000));
    }

    #[tokio::test]
    async fn test_query_runs() {
        let db = TraceDatabase::open_in_memory().unwrap();
        db.migrate().await.unwrap();

        db.insert_run("t1", "8.8.8.8", "icmp", 1000).await.unwrap();
        db.insert_run("t2", "8.8.8.8", "icmp", 2000).await.unwrap();
        db.insert_run("t3", "1.1.1.1", "udp", 3000).await.unwrap();

        // All runs
        let all = db.query_runs(None, 10).await.unwrap();
        assert_eq!(all.len(), 3);

        // Filtered by target
        let filtered = db.query_runs(Some("8.8.8.8"), 10).await.unwrap();
        assert_eq!(filtered.len(), 2);

        // Limited
        let limited = db.query_runs(None, 2).await.unwrap();
        assert_eq!(limited.len(), 2);
    }

    #[tokio::test]
    async fn test_query_hops() {
        let db = TraceDatabase::open_in_memory().unwrap();
        db.migrate().await.unwrap();

        db.insert_run("trace-hop-test", "8.8.8.8", "icmp", 1000)
            .await
            .unwrap();

        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let hops = vec![
            (make_probe(1, 0, Some(5.0), Some(ip1)), Some("hop1.local"), None, None, None, None),
            (make_probe(1, 1, Some(6.0), Some(ip1)), Some("hop1.local"), None, None, None, None),
            (make_probe(2, 0, Some(10.0), Some(ip2)), None, Some(15169u32), Some("Google"), None, None),
            (make_probe(3, 0, None, None), None, None, None, None, None),
        ];
        db.insert_hops_batch("trace-hop-test", &hops).await.unwrap();

        let result = db.query_hops("trace-hop-test").await.unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].ttl, 1);
        assert_eq!(result[0].probe_num, 0);
        assert_eq!(result[0].hostname.as_deref(), Some("hop1.local"));
        assert_eq!(result[2].asn, Some(15169));
        assert_eq!(result[2].asn_name.as_deref(), Some("Google"));
        assert_eq!(result[3].status, "timeout");
    }

    #[tokio::test]
    async fn test_list_targets() {
        let db = TraceDatabase::open_in_memory().unwrap();
        db.migrate().await.unwrap();

        db.insert_run("t1", "8.8.8.8", "icmp", 1000).await.unwrap();
        db.insert_run("t2", "1.1.1.1", "icmp", 2000).await.unwrap();
        db.insert_run("t3", "8.8.8.8", "udp", 3000).await.unwrap();

        let targets = db.list_targets().await.unwrap();
        assert_eq!(targets, vec!["1.1.1.1", "8.8.8.8"]);
    }
}
