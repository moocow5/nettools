use std::path::Path;
use std::sync::Arc;

use rusqlite::{params, Connection};
use tokio::sync::Mutex;

use crate::result::{
    DeviceType, DiscoveredDevice, PortResult, PortStatus, ScanResult, TopologyLink,
};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    subnets_scanned TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    ip TEXT NOT NULL,
    mac TEXT,
    vendor TEXT,
    hostname TEXT,
    device_type TEXT NOT NULL,
    os_guess TEXT,
    ttl INTEGER,
    subnet TEXT,
    snmp_sys_descr TEXT,
    snmp_sys_name TEXT,
    snmp_brand TEXT,
    snmp_model TEXT,
    discovered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id),
    port INTEGER NOT NULL,
    status TEXT NOT NULL,
    service TEXT,
    banner TEXT
);

CREATE TABLE IF NOT EXISTS topology_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    source_ip TEXT NOT NULL,
    target_ip TEXT NOT NULL,
    link_type TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_scan ON devices(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_device ON ports(device_id);
CREATE INDEX IF NOT EXISTS idx_links_scan ON topology_links(scan_id);
"#;

pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub async fn migrate(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute_batch(SCHEMA)?;
        Ok(())
    }

    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    pub async fn insert_scan(&self, result: &ScanResult) -> rusqlite::Result<()> {
        let conn = self.conn.lock().await;

        let subnets = result.subnets_scanned.join(", ");
        conn.execute(
            "INSERT INTO scans (scan_id, started_at, completed_at, subnets_scanned) VALUES (?1, ?2, ?3, ?4)",
            params![
                result.scan_id,
                result.started_at.to_rfc3339(),
                result.completed_at.to_rfc3339(),
                subnets,
            ],
        )?;

        for device in &result.devices {
            let (snmp_descr, snmp_name, snmp_brand, snmp_model) =
                if let Some(ref info) = device.snmp_info {
                    (
                        info.sys_descr.as_deref(),
                        info.sys_name.as_deref(),
                        info.brand.as_deref(),
                        info.model.as_deref(),
                    )
                } else {
                    (None, None, None, None)
                };

            conn.execute(
                "INSERT INTO devices (scan_id, ip, mac, vendor, hostname, device_type, os_guess, ttl, subnet, snmp_sys_descr, snmp_sys_name, snmp_brand, snmp_model, discovered_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    result.scan_id,
                    device.ip.to_string(),
                    device.mac,
                    device.vendor,
                    device.hostname,
                    format!("{}", device.device_type),
                    device.os_guess,
                    device.ttl.map(|t| t as i64),
                    device.subnet,
                    snmp_descr,
                    snmp_name,
                    snmp_brand,
                    snmp_model,
                    device.discovered_at.to_rfc3339(),
                ],
            )?;

            let device_id = conn.last_insert_rowid();

            for port in &device.ports {
                let status_str = match port.status {
                    PortStatus::Open => "open",
                    PortStatus::Closed => "closed",
                    PortStatus::Filtered => "filtered",
                };
                conn.execute(
                    "INSERT INTO ports (device_id, port, status, service, banner) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![device_id, port.port as i64, status_str, port.service, port.banner],
                )?;
            }
        }

        for link in &result.links {
            conn.execute(
                "INSERT INTO topology_links (scan_id, source_ip, target_ip, link_type) VALUES (?1, ?2, ?3, ?4)",
                params![
                    result.scan_id,
                    link.source_ip.to_string(),
                    link.target_ip.to_string(),
                    link.link_type,
                ],
            )?;
        }

        Ok(())
    }

    pub async fn list_scans(&self) -> rusqlite::Result<Vec<ScanSummary>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT scan_id, started_at, completed_at, subnets_scanned, (SELECT COUNT(*) FROM devices WHERE devices.scan_id = scans.scan_id) as device_count FROM scans ORDER BY started_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(ScanSummary {
                scan_id: row.get(0)?,
                started_at: row.get(1)?,
                completed_at: row.get(2)?,
                subnets_scanned: row.get(3)?,
                device_count: row.get(4)?,
            })
        })?;

        rows.collect()
    }

    pub async fn load_scan(&self, scan_id: &str) -> rusqlite::Result<Option<ScanResult>> {
        let conn = self.conn.lock().await;

        let mut scan_stmt =
            conn.prepare("SELECT started_at, completed_at, subnets_scanned FROM scans WHERE scan_id = ?1")?;
        let scan_row = scan_stmt.query_row(params![scan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        });

        let (started_str, completed_str, subnets_str) = match scan_row {
            Ok(r) => r,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e),
        };

        let started_at = chrono::DateTime::parse_from_rfc3339(&started_str)
            .unwrap_or_default()
            .with_timezone(&chrono::Utc);
        let completed_at = chrono::DateTime::parse_from_rfc3339(&completed_str)
            .unwrap_or_default()
            .with_timezone(&chrono::Utc);
        let subnets_scanned: Vec<String> = subnets_str.split(", ").map(String::from).collect();

        // Load devices
        let mut dev_stmt = conn.prepare(
            "SELECT id, ip, mac, vendor, hostname, device_type, os_guess, ttl, subnet, discovered_at FROM devices WHERE scan_id = ?1",
        )?;
        let device_rows: Vec<(i64, String, Option<String>, Option<String>, Option<String>, String, Option<String>, Option<i64>, Option<String>, String)> =
            dev_stmt.query_map(params![scan_id], |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                ))
            })?.collect::<rusqlite::Result<Vec<_>>>()?;

        let mut devices = Vec::new();
        for (dev_id, ip_str, mac, vendor, hostname, dtype_str, os_guess, ttl, subnet, disc_str) in device_rows {
            let ip: std::net::IpAddr = ip_str.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            let device_type = parse_device_type(&dtype_str);
            let discovered_at = chrono::DateTime::parse_from_rfc3339(&disc_str)
                .unwrap_or_default()
                .with_timezone(&chrono::Utc);

            // Load ports for this device
            let mut port_stmt = conn.prepare(
                "SELECT port, status, service, banner FROM ports WHERE device_id = ?1",
            )?;
            let ports: Vec<PortResult> = port_stmt.query_map(params![dev_id], |row| {
                let port: i64 = row.get(0)?;
                let status_str: String = row.get(1)?;
                let service: Option<String> = row.get(2)?;
                let banner: Option<String> = row.get(3)?;
                let status = match status_str.as_str() {
                    "open" => PortStatus::Open,
                    "closed" => PortStatus::Closed,
                    _ => PortStatus::Filtered,
                };
                Ok(PortResult { port: port as u16, status, service, banner })
            })?.collect::<rusqlite::Result<Vec<_>>>()?;

            devices.push(DiscoveredDevice {
                ip,
                mac,
                vendor,
                hostname,
                device_type,
                os_guess,
                ttl: ttl.map(|t| t as u8),
                ports,
                snmp_info: None,
                subnet,
                discovered_at,
            });
        }

        // Load links
        let mut link_stmt = conn.prepare(
            "SELECT source_ip, target_ip, link_type FROM topology_links WHERE scan_id = ?1",
        )?;
        let links: Vec<TopologyLink> = link_stmt.query_map(params![scan_id], |row| {
            let src: String = row.get(0)?;
            let dst: String = row.get(1)?;
            let lt: String = row.get(2)?;
            Ok(TopologyLink {
                source_ip: src.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                target_ip: dst.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                link_type: lt,
            })
        })?.collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(Some(ScanResult {
            scan_id: scan_id.to_string(),
            devices,
            links,
            started_at,
            completed_at,
            subnets_scanned,
        }))
    }
}

fn parse_device_type(s: &str) -> DeviceType {
    match s {
        "Router" => DeviceType::Router,
        "Switch" => DeviceType::Switch,
        "Firewall" => DeviceType::Firewall,
        "Server" => DeviceType::Server,
        "Workstation" => DeviceType::Workstation,
        "Printer" => DeviceType::Printer,
        "Access Point" => DeviceType::AccessPoint,
        "IoT" => DeviceType::IoT,
        _ => DeviceType::Unknown,
    }
}

#[derive(Debug, Clone)]
pub struct ScanSummary {
    pub scan_id: String,
    pub started_at: String,
    pub completed_at: String,
    pub subnets_scanned: String,
    pub device_count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_test_result() -> ScanResult {
        ScanResult {
            scan_id: "test-001".to_string(),
            devices: vec![DiscoveredDevice {
                ip: "192.168.1.1".parse().unwrap(),
                mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
                vendor: Some("Cisco Systems".to_string()),
                hostname: Some("router.local".to_string()),
                device_type: DeviceType::Router,
                os_guess: Some("Cisco IOS".to_string()),
                ttl: Some(255),
                ports: vec![PortResult {
                    port: 22,
                    status: PortStatus::Open,
                    service: Some("ssh".to_string()),
                    banner: None,
                }],
                snmp_info: None,
                subnet: Some("192.168.1.0/24".to_string()),
                discovered_at: Utc::now(),
            }],
            links: vec![TopologyLink {
                source_ip: "192.168.1.1".parse().unwrap(),
                target_ip: "192.168.1.100".parse().unwrap(),
                link_type: "gateway".to_string(),
            }],
            started_at: Utc::now(),
            completed_at: Utc::now(),
            subnets_scanned: vec!["192.168.1.0/24".to_string()],
        }
    }

    #[tokio::test]
    async fn test_db_roundtrip() {
        let db = Database::open_in_memory().unwrap();
        db.migrate().await.unwrap();

        let result = make_test_result();
        db.insert_scan(&result).await.unwrap();

        let scans = db.list_scans().await.unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].device_count, 1);

        let loaded = db.load_scan("test-001").await.unwrap().unwrap();
        assert_eq!(loaded.devices.len(), 1);
        assert_eq!(loaded.devices[0].ip.to_string(), "192.168.1.1");
        assert_eq!(loaded.devices[0].device_type, DeviceType::Router);
        assert_eq!(loaded.devices[0].ports.len(), 1);
        assert_eq!(loaded.devices[0].ports[0].port, 22);
        assert_eq!(loaded.links.len(), 1);
    }

    #[tokio::test]
    async fn test_load_nonexistent() {
        let db = Database::open_in_memory().unwrap();
        db.migrate().await.unwrap();
        let result = db.load_scan("nonexistent").await.unwrap();
        assert!(result.is_none());
    }
}
