use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    Router,
    Switch,
    Firewall,
    Server,
    Workstation,
    Printer,
    AccessPoint,
    IoT,
    Unknown,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Router => write!(f, "Router"),
            DeviceType::Switch => write!(f, "Switch"),
            DeviceType::Firewall => write!(f, "Firewall"),
            DeviceType::Server => write!(f, "Server"),
            DeviceType::Workstation => write!(f, "Workstation"),
            DeviceType::Printer => write!(f, "Printer"),
            DeviceType::AccessPoint => write!(f, "Access Point"),
            DeviceType::IoT => write!(f, "IoT"),
            DeviceType::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub status: PortStatus,
    pub service: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpDeviceInfo {
    pub sys_descr: Option<String>,
    pub sys_name: Option<String>,
    pub sys_object_id: Option<String>,
    pub brand: Option<String>,
    pub model: Option<String>,
    pub interfaces: Vec<SnmpInterface>,
    pub neighbors: Vec<SnmpNeighbor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpInterface {
    pub index: u32,
    pub name: String,
    pub mac: Option<String>,
    pub ip: Option<IpAddr>,
    pub speed: Option<u64>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpNeighbor {
    pub local_port: String,
    pub remote_ip: Option<IpAddr>,
    pub remote_hostname: Option<String>,
    pub remote_port: Option<String>,
    pub protocol: String, // "cdp" or "lldp"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub device_type: DeviceType,
    pub os_guess: Option<String>,
    pub ttl: Option<u8>,
    pub ports: Vec<PortResult>,
    pub snmp_info: Option<SnmpDeviceInfo>,
    pub subnet: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyLink {
    pub source_ip: IpAddr,
    pub target_ip: IpAddr,
    pub link_type: String, // "cdp", "lldp", "arp", "gateway"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub devices: Vec<DiscoveredDevice>,
    pub links: Vec<TopologyLink>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub subnets_scanned: Vec<String>,
}

/// Events emitted during scan for real-time progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanEvent {
    PhaseStarted { phase: String },
    HostDiscovered { ip: IpAddr },
    HostScanned { device: DiscoveredDevice },
    Progress { done: usize, total: usize },
    PhaseCompleted { phase: String },
    ScanCompleted { result: ScanResult },
}
