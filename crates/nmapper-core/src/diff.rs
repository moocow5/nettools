use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::result::{
    DeviceType, DiscoveredDevice, PortResult, PortStatus, ScanResult, TopologyLink,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiff {
    pub old_scan_id: String,
    pub new_scan_id: String,
    pub new_devices: Vec<DeviceSummary>,
    pub removed_devices: Vec<DeviceSummary>,
    pub changed_devices: Vec<DeviceChange>,
    pub new_links: Vec<TopologyLink>,
    pub removed_links: Vec<TopologyLink>,
    pub summary: DiffSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub device_type: DeviceType,
    pub vendor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceChange {
    pub ip: IpAddr,
    pub changes: Vec<ChangeDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeDetail {
    DeviceTypeChanged {
        old: DeviceType,
        new: DeviceType,
    },
    HostnameChanged {
        old: Option<String>,
        new: Option<String>,
    },
    OsChanged {
        old: Option<String>,
        new: Option<String>,
    },
    VendorChanged {
        old: Option<String>,
        new: Option<String>,
    },
    MacChanged {
        old: Option<String>,
        new: Option<String>,
    },
    PortOpened {
        port: u16,
        service: Option<String>,
    },
    PortClosed {
        port: u16,
    },
    SnmpNameChanged {
        old: Option<String>,
        new: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub total_new: usize,
    pub total_removed: usize,
    pub total_changed: usize,
    pub new_links: usize,
    pub removed_links: usize,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn device_summary(d: &DiscoveredDevice) -> DeviceSummary {
    DeviceSummary {
        ip: d.ip,
        hostname: d.hostname.clone(),
        device_type: d.device_type,
        vendor: d.vendor.clone(),
    }
}

fn open_ports(device: &DiscoveredDevice) -> HashMap<u16, &PortResult> {
    device
        .ports
        .iter()
        .filter(|p| p.status == PortStatus::Open)
        .map(|p| (p.port, p))
        .collect()
}

fn link_key(link: &TopologyLink) -> (IpAddr, IpAddr) {
    (link.source_ip, link.target_ip)
}

fn compare_devices(old: &DiscoveredDevice, new: &DiscoveredDevice) -> Vec<ChangeDetail> {
    let mut changes = Vec::new();

    if old.device_type != new.device_type {
        changes.push(ChangeDetail::DeviceTypeChanged {
            old: old.device_type,
            new: new.device_type,
        });
    }

    if old.hostname != new.hostname {
        changes.push(ChangeDetail::HostnameChanged {
            old: old.hostname.clone(),
            new: new.hostname.clone(),
        });
    }

    if old.os_guess != new.os_guess {
        changes.push(ChangeDetail::OsChanged {
            old: old.os_guess.clone(),
            new: new.os_guess.clone(),
        });
    }

    if old.vendor != new.vendor {
        changes.push(ChangeDetail::VendorChanged {
            old: old.vendor.clone(),
            new: new.vendor.clone(),
        });
    }

    if old.mac != new.mac {
        changes.push(ChangeDetail::MacChanged {
            old: old.mac.clone(),
            new: new.mac.clone(),
        });
    }

    // SNMP sys_name
    let old_snmp_name = old.snmp_info.as_ref().and_then(|s| s.sys_name.clone());
    let new_snmp_name = new.snmp_info.as_ref().and_then(|s| s.sys_name.clone());
    if old_snmp_name != new_snmp_name {
        changes.push(ChangeDetail::SnmpNameChanged {
            old: old_snmp_name,
            new: new_snmp_name,
        });
    }

    // Port changes
    let old_open = open_ports(old);
    let new_open = open_ports(new);

    for (&port, pr) in &new_open {
        if !old_open.contains_key(&port) {
            changes.push(ChangeDetail::PortOpened {
                port,
                service: pr.service.clone(),
            });
        }
    }

    for &port in old_open.keys() {
        if !new_open.contains_key(&port) {
            changes.push(ChangeDetail::PortClosed { port });
        }
    }

    changes
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn compare_scans(old: &ScanResult, new: &ScanResult) -> ScanDiff {
    let old_map: HashMap<IpAddr, &DiscoveredDevice> =
        old.devices.iter().map(|d| (d.ip, d)).collect();
    let new_map: HashMap<IpAddr, &DiscoveredDevice> =
        new.devices.iter().map(|d| (d.ip, d)).collect();

    let old_ips: HashSet<IpAddr> = old_map.keys().copied().collect();
    let new_ips: HashSet<IpAddr> = new_map.keys().copied().collect();

    // New devices
    let new_devices: Vec<DeviceSummary> = new_ips
        .difference(&old_ips)
        .map(|ip| device_summary(new_map[ip]))
        .collect();

    // Removed devices
    let removed_devices: Vec<DeviceSummary> = old_ips
        .difference(&new_ips)
        .map(|ip| device_summary(old_map[ip]))
        .collect();

    // Changed devices
    let changed_devices: Vec<DeviceChange> = old_ips
        .intersection(&new_ips)
        .filter_map(|ip| {
            let changes = compare_devices(old_map[ip], new_map[ip]);
            if changes.is_empty() {
                None
            } else {
                Some(DeviceChange { ip: *ip, changes })
            }
        })
        .collect();

    // Topology link diff
    let old_link_keys: HashSet<(IpAddr, IpAddr)> = old.links.iter().map(link_key).collect();
    let new_link_keys: HashSet<(IpAddr, IpAddr)> = new.links.iter().map(link_key).collect();

    let new_links: Vec<TopologyLink> = new
        .links
        .iter()
        .filter(|l| !old_link_keys.contains(&link_key(l)))
        .cloned()
        .collect();

    let removed_links: Vec<TopologyLink> = old
        .links
        .iter()
        .filter(|l| !new_link_keys.contains(&link_key(l)))
        .cloned()
        .collect();

    let summary = DiffSummary {
        total_new: new_devices.len(),
        total_removed: removed_devices.len(),
        total_changed: changed_devices.len(),
        new_links: new_links.len(),
        removed_links: removed_links.len(),
    };

    ScanDiff {
        old_scan_id: old.scan_id.clone(),
        new_scan_id: new.scan_id.clone(),
        new_devices,
        removed_devices,
        changed_devices,
        new_links,
        removed_links,
        summary,
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl fmt::Display for ScanDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Scan diff: {} new devices, {} removed, {} changed, {} new links, {} removed links",
            self.summary.total_new,
            self.summary.total_removed,
            self.summary.total_changed,
            self.summary.new_links,
            self.summary.removed_links,
        )?;

        if !self.new_devices.is_empty() {
            writeln!(f, "\nNew devices:")?;
            for d in &self.new_devices {
                writeln!(f, "  + {} ({})", d.ip, d.device_type)?;
            }
        }

        if !self.removed_devices.is_empty() {
            writeln!(f, "\nRemoved devices:")?;
            for d in &self.removed_devices {
                writeln!(f, "  - {} ({})", d.ip, d.device_type)?;
            }
        }

        if !self.changed_devices.is_empty() {
            writeln!(f, "\nChanged devices:")?;
            for dc in &self.changed_devices {
                writeln!(f, "  ~ {}:", dc.ip)?;
                for change in &dc.changes {
                    match change {
                        ChangeDetail::DeviceTypeChanged { old, new } => {
                            writeln!(f, "      device type: {} -> {}", old, new)?;
                        }
                        ChangeDetail::HostnameChanged { old, new } => {
                            writeln!(
                                f,
                                "      hostname: {} -> {}",
                                old.as_deref().unwrap_or("(none)"),
                                new.as_deref().unwrap_or("(none)")
                            )?;
                        }
                        ChangeDetail::OsChanged { old, new } => {
                            writeln!(
                                f,
                                "      OS: {} -> {}",
                                old.as_deref().unwrap_or("(none)"),
                                new.as_deref().unwrap_or("(none)")
                            )?;
                        }
                        ChangeDetail::VendorChanged { old, new } => {
                            writeln!(
                                f,
                                "      vendor: {} -> {}",
                                old.as_deref().unwrap_or("(none)"),
                                new.as_deref().unwrap_or("(none)")
                            )?;
                        }
                        ChangeDetail::MacChanged { old, new } => {
                            writeln!(
                                f,
                                "      MAC: {} -> {}",
                                old.as_deref().unwrap_or("(none)"),
                                new.as_deref().unwrap_or("(none)")
                            )?;
                        }
                        ChangeDetail::PortOpened { port, service } => {
                            writeln!(
                                f,
                                "      port opened: {}{}",
                                port,
                                service
                                    .as_ref()
                                    .map(|s| format!(" ({})", s))
                                    .unwrap_or_default()
                            )?;
                        }
                        ChangeDetail::PortClosed { port } => {
                            writeln!(f, "      port closed: {}", port)?;
                        }
                        ChangeDetail::SnmpNameChanged { old, new } => {
                            writeln!(
                                f,
                                "      SNMP name: {} -> {}",
                                old.as_deref().unwrap_or("(none)"),
                                new.as_deref().unwrap_or("(none)")
                            )?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_device(ip: &str, device_type: DeviceType) -> DiscoveredDevice {
        DiscoveredDevice {
            ip: ip.parse().unwrap(),
            mac: None,
            vendor: None,
            hostname: None,
            device_type,
            os_guess: None,
            ttl: None,
            ports: Vec::new(),
            snmp_info: None,
            subnet: None,
            discovered_at: Utc::now(),
        }
    }

    fn make_scan(id: &str, devices: Vec<DiscoveredDevice>, links: Vec<TopologyLink>) -> ScanResult {
        let now = Utc::now();
        ScanResult {
            scan_id: id.to_string(),
            devices,
            links,
            started_at: now,
            completed_at: now,
            subnets_scanned: vec!["10.0.0.0/24".to_string()],
        }
    }

    fn make_link(src: &str, dst: &str) -> TopologyLink {
        TopologyLink {
            source_ip: src.parse().unwrap(),
            target_ip: dst.parse().unwrap(),
            link_type: "arp".to_string(),
        }
    }

    #[test]
    fn test_identical_scans() {
        let d = make_device("10.0.0.1", DeviceType::Server);
        let old = make_scan("a", vec![d.clone()], vec![]);
        let new = make_scan("b", vec![d], vec![]);
        let diff = compare_scans(&old, &new);

        assert!(diff.new_devices.is_empty());
        assert!(diff.removed_devices.is_empty());
        assert!(diff.changed_devices.is_empty());
        assert_eq!(diff.summary.total_new, 0);
        assert_eq!(diff.summary.total_removed, 0);
        assert_eq!(diff.summary.total_changed, 0);
    }

    #[test]
    fn test_new_device() {
        let d1 = make_device("10.0.0.1", DeviceType::Server);
        let d2 = make_device("10.0.0.2", DeviceType::Workstation);

        let old = make_scan("a", vec![d1.clone()], vec![]);
        let new = make_scan("b", vec![d1, d2], vec![]);
        let diff = compare_scans(&old, &new);

        assert_eq!(diff.new_devices.len(), 1);
        assert_eq!(diff.new_devices[0].ip, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert!(diff.removed_devices.is_empty());
        assert_eq!(diff.summary.total_new, 1);
    }

    #[test]
    fn test_removed_device() {
        let d1 = make_device("10.0.0.1", DeviceType::Server);
        let d2 = make_device("10.0.0.2", DeviceType::Workstation);

        let old = make_scan("a", vec![d1.clone(), d2], vec![]);
        let new = make_scan("b", vec![d1], vec![]);
        let diff = compare_scans(&old, &new);

        assert!(diff.new_devices.is_empty());
        assert_eq!(diff.removed_devices.len(), 1);
        assert_eq!(diff.removed_devices[0].ip, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(diff.summary.total_removed, 1);
    }

    #[test]
    fn test_port_opened() {
        let d_old = make_device("10.0.0.1", DeviceType::Server);
        let mut d_new = make_device("10.0.0.1", DeviceType::Server);
        d_new.ports.push(PortResult {
            port: 443,
            status: PortStatus::Open,
            service: Some("https".to_string()),
            banner: None,
        });

        let old = make_scan("a", vec![d_old], vec![]);
        let new = make_scan("b", vec![d_new], vec![]);
        let diff = compare_scans(&old, &new);

        assert_eq!(diff.changed_devices.len(), 1);
        assert!(diff.changed_devices[0].changes.iter().any(|c| matches!(
            c,
            ChangeDetail::PortOpened { port: 443, .. }
        )));
    }

    #[test]
    fn test_port_closed() {
        let mut d_old = make_device("10.0.0.1", DeviceType::Server);
        d_old.ports.push(PortResult {
            port: 80,
            status: PortStatus::Open,
            service: Some("http".to_string()),
            banner: None,
        });
        let d_new = make_device("10.0.0.1", DeviceType::Server);

        let old = make_scan("a", vec![d_old], vec![]);
        let new = make_scan("b", vec![d_new], vec![]);
        let diff = compare_scans(&old, &new);

        assert_eq!(diff.changed_devices.len(), 1);
        assert!(diff.changed_devices[0].changes.iter().any(|c| matches!(
            c,
            ChangeDetail::PortClosed { port: 80 }
        )));
    }

    #[test]
    fn test_device_type_changed() {
        let d_old = make_device("10.0.0.1", DeviceType::Unknown);
        let d_new = make_device("10.0.0.1", DeviceType::Router);

        let old = make_scan("a", vec![d_old], vec![]);
        let new = make_scan("b", vec![d_new], vec![]);
        let diff = compare_scans(&old, &new);

        assert_eq!(diff.changed_devices.len(), 1);
        assert!(diff.changed_devices[0].changes.iter().any(|c| matches!(
            c,
            ChangeDetail::DeviceTypeChanged {
                old: DeviceType::Unknown,
                new: DeviceType::Router,
            }
        )));
    }

    #[test]
    fn test_hostname_changed() {
        let mut d_old = make_device("10.0.0.1", DeviceType::Server);
        d_old.hostname = Some("alpha".to_string());
        let mut d_new = make_device("10.0.0.1", DeviceType::Server);
        d_new.hostname = Some("beta".to_string());

        let old = make_scan("a", vec![d_old], vec![]);
        let new = make_scan("b", vec![d_new], vec![]);
        let diff = compare_scans(&old, &new);

        assert_eq!(diff.changed_devices.len(), 1);
        assert!(diff.changed_devices[0].changes.iter().any(|c| matches!(
            c,
            ChangeDetail::HostnameChanged { .. }
        )));
    }

    #[test]
    fn test_link_changes() {
        let d = make_device("10.0.0.1", DeviceType::Router);
        let link_old = make_link("10.0.0.1", "10.0.0.2");
        let link_new = make_link("10.0.0.1", "10.0.0.3");

        let old = make_scan("a", vec![d.clone()], vec![link_old]);
        let new = make_scan("b", vec![d], vec![link_new]);
        let diff = compare_scans(&old, &new);

        assert_eq!(diff.new_links.len(), 1);
        assert_eq!(diff.removed_links.len(), 1);
        assert_eq!(diff.summary.new_links, 1);
        assert_eq!(diff.summary.removed_links, 1);
    }

    #[test]
    fn test_multiple_changes() {
        let mut d_old = make_device("10.0.0.1", DeviceType::Unknown);
        d_old.hostname = Some("old-host".to_string());
        d_old.vendor = Some("VendorA".to_string());
        d_old.ports.push(PortResult {
            port: 22,
            status: PortStatus::Open,
            service: Some("ssh".to_string()),
            banner: None,
        });

        let mut d_new = make_device("10.0.0.1", DeviceType::Server);
        d_new.hostname = Some("new-host".to_string());
        d_new.vendor = Some("VendorB".to_string());
        d_new.ports.push(PortResult {
            port: 443,
            status: PortStatus::Open,
            service: Some("https".to_string()),
            banner: None,
        });

        let old = make_scan("a", vec![d_old], vec![]);
        let new = make_scan("b", vec![d_new], vec![]);
        let diff = compare_scans(&old, &new);

        assert_eq!(diff.changed_devices.len(), 1);
        let changes = &diff.changed_devices[0].changes;
        // device type + hostname + vendor + port opened (443) + port closed (22) = 5
        assert!(changes.len() >= 5);
        assert!(changes.iter().any(|c| matches!(c, ChangeDetail::DeviceTypeChanged { .. })));
        assert!(changes.iter().any(|c| matches!(c, ChangeDetail::HostnameChanged { .. })));
        assert!(changes.iter().any(|c| matches!(c, ChangeDetail::VendorChanged { .. })));
        assert!(changes.iter().any(|c| matches!(c, ChangeDetail::PortOpened { port: 443, .. })));
        assert!(changes.iter().any(|c| matches!(c, ChangeDetail::PortClosed { port: 22 })));
    }

    #[test]
    fn test_display() {
        let d_old = make_device("10.0.0.1", DeviceType::Unknown);
        let d_new = make_device("10.0.0.1", DeviceType::Router);
        let d_added = make_device("10.0.0.2", DeviceType::Server);

        let old = make_scan("a", vec![d_old], vec![]);
        let new = make_scan("b", vec![d_new, d_added], vec![]);
        let diff = compare_scans(&old, &new);

        let text = diff.to_string();
        assert!(text.contains("1 new devices"));
        assert!(text.contains("1 changed"));
    }
}
