use std::fmt::Write;

use crate::result::{PortStatus, ScanResult};

/// Export a scan result to a CSV string.
///
/// Columns: IP, MAC, Vendor, Hostname, Type, OS, Open Ports, Subnet, SNMP sysName
pub fn export_csv(result: &ScanResult) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str("IP,MAC,Vendor,Hostname,Type,OS,Open Ports,Subnet,SNMP sysName\n");

    for device in &result.devices {
        let mac = device.mac.as_deref().unwrap_or("");
        let vendor = device.vendor.as_deref().unwrap_or("");
        let hostname = device.hostname.as_deref().unwrap_or("");
        let os = device.os_guess.as_deref().unwrap_or("");
        let subnet = device.subnet.as_deref().unwrap_or("");
        let snmp_sys_name = device
            .snmp_info
            .as_ref()
            .and_then(|s| s.sys_name.as_deref())
            .unwrap_or("");

        let open_ports: Vec<String> = device
            .ports
            .iter()
            .filter(|p| p.status == PortStatus::Open)
            .map(|p| {
                if let Some(ref svc) = p.service {
                    format!("{}/{}", p.port, svc)
                } else {
                    p.port.to_string()
                }
            })
            .collect();
        let open_ports_str = open_ports.join(";");

        write!(
            out,
            "{},{},{},{},{},{},\"{}\",{},{}\n",
            csv_escape(&device.ip.to_string()),
            csv_escape(mac),
            csv_escape(vendor),
            csv_escape(hostname),
            device.device_type,
            csv_escape(os),
            open_ports_str,
            csv_escape(subnet),
            csv_escape(snmp_sys_name),
        )
        .unwrap();
    }

    out
}

/// Escape a CSV field: if it contains commas, quotes, or newlines, wrap in
/// double quotes and double any existing quotes.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        let escaped = s.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{
        DeviceType, DiscoveredDevice, PortResult, PortStatus, ScanResult, SnmpDeviceInfo,
    };
    use chrono::Utc;

    fn make_result() -> ScanResult {
        let now = Utc::now();
        ScanResult {
            scan_id: "test-1".into(),
            devices: vec![
                DiscoveredDevice {
                    ip: "10.0.0.1".parse().unwrap(),
                    mac: Some("AA:BB:CC:DD:EE:FF".into()),
                    vendor: Some("Cisco".into()),
                    hostname: Some("router1".into()),
                    device_type: DeviceType::Router,
                    os_guess: Some("IOS 15".into()),
                    ttl: Some(255),
                    ports: vec![
                        PortResult {
                            port: 22,
                            status: PortStatus::Open,
                            service: Some("ssh".into()),
                            banner: None,
                        },
                        PortResult {
                            port: 80,
                            status: PortStatus::Closed,
                            service: None,
                            banner: None,
                        },
                    ],
                    snmp_info: Some(SnmpDeviceInfo {
                        sys_descr: None,
                        sys_name: Some("core-rtr".into()),
                        sys_object_id: None,
                        brand: None,
                        model: None,
                        interfaces: vec![],
                        neighbors: vec![],
                    }),
                    subnet: Some("10.0.0.0/24".into()),
                    discovered_at: now,
                },
                DiscoveredDevice {
                    ip: "10.0.0.100".parse().unwrap(),
                    mac: None,
                    vendor: None,
                    hostname: None,
                    device_type: DeviceType::Server,
                    os_guess: None,
                    ttl: None,
                    ports: vec![
                        PortResult {
                            port: 443,
                            status: PortStatus::Open,
                            service: Some("https".into()),
                            banner: None,
                        },
                    ],
                    snmp_info: None,
                    subnet: Some("10.0.0.0/24".into()),
                    discovered_at: now,
                },
            ],
            links: vec![],
            started_at: now,
            completed_at: now,
            subnets_scanned: vec!["10.0.0.0/24".into()],
        }
    }

    #[test]
    fn test_csv_header() {
        let result = make_result();
        let csv = export_csv(&result);
        let first_line = csv.lines().next().unwrap();
        assert_eq!(
            first_line,
            "IP,MAC,Vendor,Hostname,Type,OS,Open Ports,Subnet,SNMP sysName"
        );
    }

    #[test]
    fn test_csv_row_count() {
        let result = make_result();
        let csv = export_csv(&result);
        // Header + 2 device rows.
        assert_eq!(csv.lines().count(), 3);
    }

    #[test]
    fn test_csv_open_ports() {
        let result = make_result();
        let csv = export_csv(&result);
        let router_line = csv.lines().nth(1).unwrap();
        // Only port 22/ssh should appear (port 80 is closed).
        assert!(router_line.contains("22/ssh"));
        assert!(!router_line.contains("80"));
    }

    #[test]
    fn test_csv_snmp_sys_name() {
        let result = make_result();
        let csv = export_csv(&result);
        let router_line = csv.lines().nth(1).unwrap();
        assert!(router_line.contains("core-rtr"));
    }

    #[test]
    fn test_csv_escape_commas() {
        assert_eq!(csv_escape("hello,world"), "\"hello,world\"");
        assert_eq!(csv_escape("plain"), "plain");
    }
}
