use crate::result::{DeviceType, PortResult, PortStatus};

/// Classify a device based on TTL, open ports, and vendor string.
pub fn fingerprint_device(
    ttl: Option<u8>,
    ports: &[PortResult],
    vendor: Option<&str>,
) -> (DeviceType, Option<String>) {
    let open_ports: Vec<u16> = ports
        .iter()
        .filter(|p| p.status == PortStatus::Open)
        .map(|p| p.port)
        .collect();

    let has_port = |p: u16| open_ports.contains(&p);
    let vendor_lower = vendor.map(|v| v.to_lowercase()).unwrap_or_default();

    // Network equipment vendors
    let is_network_vendor = vendor_lower.contains("cisco")
        || vendor_lower.contains("juniper")
        || vendor_lower.contains("arista")
        || vendor_lower.contains("mikrotik")
        || vendor_lower.contains("ubiquiti")
        || vendor_lower.contains("netgear")
        || vendor_lower.contains("tp-link")
        || vendor_lower.contains("fortinet")
        || vendor_lower.contains("palo alto")
        || vendor_lower.contains("sonicwall");

    // Firewall vendors
    let is_firewall_vendor = vendor_lower.contains("fortinet")
        || vendor_lower.contains("palo alto")
        || vendor_lower.contains("sonicwall")
        || vendor_lower.contains("checkpoint");

    // Printer detection: LPD/IPP/JetDirect ports
    if has_port(515) || has_port(631) || has_port(9100) {
        let os = if has_port(631) {
            Some("CUPS/IPP Printer".to_string())
        } else {
            Some("Network Printer".to_string())
        };
        return (DeviceType::Printer, os);
    }

    // Firewall detection
    if is_firewall_vendor {
        return (DeviceType::Firewall, Some(format_vendor_os(&vendor_lower)));
    }

    // Router/Switch detection: SNMP + high TTL
    if let Some(t) = ttl {
        if t >= 250 && has_port(161) {
            if has_port(23) || has_port(22) {
                // Telnet/SSH + SNMP + high TTL = managed network device
                let device_type = if is_network_vendor {
                    if vendor_lower.contains("cisco") || vendor_lower.contains("juniper") {
                        DeviceType::Router
                    } else {
                        DeviceType::Switch
                    }
                } else {
                    DeviceType::Router
                };
                return (device_type, guess_network_os(&vendor_lower, ttl));
            }
            return (DeviceType::Switch, guess_network_os(&vendor_lower, ttl));
        }
    }

    // Access point detection
    if vendor_lower.contains("ubiquiti")
        || vendor_lower.contains("ruckus")
        || vendor_lower.contains("aruba")
    {
        return (DeviceType::AccessPoint, Some(format_vendor_os(&vendor_lower)));
    }

    // Server detection: multiple server ports open
    let server_ports = [22, 25, 53, 80, 110, 143, 443, 445, 3306, 5432];
    let server_port_count = server_ports.iter().filter(|&&p| has_port(p)).count();
    if server_port_count >= 3 {
        let os = guess_os_from_ttl(ttl);
        return (DeviceType::Server, os);
    }

    // RDP = Windows workstation
    if has_port(3389) {
        return (DeviceType::Workstation, Some("Windows".to_string()));
    }

    // OS guess from TTL
    let os = guess_os_from_ttl(ttl);

    // If SNMP open on a network vendor, call it a switch
    if has_port(161) && is_network_vendor {
        return (DeviceType::Switch, guess_network_os(&vendor_lower, ttl));
    }

    // Default: workstation if we have a TTL, unknown otherwise
    if ttl.is_some() {
        (DeviceType::Workstation, os)
    } else {
        (DeviceType::Unknown, None)
    }
}

fn guess_os_from_ttl(ttl: Option<u8>) -> Option<String> {
    match ttl {
        Some(t) if t > 200 => Some("Network Device".to_string()),
        Some(t) if t > 64 && t <= 128 => Some("Windows".to_string()),
        Some(t) if t <= 64 => Some("Linux/macOS".to_string()),
        _ => None,
    }
}

fn guess_network_os(vendor: &str, _ttl: Option<u8>) -> Option<String> {
    if vendor.contains("cisco") {
        Some("Cisco IOS".to_string())
    } else if vendor.contains("juniper") {
        Some("Junos".to_string())
    } else if vendor.contains("mikrotik") {
        Some("RouterOS".to_string())
    } else {
        Some("Network OS".to_string())
    }
}

fn format_vendor_os(vendor: &str) -> String {
    if vendor.contains("fortinet") {
        "FortiOS".to_string()
    } else if vendor.contains("palo alto") {
        "PAN-OS".to_string()
    } else {
        "Firewall OS".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{PortResult, PortStatus};

    fn open_port(port: u16) -> PortResult {
        PortResult {
            port,
            status: PortStatus::Open,
            service: None,
            banner: None,
        }
    }

    #[test]
    fn test_printer_detection() {
        let ports = vec![open_port(9100), open_port(80)];
        let (dt, _) = fingerprint_device(Some(64), &ports, None);
        assert_eq!(dt, DeviceType::Printer);
    }

    #[test]
    fn test_router_high_ttl_snmp() {
        let ports = vec![open_port(22), open_port(161)];
        let (dt, os) = fingerprint_device(Some(255), &ports, Some("Cisco Systems"));
        assert_eq!(dt, DeviceType::Router);
        assert_eq!(os, Some("Cisco IOS".to_string()));
    }

    #[test]
    fn test_windows_workstation() {
        let ports = vec![open_port(3389), open_port(445)];
        let (dt, os) = fingerprint_device(Some(128), &ports, None);
        assert_eq!(dt, DeviceType::Workstation);
        assert_eq!(os, Some("Windows".to_string()));
    }

    #[test]
    fn test_linux_server() {
        let ports = vec![open_port(22), open_port(80), open_port(443)];
        let (dt, os) = fingerprint_device(Some(64), &ports, None);
        assert_eq!(dt, DeviceType::Server);
        assert_eq!(os, Some("Linux/macOS".to_string()));
    }

    #[test]
    fn test_firewall_vendor() {
        let ports = vec![open_port(443)];
        let (dt, _) = fingerprint_device(Some(255), &ports, Some("Fortinet Inc"));
        assert_eq!(dt, DeviceType::Firewall);
    }

    #[test]
    fn test_unknown_no_info() {
        let (dt, os) = fingerprint_device(None, &[], None);
        assert_eq!(dt, DeviceType::Unknown);
        assert_eq!(os, None);
    }
}
