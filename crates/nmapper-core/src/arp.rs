use std::collections::HashMap;
use std::net::IpAddr;

use tracing::debug;

/// Query the system ARP cache and return a map of IP → MAC address.
pub async fn get_arp_table() -> HashMap<IpAddr, String> {
    tokio::task::spawn_blocking(get_arp_table_blocking)
        .await
        .unwrap_or_default()
}

fn get_arp_table_blocking() -> HashMap<IpAddr, String> {
    let output = match std::process::Command::new("arp").arg("-a").output() {
        Ok(o) => o,
        Err(e) => {
            debug!("failed to run arp -a: {}", e);
            return HashMap::new();
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut map = HashMap::new();

    for line in stdout.lines() {
        if let Some((ip, mac)) = parse_arp_line(line) {
            map.insert(ip, mac);
        }
    }

    debug!("ARP cache: {} entries", map.len());
    map
}

/// Parse a single line from `arp -a` output.
/// macOS format: `host (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]`
/// Linux format: `host (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0`
fn parse_arp_line(line: &str) -> Option<(IpAddr, String)> {
    // Extract IP from parentheses
    let ip_start = line.find('(')? + 1;
    let ip_end = line.find(')')?;
    let ip_str = &line[ip_start..ip_end];
    let ip: IpAddr = ip_str.parse().ok()?;

    // Find MAC after " at "
    let at_idx = line.find(" at ")?;
    let after_at = &line[at_idx + 4..];
    let mac_end = after_at.find(' ').unwrap_or(after_at.len());
    let mac = &after_at[..mac_end];

    // Skip incomplete entries
    if mac == "(incomplete)" || mac == "<incomplete>" {
        return None;
    }

    // Validate MAC format (contains colons or dashes)
    if !mac.contains(':') && !mac.contains('-') {
        return None;
    }

    // Normalize MAC to lowercase colon-separated
    let mac_normalized = mac.replace('-', ":").to_lowercase();

    Some((ip, mac_normalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_macos_arp() {
        let line = "router (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]";
        let (ip, mac) = parse_arp_line(line).unwrap();
        assert_eq!(ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(mac, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_parse_linux_arp() {
        let line = "host (10.0.0.5) at 11:22:33:44:55:66 [ether] on eth0";
        let (ip, mac) = parse_arp_line(line).unwrap();
        assert_eq!(ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(mac, "11:22:33:44:55:66");
    }

    #[test]
    fn test_parse_incomplete() {
        let line = "? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]";
        assert!(parse_arp_line(line).is_none());
    }

    #[test]
    fn test_parse_dash_mac() {
        let line = "host (192.168.1.5) at AA-BB-CC-DD-EE-FF on en0";
        let (_, mac) = parse_arp_line(line).unwrap();
        assert_eq!(mac, "aa:bb:cc:dd:ee:ff");
    }
}
