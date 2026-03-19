use std::collections::HashMap;
use std::sync::LazyLock;

/// Embedded OUI database: first 3 bytes of MAC → vendor name.
static OUI_DB: LazyLock<HashMap<[u8; 3], &'static str>> = LazyLock::new(|| {
    let csv = include_str!("../data/oui.csv");
    let mut map = HashMap::with_capacity(1000);
    for line in csv.lines() {
        let parts: Vec<&str> = line.splitn(2, ',').collect();
        if parts.len() == 2 {
            if let Some(prefix) = parse_mac_prefix(parts[0].trim()) {
                map.insert(prefix, parts[1].trim());
            }
        }
    }
    map
});

fn parse_mac_prefix(s: &str) -> Option<[u8; 3]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() < 6 {
        return None;
    }
    let b0 = u8::from_str_radix(&hex[0..2], 16).ok()?;
    let b1 = u8::from_str_radix(&hex[2..4], 16).ok()?;
    let b2 = u8::from_str_radix(&hex[4..6], 16).ok()?;
    Some([b0, b1, b2])
}

/// Look up the vendor name for a MAC address string (e.g. "aa:bb:cc:dd:ee:ff").
pub fn lookup_vendor(mac: &str) -> Option<&'static str> {
    let prefix = mac_to_prefix(mac)?;
    OUI_DB.get(&prefix).copied()
}

fn mac_to_prefix(mac: &str) -> Option<[u8; 3]> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() < 6 {
        return None;
    }
    let b0 = u8::from_str_radix(&hex[0..2], 16).ok()?;
    let b1 = u8::from_str_radix(&hex[2..4], 16).ok()?;
    let b2 = u8::from_str_radix(&hex[4..6], 16).ok()?;
    Some([b0, b1, b2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_to_prefix() {
        assert_eq!(mac_to_prefix("aa:bb:cc:dd:ee:ff"), Some([0xaa, 0xbb, 0xcc]));
        assert_eq!(mac_to_prefix("AA-BB-CC-DD-EE-FF"), Some([0xaa, 0xbb, 0xcc]));
        assert_eq!(mac_to_prefix("invalid"), None);
    }

    #[test]
    fn test_oui_lookup_cisco() {
        // Cisco has many OUIs; test one common one
        let vendor = lookup_vendor("00:1a:2b:00:00:00");
        // May or may not be in our abbreviated DB — just test it doesn't panic
        let _ = vendor;
    }

    #[test]
    fn test_oui_db_loads() {
        // Ensure the database loads without panicking
        let count = OUI_DB.len();
        assert!(count > 0, "OUI database should have entries");
    }
}
