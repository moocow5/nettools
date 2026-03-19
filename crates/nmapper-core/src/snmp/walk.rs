use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use super::codec::SnmpValue;
use super::oids;
use crate::result::{SnmpInterface, SnmpNeighbor};

/// Extract sys_descr, sys_name, and sys_object_id from SNMP GET varbinds.
///
/// Returns `(sys_descr, sys_name, sys_object_id)`.
pub fn parse_sys_info(
    varbinds: &[(String, SnmpValue)],
) -> (Option<String>, Option<String>, Option<String>) {
    let mut sys_descr = None;
    let mut sys_name = None;
    let mut sys_object_id = None;

    for (oid, value) in varbinds {
        if oid == oids::SYS_DESCR {
            sys_descr = snmp_value_to_string(value);
        } else if oid == oids::SYS_NAME {
            sys_name = snmp_value_to_string(value);
        } else if oid == oids::SYS_OBJECT_ID {
            sys_object_id = match value {
                SnmpValue::ObjectIdentifier(s) => Some(s.clone()),
                _ => snmp_value_to_string(value),
            };
        }
    }

    (sys_descr, sys_name, sys_object_id)
}

/// Attempt to parse brand and model from an SNMP sysDescr string.
///
/// Handles common patterns from Cisco, Juniper, HP/Aruba, and others.
pub fn parse_brand_model(sys_descr: &str) -> (Option<String>, Option<String>) {
    let lower = sys_descr.to_lowercase();

    // Cisco IOS / IOS XE / NX-OS
    if lower.contains("cisco") {
        let brand = Some("Cisco".to_string());
        // Try to extract model from patterns like "C2960 Software" or "Catalyst 3750"
        let model = extract_cisco_model(sys_descr);
        return (brand, model);
    }

    // Juniper
    if lower.contains("juniper") || lower.contains("junos") {
        let brand = Some("Juniper".to_string());
        let model = extract_word_after(sys_descr, &["juniper", "JUNOS"])
            .or_else(|| extract_model_token(sys_descr));
        return (brand, model);
    }

    // HP / Aruba / ProCurve
    if lower.contains("hp") || lower.contains("aruba") || lower.contains("procurve") {
        let brand = if lower.contains("aruba") {
            Some("Aruba".to_string())
        } else {
            Some("HP".to_string())
        };
        let model = extract_model_token(sys_descr);
        return (brand, model);
    }

    // Arista
    if lower.contains("arista") {
        let brand = Some("Arista".to_string());
        let model = extract_model_token(sys_descr);
        return (brand, model);
    }

    // Linux / generic
    if lower.starts_with("linux") {
        return (Some("Linux".to_string()), None);
    }

    (None, None)
}

/// Parse ifTable walk results into structured `SnmpInterface` entries.
pub fn parse_interfaces(varbinds: &[(String, SnmpValue)]) -> Vec<SnmpInterface> {
    // Group varbinds by interface index.
    // OIDs look like 1.3.6.1.2.1.2.2.1.<column>.<index>
    let if_table_prefix = format!("{}.", oids::IF_TABLE);
    let mut iface_data: HashMap<u32, InterfaceBuilder> = HashMap::new();

    for (oid, value) in varbinds {
        if !oid.starts_with(&if_table_prefix) {
            continue;
        }
        // Parse column and index from the OID suffix
        let suffix = &oid[if_table_prefix.len()..];
        let parts: Vec<&str> = suffix.splitn(2, '.').collect();
        if parts.len() != 2 {
            continue;
        }
        let column: u32 = match parts[0].parse() {
            Ok(c) => c,
            Err(_) => continue,
        };
        let index: u32 = match parts[1].parse() {
            Ok(i) => i,
            Err(_) => continue,
        };

        let entry = iface_data.entry(index).or_insert_with(|| InterfaceBuilder {
            index,
            name: None,
            mac: None,
            speed: None,
            status: None,
        });

        match column {
            2 => entry.name = snmp_value_to_string(value), // ifDescr
            5 => {
                // ifSpeed
                if let SnmpValue::Gauge32(v) = value {
                    entry.speed = Some(*v as u64);
                } else if let SnmpValue::Integer(v) = value {
                    entry.speed = Some(*v as u64);
                }
            }
            6 => {
                // ifPhysAddress
                if let SnmpValue::OctetString(bytes) = value {
                    if bytes.len() == 6 {
                        let mac = bytes
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(":");
                        entry.mac = Some(mac);
                    }
                }
            }
            8 => {
                // ifOperStatus
                if let SnmpValue::Integer(v) = value {
                    entry.status = Some(match v {
                        1 => "up".to_string(),
                        2 => "down".to_string(),
                        3 => "testing".to_string(),
                        _ => format!("unknown({})", v),
                    });
                }
            }
            _ => {}
        }
    }

    let mut interfaces: Vec<SnmpInterface> = iface_data
        .into_values()
        .map(|b| SnmpInterface {
            index: b.index,
            name: b.name.unwrap_or_else(|| format!("if{}", b.index)),
            mac: b.mac,
            ip: None, // IP addresses come from ipAddrTable, not ifTable
            speed: b.speed,
            status: b.status,
        })
        .collect();

    interfaces.sort_by_key(|i| i.index);
    interfaces
}

/// Parse CDP cache walk results into `SnmpNeighbor` entries.
pub fn parse_cdp_neighbors(varbinds: &[(String, SnmpValue)]) -> Vec<SnmpNeighbor> {
    // CDP OIDs: 1.3.6.1.4.1.9.9.23.1.2.1.1.<column>.<ifIndex>.<cdpIndex>
    let cdp_prefix = format!("{}.", oids::CDP_CACHE_TABLE);
    let mut entries: HashMap<String, CdpBuilder> = HashMap::new();

    for (oid, value) in varbinds {
        if !oid.starts_with(&cdp_prefix) {
            continue;
        }
        let suffix = &oid[cdp_prefix.len()..];
        let parts: Vec<&str> = suffix.splitn(2, '.').collect();
        if parts.len() != 2 {
            continue;
        }
        let column: u32 = match parts[0].parse() {
            Ok(c) => c,
            Err(_) => continue,
        };
        let key = parts[1].to_string(); // "ifIndex.cdpIndex"

        let entry = entries.entry(key.clone()).or_insert_with(|| CdpBuilder {
            local_port_index: key.split('.').next().unwrap_or("0").to_string(),
            address: None,
            device_id: None,
            device_port: None,
        });

        match column {
            4 => {
                // cdpCacheAddress
                if let SnmpValue::OctetString(bytes) = value {
                    if bytes.len() == 4 {
                        let ip = IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]));
                        entry.address = Some(ip);
                    }
                } else if let SnmpValue::IpAddress(addr) = value {
                    entry.address = Some(IpAddr::V4(*addr));
                }
            }
            6 => entry.device_id = snmp_value_to_string(value), // cdpCacheDeviceId
            7 => entry.device_port = snmp_value_to_string(value), // cdpCacheDevicePort
            _ => {}
        }
    }

    entries
        .into_values()
        .map(|b| SnmpNeighbor {
            local_port: b.local_port_index,
            remote_ip: b.address,
            remote_hostname: b.device_id,
            remote_port: b.device_port,
            protocol: "cdp".to_string(),
        })
        .collect()
}

/// Parse LLDP remote table walk results into `SnmpNeighbor` entries.
pub fn parse_lldp_neighbors(varbinds: &[(String, SnmpValue)]) -> Vec<SnmpNeighbor> {
    // LLDP OIDs: 1.0.8802.1.1.2.1.4.1.1.<column>.<timeMark>.<localPort>.<remoteIndex>
    let lldp_prefix = format!("{}.", oids::LLDP_REM_TABLE);
    let mut entries: HashMap<String, LldpBuilder> = HashMap::new();

    for (oid, value) in varbinds {
        if !oid.starts_with(&lldp_prefix) {
            continue;
        }
        let suffix = &oid[lldp_prefix.len()..];
        // suffix: <column>.<timeMark>.<localPort>.<remoteIndex>
        let parts: Vec<&str> = suffix.splitn(2, '.').collect();
        if parts.len() != 2 {
            continue;
        }
        let column: u32 = match parts[0].parse() {
            Ok(c) => c,
            Err(_) => continue,
        };
        let key = parts[1].to_string();

        let entry = entries.entry(key.clone()).or_insert_with(|| {
            // Extract localPort from the key (timeMark.localPort.remoteIndex)
            let key_parts: Vec<&str> = key.split('.').collect();
            let local_port = if key_parts.len() >= 2 {
                key_parts[1].to_string()
            } else {
                "0".to_string()
            };
            LldpBuilder {
                local_port,
                sys_name: None,
                port_id: None,
                port_desc: None,
            }
        });

        match column {
            7 => entry.port_id = snmp_value_to_string(value),    // lldpRemPortId
            8 => entry.port_desc = snmp_value_to_string(value),  // lldpRemPortDesc
            9 => entry.sys_name = snmp_value_to_string(value),   // lldpRemSysName
            _ => {}
        }
    }

    entries
        .into_values()
        .map(|b| SnmpNeighbor {
            local_port: b.local_port,
            remote_ip: None,
            remote_hostname: b.sys_name,
            remote_port: b.port_id.or(b.port_desc),
            protocol: "lldp".to_string(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

struct InterfaceBuilder {
    index: u32,
    name: Option<String>,
    mac: Option<String>,
    speed: Option<u64>,
    status: Option<String>,
}

struct CdpBuilder {
    local_port_index: String,
    address: Option<IpAddr>,
    device_id: Option<String>,
    device_port: Option<String>,
}

struct LldpBuilder {
    local_port: String,
    sys_name: Option<String>,
    port_id: Option<String>,
    port_desc: Option<String>,
}

fn snmp_value_to_string(value: &SnmpValue) -> Option<String> {
    match value {
        SnmpValue::OctetString(bytes) => {
            String::from_utf8(bytes.clone()).ok().map(|s| s.trim().to_string())
        }
        SnmpValue::Integer(v) => Some(v.to_string()),
        SnmpValue::ObjectIdentifier(s) => Some(s.clone()),
        SnmpValue::IpAddress(addr) => Some(addr.to_string()),
        SnmpValue::Counter32(v) => Some(v.to_string()),
        SnmpValue::Gauge32(v) => Some(v.to_string()),
        SnmpValue::TimeTicks(v) => Some(v.to_string()),
        SnmpValue::Null => None,
    }
}

fn extract_cisco_model(descr: &str) -> Option<String> {
    // Look for patterns like "C2960", "C3750", "WS-C3560", "N9K-C93180YC-EX", etc.
    for token in descr.split(|c: char| c.is_whitespace() || c == ',') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }
        // Common Cisco model patterns
        if (t.starts_with("C") || t.starts_with("WS-") || t.starts_with("N"))
            && t.chars().any(|c| c.is_ascii_digit())
            && t.len() >= 3
        {
            return Some(t.to_string());
        }
        // "Catalyst XXXX"
        if t.eq_ignore_ascii_case("catalyst") {
            // Next token might be the model
        }
    }

    // Fallback: look for "CXXXX" pattern anywhere
    let tokens: Vec<&str> = descr.split_whitespace().collect();
    for (i, t) in tokens.iter().enumerate() {
        if t.eq_ignore_ascii_case("catalyst") || t.eq_ignore_ascii_case("nexus") {
            if let Some(next) = tokens.get(i + 1) {
                return Some(next.to_string());
            }
        }
    }

    None
}

fn extract_word_after(descr: &str, keywords: &[&str]) -> Option<String> {
    let lower = descr.to_lowercase();
    for kw in keywords {
        let kw_lower = kw.to_lowercase();
        if let Some(pos) = lower.find(&kw_lower) {
            let after = &descr[pos + kw.len()..];
            let trimmed = after.trim_start_matches(|c: char| !c.is_alphanumeric());
            if let Some(word) = trimmed.split_whitespace().next() {
                let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-');
                if !clean.is_empty() {
                    return Some(clean.to_string());
                }
            }
        }
    }
    None
}

fn extract_model_token(descr: &str) -> Option<String> {
    // Find the first token that contains both letters and digits, likely a model number.
    for token in descr.split_whitespace() {
        let has_alpha = token.chars().any(|c| c.is_ascii_alphabetic());
        let has_digit = token.chars().any(|c| c.is_ascii_digit());
        if has_alpha && has_digit && token.len() >= 3 {
            return Some(token.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_brand_model_cisco_ios() {
        let (brand, model) =
            parse_brand_model("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE");
        assert_eq!(brand.as_deref(), Some("Cisco"));
        assert_eq!(model.as_deref(), Some("C2960"));
    }

    #[test]
    fn test_parse_brand_model_cisco_catalyst() {
        let (brand, model) = parse_brand_model("Cisco IOS Software, Catalyst 3750 L3 Switch Software");
        assert_eq!(brand.as_deref(), Some("Cisco"));
        assert_eq!(model.as_deref(), Some("3750"));
    }

    #[test]
    fn test_parse_brand_model_juniper() {
        let (brand, _model) = parse_brand_model("Juniper Networks, Inc. ex4300-48t");
        assert_eq!(brand.as_deref(), Some("Juniper"));
    }

    #[test]
    fn test_parse_brand_model_linux() {
        let (brand, model) = parse_brand_model("Linux server01 5.4.0-42-generic");
        assert_eq!(brand.as_deref(), Some("Linux"));
        assert_eq!(model, None);
    }

    #[test]
    fn test_parse_brand_model_unknown() {
        let (brand, model) = parse_brand_model("some random device");
        assert_eq!(brand, None);
        assert_eq!(model, None);
    }

    #[test]
    fn test_parse_sys_info() {
        let varbinds = vec![
            (
                oids::SYS_DESCR.to_string(),
                SnmpValue::OctetString(b"Cisco IOS".to_vec()),
            ),
            (
                oids::SYS_NAME.to_string(),
                SnmpValue::OctetString(b"switch01".to_vec()),
            ),
            (
                oids::SYS_OBJECT_ID.to_string(),
                SnmpValue::ObjectIdentifier("1.3.6.1.4.1.9.1.1227".to_string()),
            ),
        ];
        let (descr, name, obj_id) = parse_sys_info(&varbinds);
        assert_eq!(descr.as_deref(), Some("Cisco IOS"));
        assert_eq!(name.as_deref(), Some("switch01"));
        assert_eq!(obj_id.as_deref(), Some("1.3.6.1.4.1.9.1.1227"));
    }
}
