//! ASN lookup via Team Cymru DNS TXT records.

use std::net::IpAddr;

use super::AsnInfo;

/// Look up ASN information for an IP address using Team Cymru's DNS service.
/// Queries TXT record at `d.c.b.a.origin.asn.cymru.com` for IPv4 address `a.b.c.d`.
/// Only IPv4 is supported.
pub async fn lookup_asn(ip: IpAddr) -> Option<AsnInfo> {
    let ip = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return None,
    };

    let octets = ip.octets();
    let query = format!(
        "{}.{}.{}.{}.origin.asn.cymru.com",
        octets[3], octets[2], octets[1], octets[0]
    );

    tokio::task::spawn_blocking(move || lookup_asn_blocking(&query))
        .await
        .ok()
        .flatten()
}

fn lookup_asn_blocking(query: &str) -> Option<AsnInfo> {
    let output = std::process::Command::new("dig")
        .args(["+short", "TXT", query])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next()?;
    parse_cymru_txt(line)
}

/// Parse a Team Cymru TXT response line.
/// Format: `"ASN | prefix | CC | registry | date"`
/// Example: `"15169 | 8.8.8.0/24 | US | arin | 2023-12-25"`
pub fn parse_cymru_txt(line: &str) -> Option<AsnInfo> {
    let line = line.trim().trim_matches('"');
    let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
    if parts.len() < 3 {
        return None;
    }

    let asn = parts[0].parse::<u32>().ok()?;
    let prefix = parts[1].to_string();
    let country = parts[2].to_string();

    // Try to get ASN name via cymru name query
    let name = None; // Name lookup would require a second DNS query; keep it simple

    Some(AsnInfo {
        asn,
        name,
        prefix,
        country,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cymru_txt_basic() {
        let line = r#""15169 | 8.8.8.0/24 | US | arin | 2023-12-25""#;
        let info = parse_cymru_txt(line).unwrap();
        assert_eq!(info.asn, 15169);
        assert_eq!(info.prefix, "8.8.8.0/24");
        assert_eq!(info.country, "US");
    }

    #[test]
    fn test_parse_cymru_txt_no_quotes() {
        let line = "13335 | 1.1.1.0/24 | US | arin | 2014-03-28";
        let info = parse_cymru_txt(line).unwrap();
        assert_eq!(info.asn, 13335);
        assert_eq!(info.prefix, "1.1.1.0/24");
        assert_eq!(info.country, "US");
    }

    #[test]
    fn test_parse_cymru_txt_short() {
        let line = "bad";
        assert!(parse_cymru_txt(line).is_none());
    }

    #[test]
    fn test_parse_cymru_txt_invalid_asn() {
        let line = "notanum | 8.8.8.0/24 | US";
        assert!(parse_cymru_txt(line).is_none());
    }
}
