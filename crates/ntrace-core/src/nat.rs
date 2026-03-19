//! NAT detection via IP Identification field analysis.
//!
//! Dublin Traceroute-style NAT detection by comparing IP Identification fields.
//! When we send a probe with a known IP ID, intermediate routers quote the
//! original IP header in their ICMP Time Exceeded response. If a NAT device
//! rewrote the IP ID, the quoted value won't match what we sent.
//!
//! NOTE: Actually using controlled IP IDs requires `IP_HDRINCL` raw sockets.
//! This module provides the parsing infrastructure. The actual IP ID injection
//! would be added when raw socket support is expanded.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Result of NAT detection at a hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatDetection {
    /// TTL of the hop where detection was performed.
    pub ttl: u8,
    /// The IP ID we set in the outgoing probe.
    pub expected_ip_id: u16,
    /// The IP ID found in the quoted original header of the ICMP error.
    pub received_ip_id: u16,
    /// Whether NAT was detected (expected != received).
    pub is_nat: bool,
    /// The source address of the ICMP error (the router).
    pub source: Option<IpAddr>,
}

impl std::fmt::Display for NatDetection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_nat {
            write!(
                f,
                "NAT detected at TTL {}: expected IP ID 0x{:04X}, got 0x{:04X}",
                self.ttl, self.expected_ip_id, self.received_ip_id
            )
        } else {
            write!(
                f,
                "No NAT at TTL {}: IP ID 0x{:04X} matches",
                self.ttl, self.expected_ip_id
            )
        }
    }
}

/// Extract the IP Identification field from a quoted original IP header
/// inside an ICMP error message payload.
///
/// The ICMP error payload (after the 8-byte ICMP header) contains the
/// original IP header. The IP ID is at bytes 4-5 of the original IP header,
/// which means offset 4-5 from the start of the payload we receive.
///
/// `icmp_payload` should be the data after the 8-byte ICMP header (i.e., it
/// starts with the quoted original IP header).
pub fn extract_quoted_ip_id(icmp_payload: &[u8]) -> Option<u16> {
    // Need at least 6 bytes to reach IP ID (bytes 4-5 of the IP header)
    if icmp_payload.len() < 6 {
        return None;
    }

    // Verify this looks like an IP header (version = 4)
    let version = (icmp_payload[0] >> 4) & 0x0F;
    if version != 4 {
        return None;
    }

    Some(u16::from_be_bytes([icmp_payload[4], icmp_payload[5]]))
}

/// Check if NAT is detected by comparing sent vs quoted IP ID.
///
/// `expected_ip_id` is the IP ID we set in the outgoing probe.
/// `icmp_payload` is the data after the 8-byte ICMP header (starts with the
/// quoted original IP header).
/// `ttl` is the TTL of the hop.
/// `source` is the source address of the ICMP error response.
pub fn check_nat(
    expected_ip_id: u16,
    icmp_payload: &[u8],
    ttl: u8,
    source: Option<IpAddr>,
) -> Option<NatDetection> {
    let received_ip_id = extract_quoted_ip_id(icmp_payload)?;

    Some(NatDetection {
        ttl,
        expected_ip_id,
        received_ip_id,
        is_nat: expected_ip_id != received_ip_id,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal quoted original IP header for testing.
    /// Returns bytes starting from the IP header (what comes after the 8-byte ICMP header).
    fn build_quoted_ip_header(ip_id: u16) -> Vec<u8> {
        let mut hdr = vec![0u8; 28]; // 20 IP header + 8 L4

        hdr[0] = 0x45; // version=4, IHL=5
        hdr[1] = 0x00; // TOS
        hdr[2] = 0x00;
        hdr[3] = 0x3C; // total length = 60
        hdr[4] = (ip_id >> 8) as u8; // IP ID high byte
        hdr[5] = (ip_id & 0xFF) as u8; // IP ID low byte
        hdr[6] = 0x00;
        hdr[7] = 0x00; // flags + frag offset
        hdr[8] = 0x01; // TTL
        hdr[9] = 0x01; // protocol = ICMP
        hdr[10] = 0x00;
        hdr[11] = 0x00; // header checksum
        // Source IP: 192.168.1.100
        hdr[12] = 192;
        hdr[13] = 168;
        hdr[14] = 1;
        hdr[15] = 100;
        // Dest IP: 8.8.8.8
        hdr[16] = 8;
        hdr[17] = 8;
        hdr[18] = 8;
        hdr[19] = 8;

        hdr
    }

    #[test]
    fn test_extract_ip_id() {
        let payload = build_quoted_ip_header(0xABCD);
        let ip_id = extract_quoted_ip_id(&payload);
        assert_eq!(ip_id, Some(0xABCD));
    }

    #[test]
    fn test_extract_ip_id_zero() {
        let payload = build_quoted_ip_header(0x0000);
        let ip_id = extract_quoted_ip_id(&payload);
        assert_eq!(ip_id, Some(0x0000));
    }

    #[test]
    fn test_extract_ip_id_max() {
        let payload = build_quoted_ip_header(0xFFFF);
        let ip_id = extract_quoted_ip_id(&payload);
        assert_eq!(ip_id, Some(0xFFFF));
    }

    #[test]
    fn test_extract_ip_id_too_short() {
        // Only 5 bytes, need at least 6
        let payload = vec![0x45, 0x00, 0x00, 0x3C, 0xAB];
        assert_eq!(extract_quoted_ip_id(&payload), None);
    }

    #[test]
    fn test_extract_ip_id_wrong_version() {
        let mut payload = build_quoted_ip_header(0x1234);
        payload[0] = 0x65; // version=6, not IPv4
        assert_eq!(extract_quoted_ip_id(&payload), None);
    }

    #[test]
    fn test_nat_detected_mismatch() {
        let payload = build_quoted_ip_header(0x5678);
        let src: IpAddr = "10.0.0.1".parse().unwrap();
        let result = check_nat(0x1234, &payload, 3, Some(src)).unwrap();

        assert!(result.is_nat);
        assert_eq!(result.expected_ip_id, 0x1234);
        assert_eq!(result.received_ip_id, 0x5678);
        assert_eq!(result.ttl, 3);
        assert_eq!(result.source, Some(src));
    }

    #[test]
    fn test_no_nat_matching_ids() {
        let payload = build_quoted_ip_header(0x1234);
        let src: IpAddr = "10.0.0.1".parse().unwrap();
        let result = check_nat(0x1234, &payload, 5, Some(src)).unwrap();

        assert!(!result.is_nat);
        assert_eq!(result.expected_ip_id, 0x1234);
        assert_eq!(result.received_ip_id, 0x1234);
    }

    #[test]
    fn test_check_nat_too_short_payload() {
        let payload = vec![0x45, 0x00, 0x00]; // too short
        let result = check_nat(0x1234, &payload, 1, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_nat_detection_display() {
        let nat = NatDetection {
            ttl: 3,
            expected_ip_id: 0x1234,
            received_ip_id: 0x5678,
            is_nat: true,
            source: Some("10.0.0.1".parse().unwrap()),
        };
        let s = format!("{}", nat);
        assert!(s.contains("NAT detected"));
        assert!(s.contains("TTL 3"));

        let no_nat = NatDetection {
            ttl: 5,
            expected_ip_id: 0xAAAA,
            received_ip_id: 0xAAAA,
            is_nat: false,
            source: None,
        };
        let s = format!("{}", no_nat);
        assert!(s.contains("No NAT"));
    }
}
