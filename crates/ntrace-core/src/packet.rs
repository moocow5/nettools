//! ICMP packet construction and parsing for traceroute.
//!
//! Extends nping-core's packet module with parsing for ICMP Time Exceeded
//! and Destination Unreachable messages, which contain the original IP header
//! + first 8 bytes of the triggering packet.

use std::net::Ipv4Addr;

// Re-export nping-core packet utilities
pub use nping_core::packet::{
    build_echo_request, internet_checksum, parse_echo_reply, strip_ip_header,
    EchoReply, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, ICMP_HEADER_SIZE,
};

/// ICMP Time Exceeded type
pub const ICMP_TIME_EXCEEDED: u8 = 11;
/// ICMP Destination Unreachable type
pub const ICMP_DEST_UNREACHABLE: u8 = 3;
/// ICMP Time Exceeded - TTL exceeded in transit
pub const ICMP_TTL_EXCEEDED_CODE: u8 = 0;
/// Minimum IP header size (no options)
pub const IP_HEADER_MIN_SIZE: usize = 20;

/// Parsed ICMP error message (Time Exceeded or Destination Unreachable)
#[derive(Debug, Clone)]
pub struct IcmpErrorMessage {
    /// ICMP type (11 = Time Exceeded, 3 = Dest Unreachable)
    pub icmp_type: u8,
    /// ICMP code
    pub icmp_code: u8,
    /// ICMP checksum
    pub checksum: u16,
    /// The original IP header + first 8 bytes of L4, extracted from the error payload
    pub original_header: OriginalHeader,
}

/// Extracted fields from the original IP header quoted in an ICMP error
#[derive(Debug, Clone)]
pub struct OriginalHeader {
    /// IP protocol number (1=ICMP, 6=TCP, 17=UDP)
    pub protocol: u8,
    /// Original source IP
    pub src_ip: Ipv4Addr,
    /// Original destination IP
    pub dst_ip: Ipv4Addr,
    /// IP Identification field (useful for NAT detection)
    pub ip_id: u16,
    /// Original TTL from IP header
    pub ttl: u8,
    /// First 8 bytes of the original L4 header (ICMP/TCP/UDP)
    pub l4_header: [u8; 8],
}

impl OriginalHeader {
    /// For ICMP probes: extract the ICMP identifier from the quoted L4 header
    pub fn icmp_identifier(&self) -> u16 {
        u16::from_be_bytes([self.l4_header[4], self.l4_header[5]])
    }

    /// For ICMP probes: extract the ICMP sequence number from the quoted L4 header
    pub fn icmp_sequence(&self) -> u16 {
        u16::from_be_bytes([self.l4_header[6], self.l4_header[7]])
    }

    /// For UDP probes: extract source port from quoted L4 header
    pub fn udp_src_port(&self) -> u16 {
        u16::from_be_bytes([self.l4_header[0], self.l4_header[1]])
    }

    /// For UDP probes: extract destination port from quoted L4 header
    pub fn udp_dst_port(&self) -> u16 {
        u16::from_be_bytes([self.l4_header[2], self.l4_header[3]])
    }

    /// For TCP probes: extract source port from quoted L4 header
    pub fn tcp_src_port(&self) -> u16 {
        u16::from_be_bytes([self.l4_header[0], self.l4_header[1]])
    }

    /// For TCP probes: extract destination port from quoted L4 header
    pub fn tcp_dst_port(&self) -> u16 {
        u16::from_be_bytes([self.l4_header[2], self.l4_header[3]])
    }
}

/// Parse an ICMP error message (Time Exceeded or Destination Unreachable).
///
/// These messages have the format:
/// - Bytes 0-7: ICMP header (type, code, checksum, unused/pointer)
/// - Bytes 8+: Original IP header + at least first 8 bytes of original L4 packet
///
/// The `data` parameter should be the raw ICMP message (after stripping the outer IP header).
pub fn parse_icmp_error(data: &[u8]) -> std::result::Result<IcmpErrorMessage, String> {
    // Need at least: 8 (ICMP header) + 20 (min IP header) + 8 (L4 header) = 36 bytes
    if data.len() < 36 {
        return Err(format!(
            "ICMP error message too short: {} bytes (need at least 36)",
            data.len()
        ));
    }

    let icmp_type = data[0];
    let icmp_code = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);

    // Validate this is actually an error message
    if icmp_type != ICMP_TIME_EXCEEDED && icmp_type != ICMP_DEST_UNREACHABLE {
        return Err(format!(
            "Not an ICMP error message: type {}",
            icmp_type
        ));
    }

    // Parse the original IP header starting at byte 8
    let ip_start = 8;
    let ip_data = &data[ip_start..];

    // Get IHL (lower 4 bits of first byte) to determine IP header length
    let ihl = (ip_data[0] & 0x0F) as usize;
    let ip_header_len = ihl * 4;

    if ip_header_len < IP_HEADER_MIN_SIZE {
        return Err(format!(
            "Invalid IP header length: {} (IHL={})",
            ip_header_len, ihl
        ));
    }

    if ip_data.len() < ip_header_len + 8 {
        return Err(format!(
            "Not enough data for IP header ({}) + 8 bytes L4: have {}",
            ip_header_len,
            ip_data.len()
        ));
    }

    let protocol = ip_data[9];
    let ttl = ip_data[8];
    let ip_id = u16::from_be_bytes([ip_data[4], ip_data[5]]);
    let src_ip = Ipv4Addr::new(ip_data[12], ip_data[13], ip_data[14], ip_data[15]);
    let dst_ip = Ipv4Addr::new(ip_data[16], ip_data[17], ip_data[18], ip_data[19]);

    let l4_start = ip_header_len;
    let mut l4_header = [0u8; 8];
    l4_header.copy_from_slice(&ip_data[l4_start..l4_start + 8]);

    Ok(IcmpErrorMessage {
        icmp_type,
        icmp_code,
        checksum,
        original_header: OriginalHeader {
            protocol,
            src_ip,
            dst_ip,
            ip_id,
            ttl,
            l4_header,
        },
    })
}

/// Check if an ICMP message is a Time Exceeded response
pub fn is_time_exceeded(icmp_type: u8) -> bool {
    icmp_type == ICMP_TIME_EXCEEDED
}

/// Check if an ICMP message is a Destination Unreachable response
pub fn is_dest_unreachable(icmp_type: u8) -> bool {
    icmp_type == ICMP_DEST_UNREACHABLE
}

/// Check if an ICMP message is an Echo Reply
pub fn is_echo_reply(icmp_type: u8) -> bool {
    icmp_type == ICMP_ECHO_REPLY
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_time_exceeded_packet(
        identifier: u16,
        sequence: u16,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
    ) -> Vec<u8> {
        let mut pkt = Vec::new();

        // ICMP header: type=11, code=0, checksum=0 (placeholder), unused=0
        pkt.push(ICMP_TIME_EXCEEDED); // type
        pkt.push(0); // code
        pkt.extend_from_slice(&[0, 0]); // checksum (placeholder)
        pkt.extend_from_slice(&[0, 0, 0, 0]); // unused

        // Original IP header (minimum 20 bytes)
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0); // TOS
        pkt.extend_from_slice(&[0, 60]); // total length
        pkt.extend_from_slice(&[0x12, 0x34]); // IP ID
        pkt.extend_from_slice(&[0, 0]); // flags + fragment offset
        pkt.push(1); // TTL (was 1 when it expired)
        pkt.push(1); // protocol = ICMP
        pkt.extend_from_slice(&[0, 0]); // header checksum
        pkt.extend_from_slice(&src_ip); // source IP
        pkt.extend_from_slice(&dst_ip); // dest IP

        // First 8 bytes of original ICMP packet
        pkt.push(8); // type = echo request
        pkt.push(0); // code
        pkt.extend_from_slice(&[0, 0]); // checksum
        pkt.extend_from_slice(&identifier.to_be_bytes()); // identifier
        pkt.extend_from_slice(&sequence.to_be_bytes()); // sequence

        pkt
    }

    #[test]
    fn test_parse_time_exceeded() {
        let pkt = build_time_exceeded_packet(0xABCD, 42, [192, 168, 1, 100], [8, 8, 8, 8]);
        let parsed = parse_icmp_error(&pkt).unwrap();

        assert_eq!(parsed.icmp_type, ICMP_TIME_EXCEEDED);
        assert_eq!(parsed.icmp_code, 0);
        assert_eq!(parsed.original_header.protocol, 1); // ICMP
        assert_eq!(parsed.original_header.src_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(parsed.original_header.dst_ip, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(parsed.original_header.ip_id, 0x1234);
        assert_eq!(parsed.original_header.icmp_identifier(), 0xABCD);
        assert_eq!(parsed.original_header.icmp_sequence(), 42);
    }

    #[test]
    fn test_parse_dest_unreachable() {
        let mut pkt = build_time_exceeded_packet(0x1234, 10, [10, 0, 0, 1], [1, 1, 1, 1]);
        pkt[0] = ICMP_DEST_UNREACHABLE; // change type
        pkt[1] = 3; // port unreachable

        let parsed = parse_icmp_error(&pkt).unwrap();
        assert_eq!(parsed.icmp_type, ICMP_DEST_UNREACHABLE);
        assert_eq!(parsed.icmp_code, 3);
        assert_eq!(parsed.original_header.icmp_identifier(), 0x1234);
        assert_eq!(parsed.original_header.icmp_sequence(), 10);
    }

    #[test]
    fn test_parse_too_short() {
        let pkt = vec![11, 0, 0, 0]; // way too short
        assert!(parse_icmp_error(&pkt).is_err());
    }

    #[test]
    fn test_parse_wrong_type() {
        let mut pkt = build_time_exceeded_packet(0, 0, [0; 4], [0; 4]);
        pkt[0] = 0; // echo reply, not an error
        assert!(parse_icmp_error(&pkt).is_err());
    }

    #[test]
    fn test_udp_port_extraction() {
        let mut pkt = build_time_exceeded_packet(0, 0, [10, 0, 0, 1], [8, 8, 8, 8]);
        // Change protocol to UDP
        pkt[8 + 9] = 17; // protocol = UDP
        // Replace L4 header with UDP: src_port=12345, dst_port=33434
        let l4_start = 8 + 20;
        pkt[l4_start..l4_start + 2].copy_from_slice(&12345u16.to_be_bytes());
        pkt[l4_start + 2..l4_start + 4].copy_from_slice(&33434u16.to_be_bytes());

        let parsed = parse_icmp_error(&pkt).unwrap();
        assert_eq!(parsed.original_header.protocol, 17);
        assert_eq!(parsed.original_header.udp_src_port(), 12345);
        assert_eq!(parsed.original_header.udp_dst_port(), 33434);
    }
}
