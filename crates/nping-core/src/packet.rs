/// ICMP packet construction and parsing.
///
/// Provides utilities for building ICMP echo request packets, parsing echo
/// reply packets, and computing the RFC 1071 Internet Checksum.

/// ICMP type field value for an Echo Request.
pub const ICMP_ECHO_REQUEST: u8 = 8;

/// ICMP type field value for an Echo Reply.
pub const ICMP_ECHO_REPLY: u8 = 0;

/// Size of the ICMP header in bytes (type + code + checksum + id + seq).
pub const ICMP_HEADER_SIZE: usize = 8;

/// Computes the RFC 1071 Internet Checksum over the given byte slice.
///
/// The algorithm sums all 16-bit words, folds any carry bits back into the
/// lower 16 bits, and returns the ones-complement of the result.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum consecutive 16-bit words.
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }

    // If there is a trailing odd byte, pad it with a zero byte on the right.
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum into 16 bits by adding carry bits.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return the ones-complement.
    !(sum as u16)
}

/// Builds a complete ICMP Echo Request packet.
///
/// The returned `Vec<u8>` contains the ICMP header (type 8, code 0, checksum,
/// identifier, sequence number) followed by the supplied payload. The checksum
/// field is computed over the entire packet.
pub fn build_echo_request(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = ICMP_HEADER_SIZE + payload.len();
    let mut packet = Vec::with_capacity(total_len);

    // Type: Echo Request (8)
    packet.push(ICMP_ECHO_REQUEST);
    // Code: 0
    packet.push(0);
    // Checksum placeholder (zeroed for initial computation).
    packet.push(0);
    packet.push(0);
    // Identifier in network byte order.
    packet.extend_from_slice(&identifier.to_be_bytes());
    // Sequence number in network byte order.
    packet.extend_from_slice(&sequence.to_be_bytes());
    // Payload.
    packet.extend_from_slice(payload);

    // Compute the checksum over the entire packet and fill it in.
    let checksum = internet_checksum(&packet);
    let checksum_bytes = checksum.to_be_bytes();
    packet[2] = checksum_bytes[0];
    packet[3] = checksum_bytes[1];

    packet
}

/// A parsed ICMP Echo Reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoReply {
    /// ICMP type field (expected to be 0 for Echo Reply).
    pub type_field: u8,
    /// ICMP code field.
    pub code: u8,
    /// ICMP checksum as received.
    pub checksum: u16,
    /// Identifier copied from the corresponding Echo Request.
    pub identifier: u16,
    /// Sequence number copied from the corresponding Echo Request.
    pub sequence: u16,
    /// Payload bytes following the ICMP header.
    pub payload: Vec<u8>,
}

/// Parses an ICMP Echo Reply from raw bytes.
///
/// The input `data` should point to the start of the ICMP header (i.e., the IP
/// header must already be stripped). Returns an error if the data is too short
/// to contain a valid ICMP header.
pub fn parse_echo_reply(data: &[u8]) -> Result<EchoReply, String> {
    if data.len() < ICMP_HEADER_SIZE {
        return Err(format!(
            "packet too short: expected at least {} bytes, got {}",
            ICMP_HEADER_SIZE,
            data.len()
        ));
    }

    let type_field = data[0];
    let code = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);
    let identifier = u16::from_be_bytes([data[4], data[5]]);
    let sequence = u16::from_be_bytes([data[6], data[7]]);
    let payload = data[ICMP_HEADER_SIZE..].to_vec();

    Ok(EchoReply {
        type_field,
        code,
        checksum,
        identifier,
        sequence,
        payload,
    })
}

/// Strips the IPv4 header from a raw packet, returning the remaining bytes.
///
/// Reads the Internet Header Length (IHL) field from the first byte of the
/// packet to determine how many bytes the IP header occupies (typically 20).
/// Returns a slice starting at the first byte after the IP header (i.e., the
/// ICMP data).
///
/// # Panics
///
/// Does not panic, but will return an empty slice if the packet is shorter
/// than the indicated header length.
pub fn strip_ip_header(data: &[u8]) -> &[u8] {
    if data.is_empty() {
        return data;
    }

    // IHL is the lower 4 bits of the first byte, measured in 32-bit words.
    let ihl = (data[0] & 0x0F) as usize;
    let header_len = ihl * 4;

    if header_len > data.len() {
        // If the header length exceeds the packet, return an empty slice.
        return &data[data.len()..];
    }

    &data[header_len..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_known_data() {
        // Sum of 16-bit words: 0x0001 + 0x00f2 + 0x00f4 + 0x00f5 + 0x00f6
        // = 0x03d8. Ones complement = 0xfc27? Let's verify by round-trip:
        // Instead, test that checksum(data ++ checksum) == 0.
        let data: Vec<u8> = vec![
            0x00, 0x01, 0x00, 0xf2, 0x00, 0xf4, 0x00, 0xf5, 0x00, 0xf6,
        ];
        let cksum = internet_checksum(&data);
        // Verify by appending the checksum and re-checksumming (should yield 0).
        let mut with_cksum = data.clone();
        with_cksum.extend_from_slice(&cksum.to_be_bytes());
        assert_eq!(internet_checksum(&with_cksum), 0);
    }

    #[test]
    fn checksum_with_odd_byte() {
        // A three-byte input should pad the last byte.
        let data = vec![0x00, 0x01, 0xf2];
        let cksum = internet_checksum(&data);
        // 0x0001 + 0xf200 = 0xf201 => ~0xf201 = 0x0dfe
        assert_eq!(cksum, 0x0dfe);
    }

    #[test]
    fn checksum_empty() {
        let cksum = internet_checksum(&[]);
        assert_eq!(cksum, 0xFFFF);
    }

    #[test]
    fn checksum_of_valid_packet_is_zero() {
        // Building a packet and then checksumming the whole thing (including
        // the checksum field) should yield zero.
        let packet = build_echo_request(0x1234, 1, b"hello");
        assert_eq!(internet_checksum(&packet), 0);
    }

    #[test]
    fn build_and_parse_round_trip() {
        let id: u16 = 0xABCD;
        let seq: u16 = 42;
        let payload = b"ping payload data";

        let packet = build_echo_request(id, seq, payload);

        // Verify basic structure.
        assert_eq!(packet[0], ICMP_ECHO_REQUEST);
        assert_eq!(packet[1], 0); // code
        assert_eq!(packet.len(), ICMP_HEADER_SIZE + payload.len());

        // Simulate receiving an echo reply by changing the type field to 0
        // and recomputing the checksum.
        let mut reply_data = packet.clone();
        reply_data[0] = ICMP_ECHO_REPLY;
        // Zero out the checksum before recomputing.
        reply_data[2] = 0;
        reply_data[3] = 0;
        let new_checksum = internet_checksum(&reply_data);
        let cksum_bytes = new_checksum.to_be_bytes();
        reply_data[2] = cksum_bytes[0];
        reply_data[3] = cksum_bytes[1];

        let reply = parse_echo_reply(&reply_data).expect("parse should succeed");
        assert_eq!(reply.type_field, ICMP_ECHO_REPLY);
        assert_eq!(reply.code, 0);
        assert_eq!(reply.identifier, id);
        assert_eq!(reply.sequence, seq);
        assert_eq!(reply.payload, payload);
    }

    #[test]
    fn build_empty_payload() {
        let packet = build_echo_request(1, 1, &[]);
        assert_eq!(packet.len(), ICMP_HEADER_SIZE);
        assert_eq!(internet_checksum(&packet), 0);

        let reply = parse_echo_reply(&packet).expect("parse should succeed");
        assert!(reply.payload.is_empty());
    }

    #[test]
    fn build_max_payload() {
        // Use a large (but not truly maximum) payload to exercise the path.
        let payload = vec![0xAA; 65507]; // max UDP-like payload size
        let packet = build_echo_request(0xFFFF, 0xFFFF, &payload);
        assert_eq!(packet.len(), ICMP_HEADER_SIZE + payload.len());
        assert_eq!(internet_checksum(&packet), 0);

        let reply = parse_echo_reply(&packet).expect("parse should succeed");
        assert_eq!(reply.identifier, 0xFFFF);
        assert_eq!(reply.sequence, 0xFFFF);
        assert_eq!(reply.payload.len(), payload.len());
    }

    #[test]
    fn parse_too_short() {
        let short = vec![0u8; ICMP_HEADER_SIZE - 1];
        let err = parse_echo_reply(&short).unwrap_err();
        assert!(err.contains("too short"));
    }

    #[test]
    fn parse_exact_header_no_payload() {
        let data = vec![0, 0, 0, 0, 0, 1, 0, 2];
        let reply = parse_echo_reply(&data).expect("parse should succeed");
        assert_eq!(reply.type_field, 0);
        assert_eq!(reply.identifier, 1);
        assert_eq!(reply.sequence, 2);
        assert!(reply.payload.is_empty());
    }

    #[test]
    fn strip_standard_ip_header() {
        // Build a fake IP header (20 bytes) + ICMP data.
        let mut raw = vec![0u8; 20 + 16];
        // Version 4, IHL 5 (5 * 4 = 20 bytes).
        raw[0] = 0x45;
        // Write a recognizable pattern in the ICMP portion.
        raw[20] = ICMP_ECHO_REPLY;
        raw[21] = 0;
        raw[22] = 0xDE;
        raw[23] = 0xAD;

        let icmp = strip_ip_header(&raw);
        assert_eq!(icmp.len(), 16);
        assert_eq!(icmp[0], ICMP_ECHO_REPLY);
        assert_eq!(icmp[2], 0xDE);
        assert_eq!(icmp[3], 0xAD);
    }

    #[test]
    fn strip_ip_header_with_options() {
        // IHL = 8 means 32 bytes of IP header (with options).
        let mut raw = vec![0u8; 32 + 8];
        raw[0] = 0x48; // Version 4, IHL 8
        raw[32] = ICMP_ECHO_REQUEST;

        let icmp = strip_ip_header(&raw);
        assert_eq!(icmp.len(), 8);
        assert_eq!(icmp[0], ICMP_ECHO_REQUEST);
    }

    #[test]
    fn strip_ip_header_empty() {
        let empty: &[u8] = &[];
        let result = strip_ip_header(empty);
        assert!(result.is_empty());
    }

    #[test]
    fn strip_ip_header_truncated() {
        // Packet claims IHL=5 (20 bytes) but is only 10 bytes long.
        let mut raw = vec![0u8; 10];
        raw[0] = 0x45;
        let result = strip_ip_header(&raw);
        assert!(result.is_empty());
    }
}
