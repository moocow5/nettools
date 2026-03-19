//! Paris-style constant-flow probing for load balancer traversal.
//!
//! Per-flow load balancers hash on flow identifiers (typically the 5-tuple).
//! Paris Traceroute keeps these constant across TTLs so all probes follow
//! the same path through load balancers.

use nping_core::packet::internet_checksum;

/// Builder for Paris-style ICMP probes with constant checksum.
///
/// Load balancers often use the ICMP checksum as part of their flow hash.
/// By keeping the checksum constant across different sequence numbers,
/// we ensure all probes follow the same path through per-flow load balancers.
#[derive(Debug)]
pub struct ParisProbeBuilder {
    identifier: u16,
    /// The target checksum value (computed from the first probe)
    target_checksum: Option<u16>,
    /// Base payload size
    payload_size: usize,
}

impl ParisProbeBuilder {
    pub fn new(identifier: u16, payload_size: usize) -> Self {
        Self {
            identifier,
            target_checksum: None,
            payload_size: payload_size.max(4), // Need at least 4 bytes for compensation
        }
    }

    /// Build an ICMP echo request with a constant checksum.
    ///
    /// The first call establishes the target checksum. Subsequent calls
    /// adjust the payload to maintain the same checksum with different sequences.
    pub fn build_probe(&mut self, sequence: u16) -> Vec<u8> {
        let payload_size = self.payload_size;
        let mut payload = vec![0u8; payload_size];

        // Encode the sequence in the first 2 bytes of payload (for our own matching)
        payload[0..2].copy_from_slice(&sequence.to_be_bytes());

        // Build the ICMP packet without checksum first
        let mut packet = Vec::with_capacity(8 + payload_size);
        packet.push(8); // type = echo request
        packet.push(0); // code
        packet.extend_from_slice(&[0, 0]); // checksum placeholder
        packet.extend_from_slice(&self.identifier.to_be_bytes());
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&payload);

        if let Some(target) = self.target_checksum {
            // We want the final checksum to equal `target`.
            // The checksum is ~S where S is the one's complement sum of all 16-bit words
            // (with the checksum field zeroed).
            //
            // Currently S_natural gives checksum_natural = ~S_natural.
            // We want ~(S_natural + comp) = target, i.e. S_natural + comp = ~target.
            // So comp = ~target - S_natural = ~target - ~checksum_natural (all one's complement).
            //
            // We compute this via the helper, then insert comp at payload[2:3] (bytes 10-11),
            // then recompute the checksum which should now equal `target`.
            let natural_checksum = internet_checksum(&packet);
            let compensation = ones_complement_subtract(!target, !natural_checksum);
            packet[10] = (compensation >> 8) as u8; // payload[2]
            packet[11] = (compensation & 0xFF) as u8; // payload[3]

            // Recompute checksum with the compensation value in place
            let adjusted_checksum = internet_checksum(&packet);
            packet[2] = (adjusted_checksum >> 8) as u8;
            packet[3] = (adjusted_checksum & 0xFF) as u8;
        } else {
            // First probe: compute checksum and set it as the target
            let natural_checksum = internet_checksum(&packet);
            self.target_checksum = Some(natural_checksum);
            packet[2] = (natural_checksum >> 8) as u8;
            packet[3] = (natural_checksum & 0xFF) as u8;
        }

        packet
    }

    /// Get the identifier used by this builder
    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    /// Get the target checksum (None if no probe has been built yet)
    pub fn target_checksum(&self) -> Option<u16> {
        self.target_checksum
    }
}

/// One's complement subtraction: compute (a - b) in 16-bit one's complement arithmetic.
///
/// In one's complement, subtraction wraps around through 0xFFFF (negative zero).
fn ones_complement_subtract(a: u16, b: u16) -> u16 {
    let a32 = a as u32;
    let b32 = b as u32;
    // Perform subtraction with borrow handling via wrap-around
    let result = if a32 >= b32 {
        a32 - b32
    } else {
        // Wrap: in one's complement, borrowing subtracts from 0xFFFF
        a32 + 0xFFFF - b32
    };
    result as u16
}

/// Configuration for Paris-style UDP probing.
///
/// For UDP, we keep (src_port, dst_port) constant and encode probe identity
/// in the payload, similar to how Paris ICMP keeps the checksum constant.
#[derive(Debug)]
pub struct ParisUdpConfig {
    /// Fixed source port to use
    pub src_port: u16,
    /// Fixed destination port
    pub dst_port: u16,
}

impl Default for ParisUdpConfig {
    fn default() -> Self {
        Self {
            src_port: 0,  // OS-assigned
            dst_port: 33434,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paris_constant_checksum() {
        let mut builder = ParisProbeBuilder::new(0x1234, 20);

        let pkt0 = builder.build_probe(0);
        let pkt1 = builder.build_probe(1);
        let pkt2 = builder.build_probe(100);

        // All packets should have the same checksum
        let cksum0 = u16::from_be_bytes([pkt0[2], pkt0[3]]);
        let cksum1 = u16::from_be_bytes([pkt1[2], pkt1[3]]);
        let cksum2 = u16::from_be_bytes([pkt2[2], pkt2[3]]);

        assert_eq!(cksum0, cksum1, "Checksum should be constant across sequences");
        assert_eq!(cksum0, cksum2, "Checksum should be constant across sequences");
    }

    #[test]
    fn test_paris_different_sequences_different_packets() {
        let mut builder = ParisProbeBuilder::new(0x1234, 20);

        let pkt0 = builder.build_probe(0);
        let pkt1 = builder.build_probe(1);

        // Sequence fields should differ
        let seq0 = u16::from_be_bytes([pkt0[6], pkt0[7]]);
        let seq1 = u16::from_be_bytes([pkt1[6], pkt1[7]]);
        assert_ne!(seq0, seq1);
    }

    #[test]
    fn test_paris_valid_icmp_packets() {
        let mut builder = ParisProbeBuilder::new(0xABCD, 16);

        for seq in 0..10 {
            let pkt = builder.build_probe(seq);

            // Verify it's a valid ICMP echo request
            assert_eq!(pkt[0], 8, "type should be echo request");
            assert_eq!(pkt[1], 0, "code should be 0");

            // Verify identifier
            let id = u16::from_be_bytes([pkt[4], pkt[5]]);
            assert_eq!(id, 0xABCD);

            // Verify checksum is valid (sum of all 16-bit words should be 0xFFFF)
            let valid = verify_checksum(&pkt);
            assert!(valid, "Checksum should validate for seq={}", seq);
        }
    }

    #[test]
    fn test_ones_complement_subtract_identity() {
        // a - a should be 0
        let result = ones_complement_subtract(0x1234, 0x1234);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_ones_complement_subtract_basic() {
        // 5 - 3 = 2
        let result = ones_complement_subtract(5, 3);
        assert_eq!(result, 2);
    }

    #[test]
    fn test_ones_complement_subtract_wrap() {
        // 0 - 1 should wrap around to 0xFFFE (borrow from 0xFFFF)
        let result = ones_complement_subtract(0, 1);
        assert_eq!(result, 0xFFFE);
    }

    /// Verify an ICMP packet's checksum by summing all 16-bit words
    fn verify_checksum(data: &[u8]) -> bool {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum == 0xFFFF
    }
}
