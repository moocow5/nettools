//! MPLS label detection via ICMP extension objects.
//!
//! Parses ICMP extension objects per RFC 4884 and MPLS label stacks per RFC 4950.
//!
//! When a router generates an ICMP Time Exceeded message, it may include ICMP
//! extension objects after the quoted original datagram. This module extracts
//! and parses those extensions, specifically MPLS label stack entries.

use serde::{Deserialize, Serialize};

/// An MPLS label stack entry (4 bytes).
///
/// Layout: label (20 bits) | TC/EXP (3 bits) | S (1 bit) | TTL (8 bits)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MplsLabel {
    /// Label value (20 bits, 0-1048575).
    pub label: u32,
    /// Traffic Class / EXP bits (3 bits).
    pub tc: u8,
    /// Bottom-of-stack bit.
    pub bottom: bool,
    /// MPLS TTL.
    pub ttl: u8,
}

impl std::fmt::Display for MplsLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[MPLS: L={} TC={} S={} TTL={}]",
            self.label, self.tc, self.bottom as u8, self.ttl
        )
    }
}

/// An ICMP extension object (RFC 4884).
///
/// Structure: length (16 bits) | class_num (8 bits) | c_type (8 bits) | data
#[derive(Debug, Clone)]
pub struct IcmpExtension {
    /// Class number identifying the extension type.
    pub class_num: u8,
    /// Sub-type within the class.
    pub c_type: u8,
    /// Raw extension object data (after the 4-byte object header).
    pub data: Vec<u8>,
}

/// ICMP extension header version (should be 2 per RFC 4884).
const EXTENSION_VERSION: u8 = 2;

/// Minimum size of the original datagram portion in an ICMP error payload.
/// RFC 4884 requires at least 128 bytes (padded if the original was shorter).
const MIN_ORIGINAL_DATAGRAM_LEN: usize = 128;

/// MPLS label stack class number (RFC 4950).
const MPLS_CLASS_NUM: u8 = 1;
/// MPLS label stack c_type (RFC 4950).
const MPLS_C_TYPE: u8 = 1;

/// Compute the one's complement checksum over a byte slice (RFC 1071 style).
fn ones_complement_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Parse ICMP extension objects from an ICMP Time Exceeded message payload.
///
/// The `icmp_payload` should be the raw ICMP payload **after** the 8-byte ICMP
/// header. Extensions start after the original datagram, which is at least 128
/// bytes per RFC 4884, or as indicated by the "length" field (byte 5 of the
/// ICMP header, which is byte index 4 of `icmp_payload` offset by -8 -- but
/// we expect the caller to pass the payload starting after the 8-byte header).
///
/// In practice, the original datagram length in the ICMP header is at byte 5
/// (the second byte of the "unused" field in the ICMP header). Since we receive
/// the payload after the 8-byte ICMP header, we need the caller to pass us
/// just the data after the ICMP header.
///
/// We assume the original datagram occupies the first 128 bytes (padded).
pub fn parse_icmp_extensions(icmp_payload: &[u8]) -> Vec<IcmpExtension> {
    // Need at least 128 bytes of original datagram + 4 bytes extension header
    if icmp_payload.len() < MIN_ORIGINAL_DATAGRAM_LEN + 4 {
        return Vec::new();
    }

    let ext_start = MIN_ORIGINAL_DATAGRAM_LEN;
    let ext_data = &icmp_payload[ext_start..];

    // Parse extension header: version (4 bits) | reserved (12 bits) | checksum (16 bits)
    let version = (ext_data[0] >> 4) & 0x0F;
    if version != EXTENSION_VERSION {
        return Vec::new();
    }

    let stated_checksum = u16::from_be_bytes([ext_data[2], ext_data[3]]);

    // Verify checksum if non-zero
    if stated_checksum != 0 {
        let computed = ones_complement_checksum(ext_data);
        if computed != 0 {
            return Vec::new();
        }
    }

    // Parse extension objects starting after the 4-byte extension header
    let mut objects = Vec::new();
    let mut offset = 4;

    while offset + 4 <= ext_data.len() {
        let obj_len = u16::from_be_bytes([ext_data[offset], ext_data[offset + 1]]) as usize;
        let class_num = ext_data[offset + 2];
        let c_type = ext_data[offset + 3];

        // Object length includes the 4-byte object header
        if obj_len < 4 || offset + obj_len > ext_data.len() {
            break;
        }

        let data = ext_data[offset + 4..offset + obj_len].to_vec();
        objects.push(IcmpExtension {
            class_num,
            c_type,
            data,
        });

        offset += obj_len;
    }

    objects
}

/// Parse MPLS label stack entries from an ICMP extension object.
///
/// Only valid for class_num=1, c_type=1 objects per RFC 4950.
/// Each label entry is 4 bytes.
pub fn parse_mpls_labels(extension: &IcmpExtension) -> Vec<MplsLabel> {
    if extension.class_num != MPLS_CLASS_NUM || extension.c_type != MPLS_C_TYPE {
        return Vec::new();
    }

    let mut labels = Vec::new();
    let mut offset = 0;

    while offset + 4 <= extension.data.len() {
        let word = u32::from_be_bytes([
            extension.data[offset],
            extension.data[offset + 1],
            extension.data[offset + 2],
            extension.data[offset + 3],
        ]);

        let label = (word >> 12) & 0xFFFFF; // top 20 bits
        let tc = ((word >> 9) & 0x07) as u8; // next 3 bits
        let bottom = ((word >> 8) & 0x01) != 0; // next 1 bit
        let ttl = (word & 0xFF) as u8; // bottom 8 bits

        labels.push(MplsLabel {
            label,
            tc,
            bottom,
            ttl,
        });

        offset += 4;

        // If bottom-of-stack bit is set, stop parsing
        if bottom {
            break;
        }
    }

    labels
}

/// Convenience: extract all MPLS labels from an ICMP Time Exceeded payload.
///
/// The `icmp_payload` is the data after the 8-byte ICMP header.
pub fn extract_mpls_labels(icmp_payload: &[u8]) -> Vec<MplsLabel> {
    let extensions = parse_icmp_extensions(icmp_payload);
    let mut all_labels = Vec::new();

    for ext in &extensions {
        if ext.class_num == MPLS_CLASS_NUM && ext.c_type == MPLS_C_TYPE {
            all_labels.extend(parse_mpls_labels(ext));
        }
    }

    all_labels
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid ICMP extension header + objects and append to a 128-byte
    /// original datagram payload.
    fn build_payload_with_extensions(ext_objects: &[&IcmpExtension]) -> Vec<u8> {
        // 128 bytes of original datagram (zeroed)
        let mut payload = vec![0u8; MIN_ORIGINAL_DATAGRAM_LEN];

        // Build extension data (header + objects) first without checksum
        let mut ext_data = Vec::new();

        // Extension header: version=2, reserved=0, checksum=0 (placeholder)
        ext_data.push(EXTENSION_VERSION << 4); // version in top nibble
        ext_data.push(0); // reserved
        ext_data.push(0); // checksum high (placeholder)
        ext_data.push(0); // checksum low (placeholder)

        // Append each object
        for obj in ext_objects {
            let obj_len = (4 + obj.data.len()) as u16;
            ext_data.extend_from_slice(&obj_len.to_be_bytes());
            ext_data.push(obj.class_num);
            ext_data.push(obj.c_type);
            ext_data.extend_from_slice(&obj.data);
        }

        // Compute checksum over entire extension data
        let checksum = ones_complement_checksum(&ext_data);
        ext_data[2] = (checksum >> 8) as u8;
        ext_data[3] = (checksum & 0xFF) as u8;

        payload.extend_from_slice(&ext_data);
        payload
    }

    /// Encode a single MPLS label entry as 4 bytes.
    fn encode_mpls_entry(label: u32, tc: u8, bottom: bool, ttl: u8) -> [u8; 4] {
        let word: u32 =
            (label << 12) | ((tc as u32 & 0x07) << 9) | ((bottom as u32) << 8) | (ttl as u32);
        word.to_be_bytes()
    }

    #[test]
    fn test_no_extensions_short_payload() {
        // Payload shorter than 132 bytes (128 + 4) => no extensions
        let payload = vec![0u8; 100];
        let exts = parse_icmp_extensions(&payload);
        assert!(exts.is_empty());
    }

    #[test]
    fn test_no_extensions_wrong_version() {
        let mut payload = vec![0u8; MIN_ORIGINAL_DATAGRAM_LEN + 8];
        // Set version to 1 instead of 2
        payload[MIN_ORIGINAL_DATAGRAM_LEN] = 0x10;
        let exts = parse_icmp_extensions(&payload);
        assert!(exts.is_empty());
    }

    #[test]
    fn test_single_mpls_label() {
        let entry = encode_mpls_entry(12345, 5, true, 64);
        let ext = IcmpExtension {
            class_num: MPLS_CLASS_NUM,
            c_type: MPLS_C_TYPE,
            data: entry.to_vec(),
        };

        let payload = build_payload_with_extensions(&[&ext]);
        let extensions = parse_icmp_extensions(&payload);

        assert_eq!(extensions.len(), 1);
        assert_eq!(extensions[0].class_num, MPLS_CLASS_NUM);
        assert_eq!(extensions[0].c_type, MPLS_C_TYPE);

        let labels = parse_mpls_labels(&extensions[0]);
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].label, 12345);
        assert_eq!(labels[0].tc, 5);
        assert!(labels[0].bottom);
        assert_eq!(labels[0].ttl, 64);
    }

    #[test]
    fn test_mpls_label_stack_three_entries() {
        let mut data = Vec::new();
        data.extend_from_slice(&encode_mpls_entry(100, 0, false, 255));
        data.extend_from_slice(&encode_mpls_entry(200, 3, false, 128));
        data.extend_from_slice(&encode_mpls_entry(300, 7, true, 1));

        let ext = IcmpExtension {
            class_num: MPLS_CLASS_NUM,
            c_type: MPLS_C_TYPE,
            data,
        };

        let payload = build_payload_with_extensions(&[&ext]);
        let labels = extract_mpls_labels(&payload);

        assert_eq!(labels.len(), 3);

        assert_eq!(labels[0].label, 100);
        assert_eq!(labels[0].tc, 0);
        assert!(!labels[0].bottom);
        assert_eq!(labels[0].ttl, 255);

        assert_eq!(labels[1].label, 200);
        assert_eq!(labels[1].tc, 3);
        assert!(!labels[1].bottom);
        assert_eq!(labels[1].ttl, 128);

        assert_eq!(labels[2].label, 300);
        assert_eq!(labels[2].tc, 7);
        assert!(labels[2].bottom);
        assert_eq!(labels[2].ttl, 1);
    }

    #[test]
    fn test_truncated_extension_object() {
        // Build payload with extension header but truncated object
        let mut payload = vec![0u8; MIN_ORIGINAL_DATAGRAM_LEN];

        // Extension header: version=2, reserved=0, checksum=0
        let mut ext_hdr = vec![EXTENSION_VERSION << 4, 0, 0, 0];
        // Object header claiming length=20 but only 2 bytes of data follow
        ext_hdr.extend_from_slice(&8u16.to_be_bytes()); // length = 8
        ext_hdr.push(MPLS_CLASS_NUM);
        ext_hdr.push(MPLS_C_TYPE);
        // Only 2 bytes instead of 4 for the object data
        ext_hdr.push(0);
        ext_hdr.push(0);
        // Missing 2 more bytes — but length says 8 (4 header + 4 data)

        // Compute checksum
        let checksum = ones_complement_checksum(&ext_hdr);
        ext_hdr[2] = (checksum >> 8) as u8;
        ext_hdr[3] = (checksum & 0xFF) as u8;

        payload.extend_from_slice(&ext_hdr);

        // The object says length=8 but total ext data after header only has 6 bytes
        // The parse should fail gracefully since offset + obj_len > ext_data.len()
        let extensions = parse_icmp_extensions(&payload);
        // Object claims 8 bytes but we have exactly 8 bytes of object data (4 hdr + 2 data + 2 padding)
        // Actually let's check: ext_hdr is 4(header) + 2(len) + 1(class) + 1(ctype) + 2(data) = 10
        // ext_data starts at offset 128, has 10 bytes. offset=4, obj_len=8, offset+obj_len=12 > 10
        // So the object is truncated and should be skipped.
        assert!(extensions.is_empty());
    }

    #[test]
    fn test_extension_header_checksum_validation() {
        let entry = encode_mpls_entry(99999, 2, true, 30);
        let ext = IcmpExtension {
            class_num: MPLS_CLASS_NUM,
            c_type: MPLS_C_TYPE,
            data: entry.to_vec(),
        };

        let mut payload = build_payload_with_extensions(&[&ext]);

        // Verify it parses correctly with valid checksum
        let labels = extract_mpls_labels(&payload);
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].label, 99999);

        // Corrupt the checksum
        payload[MIN_ORIGINAL_DATAGRAM_LEN + 2] ^= 0xFF;

        // Should fail to parse due to bad checksum
        let labels = extract_mpls_labels(&payload);
        assert!(labels.is_empty());
    }

    #[test]
    fn test_wrong_class_num_ignored() {
        let ext = IcmpExtension {
            class_num: 5, // Not MPLS
            c_type: 1,
            data: vec![0; 4],
        };
        let labels = parse_mpls_labels(&ext);
        assert!(labels.is_empty());
    }

    #[test]
    fn test_display_format() {
        let label = MplsLabel {
            label: 12345,
            tc: 5,
            bottom: true,
            ttl: 64,
        };
        assert_eq!(format!("{}", label), "[MPLS: L=12345 TC=5 S=1 TTL=64]");

        let label2 = MplsLabel {
            label: 0,
            tc: 0,
            bottom: false,
            ttl: 0,
        };
        assert_eq!(format!("{}", label2), "[MPLS: L=0 TC=0 S=0 TTL=0]");
    }

    #[test]
    fn test_bottom_of_stack_stops_parsing() {
        // Two entries: first has bottom=true, second should be ignored
        let mut data = Vec::new();
        data.extend_from_slice(&encode_mpls_entry(111, 0, true, 64)); // bottom=true
        data.extend_from_slice(&encode_mpls_entry(222, 0, false, 32)); // should be ignored

        let ext = IcmpExtension {
            class_num: MPLS_CLASS_NUM,
            c_type: MPLS_C_TYPE,
            data,
        };

        let labels = parse_mpls_labels(&ext);
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].label, 111);
    }

    #[test]
    fn test_extract_mpls_labels_convenience() {
        let entry = encode_mpls_entry(54321, 1, true, 100);
        let ext = IcmpExtension {
            class_num: MPLS_CLASS_NUM,
            c_type: MPLS_C_TYPE,
            data: entry.to_vec(),
        };

        let payload = build_payload_with_extensions(&[&ext]);
        let labels = extract_mpls_labels(&payload);

        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].label, 54321);
        assert_eq!(labels[0].tc, 1);
        assert!(labels[0].bottom);
        assert_eq!(labels[0].ttl, 100);
    }
}
