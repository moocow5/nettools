use crate::{NmapperError, Result};
use std::fmt;
use std::net::Ipv4Addr;

// BER/ASN.1 tag constants
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_IP_ADDRESS: u8 = 0x40;
const TAG_COUNTER32: u8 = 0x41;
const TAG_GAUGE32: u8 = 0x42;
const TAG_TIMETICKS: u8 = 0x43;
const TAG_GET_REQUEST: u8 = 0xA0;
const TAG_GET_NEXT_REQUEST: u8 = 0xA1;
const TAG_GET_RESPONSE: u8 = 0xA2;
const TAG_SNMPV2_TRAP: u8 = 0xA7;

/// Represents a decoded SNMP value.
#[derive(Debug, Clone, PartialEq)]
pub enum SnmpValue {
    Integer(i64),
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(String),
    IpAddress(Ipv4Addr),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
}

impl fmt::Display for SnmpValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnmpValue::Integer(v) => write!(f, "{}", v),
            SnmpValue::OctetString(v) => {
                if let Ok(s) = std::str::from_utf8(v) {
                    if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                        return write!(f, "{}", s);
                    }
                }
                // Hex-encode non-printable strings
                let hex: Vec<String> = v.iter().map(|b| format!("{:02x}", b)).collect();
                write!(f, "{}", hex.join(":"))
            }
            SnmpValue::Null => write!(f, "NULL"),
            SnmpValue::ObjectIdentifier(oid) => write!(f, "{}", oid),
            SnmpValue::IpAddress(addr) => write!(f, "{}", addr),
            SnmpValue::Counter32(v) => write!(f, "{}", v),
            SnmpValue::Gauge32(v) => write!(f, "{}", v),
            SnmpValue::TimeTicks(v) => write!(f, "{}", v),
        }
    }
}

/// A decoded SNMP response.
#[derive(Debug)]
pub struct SnmpResponse {
    pub request_id: i32,
    pub error_status: i32,
    pub error_index: i32,
    pub varbinds: Vec<(String, SnmpValue)>,
}

// ---------------------------------------------------------------------------
// BER length encoding / decoding
// ---------------------------------------------------------------------------

/// Encode a BER definite-form length.
pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        // 3-byte length (up to 16 MiB) — sufficient for SNMP
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

/// Decode a BER definite-form length starting at `offset`.
/// Returns `(length, new_offset)`.
pub fn decode_length(data: &[u8], offset: usize) -> Result<(usize, usize)> {
    if offset >= data.len() {
        return Err(NmapperError::Other("truncated length".into()));
    }
    let first = data[offset];
    if first < 128 {
        Ok((first as usize, offset + 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || offset + 1 + num_bytes > data.len() {
            return Err(NmapperError::Other("invalid length encoding".into()));
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (data[offset + 1 + i] as usize);
        }
        Ok((len, offset + 1 + num_bytes))
    }
}

// ---------------------------------------------------------------------------
// OID encoding / decoding
// ---------------------------------------------------------------------------

/// Encode a dotted-decimal OID string into BER OID content bytes (no tag/length wrapper).
pub fn encode_oid(oid_str: &str) -> Result<Vec<u8>> {
    let parts: Vec<u32> = oid_str
        .split('.')
        .map(|s| {
            s.parse::<u32>()
                .map_err(|_| NmapperError::Other(format!("invalid OID component: {}", s)))
        })
        .collect::<Result<Vec<u32>>>()?;
    if parts.len() < 2 {
        return Err(NmapperError::Other("OID too short".into()));
    }
    let mut out = Vec::new();
    // First two components are encoded as 40*X + Y
    out.push((parts[0] * 40 + parts[1]) as u8);
    for &v in &parts[2..] {
        encode_oid_subid(&mut out, v);
    }
    Ok(out)
}

fn encode_oid_subid(out: &mut Vec<u8>, mut value: u32) {
    if value == 0 {
        out.push(0);
        return;
    }
    // Collect base-128 digits in reverse
    let mut bytes = Vec::new();
    while value > 0 {
        bytes.push((value & 0x7F) as u8);
        value >>= 7;
    }
    bytes.reverse();
    // Set high bit on all but the last byte
    let last = bytes.len() - 1;
    for (i, b) in bytes.iter_mut().enumerate() {
        if i < last {
            *b |= 0x80;
        }
    }
    out.extend_from_slice(&bytes);
}

/// Decode BER OID content bytes into a dotted-decimal string.
pub fn decode_oid(data: &[u8]) -> Result<String> {
    if data.is_empty() {
        return Err(NmapperError::Other("empty OID data".into()));
    }
    let first = data[0];
    let mut parts = vec![
        (first / 40) as u32,
        (first % 40) as u32,
    ];
    let mut i = 1;
    while i < data.len() {
        let mut value: u32 = 0;
        loop {
            if i >= data.len() {
                return Err(NmapperError::Other("truncated OID".into()));
            }
            let b = data[i];
            i += 1;
            value = (value << 7) | ((b & 0x7F) as u32);
            if b & 0x80 == 0 {
                break;
            }
        }
        parts.push(value);
    }
    Ok(parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("."))
}

// ---------------------------------------------------------------------------
// BER primitive encoding helpers
// ---------------------------------------------------------------------------

fn encode_integer(value: i32) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    // Strip leading 0x00 / 0xFF padding, preserving sign
    while bytes.len() > 1 {
        if bytes[0] == 0x00 && bytes[1] & 0x80 == 0 {
            bytes.remove(0);
        } else if bytes[0] == 0xFF && bytes[1] & 0x80 != 0 {
            bytes.remove(0);
        } else {
            break;
        }
    }
    let mut out = vec![TAG_INTEGER];
    out.extend(encode_length(bytes.len()));
    out.extend(bytes);
    out
}

fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![TAG_OCTET_STRING];
    out.extend(encode_length(data.len()));
    out.extend_from_slice(data);
    out
}

fn encode_null() -> Vec<u8> {
    vec![TAG_NULL, 0x00]
}

fn encode_oid_tlv(oid_str: &str) -> Result<Vec<u8>> {
    let content = encode_oid(oid_str)?;
    let mut out = vec![TAG_OID];
    out.extend(encode_length(content.len()));
    out.extend(content);
    Ok(out)
}

fn encode_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = vec![TAG_SEQUENCE];
    out.extend(encode_length(content.len()));
    out.extend_from_slice(content);
    out
}

fn encode_pdu(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(encode_length(content.len()));
    out.extend_from_slice(content);
    out
}

// ---------------------------------------------------------------------------
// SNMP message encoding
// ---------------------------------------------------------------------------

fn encode_snmp_message(community: &str, pdu: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    // version: SNMPv2c = 1
    content.extend(encode_integer(1));
    // community string
    content.extend(encode_octet_string(community.as_bytes()));
    // PDU
    content.extend_from_slice(pdu);
    encode_sequence(&content)
}

fn encode_varbind_list(oids: &[&str]) -> Result<Vec<u8>> {
    let mut varbinds = Vec::new();
    for oid in oids {
        let mut vb = Vec::new();
        vb.extend(encode_oid_tlv(oid)?);
        vb.extend(encode_null());
        varbinds.extend(encode_sequence(&vb));
    }
    Ok(encode_sequence(&varbinds))
}

/// Encode an SNMPv2c GetRequest message.
pub fn encode_get_request(request_id: i32, community: &str, oids: &[&str]) -> Result<Vec<u8>> {
    let mut pdu_content = Vec::new();
    pdu_content.extend(encode_integer(request_id));
    pdu_content.extend(encode_integer(0)); // error-status
    pdu_content.extend(encode_integer(0)); // error-index
    pdu_content.extend(encode_varbind_list(oids)?);
    let pdu = encode_pdu(TAG_GET_REQUEST, &pdu_content);
    Ok(encode_snmp_message(community, &pdu))
}

/// Encode an SNMPv2c GetNextRequest message.
pub fn encode_get_next_request(request_id: i32, community: &str, oid: &str) -> Result<Vec<u8>> {
    let mut pdu_content = Vec::new();
    pdu_content.extend(encode_integer(request_id));
    pdu_content.extend(encode_integer(0)); // error-status
    pdu_content.extend(encode_integer(0)); // error-index
    pdu_content.extend(encode_varbind_list(&[oid])?);
    let pdu = encode_pdu(TAG_GET_NEXT_REQUEST, &pdu_content);
    Ok(encode_snmp_message(community, &pdu))
}

// ---------------------------------------------------------------------------
// SNMP response decoding
// ---------------------------------------------------------------------------

/// Decode an SNMPv2c response message.
pub fn decode_response(data: &[u8]) -> Result<SnmpResponse> {
    let mut offset = 0;

    // Outer SEQUENCE
    if offset >= data.len() || data[offset] != TAG_SEQUENCE {
        return Err(NmapperError::Other("expected SEQUENCE".into()));
    }
    offset += 1;
    let (_seq_len, new_off) = decode_length(data, offset)?;
    offset = new_off;

    // Version (INTEGER)
    let (_version, new_off) = decode_integer(data, offset)?;
    offset = new_off;

    // Community (OCTET STRING)
    let (_community, new_off) = decode_octet_string_raw(data, offset)?;
    offset = new_off;

    // PDU — expect GetResponse (0xA2) but tolerate others
    if offset >= data.len() {
        return Err(NmapperError::Other("truncated PDU".into()));
    }
    let pdu_tag = data[offset];
    if pdu_tag != TAG_GET_RESPONSE
        && pdu_tag != TAG_GET_REQUEST
        && pdu_tag != TAG_GET_NEXT_REQUEST
        && pdu_tag != TAG_SNMPV2_TRAP
    {
        return Err(NmapperError::Other(format!(
            "unexpected PDU tag: 0x{:02X}",
            pdu_tag
        )));
    }
    offset += 1;
    let (_pdu_len, new_off) = decode_length(data, offset)?;
    offset = new_off;

    // request-id
    let (request_id, new_off) = decode_integer(data, offset)?;
    offset = new_off;

    // error-status
    let (error_status, new_off) = decode_integer(data, offset)?;
    offset = new_off;

    // error-index
    let (error_index, new_off) = decode_integer(data, offset)?;
    offset = new_off;

    // VarBindList (SEQUENCE)
    if offset >= data.len() || data[offset] != TAG_SEQUENCE {
        return Err(NmapperError::Other("expected VarBindList SEQUENCE".into()));
    }
    offset += 1;
    let (vbl_len, new_off) = decode_length(data, offset)?;
    offset = new_off;
    let vbl_end = offset + vbl_len;

    let mut varbinds = Vec::new();
    while offset < vbl_end {
        // Each VarBind is a SEQUENCE
        if data[offset] != TAG_SEQUENCE {
            return Err(NmapperError::Other("expected VarBind SEQUENCE".into()));
        }
        offset += 1;
        let (_vb_len, new_off) = decode_length(data, offset)?;
        offset = new_off;

        // OID
        if offset >= data.len() || data[offset] != TAG_OID {
            return Err(NmapperError::Other("expected OID in VarBind".into()));
        }
        offset += 1;
        let (oid_len, new_off) = decode_length(data, offset)?;
        offset = new_off;
        let oid = decode_oid(&data[offset..offset + oid_len])?;
        offset += oid_len;

        // Value
        let (value, new_off) = decode_value(data, offset)?;
        offset = new_off;

        varbinds.push((oid, value));
    }

    Ok(SnmpResponse {
        request_id: request_id as i32,
        error_status: error_status as i32,
        error_index: error_index as i32,
        varbinds,
    })
}

// ---------------------------------------------------------------------------
// BER decoding helpers
// ---------------------------------------------------------------------------

fn decode_integer(data: &[u8], offset: usize) -> Result<(i64, usize)> {
    if offset >= data.len() || data[offset] != TAG_INTEGER {
        return Err(NmapperError::Other("expected INTEGER".into()));
    }
    let (len, off) = decode_length(data, offset + 1)?;
    if off + len > data.len() {
        return Err(NmapperError::Other("truncated INTEGER".into()));
    }
    let bytes = &data[off..off + len];
    let mut value: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in bytes {
        value = (value << 8) | (b as i64);
    }
    Ok((value, off + len))
}

fn decode_unsigned32(data: &[u8], offset: usize) -> Result<(u32, usize)> {
    let tag = data[offset];
    let (len, off) = decode_length(data, offset + 1)?;
    if off + len > data.len() {
        return Err(NmapperError::Other(format!(
            "truncated value for tag 0x{:02X}",
            tag
        )));
    }
    let bytes = &data[off..off + len];
    let mut value: u32 = 0;
    for &b in bytes {
        value = (value << 8) | (b as u32);
    }
    Ok((value, off + len))
}

fn decode_octet_string_raw(data: &[u8], offset: usize) -> Result<(Vec<u8>, usize)> {
    if offset >= data.len() || data[offset] != TAG_OCTET_STRING {
        return Err(NmapperError::Other("expected OCTET STRING".into()));
    }
    let (len, off) = decode_length(data, offset + 1)?;
    if off + len > data.len() {
        return Err(NmapperError::Other("truncated OCTET STRING".into()));
    }
    Ok((data[off..off + len].to_vec(), off + len))
}

fn decode_value(data: &[u8], offset: usize) -> Result<(SnmpValue, usize)> {
    if offset >= data.len() {
        return Err(NmapperError::Other("truncated value".into()));
    }
    let tag = data[offset];
    match tag {
        TAG_INTEGER => {
            let (v, off) = decode_integer(data, offset)?;
            Ok((SnmpValue::Integer(v), off))
        }
        TAG_OCTET_STRING => {
            let (v, off) = decode_octet_string_raw(data, offset)?;
            Ok((SnmpValue::OctetString(v), off))
        }
        TAG_NULL => {
            let (len, off) = decode_length(data, offset + 1)?;
            Ok((SnmpValue::Null, off + len))
        }
        TAG_OID => {
            let (len, off) = decode_length(data, offset + 1)?;
            if off + len > data.len() {
                return Err(NmapperError::Other("truncated OID".into()));
            }
            let oid = decode_oid(&data[off..off + len])?;
            Ok((SnmpValue::ObjectIdentifier(oid), off + len))
        }
        TAG_IP_ADDRESS => {
            let (len, off) = decode_length(data, offset + 1)?;
            if len != 4 || off + 4 > data.len() {
                return Err(NmapperError::Other("invalid IpAddress".into()));
            }
            let addr = Ipv4Addr::new(data[off], data[off + 1], data[off + 2], data[off + 3]);
            Ok((SnmpValue::IpAddress(addr), off + 4))
        }
        TAG_COUNTER32 => {
            let (v, off) = decode_unsigned32(data, offset)?;
            Ok((SnmpValue::Counter32(v), off))
        }
        TAG_GAUGE32 => {
            let (v, off) = decode_unsigned32(data, offset)?;
            Ok((SnmpValue::Gauge32(v), off))
        }
        TAG_TIMETICKS => {
            let (v, off) = decode_unsigned32(data, offset)?;
            Ok((SnmpValue::TimeTicks(v), off))
        }
        // SNMPv2 exception types: noSuchObject (0x80), noSuchInstance (0x81), endOfMibView (0x82)
        0x80 | 0x81 | 0x82 => {
            let (len, off) = decode_length(data, offset + 1)?;
            Ok((SnmpValue::Null, off + len))
        }
        _ => {
            // Skip unknown types
            let (len, off) = decode_length(data, offset + 1)?;
            Ok((SnmpValue::OctetString(data[off..off + len].to_vec()), off + len))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_encode_decode_round_trip() {
        let oid = "1.3.6.1.2.1.1.1.0";
        let encoded = encode_oid(oid).unwrap();
        let decoded = decode_oid(&encoded).unwrap();
        assert_eq!(decoded, oid);
    }

    #[test]
    fn test_oid_encode_decode_large_subid() {
        // OID with a large sub-identifier (8802)
        let oid = "1.0.8802.1.1.2.1.4.1.1";
        let encoded = encode_oid(oid).unwrap();
        let decoded = decode_oid(&encoded).unwrap();
        assert_eq!(decoded, oid);
    }

    #[test]
    fn test_length_encoding_short() {
        assert_eq!(encode_length(0), vec![0x00]);
        assert_eq!(encode_length(42), vec![42]);
        assert_eq!(encode_length(127), vec![127]);
    }

    #[test]
    fn test_length_encoding_long() {
        assert_eq!(encode_length(128), vec![0x81, 128]);
        assert_eq!(encode_length(255), vec![0x81, 255]);
        assert_eq!(encode_length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(encode_length(1024), vec![0x82, 0x04, 0x00]);
    }

    #[test]
    fn test_length_decode_short() {
        let (len, off) = decode_length(&[42], 0).unwrap();
        assert_eq!(len, 42);
        assert_eq!(off, 1);
    }

    #[test]
    fn test_length_decode_long() {
        let (len, off) = decode_length(&[0x82, 0x01, 0x00], 0).unwrap();
        assert_eq!(len, 256);
        assert_eq!(off, 3);
    }

    #[test]
    fn test_get_request_encode_decode_round_trip() {
        let req_id = 12345;
        let community = "public";
        let oids = &["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"];

        let encoded = encode_get_request(req_id, community, oids).unwrap();

        // The encoded message is a valid SNMP message. We can partially decode it
        // by treating it as a response (the structure is compatible for parsing).
        // Modify the PDU tag from GetRequest (0xA0) to GetResponse (0xA2) to test decode.
        let mut modified = encoded.clone();
        // Find the PDU tag — it follows the SEQUENCE, version INTEGER, and community OCTET STRING.
        // We need to locate TAG_GET_REQUEST in the packet and replace it.
        if let Some(pos) = modified.iter().position(|&b| b == TAG_GET_REQUEST) {
            modified[pos] = TAG_GET_RESPONSE;
        }

        let response = decode_response(&modified).unwrap();
        assert_eq!(response.request_id, req_id);
        assert_eq!(response.error_status, 0);
        assert_eq!(response.error_index, 0);
        assert_eq!(response.varbinds.len(), 2);
        assert_eq!(response.varbinds[0].0, "1.3.6.1.2.1.1.1.0");
        assert_eq!(response.varbinds[0].1, SnmpValue::Null);
        assert_eq!(response.varbinds[1].0, "1.3.6.1.2.1.1.5.0");
        assert_eq!(response.varbinds[1].1, SnmpValue::Null);
    }

    #[test]
    fn test_get_next_request_encode() {
        let encoded =
            encode_get_next_request(1, "public", "1.3.6.1.2.1.2.2.1").unwrap();
        // Verify it starts with a SEQUENCE tag
        assert_eq!(encoded[0], TAG_SEQUENCE);
        // Verify it contains the GetNextRequest PDU tag somewhere
        assert!(encoded.contains(&TAG_GET_NEXT_REQUEST));
    }
}
