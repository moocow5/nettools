use crate::{NmapperError, Result};

use super::codec::{
    decode_length, decode_oid, encode_length, encode_oid, SnmpResponse, SnmpValue,
};

use des::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;

// BER/ASN.1 tag constants
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_GET_REQUEST: u8 = 0xA0;
const TAG_GET_NEXT_REQUEST: u8 = 0xA1;
const TAG_GET_RESPONSE: u8 = 0xA2;

const SNMP_V3: i32 = 3;
const USM_SECURITY_MODEL: i32 = 3;
const MSG_MAX_SIZE: i32 = 65507;

type HmacMd5 = Hmac<Md5>;
type HmacSha1 = Hmac<Sha1>;
type DesCbcEnc = cbc::Encryptor<des::Des>;
type DesCbcDec = cbc::Decryptor<des::Des>;

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SnmpV3Config {
    pub username: String,
    pub auth_protocol: AuthProtocol,
    pub auth_password: Option<String>,
    pub priv_protocol: PrivProtocol,
    pub priv_password: Option<String>,
    pub security_level: SecurityLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    None,
    Md5,
    Sha1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivProtocol {
    None,
    Des,
    Aes128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    NoAuthNoPriv,
    AuthNoPriv,
    AuthPriv,
}

impl SecurityLevel {
    /// Return the msgFlags byte for this security level.
    pub fn to_flags(self) -> u8 {
        match self {
            SecurityLevel::NoAuthNoPriv => 0x00,
            SecurityLevel::AuthNoPriv => 0x01,
            SecurityLevel::AuthPriv => 0x03,
        }
    }

    /// Return the msgFlags byte with the reportable bit set.
    pub fn to_flags_reportable(self) -> u8 {
        self.to_flags() | 0x04
    }
}

// ---------------------------------------------------------------------------
// Password-to-key (RFC 3414)
// ---------------------------------------------------------------------------

const PASSWORD_EXPANSION_LEN: usize = 1_048_576; // 1 MB

/// RFC 3414 password-to-key localization for MD5.
pub fn password_to_key_md5(password: &str, engine_id: &[u8]) -> [u8; 16] {
    use md5::Digest;
    let pwd = password.as_bytes();
    let pwd_len = pwd.len();

    // Step 1: Hash password repeated to fill 1MB
    let mut hasher = Md5::new();
    let mut count = 0usize;
    let mut i = 0usize;
    while count < PASSWORD_EXPANSION_LEN {
        hasher.update(&[pwd[i % pwd_len]]);
        i += 1;
        count += 1;
    }
    let key: [u8; 16] = hasher.finalize().into();

    // Step 2: Localize with engine_id
    let mut hasher = Md5::new();
    hasher.update(key);
    hasher.update(engine_id);
    hasher.update(key);
    hasher.finalize().into()
}

/// RFC 3414 password-to-key localization for SHA-1.
pub fn password_to_key_sha1(password: &str, engine_id: &[u8]) -> [u8; 20] {
    use sha1::Digest;
    let pwd = password.as_bytes();
    let pwd_len = pwd.len();

    let mut hasher = Sha1::new();
    let mut count = 0usize;
    let mut i = 0usize;
    while count < PASSWORD_EXPANSION_LEN {
        hasher.update(&[pwd[i % pwd_len]]);
        i += 1;
        count += 1;
    }
    let key: [u8; 20] = hasher.finalize().into();

    let mut hasher = Sha1::new();
    hasher.update(key);
    hasher.update(engine_id);
    hasher.update(key);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// HMAC functions
// ---------------------------------------------------------------------------

/// HMAC-MD5, truncated to 12 bytes (96 bits).
pub fn hmac_md5_96(key: &[u8], data: &[u8]) -> [u8; 12] {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 12];
    out.copy_from_slice(&result[..12]);
    out
}

/// HMAC-SHA-1, truncated to 12 bytes (96 bits).
pub fn hmac_sha1_96(key: &[u8], data: &[u8]) -> [u8; 12] {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 12];
    out.copy_from_slice(&result[..12]);
    out
}

// ---------------------------------------------------------------------------
// DES encryption / decryption (RFC 3414)
// ---------------------------------------------------------------------------

/// DES-CBC encryption per RFC 3414.
/// Returns (encrypted_data, priv_params/salt).
pub fn encrypt_des(
    key: &[u8],
    engine_boots: u32,
    salt_counter: u32,
    data: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let des_key = &key[..8];
    let pre_iv = &key[8..16];

    // Salt = engine_boots (4 bytes BE) + salt_counter (4 bytes BE)
    let mut salt = Vec::with_capacity(8);
    salt.extend_from_slice(&engine_boots.to_be_bytes());
    salt.extend_from_slice(&salt_counter.to_be_bytes());

    // IV = pre_iv XOR salt
    let mut iv = [0u8; 8];
    for i in 0..8 {
        iv[i] = pre_iv[i] ^ salt[i];
    }

    // Pad data to 8-byte boundary
    let mut padded = data.to_vec();
    let pad_len = (8 - (padded.len() % 8)) % 8;
    padded.extend(std::iter::repeat(0u8).take(pad_len));

    let encryptor = DesCbcEnc::new(des_key.into(), &iv.into());
    let encrypted = encryptor.encrypt_padded_vec_mut::<des::cipher::block_padding::NoPadding>(&padded);

    (encrypted, salt)
}

/// DES-CBC decryption per RFC 3414.
pub fn decrypt_des(key: &[u8], priv_params: &[u8], data: &[u8]) -> Vec<u8> {
    let des_key = &key[..8];
    let pre_iv = &key[8..16];

    // IV = pre_iv XOR priv_params (salt)
    let mut iv = [0u8; 8];
    for i in 0..8 {
        iv[i] = pre_iv[i] ^ priv_params[i];
    }

    let decryptor = DesCbcDec::new(des_key.into(), &iv.into());
    decryptor
        .decrypt_padded_vec_mut::<des::cipher::block_padding::NoPadding>(data)
        .unwrap_or_else(|_| data.to_vec())
}

// ---------------------------------------------------------------------------
// AES-128-CFB encryption / decryption (RFC 3826)
// ---------------------------------------------------------------------------

/// AES-128-CFB encryption per RFC 3826.
/// Returns (encrypted_data, priv_params/salt).
pub fn encrypt_aes128(
    key: &[u8],
    engine_boots: u32,
    engine_time: u32,
    salt_counter: u32,
    data: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    use cfb_mode::BufEncryptor;

    let aes_key = &key[..16];

    // Salt for AES = local integer (8 bytes, we use salt_counter extended)
    let mut salt = Vec::with_capacity(8);
    salt.extend_from_slice(&[0u8; 4]);
    salt.extend_from_slice(&salt_counter.to_be_bytes());

    // IV = engine_boots (4 BE) + engine_time (4 BE) + salt (8 bytes)
    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&engine_boots.to_be_bytes());
    iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
    iv[8..16].copy_from_slice(&salt);

    let mut encrypted = data.to_vec();
    let mut cipher = BufEncryptor::<aes::Aes128>::new(aes_key.into(), &iv.into());
    cipher.encrypt(&mut encrypted);

    (encrypted, salt)
}

/// AES-128-CFB decryption per RFC 3826.
pub fn decrypt_aes128(
    key: &[u8],
    engine_boots: u32,
    engine_time: u32,
    priv_params: &[u8],
    data: &[u8],
) -> Vec<u8> {
    use cfb_mode::BufDecryptor;

    let aes_key = &key[..16];

    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&engine_boots.to_be_bytes());
    iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
    let copy_len = priv_params.len().min(8);
    iv[8..8 + copy_len].copy_from_slice(&priv_params[..copy_len]);

    let mut decrypted = data.to_vec();
    let mut cipher = BufDecryptor::<aes::Aes128>::new(aes_key.into(), &iv.into());
    cipher.decrypt(&mut decrypted);

    decrypted
}

// ---------------------------------------------------------------------------
// BER encoding helpers (internal to v3)
// ---------------------------------------------------------------------------

fn encode_integer_v3(value: i32) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
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

fn encode_octet_string_v3(data: &[u8]) -> Vec<u8> {
    let mut out = vec![TAG_OCTET_STRING];
    out.extend(encode_length(data.len()));
    out.extend_from_slice(data);
    out
}

fn encode_sequence_v3(content: &[u8]) -> Vec<u8> {
    let mut out = vec![TAG_SEQUENCE];
    out.extend(encode_length(content.len()));
    out.extend_from_slice(content);
    out
}

// ---------------------------------------------------------------------------
// SNMPv3 message encoding
// ---------------------------------------------------------------------------

/// Encode a complete SNMPv3 message.
///
/// Returns the encoded message bytes. If authentication is enabled, the
/// auth_params placeholder (12 zero bytes) is replaced with the computed
/// HMAC digest.
pub fn encode_v3_message(
    msg_id: i32,
    security_level: SecurityLevel,
    engine_id: &[u8],
    engine_boots: u32,
    engine_time: u32,
    username: &str,
    auth_key: Option<&[u8]>,
    auth_protocol: AuthProtocol,
    priv_params: &[u8],
    scoped_pdu: &[u8],
) -> Result<Vec<u8>> {
    // --- msgGlobalData (HeaderData) ---
    let mut header_content = Vec::new();
    header_content.extend(encode_integer_v3(msg_id));
    header_content.extend(encode_integer_v3(MSG_MAX_SIZE));
    // msgFlags: single octet in an OCTET STRING
    let flags = security_level.to_flags_reportable();
    header_content.extend(encode_octet_string_v3(&[flags]));
    // msgSecurityModel: USM = 3
    header_content.extend(encode_integer_v3(USM_SECURITY_MODEL));
    let header_data = encode_sequence_v3(&header_content);

    // --- USM security parameters ---
    let mut usm_content = Vec::new();
    usm_content.extend(encode_octet_string_v3(engine_id));
    usm_content.extend(encode_integer_v3(engine_boots as i32));
    usm_content.extend(encode_integer_v3(engine_time as i32));
    usm_content.extend(encode_octet_string_v3(username.as_bytes()));
    // authParams placeholder: 12 zero bytes (or empty if no auth)
    let auth_placeholder = if security_level != SecurityLevel::NoAuthNoPriv {
        vec![0u8; 12]
    } else {
        vec![]
    };
    usm_content.extend(encode_octet_string_v3(&auth_placeholder));
    usm_content.extend(encode_octet_string_v3(priv_params));
    let usm_bytes = encode_sequence_v3(&usm_content);
    // USM is wrapped in an OCTET STRING in the message
    let usm_octet_string = encode_octet_string_v3(&usm_bytes);

    // --- Build complete message ---
    let mut msg_content = Vec::new();
    // msgVersion
    msg_content.extend(encode_integer_v3(SNMP_V3 - 1)); // version field is 0-indexed: v3 = 3, so value = 3
    // Actually SNMPv3 version field = 3 (not 0-indexed in practice for v3)
    // Let me correct: version = 3 for SNMPv3
    let mut msg_content = Vec::new();
    msg_content.extend(encode_integer_v3(SNMP_V3));
    msg_content.extend_from_slice(&header_data);
    msg_content.extend_from_slice(&usm_octet_string);
    msg_content.extend_from_slice(scoped_pdu);

    let mut message = encode_sequence_v3(&msg_content);

    // --- Compute and insert authentication digest ---
    if security_level != SecurityLevel::NoAuthNoPriv {
        if let Some(key) = auth_key {
            // Find the 12-byte auth placeholder in the message and compute HMAC
            let auth_digest = match auth_protocol {
                AuthProtocol::Md5 => hmac_md5_96(key, &message).to_vec(),
                AuthProtocol::Sha1 => hmac_sha1_96(key, &message).to_vec(),
                AuthProtocol::None => {
                    return Err(NmapperError::Other(
                        "auth protocol required for authenticated messages".into(),
                    ));
                }
            };

            // Find and replace the 12-byte zero placeholder
            if let Some(pos) = find_auth_placeholder(&message) {
                message[pos..pos + 12].copy_from_slice(&auth_digest);
            }
        }
    }

    Ok(message)
}

/// Find the position of the 12-byte auth params placeholder (12 zeros)
/// inside the USM security parameters within the message.
fn find_auth_placeholder(message: &[u8]) -> Option<usize> {
    // The auth params are encoded as OCTET STRING with 12 zero bytes:
    // 0x04 0x0C 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    let needle = [0x04, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    for i in 0..message.len().saturating_sub(needle.len()) {
        if message[i..i + needle.len()] == needle {
            return Some(i + 2); // skip tag + length, point to the 12-byte content
        }
    }
    None
}

/// Encode a ScopedPDU: SEQUENCE { contextEngineID, contextName, PDU }
pub fn encode_scoped_pdu(context_engine_id: &[u8], context_name: &str, pdu: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend(encode_octet_string_v3(context_engine_id));
    content.extend(encode_octet_string_v3(context_name.as_bytes()));
    content.extend_from_slice(pdu);
    encode_sequence_v3(&content)
}

/// Encode a GET PDU (for use inside a ScopedPDU).
pub fn encode_get_pdu(request_id: i32, oids: &[&str]) -> Result<Vec<u8>> {
    let mut pdu_content = Vec::new();
    pdu_content.extend(encode_integer_v3(request_id));
    pdu_content.extend(encode_integer_v3(0)); // error-status
    pdu_content.extend(encode_integer_v3(0)); // error-index
    pdu_content.extend(encode_varbind_list_v3(oids)?);
    let mut out = vec![TAG_GET_REQUEST];
    out.extend(encode_length(pdu_content.len()));
    out.extend(pdu_content);
    Ok(out)
}

/// Encode a GETNEXT PDU (for use inside a ScopedPDU).
pub fn encode_get_next_pdu(request_id: i32, oid: &str) -> Result<Vec<u8>> {
    let mut pdu_content = Vec::new();
    pdu_content.extend(encode_integer_v3(request_id));
    pdu_content.extend(encode_integer_v3(0));
    pdu_content.extend(encode_integer_v3(0));
    pdu_content.extend(encode_varbind_list_v3(&[oid])?);
    let mut out = vec![TAG_GET_NEXT_REQUEST];
    out.extend(encode_length(pdu_content.len()));
    out.extend(pdu_content);
    Ok(out)
}

fn encode_varbind_list_v3(oids: &[&str]) -> Result<Vec<u8>> {
    let mut varbinds = Vec::new();
    for oid in oids {
        let mut vb = Vec::new();
        let content = encode_oid(oid)?;
        vb.push(TAG_OID);
        vb.extend(encode_length(content.len()));
        vb.extend(content);
        vb.push(TAG_NULL);
        vb.push(0x00);
        varbinds.extend(encode_sequence_v3(&vb));
    }
    Ok(encode_sequence_v3(&varbinds))
}

// ---------------------------------------------------------------------------
// SNMPv3 response decoding
// ---------------------------------------------------------------------------

/// Decode an SNMPv3 response message.
/// Returns (SnmpResponse, engine_id, engine_boots, engine_time).
pub fn decode_v3_response(data: &[u8]) -> Result<(SnmpResponse, Vec<u8>, u32, u32)> {
    let mut offset = 0;

    // Outer SEQUENCE
    if offset >= data.len() || data[offset] != TAG_SEQUENCE {
        return Err(NmapperError::Other("expected SEQUENCE".into()));
    }
    offset += 1;
    let (_seq_len, new_off) = decode_length(data, offset)?;
    offset = new_off;

    // msgVersion (INTEGER)
    let (_version, new_off) = decode_integer_v3(data, offset)?;
    offset = new_off;

    // msgGlobalData (SEQUENCE)
    if offset >= data.len() || data[offset] != TAG_SEQUENCE {
        return Err(NmapperError::Other("expected header SEQUENCE".into()));
    }
    offset += 1;
    let (header_len, new_off) = decode_length(data, offset)?;
    offset = new_off;
    // Skip the header data (msgID, msgMaxSize, msgFlags, msgSecurityModel)
    offset += header_len;

    // msgSecurityParameters (OCTET STRING wrapping a SEQUENCE)
    if offset >= data.len() || data[offset] != TAG_OCTET_STRING {
        return Err(NmapperError::Other("expected USM OCTET STRING".into()));
    }
    offset += 1;
    let (usm_os_len, new_off) = decode_length(data, offset)?;
    offset = new_off;
    let _usm_start = offset;
    let usm_end = offset + usm_os_len;

    // Parse USM SEQUENCE inside the OCTET STRING
    if offset >= data.len() || data[offset] != TAG_SEQUENCE {
        return Err(NmapperError::Other("expected USM SEQUENCE".into()));
    }
    offset += 1;
    let (_usm_seq_len, new_off) = decode_length(data, offset)?;
    offset = new_off;

    // msgAuthoritativeEngineID (OCTET STRING)
    let (engine_id, new_off) = decode_octet_string_v3(data, offset)?;
    offset = new_off;

    // msgAuthoritativeEngineBoots (INTEGER)
    let (engine_boots, new_off) = decode_integer_v3(data, offset)?;
    offset = new_off;

    // msgAuthoritativeEngineTime (INTEGER)
    let (engine_time, new_off) = decode_integer_v3(data, offset)?;
    offset = new_off;

    // msgUserName (OCTET STRING) - skip
    let (_username, new_off) = decode_octet_string_v3(data, offset)?;
    offset = new_off;

    // msgAuthenticationParameters (OCTET STRING) - skip
    let (_auth_params, new_off) = decode_octet_string_v3(data, offset)?;
    offset = new_off;

    // msgPrivacyParameters (OCTET STRING) - skip
    let (_priv_params, _new_off) = decode_octet_string_v3(data, offset)?;

    // Skip to end of USM OCTET STRING
    offset = usm_end;

    // ScopedPDU (SEQUENCE) — may be encrypted (OCTET STRING) but we handle plaintext here
    let scoped_pdu_response = if offset < data.len() && data[offset] == TAG_SEQUENCE {
        // Plaintext ScopedPDU
        offset += 1;
        let (_scoped_len, new_off) = decode_length(data, offset)?;
        offset = new_off;

        // contextEngineID (OCTET STRING) - skip
        let (_ctx_engine_id, new_off) = decode_octet_string_v3(data, offset)?;
        offset = new_off;

        // contextName (OCTET STRING) - skip
        let (_ctx_name, new_off) = decode_octet_string_v3(data, offset)?;
        offset = new_off;

        // PDU
        decode_pdu_v3(data, offset)?
    } else if offset < data.len() && data[offset] == TAG_OCTET_STRING {
        // Encrypted ScopedPDU — return a placeholder; the client must decrypt first
        return Err(NmapperError::Other(
            "encrypted ScopedPDU: decrypt before decoding".into(),
        ));
    } else {
        return Err(NmapperError::Other("expected ScopedPDU".into()));
    };

    Ok((
        scoped_pdu_response,
        engine_id,
        engine_boots as u32,
        engine_time as u32,
    ))
}

/// Decode a v3 response that may have an encrypted ScopedPDU.
/// The caller provides the decrypted scoped_pdu bytes separately.
pub fn decode_v3_response_with_decrypted_pdu(
    data: &[u8],
    decrypted_scoped_pdu: &[u8],
) -> Result<(SnmpResponse, Vec<u8>, u32, u32)> {
    // Parse header to get engine info
    let mut offset = 0;

    if offset >= data.len() || data[offset] != TAG_SEQUENCE {
        return Err(NmapperError::Other("expected SEQUENCE".into()));
    }
    offset += 1;
    let (_seq_len, new_off) = decode_length(data, offset)?;
    offset = new_off;

    let (_version, new_off) = decode_integer_v3(data, offset)?;
    offset = new_off;

    // Skip header SEQUENCE
    if data[offset] != TAG_SEQUENCE {
        return Err(NmapperError::Other("expected header SEQUENCE".into()));
    }
    offset += 1;
    let (header_len, new_off) = decode_length(data, offset)?;
    offset = new_off + header_len;

    // Parse USM
    if data[offset] != TAG_OCTET_STRING {
        return Err(NmapperError::Other("expected USM OCTET STRING".into()));
    }
    offset += 1;
    let (_usm_os_len, new_off) = decode_length(data, offset)?;
    offset = new_off;

    if data[offset] != TAG_SEQUENCE {
        return Err(NmapperError::Other("expected USM SEQUENCE".into()));
    }
    offset += 1;
    let (_usm_seq_len, new_off) = decode_length(data, offset)?;
    offset = new_off;

    let (engine_id, new_off) = decode_octet_string_v3(data, offset)?;
    offset = new_off;
    let (engine_boots, new_off) = decode_integer_v3(data, offset)?;
    offset = new_off;
    let (engine_time, _new_off) = decode_integer_v3(data, offset)?;

    // Parse the decrypted ScopedPDU
    let mut pdu_offset = 0;
    if pdu_offset >= decrypted_scoped_pdu.len() || decrypted_scoped_pdu[pdu_offset] != TAG_SEQUENCE
    {
        return Err(NmapperError::Other(
            "expected SEQUENCE in decrypted ScopedPDU".into(),
        ));
    }
    pdu_offset += 1;
    let (_scoped_len, new_off) = decode_length(decrypted_scoped_pdu, pdu_offset)?;
    pdu_offset = new_off;

    let (_ctx_engine_id, new_off) = decode_octet_string_v3(decrypted_scoped_pdu, pdu_offset)?;
    pdu_offset = new_off;
    let (_ctx_name, new_off) = decode_octet_string_v3(decrypted_scoped_pdu, pdu_offset)?;
    pdu_offset = new_off;

    let response = decode_pdu_v3(decrypted_scoped_pdu, pdu_offset)?;

    Ok((
        response,
        engine_id,
        engine_boots as u32,
        engine_time as u32,
    ))
}

/// Extract the encrypted ScopedPDU bytes and priv_params from a v3 response.
pub fn extract_encrypted_scoped_pdu(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut offset = 0;

    if offset >= data.len() || data[offset] != TAG_SEQUENCE {
        return Err(NmapperError::Other("expected SEQUENCE".into()));
    }
    offset += 1;
    let (_seq_len, new_off) = decode_length(data, offset)?;
    offset = new_off;

    // Skip version
    let (_version, new_off) = decode_integer_v3(data, offset)?;
    offset = new_off;

    // Skip header
    if data[offset] != TAG_SEQUENCE {
        return Err(NmapperError::Other("expected header SEQUENCE".into()));
    }
    offset += 1;
    let (header_len, new_off) = decode_length(data, offset)?;
    offset = new_off + header_len;

    // Parse USM to get priv_params
    if data[offset] != TAG_OCTET_STRING {
        return Err(NmapperError::Other("expected USM OCTET STRING".into()));
    }
    offset += 1;
    let (usm_os_len, new_off) = decode_length(data, offset)?;
    offset = new_off;
    let usm_end = offset + usm_os_len;

    if data[offset] != TAG_SEQUENCE {
        return Err(NmapperError::Other("expected USM SEQUENCE".into()));
    }
    offset += 1;
    let (_usm_seq_len, new_off) = decode_length(data, offset)?;
    offset = new_off;

    // Skip engine_id, boots, time, username, auth_params
    let (_engine_id, new_off) = decode_octet_string_v3(data, offset)?;
    offset = new_off;
    let (_boots, new_off) = decode_integer_v3(data, offset)?;
    offset = new_off;
    let (_time, new_off) = decode_integer_v3(data, offset)?;
    offset = new_off;
    let (_username, new_off) = decode_octet_string_v3(data, offset)?;
    offset = new_off;
    let (_auth_params, new_off) = decode_octet_string_v3(data, offset)?;
    offset = new_off;
    let (priv_params, _new_off) = decode_octet_string_v3(data, offset)?;

    offset = usm_end;

    // Encrypted ScopedPDU is an OCTET STRING
    if offset >= data.len() || data[offset] != TAG_OCTET_STRING {
        return Err(NmapperError::Other(
            "expected encrypted ScopedPDU OCTET STRING".into(),
        ));
    }
    offset += 1;
    let (enc_len, new_off) = decode_length(data, offset)?;
    offset = new_off;
    let encrypted = data[offset..offset + enc_len].to_vec();

    Ok((encrypted, priv_params))
}

// ---------------------------------------------------------------------------
// Internal v3 decode helpers
// ---------------------------------------------------------------------------

fn decode_integer_v3(data: &[u8], offset: usize) -> Result<(i64, usize)> {
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

fn decode_octet_string_v3(data: &[u8], offset: usize) -> Result<(Vec<u8>, usize)> {
    if offset >= data.len() || data[offset] != TAG_OCTET_STRING {
        return Err(NmapperError::Other("expected OCTET STRING".into()));
    }
    let (len, off) = decode_length(data, offset + 1)?;
    if off + len > data.len() {
        return Err(NmapperError::Other("truncated OCTET STRING".into()));
    }
    Ok((data[off..off + len].to_vec(), off + len))
}

fn decode_unsigned32_v3(data: &[u8], offset: usize) -> Result<(u32, usize)> {
    let (len, off) = decode_length(data, offset + 1)?;
    if off + len > data.len() {
        return Err(NmapperError::Other("truncated value".into()));
    }
    let bytes = &data[off..off + len];
    let mut value: u32 = 0;
    for &b in bytes {
        value = (value << 8) | (b as u32);
    }
    Ok((value, off + len))
}

fn decode_pdu_v3(data: &[u8], offset: usize) -> Result<SnmpResponse> {
    if offset >= data.len() {
        return Err(NmapperError::Other("truncated PDU".into()));
    }
    let pdu_tag = data[offset];
    if pdu_tag != TAG_GET_RESPONSE && pdu_tag != TAG_GET_REQUEST && pdu_tag != TAG_GET_NEXT_REQUEST
    {
        // Report PDU (0xA8) is also acceptable during engine discovery
        if pdu_tag != 0xA8 {
            return Err(NmapperError::Other(format!(
                "unexpected PDU tag: 0x{:02X}",
                pdu_tag
            )));
        }
    }
    let mut offset = offset + 1;
    let (_pdu_len, new_off) = decode_length(data, offset)?;
    offset = new_off;

    let (request_id, new_off) = decode_integer_v3(data, offset)?;
    offset = new_off;
    let (error_status, new_off) = decode_integer_v3(data, offset)?;
    offset = new_off;
    let (error_index, new_off) = decode_integer_v3(data, offset)?;
    offset = new_off;

    // VarBindList
    if offset >= data.len() || data[offset] != TAG_SEQUENCE {
        return Err(NmapperError::Other("expected VarBindList SEQUENCE".into()));
    }
    offset += 1;
    let (vbl_len, new_off) = decode_length(data, offset)?;
    offset = new_off;
    let vbl_end = offset + vbl_len;

    let mut varbinds = Vec::new();
    while offset < vbl_end && offset < data.len() {
        if data[offset] != TAG_SEQUENCE {
            return Err(NmapperError::Other("expected VarBind SEQUENCE".into()));
        }
        offset += 1;
        let (_vb_len, new_off) = decode_length(data, offset)?;
        offset = new_off;

        if offset >= data.len() || data[offset] != TAG_OID {
            return Err(NmapperError::Other("expected OID in VarBind".into()));
        }
        offset += 1;
        let (oid_len, new_off) = decode_length(data, offset)?;
        offset = new_off;
        let oid = decode_oid(&data[offset..offset + oid_len])?;
        offset += oid_len;

        let (value, new_off) = decode_value_v3(data, offset)?;
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

fn decode_value_v3(data: &[u8], offset: usize) -> Result<(SnmpValue, usize)> {
    if offset >= data.len() {
        return Err(NmapperError::Other("truncated value".into()));
    }
    let tag = data[offset];
    match tag {
        TAG_INTEGER => {
            let (v, off) = decode_integer_v3(data, offset)?;
            Ok((SnmpValue::Integer(v), off))
        }
        TAG_OCTET_STRING => {
            let (v, off) = decode_octet_string_v3(data, offset)?;
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
        0x40 => {
            // IpAddress
            let (len, off) = decode_length(data, offset + 1)?;
            if len != 4 || off + 4 > data.len() {
                return Err(NmapperError::Other("invalid IpAddress".into()));
            }
            let addr = std::net::Ipv4Addr::new(data[off], data[off + 1], data[off + 2], data[off + 3]);
            Ok((SnmpValue::IpAddress(addr), off + 4))
        }
        0x41 => {
            let (v, off) = decode_unsigned32_v3(data, offset)?;
            Ok((SnmpValue::Counter32(v), off))
        }
        0x42 => {
            let (v, off) = decode_unsigned32_v3(data, offset)?;
            Ok((SnmpValue::Gauge32(v), off))
        }
        0x43 => {
            let (v, off) = decode_unsigned32_v3(data, offset)?;
            Ok((SnmpValue::TimeTicks(v), off))
        }
        0x80 | 0x81 | 0x82 => {
            let (len, off) = decode_length(data, offset + 1)?;
            Ok((SnmpValue::Null, off + len))
        }
        _ => {
            let (len, off) = decode_length(data, offset + 1)?;
            Ok((
                SnmpValue::OctetString(data[off..off + len].to_vec()),
                off + len,
            ))
        }
    }
}

/// Encode a discovery message to learn the remote engine's ID, boots, and time.
pub fn encode_discovery_message(msg_id: i32) -> Result<Vec<u8>> {
    // Empty USM with reportable flag
    let mut header_content = Vec::new();
    header_content.extend(encode_integer_v3(msg_id));
    header_content.extend(encode_integer_v3(MSG_MAX_SIZE));
    // msgFlags: reportable (0x04), noAuthNoPriv (0x00) = 0x04
    header_content.extend(encode_octet_string_v3(&[0x04]));
    header_content.extend(encode_integer_v3(USM_SECURITY_MODEL));
    let header_data = encode_sequence_v3(&header_content);

    // Empty USM
    let mut usm_content = Vec::new();
    usm_content.extend(encode_octet_string_v3(&[])); // engine ID
    usm_content.extend(encode_integer_v3(0)); // boots
    usm_content.extend(encode_integer_v3(0)); // time
    usm_content.extend(encode_octet_string_v3(&[])); // username
    usm_content.extend(encode_octet_string_v3(&[])); // auth params
    usm_content.extend(encode_octet_string_v3(&[])); // priv params
    let usm_bytes = encode_sequence_v3(&usm_content);
    let usm_octet_string = encode_octet_string_v3(&usm_bytes);

    // Empty ScopedPDU
    let empty_pdu = encode_get_pdu(0, &[])?;
    let scoped_pdu = encode_scoped_pdu(&[], "", &empty_pdu);

    let mut msg_content = Vec::new();
    msg_content.extend(encode_integer_v3(SNMP_V3));
    msg_content.extend_from_slice(&header_data);
    msg_content.extend_from_slice(&usm_octet_string);
    msg_content.extend_from_slice(&scoped_pdu);

    Ok(encode_sequence_v3(&msg_content))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_to_key_md5() {
        // RFC 3414 A.3.1 test vector
        let engine_id: [u8; 12] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
        let key = password_to_key_md5("maplesyrup", &engine_id);
        let expected: [u8; 16] = [
            0x52, 0x6f, 0x5e, 0xed, 0x9f, 0xcc, 0xe2, 0x6f,
            0x89, 0x64, 0xc2, 0x93, 0x07, 0x87, 0xd8, 0x2b,
        ];
        assert_eq!(key, expected);
    }

    #[test]
    fn test_password_to_key_sha1() {
        // RFC 3414 A.3.2 test vector
        let engine_id: [u8; 12] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
        let key = password_to_key_sha1("maplesyrup", &engine_id);
        let expected: [u8; 20] = [
            0x66, 0x95, 0xfe, 0xbc, 0x92, 0x88, 0xe3, 0x62,
            0x82, 0x23, 0x5f, 0xc7, 0x15, 0x1f, 0x12, 0x84,
            0x97, 0xb3, 0x8f, 0x3f,
        ];
        assert_eq!(key, expected);
    }

    #[test]
    fn test_hmac_md5_96_length() {
        let key = [0u8; 16];
        let data = b"test data";
        let result = hmac_md5_96(&key, data);
        assert_eq!(result.len(), 12);
    }

    #[test]
    fn test_hmac_sha1_96_length() {
        let key = [0u8; 20];
        let data = b"test data";
        let result = hmac_sha1_96(&key, data);
        assert_eq!(result.len(), 12);
    }

    #[test]
    fn test_des_encrypt_decrypt_roundtrip() {
        // 16-byte key: 8 for DES key + 8 for pre-IV
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let engine_boots = 1u32;
        let salt_counter = 42u32;
        let plaintext = b"Hello SNMP v3 DES encryption test!";

        let (encrypted, salt) = encrypt_des(&key, engine_boots, salt_counter, plaintext);
        let decrypted = decrypt_des(&key, &salt, &encrypted);

        // Decrypted may have padding zeros, so compare only original length
        assert_eq!(&decrypted[..plaintext.len()], &plaintext[..]);
    }

    #[test]
    fn test_security_level_flags() {
        assert_eq!(SecurityLevel::NoAuthNoPriv.to_flags(), 0x00);
        assert_eq!(SecurityLevel::AuthNoPriv.to_flags(), 0x01);
        assert_eq!(SecurityLevel::AuthPriv.to_flags(), 0x03);

        // Reportable variants
        assert_eq!(SecurityLevel::NoAuthNoPriv.to_flags_reportable(), 0x04);
        assert_eq!(SecurityLevel::AuthNoPriv.to_flags_reportable(), 0x05);
        assert_eq!(SecurityLevel::AuthPriv.to_flags_reportable(), 0x07);
    }

    #[test]
    fn test_aes128_encrypt_decrypt_roundtrip() {
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let engine_boots = 5u32;
        let engine_time = 1000u32;
        let salt_counter = 99u32;
        let plaintext = b"AES-128-CFB test for SNMPv3";

        let (encrypted, salt) =
            encrypt_aes128(&key, engine_boots, engine_time, salt_counter, plaintext);
        let decrypted =
            decrypt_aes128(&key, engine_boots, engine_time, &salt, &encrypted);

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_discovery_message_encodes() {
        let msg = encode_discovery_message(1).unwrap();
        // Should start with a SEQUENCE tag
        assert_eq!(msg[0], TAG_SEQUENCE);
        // Should be non-empty
        assert!(msg.len() > 10);
    }
}
