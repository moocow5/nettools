use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::{NmapperError, Result};

use super::codec::SnmpValue;
use super::v3::{
    decode_v3_response, decode_v3_response_with_decrypted_pdu, decrypt_aes128, decrypt_des,
    encode_discovery_message, encode_get_next_pdu, encode_get_pdu, encode_scoped_pdu,
    encode_v3_message, encrypt_aes128, encrypt_des, extract_encrypted_scoped_pdu,
    password_to_key_md5, password_to_key_sha1, AuthProtocol, PrivProtocol, SecurityLevel,
    SnmpV3Config,
};

static MSG_ID_COUNTER: AtomicI32 = AtomicI32::new(1);
static SALT_COUNTER: AtomicU32 = AtomicU32::new(1);

fn next_msg_id() -> i32 {
    MSG_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn next_salt() -> u32 {
    SALT_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Async SNMPv3 client with USM (User-based Security Model).
pub struct SnmpV3Client {
    target: SocketAddr,
    config: SnmpV3Config,
    timeout: Duration,
    engine_id: Vec<u8>,
    engine_boots: u32,
    engine_time: u32,
    auth_key: Option<Vec<u8>>,
    priv_key: Option<Vec<u8>>,
}

impl SnmpV3Client {
    /// Create a new SNMPv3 client.
    ///
    /// Performs engine discovery (sends an empty v3 message to learn the
    /// remote engine's ID, boots, and time), then derives authentication
    /// and privacy keys from the configured passwords.
    pub async fn new(
        target: SocketAddr,
        config: SnmpV3Config,
        timeout: Duration,
    ) -> Result<Self> {
        let mut client = Self {
            target,
            config,
            timeout,
            engine_id: Vec::new(),
            engine_boots: 0,
            engine_time: 0,
            auth_key: None,
            priv_key: None,
        };

        // Engine discovery
        let discovery_msg = encode_discovery_message(next_msg_id())?;
        let response_data = client.send_recv(&discovery_msg).await?;

        let (_response, engine_id, boots, time) = decode_v3_response(&response_data)?;
        client.engine_id = engine_id;
        client.engine_boots = boots;
        client.engine_time = time;

        // Derive keys
        if let Some(ref auth_password) = client.config.auth_password {
            let auth_key = match client.config.auth_protocol {
                AuthProtocol::Md5 => {
                    password_to_key_md5(auth_password, &client.engine_id).to_vec()
                }
                AuthProtocol::Sha1 => {
                    password_to_key_sha1(auth_password, &client.engine_id).to_vec()
                }
                AuthProtocol::None => Vec::new(),
            };
            if !auth_key.is_empty() {
                client.auth_key = Some(auth_key);
            }
        }

        if let Some(ref priv_password) = client.config.priv_password {
            let priv_key = match client.config.auth_protocol {
                AuthProtocol::Md5 => {
                    password_to_key_md5(priv_password, &client.engine_id).to_vec()
                }
                AuthProtocol::Sha1 => {
                    password_to_key_sha1(priv_password, &client.engine_id).to_vec()
                }
                AuthProtocol::None => Vec::new(),
            };
            if !priv_key.is_empty() {
                client.priv_key = Some(priv_key);
            }
        }

        Ok(client)
    }

    /// Send a raw packet and receive the response.
    async fn send_recv(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let bind_addr: SocketAddr = if self.target.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(bind_addr).await?;
        socket.send_to(packet, self.target).await?;

        let mut buf = vec![0u8; 65535];
        let n = tokio::time::timeout(self.timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| {
                NmapperError::Other(format!("SNMPv3 timeout from {}", self.target))
            })?
            .map_err(|e| NmapperError::Other(format!("SNMPv3 recv error: {}", e)))?;

        buf.truncate(n);
        Ok(buf)
    }

    /// Build and send an SNMPv3 request, returning the decoded varbinds.
    async fn request(&self, pdu: &[u8]) -> Result<Vec<(String, SnmpValue)>> {
        let msg_id = next_msg_id();

        let scoped_pdu_plain = encode_scoped_pdu(&self.engine_id, "", pdu);

        // Encrypt ScopedPDU if privacy is enabled
        let (scoped_pdu_for_msg, priv_params) =
            if self.config.security_level == SecurityLevel::AuthPriv {
                if let Some(ref priv_key) = self.priv_key {
                    let salt = next_salt();
                    match self.config.priv_protocol {
                        PrivProtocol::Des => {
                            let (encrypted, priv_params) =
                                encrypt_des(priv_key, self.engine_boots, salt, &scoped_pdu_plain);
                            // Wrap encrypted data as OCTET STRING
                            let mut enc_os = vec![0x04u8];
                            enc_os.extend(super::codec::encode_length(encrypted.len()));
                            enc_os.extend(encrypted);
                            (enc_os, priv_params)
                        }
                        PrivProtocol::Aes128 => {
                            let (encrypted, priv_params) = encrypt_aes128(
                                priv_key,
                                self.engine_boots,
                                self.engine_time,
                                salt,
                                &scoped_pdu_plain,
                            );
                            let mut enc_os = vec![0x04u8];
                            enc_os.extend(super::codec::encode_length(encrypted.len()));
                            enc_os.extend(encrypted);
                            (enc_os, priv_params)
                        }
                        PrivProtocol::None => (scoped_pdu_plain.clone(), vec![]),
                    }
                } else {
                    (scoped_pdu_plain.clone(), vec![])
                }
            } else {
                (scoped_pdu_plain.clone(), vec![])
            };

        let packet = encode_v3_message(
            msg_id,
            self.config.security_level,
            &self.engine_id,
            self.engine_boots,
            self.engine_time,
            &self.config.username,
            self.auth_key.as_deref(),
            self.config.auth_protocol,
            &priv_params,
            &scoped_pdu_for_msg,
        )?;

        let response_data = self.send_recv(&packet).await?;

        // Decode response
        let response = if self.config.security_level == SecurityLevel::AuthPriv {
            // Need to decrypt the ScopedPDU in the response
            if let Some(ref priv_key) = self.priv_key {
                let (encrypted, resp_priv_params) =
                    extract_encrypted_scoped_pdu(&response_data)?;

                let decrypted = match self.config.priv_protocol {
                    PrivProtocol::Des => decrypt_des(priv_key, &resp_priv_params, &encrypted),
                    PrivProtocol::Aes128 => {
                        // Extract engine_boots and engine_time from the response for AES IV
                        // For simplicity, use the stored values (they should match)
                        decrypt_aes128(
                            priv_key,
                            self.engine_boots,
                            self.engine_time,
                            &resp_priv_params,
                            &encrypted,
                        )
                    }
                    PrivProtocol::None => encrypted,
                };

                let (resp, _eid, _boots, _time) =
                    decode_v3_response_with_decrypted_pdu(&response_data, &decrypted)?;
                resp
            } else {
                let (resp, _eid, _boots, _time) = decode_v3_response(&response_data)?;
                resp
            }
        } else {
            let (resp, _eid, _boots, _time) = decode_v3_response(&response_data)?;
            resp
        };

        if response.error_status != 0 {
            return Err(NmapperError::Other(format!(
                "SNMPv3 error: status={}, index={}",
                response.error_status, response.error_index
            )));
        }

        Ok(response.varbinds)
    }

    /// Perform an SNMPv3 GET request for one or more OIDs.
    pub async fn get(&self, oids: &[&str]) -> Result<Vec<(String, SnmpValue)>> {
        let pdu = encode_get_pdu(next_msg_id(), oids)?;
        self.request(&pdu).await
    }

    /// Perform an SNMPv3 walk starting from `root_oid`.
    pub async fn walk(&self, root_oid: &str) -> Result<Vec<(String, SnmpValue)>> {
        let mut results = Vec::new();
        let mut current_oid = root_oid.to_string();
        let root_prefix = format!("{}.", root_oid);

        loop {
            let pdu = encode_get_next_pdu(next_msg_id(), &current_oid)?;
            let varbinds = self.request(&pdu).await?;

            if varbinds.is_empty() {
                break;
            }

            let (ref oid, ref value) = varbinds[0];

            if !oid.starts_with(&root_prefix) && *oid != root_oid {
                break;
            }

            if matches!(value, SnmpValue::Null) && oid == &current_oid {
                break;
            }

            current_oid = oid.clone();
            results.push((oid.clone(), value.clone()));
        }

        Ok(results)
    }
}
