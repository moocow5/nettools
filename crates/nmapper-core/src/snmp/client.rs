use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::{NmapperError, Result};

use super::codec::{
    decode_response, encode_get_next_request, encode_get_request, SnmpValue,
};

static REQUEST_ID_COUNTER: AtomicI32 = AtomicI32::new(1);

fn next_request_id() -> i32 {
    REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Async SNMPv2c client using UDP.
pub struct SnmpClient {
    target: SocketAddr,
    community: String,
    timeout: Duration,
}

impl SnmpClient {
    pub fn new(target: SocketAddr, community: &str, timeout: Duration) -> Self {
        Self {
            target,
            community: community.to_string(),
            timeout,
        }
    }

    /// Send a raw SNMP packet and receive the response.
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
            .map_err(|_| NmapperError::Other(format!("SNMP timeout from {}", self.target)))?
            .map_err(|e| NmapperError::Other(format!("SNMP recv error: {}", e)))?;

        buf.truncate(n);
        Ok(buf)
    }

    /// Perform an SNMP GET request for one or more OIDs.
    pub async fn get(&self, oids: &[&str]) -> Result<Vec<(String, SnmpValue)>> {
        let req_id = next_request_id();
        let packet = encode_get_request(req_id, &self.community, oids)?;
        let response_data = self.send_recv(&packet).await?;
        let response = decode_response(&response_data)?;

        if response.error_status != 0 {
            return Err(NmapperError::Other(format!(
                "SNMP error: status={}, index={}",
                response.error_status, response.error_index
            )));
        }

        Ok(response.varbinds)
    }

    /// Perform an SNMP walk starting from `root_oid`.
    ///
    /// Uses GetNext requests iteratively until the returned OID is no longer
    /// a child of `root_oid`.
    pub async fn walk(&self, root_oid: &str) -> Result<Vec<(String, SnmpValue)>> {
        let mut results = Vec::new();
        let mut current_oid = root_oid.to_string();
        let root_prefix = format!("{}.", root_oid);

        loop {
            let req_id = next_request_id();
            let packet = encode_get_next_request(req_id, &self.community, &current_oid)?;
            let response_data = self.send_recv(&packet).await?;
            let response = decode_response(&response_data)?;

            if response.error_status != 0 {
                // End of MIB or error — stop walking
                break;
            }

            if response.varbinds.is_empty() {
                break;
            }

            let (ref oid, ref value) = response.varbinds[0];

            // Check if the returned OID is still under our root
            if !oid.starts_with(&root_prefix) && *oid != root_oid {
                break;
            }

            // endOfMibView is represented as Null in our decoder
            if matches!(value, SnmpValue::Null) && oid == &current_oid {
                break;
            }

            current_oid = oid.clone();
            results.push((oid.clone(), value.clone()));
        }

        Ok(results)
    }
}
