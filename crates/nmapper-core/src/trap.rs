use std::net::SocketAddr;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::snmp::codec::{decode_response, SnmpValue};

/// OID for snmpTrapOID.0 — the standard varbind that carries the trap identity.
const SNMP_TRAP_OID: &str = "1.3.6.1.6.3.1.1.4.1.0";

/// An SNMP trap event received by the listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrapEvent {
    /// Source address of the trap sender.
    pub source: SocketAddr,
    /// The trap OID (extracted from the snmpTrapOID.0 varbind, if present).
    pub trap_oid: Option<String>,
    /// All varbinds as (OID, value-as-string) pairs.
    pub varbinds: Vec<(String, String)>,
    /// When the trap was received.
    pub received_at: chrono::DateTime<chrono::Utc>,
}

/// Listen for SNMPv2c trap notifications on `bind_addr` and broadcast each
/// decoded trap as a `TrapEvent`.
///
/// Typical bind address: `0.0.0.0:162` (requires root/admin on most systems).
/// Malformed packets are logged as warnings and skipped.
pub async fn listen_traps(
    bind_addr: SocketAddr,
    tx: broadcast::Sender<TrapEvent>,
) -> crate::Result<()> {
    let socket = UdpSocket::bind(bind_addr).await?;
    info!("SNMP trap listener started on {}", bind_addr);

    let mut buf = [0u8; 65535];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!("recv_from error: {}", e);
                continue;
            }
        };

        let data = &buf[..len];

        let response = match decode_response(data) {
            Ok(r) => r,
            Err(e) => {
                warn!("failed to decode SNMP message from {}: {}", src, e);
                continue;
            }
        };

        let mut trap_oid: Option<String> = None;
        let mut varbinds: Vec<(String, String)> = Vec::new();

        for (oid, value) in &response.varbinds {
            let value_str = match value {
                SnmpValue::ObjectIdentifier(s) => s.clone(),
                other => other.to_string(),
            };

            if oid == SNMP_TRAP_OID {
                trap_oid = Some(value_str.clone());
            }

            varbinds.push((oid.clone(), value_str));
        }

        let event = TrapEvent {
            source: src,
            trap_oid,
            varbinds,
            received_at: Utc::now(),
        };

        info!("trap received from {}", src);

        // Ignore send errors (no active subscribers).
        let _ = tx.send(event);
    }
}
