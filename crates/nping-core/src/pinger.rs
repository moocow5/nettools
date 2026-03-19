//! Unified pinger that dispatches to the appropriate protocol handler.

use std::net::IpAddr;

use tokio::sync::mpsc;

use crate::config::{PingConfig, PingMode};
use crate::error::{NpingError, Result};
use crate::icmp::IcmpPinger;
use crate::result::PingResult;
use crate::socket::PingSocket;
use crate::tcp;
use crate::udp;

/// Resolve a target hostname to an IP address.
async fn resolve_target(target: &str) -> Result<IpAddr> {
    // Try parsing as a bare IP first.
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    let lookup = format!("{target}:0");
    let addr = tokio::net::lookup_host(&lookup)
        .await
        .map_err(|e| NpingError::DnsResolution {
            hostname: target.to_string(),
            source: e,
        })?
        .next()
        .ok_or_else(|| NpingError::DnsResolution {
            hostname: target.to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no addresses returned",
            ),
        })?;

    Ok(addr.ip())
}

/// Run a ping session using the appropriate protocol based on config.mode.
///
/// Returns the identifier (for ICMP) or 0 (for TCP/UDP).
pub async fn run<S: PingSocket>(
    config: &PingConfig,
    socket: &S,
    tx: mpsc::Sender<PingResult>,
) -> Result<u16> {
    let target_ip = resolve_target(&config.target).await?;

    match config.mode {
        PingMode::Icmp => {
            let pinger = IcmpPinger::new(config.clone());
            let id = pinger.identifier();
            pinger.run(socket, tx).await?;
            Ok(id)
        }
        PingMode::TcpConnect => {
            tcp::run_tcp_connect(config, target_ip, tx).await?;
            Ok(0)
        }
        PingMode::Tcp => {
            tcp::run_tcp_syn(config, target_ip, tx).await?;
            Ok(0)
        }
        PingMode::Udp => {
            udp::run_udp_ping(config, target_ip, tx).await?;
            Ok(0)
        }
    }
}
