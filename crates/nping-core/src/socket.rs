use crate::error::Result;
use std::net::IpAddr;
use std::time::Duration;

/// Result of receiving a ping reply.
#[derive(Debug, Clone)]
pub struct RecvResult {
    /// Number of bytes in the ICMP payload received.
    pub bytes_received: usize,
    /// IP address of the host that sent the reply.
    pub source: IpAddr,
    /// Time-to-live from the reply, if available.
    pub ttl: Option<u8>,
    /// Raw ICMP data with the IP header already stripped.
    pub icmp_data: Vec<u8>,
}

/// Platform-abstracted ICMP ping socket.
///
/// Implementations must be safe to share across tasks (`Send + Sync`).
pub trait PingSocket: Send + Sync {
    /// Send an ICMP echo-request packet to `target`.
    fn send_ping(
        &self,
        packet: &[u8],
        target: IpAddr,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Wait for a ping reply, returning `None` if `timeout` elapses first.
    fn recv_ping(
        &self,
        timeout: Duration,
    ) -> impl std::future::Future<Output = Result<Option<RecvResult>>> + Send;
}
