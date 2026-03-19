//! Traceroute socket trait for cross-platform abstraction.

use crate::Result;
use std::net::IpAddr;
use std::time::Duration;

/// Result from receiving an ICMP packet
#[derive(Debug, Clone)]
pub struct RecvResult {
    /// Number of bytes received
    pub bytes_received: usize,
    /// Source IP of the response
    pub source: IpAddr,
    /// Raw ICMP data (after IP header stripping)
    pub icmp_data: Vec<u8>,
}

/// Trait abstracting the platform-specific socket operations for traceroute.
///
/// Unlike ping which only needs Echo Reply, traceroute must receive:
/// - ICMP Time Exceeded (type 11) from intermediate routers
/// - ICMP Echo Reply (type 0) from the destination
/// - ICMP Destination Unreachable (type 3) from the destination
pub trait TraceSocketTrait: Send + Sync {
    /// Send a probe packet to the target with the specified TTL.
    /// The implementation must set the socket TTL before sending.
    fn send_probe(
        &self,
        packet: &[u8],
        target: IpAddr,
        ttl: u8,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Receive an ICMP packet with the given timeout.
    /// Returns None if the timeout expires without receiving a packet.
    fn recv_icmp(
        &self,
        timeout: Duration,
    ) -> impl std::future::Future<Output = Result<Option<RecvResult>>> + Send;
}
