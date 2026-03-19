use crate::error::{NpingError, Result};
use crate::socket::{PingSocket, RecvResult};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::unix::AsyncFd;

/// ICMP socket for Unix platforms (macOS and Linux).
///
/// Uses a DGRAM/ICMP socket (unprivileged on Linux when `net.ipv4.ping_group_range`
/// is configured, or with `CAP_NET_RAW`; on macOS DGRAM ICMP is always allowed).
///
/// The underlying socket is non-blocking and wrapped in [`AsyncFd`] so that
/// tokio can drive readiness notifications.
pub struct IcmpSocket {
    inner: AsyncFd<Socket>,
}

impl IcmpSocket {
    /// Create a new non-blocking ICMP socket.
    pub fn new() -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::EPERM)
                    || e.raw_os_error() == Some(libc::EACCES)
                {
                    NpingError::PermissionDenied(
                        "could not create ICMP socket — try running with sudo, \
                         or on Linux ensure your user is in the ping group \
                         (sysctl net.ipv4.ping_group_range)"
                            .into(),
                    )
                } else {
                    NpingError::SocketCreate(e)
                }
            })?;

        socket.set_nonblocking(true).map_err(NpingError::SocketCreate)?;

        let async_fd = AsyncFd::new(socket).map_err(NpingError::SocketCreate)?;

        Ok(Self { inner: async_fd })
    }

    /// Set the IP TTL (Time To Live) on the socket.
    pub fn set_ttl(&self, ttl: u8) -> Result<()> {
        self.inner
            .get_ref()
            .set_ttl(ttl as u32)
            .map_err(NpingError::SocketCreate)
    }

    /// Set the IP ToS (Type of Service) / DSCP value on the socket.
    pub fn set_tos(&self, tos: u8) -> Result<()> {
        self.inner
            .get_ref()
            .set_tos(tos as u32)
            .map_err(NpingError::SocketCreate)
    }
}

impl PingSocket for IcmpSocket {
    async fn send_ping(&self, packet: &[u8], target: IpAddr) -> Result<()> {
        let sock_addr = SockAddr::from(SocketAddr::new(target, 0));

        loop {
            let mut guard = self.inner.writable().await.map_err(|e| NpingError::Send {
                target,
                source: e,
            })?;

            match guard.try_io(|fd| {
                fd.get_ref()
                    .send_to(packet, &sock_addr)
                    .map(|_bytes_sent| ())
            }) {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => {
                    return Err(if e.raw_os_error() == Some(libc::EPERM)
                        || e.raw_os_error() == Some(libc::EACCES)
                    {
                        NpingError::PermissionDenied(
                            "permission denied when sending ICMP packet".into(),
                        )
                    } else {
                        NpingError::Send { target, source: e }
                    });
                }
                // WouldBlock — readiness was a false positive; retry.
                Err(_would_block) => continue,
            }
        }
    }

    async fn recv_ping(&self, timeout: Duration) -> Result<Option<RecvResult>> {
        let recv_fut = async {
            loop {
                let mut guard = self.inner.readable().await.map_err(NpingError::Recv)?;

                // 1500 bytes is enough for any ICMP reply (+ IP header on macOS).
                let mut buf = [MaybeUninit::<u8>::uninit(); 1500];

                match guard.try_io(|fd| fd.get_ref().recv_from(&mut buf)) {
                    Ok(Ok((n, addr))) => {
                        // SAFETY: recv_from initialised `n` bytes of `buf`.
                        let data: Vec<u8> = buf[..n]
                            .iter()
                            .map(|b| unsafe { b.assume_init() })
                            .collect();

                        let source = addr
                            .as_socket()
                            .map(|sa| sa.ip())
                            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

                        let (ttl, icmp_data) = parse_platform_reply(&data);

                        return Ok(Some(RecvResult {
                            bytes_received: icmp_data.len(),
                            source,
                            ttl,
                            icmp_data,
                        }));
                    }
                    Ok(Err(e)) => return Err(NpingError::Recv(e)),
                    // WouldBlock — false positive; wait for readiness again.
                    Err(_would_block) => continue,
                }
            }
        };

        match tokio::time::timeout(timeout, recv_fut).await {
            Ok(result) => result,
            Err(_elapsed) => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Platform-specific reply parsing
// ---------------------------------------------------------------------------

/// On macOS DGRAM ICMP sockets the kernel prepends the IP header to the
/// received buffer.  On Linux the kernel strips it for us.
///
/// Returns `(ttl, icmp_payload)`.
fn parse_platform_reply(data: &[u8]) -> (Option<u8>, Vec<u8>) {
    if cfg!(target_os = "macos") {
        parse_macos_reply(data)
    } else {
        // Linux DGRAM ICMP: data is pure ICMP, no IP header.
        // TTL is not directly available from a DGRAM socket without
        // IP_RECVTTL + recvmsg; we leave it as None for now.
        (None, data.to_vec())
    }
}

/// Strip the IPv4 header that macOS includes and extract the TTL field.
fn parse_macos_reply(data: &[u8]) -> (Option<u8>, Vec<u8>) {
    if data.is_empty() {
        return (None, Vec::new());
    }

    // IPv4 header: version+IHL is in byte 0, TTL is byte 8.
    let ihl = (data[0] & 0x0F) as usize * 4;
    if data.len() < ihl {
        // Malformed — return everything and hope the caller can cope.
        return (None, data.to_vec());
    }

    let ttl = if data.len() > 8 { Some(data[8]) } else { None };
    let icmp_data = data[ihl..].to_vec();
    (ttl, icmp_data)
}

// ---------------------------------------------------------------------------
// Enable `AsyncFd<Socket>` — Socket must implement `AsRawFd` (it does).
// ---------------------------------------------------------------------------

// `socket2::Socket` already implements `AsRawFd` on Unix, so `AsyncFd`
// accepts it directly.  No additional trait impls are needed.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ip_header_macos() {
        // Fake IPv4 header (IHL = 5 → 20 bytes) + 8-byte ICMP stub.
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[8] = 64; // TTL
        pkt[20] = 0x00; // ICMP echo reply type
        pkt[21] = 0x00; // code 0

        let (ttl, icmp) = parse_macos_reply(&pkt);
        assert_eq!(ttl, Some(64));
        assert_eq!(icmp.len(), 8);
        assert_eq!(icmp[0], 0x00); // echo reply type
    }

    #[test]
    fn empty_data_does_not_panic() {
        let (ttl, icmp) = parse_macos_reply(&[]);
        assert_eq!(ttl, None);
        assert!(icmp.is_empty());
    }
}
