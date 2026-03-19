use crate::error::{NpingError, Result};
use crate::socket::{PingSocket, RecvResult};

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY, IP_OPTION_INFORMATION,
};

// ---------------------------------------------------------------------------
// IcmpSocket — Windows implementation
// ---------------------------------------------------------------------------

/// ICMP socket for Windows using the IcmpSendEcho API.
///
/// The Windows ICMP helper API combines send and receive into a single
/// blocking call (`IcmpSendEcho`).  To fit the [`PingSocket`] trait, which
/// separates the two, we store the request parameters in [`send_ping`] and
/// perform the actual send+receive in [`recv_ping`] via
/// [`tokio::task::spawn_blocking`].
pub struct IcmpSocket {
    handle: IcmpHandle,
    /// Pending request stashed by `send_ping`, consumed by `recv_ping`.
    pending: Mutex<Option<PendingRequest>>,
    ttl: Mutex<Option<u8>>,
    tos: Mutex<Option<u8>>,
}

struct PendingRequest {
    packet: Vec<u8>,
    target: IpAddr,
}

/// Thin wrapper so we can `Send + Sync` the raw HANDLE.
struct IcmpHandle(HANDLE);

// The ICMP handle is not tied to a particular thread.
unsafe impl Send for IcmpHandle {}
unsafe impl Sync for IcmpHandle {}

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        unsafe {
            IcmpCloseHandle(self.0);
        }
    }
}

impl IcmpSocket {
    /// Open an ICMP handle via `IcmpCreateFile`.
    pub fn new() -> Result<Self> {
        let handle = unsafe { IcmpCreateFile() };
        if handle == INVALID_HANDLE_VALUE {
            return Err(NpingError::SocketCreate(std::io::Error::last_os_error()));
        }
        Ok(Self {
            handle: IcmpHandle(handle),
            pending: Mutex::new(None),
            ttl: Mutex::new(None),
            tos: Mutex::new(None),
        })
    }

    /// Set the IP TTL (Time To Live) for subsequent pings.
    pub fn set_ttl(&self, ttl: u8) -> Result<()> {
        *self.ttl.lock().unwrap() = Some(ttl);
        Ok(())
    }

    /// Set the IP ToS (Type of Service) / DSCP value for subsequent pings.
    pub fn set_tos(&self, tos: u8) -> Result<()> {
        *self.tos.lock().unwrap() = Some(tos);
        Ok(())
    }
}

impl PingSocket for IcmpSocket {
    /// Stash the packet and target for the subsequent [`recv_ping`] call.
    ///
    /// No network I/O happens here on Windows.
    async fn send_ping(&self, packet: &[u8], target: IpAddr) -> Result<()> {
        let req = PendingRequest {
            packet: packet.to_vec(),
            target,
        };
        *self.pending.lock().unwrap() = Some(req);
        Ok(())
    }

    /// Execute the ICMP send+receive via `IcmpSendEcho` on a blocking thread.
    ///
    /// Returns `None` if the request times out.
    async fn recv_ping(&self, timeout: Duration) -> Result<Option<RecvResult>> {
        let pending = self
            .pending
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| NpingError::Other("recv_ping called without a prior send_ping".into()))?;

        // Cast HANDLE to isize so it is Send-safe for the blocking closure.
        let handle = self.handle.0 as isize;
        let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        let ttl = *self.ttl.lock().unwrap();
        let tos = *self.tos.lock().unwrap();

        // IcmpSendEcho is blocking, so offload to the tokio blocking pool.
        tokio::task::spawn_blocking(move || {
            icmp_send_echo(handle as HANDLE, &pending.packet, pending.target, timeout_ms, ttl, tos)
        })
        .await
        .map_err(|e| NpingError::Other(format!("blocking task panicked: {e}")))?
    }
}

/// Perform the actual `IcmpSendEcho` call and translate the result.
fn icmp_send_echo(
    handle: HANDLE,
    packet: &[u8],
    target: IpAddr,
    timeout_ms: u32,
    ttl: Option<u8>,
    tos: Option<u8>,
) -> Result<Option<RecvResult>> {
    let dest_addr: u32 = match target {
        IpAddr::V4(v4) => u32::from_ne_bytes(v4.octets()),
        IpAddr::V6(_) => {
            return Err(NpingError::Other(
                "IPv6 is not supported by the Windows ICMP helper API \
                 (use Icmp6SendEcho2 for IPv6)"
                    .into(),
            ));
        }
    };

    // The ICMP echo-request body starts after the 8-byte ICMP header.
    let request_data = if packet.len() > 8 {
        &packet[8..]
    } else {
        &[]
    };

    // Reply buffer must be large enough for ICMP_ECHO_REPLY + payload + 8
    // bytes of ICMP error data.
    let reply_buf_size =
        std::mem::size_of::<ICMP_ECHO_REPLY>() + request_data.len().max(8) + 8;
    let mut reply_buf = vec![0u8; reply_buf_size];

    // Build IP_OPTION_INFORMATION if TTL or TOS was requested.
    let mut ip_opts = IP_OPTION_INFORMATION {
        Ttl: ttl.unwrap_or(128),
        Tos: tos.unwrap_or(0),
        Flags: 0,
        OptionsSize: 0,
        OptionsData: std::ptr::null_mut(),
    };
    let opts_ptr = if ttl.is_some() || tos.is_some() {
        &mut ip_opts as *mut IP_OPTION_INFORMATION
    } else {
        std::ptr::null_mut()
    };

    let ret = unsafe {
        IcmpSendEcho(
            handle,
            dest_addr,
            request_data.as_ptr() as *mut _,
            request_data.len() as u16,
            opts_ptr as *mut _,
            reply_buf.as_mut_ptr() as *mut _,
            reply_buf_size as u32,
            timeout_ms,
        )
    };

    if ret == 0 {
        let err = std::io::Error::last_os_error();
        // ERROR_TIMEOUT (= 11010) or IP_REQ_TIMED_OUT (= 11010)
        if err.raw_os_error() == Some(11010) {
            return Ok(None);
        }
        return Err(NpingError::Recv(err));
    }

    // Parse the first ICMP_ECHO_REPLY from the reply buffer.
    let reply: &ICMP_ECHO_REPLY =
        unsafe { &*(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY) };

    let source = IpAddr::V4(std::net::Ipv4Addr::from(
        u32::from_ne_bytes(reply.Address.to_ne_bytes()),
    ));

    let ttl = Some(reply.Options.Ttl);

    // Reconstruct a minimal ICMP echo-reply packet for the caller:
    // type(0) + code(0) + checksum(0,0) + id(from original) + seq(from original)
    // + reply payload.
    let data_offset = std::mem::size_of::<ICMP_ECHO_REPLY>();
    let data_len = reply.DataSize as usize;
    let reply_payload = if data_offset + data_len <= reply_buf.len() {
        reply_buf[data_offset..data_offset + data_len].to_vec()
    } else {
        Vec::new()
    };

    // Build an 8-byte ICMP header + payload so callers get a consistent format.
    let mut icmp_data = Vec::with_capacity(8 + reply_payload.len());
    icmp_data.push(0); // type: echo reply
    icmp_data.push(0); // code
    icmp_data.extend_from_slice(&[0, 0]); // checksum (not validated here)
    // Copy id + sequence from the original request if available.
    if packet.len() >= 8 {
        icmp_data.extend_from_slice(&packet[4..8]); // id + seq
    } else {
        icmp_data.extend_from_slice(&[0, 0, 0, 0]);
    }
    icmp_data.extend_from_slice(&reply_payload);

    Ok(Some(RecvResult {
        bytes_received: icmp_data.len(),
        source,
        ttl,
        icmp_data,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_addr_to_u32_roundtrip() {
        let addr = std::net::Ipv4Addr::new(8, 8, 8, 8);
        let raw = u32::from_ne_bytes(addr.octets());
        let back = std::net::Ipv4Addr::from(u32::from_ne_bytes(raw.to_ne_bytes()));
        assert_eq!(addr, back);
    }
}
