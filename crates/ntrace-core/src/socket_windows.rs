//! Windows traceroute socket implementation.
//!
//! Uses the Windows ICMP Helper API (`IcmpSendEcho`) with TTL control via
//! `IP_OPTION_INFORMATION` to implement traceroute. Each `send_probe` stashes
//! the request parameters, and `recv_icmp` performs the actual blocking
//! `IcmpSendEcho` call on a tokio blocking thread.
//!
//! This approach supports:
//! - ICMP Time Exceeded from intermediate routers (IP_TTL_EXPIRED_TRANSIT)
//! - ICMP Echo Reply from the destination (IP_SUCCESS)
//! - ICMP Destination Unreachable (IP_DEST_*)

use crate::socket::{RecvResult, TraceSocketTrait};
use crate::{NtraceError, Result};

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::Duration;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY, IP_OPTION_INFORMATION,
};
use windows_sys::Win32::Networking::WinSock::IPAddr;

// Windows ICMP status codes
const IP_SUCCESS: u32 = 0;
const IP_TTL_EXPIRED_TRANSIT: u32 = 11013;
const IP_TTL_EXPIRED_REASSEM: u32 = 11014;
const IP_DEST_NET_UNREACHABLE: u32 = 11002;
const IP_DEST_HOST_UNREACHABLE: u32 = 11003;
const IP_DEST_PROT_UNREACHABLE: u32 = 11004;
const IP_DEST_PORT_UNREACHABLE: u32 = 11005;

/// Traceroute socket for Windows using the ICMP Helper API.
///
/// The `IcmpSendEcho` API combines send and receive into a single blocking
/// call. To fit the `TraceSocketTrait`, which separates the two, we stash
/// the request in `send_probe` and perform the actual work in `recv_icmp`
/// via `tokio::task::spawn_blocking`.
pub struct TraceSocket {
    handle: IcmpHandle,
    /// Pending probe stashed by `send_probe`, consumed by `recv_icmp`.
    pending: Mutex<Option<PendingProbe>>,
}

struct PendingProbe {
    target: IpAddr,
    ttl: u8,
    packet: Vec<u8>,
}

/// Thin wrapper so we can `Send + Sync` the raw HANDLE.
struct IcmpHandle(HANDLE);
unsafe impl Send for IcmpHandle {}
unsafe impl Sync for IcmpHandle {}

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        unsafe {
            IcmpCloseHandle(self.0);
        }
    }
}

impl TraceSocket {
    /// Open an ICMP handle via `IcmpCreateFile`.
    pub fn new() -> Result<Self> {
        let handle = unsafe { IcmpCreateFile() };
        if handle == INVALID_HANDLE_VALUE {
            return Err(NtraceError::SocketCreate(format!(
                "IcmpCreateFile failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self {
            handle: IcmpHandle(handle),
            pending: Mutex::new(None),
        })
    }
}

impl TraceSocketTrait for TraceSocket {
    /// Stash the probe parameters for the subsequent `recv_icmp` call.
    ///
    /// No network I/O happens here on Windows.
    async fn send_probe(&self, packet: &[u8], target: IpAddr, ttl: u8) -> Result<()> {
        let probe = PendingProbe {
            target,
            ttl,
            packet: packet.to_vec(),
        };
        *self.pending.lock().unwrap() = Some(probe);
        Ok(())
    }

    /// Execute the ICMP send+receive via `IcmpSendEcho` on a blocking thread.
    ///
    /// Returns the result classified as:
    /// - `RecvResult` with ICMP Time Exceeded (type 11) for intermediate hops
    /// - `RecvResult` with ICMP Echo Reply (type 0) for the destination
    /// - `RecvResult` with ICMP Dest Unreachable (type 3) for unreachable hops
    /// - `None` on timeout
    async fn recv_icmp(&self, timeout: Duration) -> Result<Option<RecvResult>> {
        let pending = self
            .pending
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| {
                NtraceError::Recv("recv_icmp called without a prior send_probe".into())
            })?;

        let handle = self.handle.0;
        let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;

        tokio::task::spawn_blocking(move || {
            icmp_trace_probe(handle, &pending.packet, pending.target, pending.ttl, timeout_ms)
        })
        .await
        .map_err(|e| NtraceError::Recv(format!("blocking task panicked: {e}")))?
    }
}

/// Perform the actual `IcmpSendEcho` call with TTL control and translate the
/// result into the format expected by the traceroute engine.
fn icmp_trace_probe(
    handle: HANDLE,
    packet: &[u8],
    target: IpAddr,
    ttl: u8,
    timeout_ms: u32,
) -> Result<Option<RecvResult>> {
    let dest_addr: u32 = match target {
        IpAddr::V4(v4) => u32::from_ne_bytes(v4.octets()),
        IpAddr::V6(_) => {
            return Err(NtraceError::Other(
                "IPv6 traceroute is not supported on Windows".into(),
            ));
        }
    };

    // The ICMP echo-request body starts after the 8-byte ICMP header.
    let request_data = if packet.len() > 8 {
        &packet[8..]
    } else {
        &[]
    };

    // Set TTL via IP_OPTION_INFORMATION
    let ip_options = IP_OPTION_INFORMATION {
        Ttl: ttl,
        Tos: 0,
        Flags: 0,
        OptionsSize: 0,
        OptionsData: std::ptr::null_mut(),
    };

    // Reply buffer must be large enough for ICMP_ECHO_REPLY + payload + 8
    // bytes of ICMP error data.
    let reply_buf_size =
        std::mem::size_of::<ICMP_ECHO_REPLY>() + request_data.len().max(8) + 8;
    let mut reply_buf = vec![0u8; reply_buf_size];

    let ret = unsafe {
        IcmpSendEcho(
            handle,
            dest_addr as IPAddr,
            request_data.as_ptr() as *mut _,
            request_data.len() as u16,
            &ip_options as *const _ as *mut _,
            reply_buf.as_mut_ptr() as *mut _,
            reply_buf_size as u32,
            timeout_ms,
        )
    };

    // Parse the ICMP_ECHO_REPLY regardless of return value.
    // When ret == 0 AND the error is a TTL expiry, the reply struct still
    // contains the responding router's address.
    if ret == 0 {
        let err = std::io::Error::last_os_error();
        let os_err = err.raw_os_error().unwrap_or(0) as u32;

        match os_err {
            // Timeout — no response at all
            11010 => return Ok(None),

            // TTL expired in transit — intermediate router responded
            IP_TTL_EXPIRED_TRANSIT | IP_TTL_EXPIRED_REASSEM => {
                let reply: &ICMP_ECHO_REPLY =
                    unsafe { &*(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY) };

                let source = IpAddr::V4(Ipv4Addr::from(
                    u32::from_ne_bytes(reply.Address.to_ne_bytes()),
                ));

                // Build ICMP Time Exceeded response (type 11, code 0)
                // followed by the original IP+ICMP header so the engine
                // can match it to the outstanding probe.
                let icmp_data = build_time_exceeded_response(packet);

                return Ok(Some(RecvResult {
                    bytes_received: icmp_data.len(),
                    source,
                    icmp_data,
                }));
            }

            // Destination unreachable variants
            IP_DEST_NET_UNREACHABLE
            | IP_DEST_HOST_UNREACHABLE
            | IP_DEST_PROT_UNREACHABLE
            | IP_DEST_PORT_UNREACHABLE => {
                let reply: &ICMP_ECHO_REPLY =
                    unsafe { &*(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY) };

                let source = IpAddr::V4(Ipv4Addr::from(
                    u32::from_ne_bytes(reply.Address.to_ne_bytes()),
                ));

                // Map Windows error to ICMP dest unreachable code
                let code = match os_err {
                    IP_DEST_NET_UNREACHABLE => 0,
                    IP_DEST_HOST_UNREACHABLE => 1,
                    IP_DEST_PROT_UNREACHABLE => 2,
                    IP_DEST_PORT_UNREACHABLE => 3,
                    _ => 0,
                };

                let icmp_data = build_dest_unreachable_response(code, packet);

                return Ok(Some(RecvResult {
                    bytes_received: icmp_data.len(),
                    source,
                    icmp_data,
                }));
            }

            // Other error — treat as failure
            _ => {
                return Err(NtraceError::Recv(format!(
                    "IcmpSendEcho failed: {} (os error {})",
                    err, os_err
                )));
            }
        }
    }

    // ret > 0 means success — we got an Echo Reply from the destination.
    let reply: &ICMP_ECHO_REPLY =
        unsafe { &*(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY) };

    let source = IpAddr::V4(Ipv4Addr::from(
        u32::from_ne_bytes(reply.Address.to_ne_bytes()),
    ));

    // Build an ICMP Echo Reply packet that the engine can parse.
    // Type 0 (Echo Reply), code 0, checksum 0, then id+seq from original.
    let mut icmp_data = Vec::with_capacity(8);
    icmp_data.push(0); // type: echo reply
    icmp_data.push(0); // code
    icmp_data.extend_from_slice(&[0, 0]); // checksum (not validated)
    // Copy id + sequence from the original request if available
    if packet.len() >= 8 {
        icmp_data.extend_from_slice(&packet[4..8]); // id + seq
    } else {
        icmp_data.extend_from_slice(&[0, 0, 0, 0]);
    }

    Ok(Some(RecvResult {
        bytes_received: icmp_data.len(),
        source,
        icmp_data,
    }))
}

/// Build a synthetic ICMP Time Exceeded (type 11, code 0) response that
/// includes the original IP header + first 8 bytes of ICMP data.
///
/// The traceroute engine's `classify_icmp_response` expects to find the
/// original probe's identifier and sequence in the quoted ICMP header
/// (bytes 4-7 of the original ICMP packet) embedded after the ICMP error
/// header (8 bytes) and original IP header (20 bytes).
///
/// Layout: [type=11][code=0][checksum=0,0][unused=0,0,0,0]
///         [original IP header (20 bytes)]
///         [first 8 bytes of original ICMP packet]
fn build_time_exceeded_response(original_icmp_packet: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + 20 + 8);

    // ICMP Time Exceeded header
    data.push(11); // type
    data.push(0);  // code: TTL expired in transit
    data.extend_from_slice(&[0, 0]); // checksum
    data.extend_from_slice(&[0, 0, 0, 0]); // unused

    // Synthetic original IP header (protocol = ICMP = 1)
    let mut ip_header = [0u8; 20];
    ip_header[0] = 0x45; // version 4, IHL 5
    ip_header[9] = 1;    // protocol: ICMP
    data.extend_from_slice(&ip_header);

    // First 8 bytes of the original ICMP packet (contains id + sequence)
    let icmp_bytes = if original_icmp_packet.len() >= 8 {
        &original_icmp_packet[..8]
    } else {
        original_icmp_packet
    };
    data.extend_from_slice(icmp_bytes);
    // Pad to 8 bytes if needed
    if icmp_bytes.len() < 8 {
        data.extend(std::iter::repeat(0).take(8 - icmp_bytes.len()));
    }

    data
}

/// Build a synthetic ICMP Destination Unreachable (type 3) response.
///
/// Same layout as Time Exceeded but with type=3 and the given code.
fn build_dest_unreachable_response(code: u8, original_icmp_packet: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + 20 + 8);

    // ICMP Dest Unreachable header
    data.push(3);    // type
    data.push(code); // code
    data.extend_from_slice(&[0, 0]); // checksum
    data.extend_from_slice(&[0, 0, 0, 0]); // unused

    // Synthetic original IP header (protocol = ICMP = 1)
    let mut ip_header = [0u8; 20];
    ip_header[0] = 0x45;
    ip_header[9] = 1; // protocol: ICMP
    data.extend_from_slice(&ip_header);

    // First 8 bytes of the original ICMP packet
    let icmp_bytes = if original_icmp_packet.len() >= 8 {
        &original_icmp_packet[..8]
    } else {
        original_icmp_packet
    };
    data.extend_from_slice(icmp_bytes);
    if icmp_bytes.len() < 8 {
        data.extend(std::iter::repeat(0).take(8 - icmp_bytes.len()));
    }

    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_exceeded_response_has_correct_structure() {
        // Simulate an ICMP Echo Request packet: type=8, code=0, cksum, id, seq
        let original = vec![8, 0, 0, 0, 0xAB, 0xCD, 0x00, 0x01, 0xFF, 0xFF];
        let resp = build_time_exceeded_response(&original);

        // Total: 8 (ICMP header) + 20 (IP header) + 8 (quoted ICMP)
        assert_eq!(resp.len(), 36);
        // Type = Time Exceeded
        assert_eq!(resp[0], 11);
        // Code = 0
        assert_eq!(resp[1], 0);
        // IP header starts at byte 8, protocol at byte 8+9=17
        assert_eq!(resp[17], 1); // ICMP protocol
        // Quoted ICMP starts at byte 28
        assert_eq!(resp[28], 8); // original type
        // Identifier at bytes 32-33
        assert_eq!(resp[32], 0xAB);
        assert_eq!(resp[33], 0xCD);
        // Sequence at bytes 34-35
        assert_eq!(resp[34], 0x00);
        assert_eq!(resp[35], 0x01);
    }

    #[test]
    fn dest_unreachable_response_has_correct_code() {
        let original = vec![8, 0, 0, 0, 0, 1, 0, 2];
        let resp = build_dest_unreachable_response(3, &original);

        assert_eq!(resp[0], 3);  // type = dest unreachable
        assert_eq!(resp[1], 3);  // code = port unreachable
    }

    #[test]
    fn short_original_packet_is_padded() {
        let original = vec![8, 0, 0, 0]; // only 4 bytes
        let resp = build_time_exceeded_response(&original);
        // Should still be 36 bytes (padded to 8 bytes for quoted ICMP)
        assert_eq!(resp.len(), 36);
    }
}
