//! Traceroute engine: orchestrates probe sending and response matching.

use crate::config::{ProbeMethod, TraceConfig};
use crate::packet::{
    build_echo_request, is_dest_unreachable, is_echo_reply, is_time_exceeded,
    parse_icmp_error,
};
use crate::probe::{generate_identifier, PortProbeTracker, ProbeTracker};
use crate::probe_tcp::{send_tcp_probe, TcpProbeOutcome};
use crate::probe_udp::UdpProbeSender;
use crate::result::{HopResult, ProbeResult, ProbeStatus, TraceResult};
use crate::socket::{RecvResult, TraceSocketTrait};
use crate::Result;
use std::net::IpAddr;
use std::time::{Instant, SystemTime};
use tokio::sync::mpsc;

/// Resolve a hostname to an IP address
async fn resolve_target(target: &str) -> Result<(IpAddr, Option<String>)> {
    // Try parsing as IP first
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok((ip, None));
    }

    // DNS resolution
    let addr = tokio::net::lookup_host(format!("{}:0", target))
        .await
        .map_err(|e| crate::NtraceError::DnsResolution(format!("{}: {}", target, e)))?
        .next()
        .ok_or_else(|| {
            crate::NtraceError::DnsResolution(format!("no addresses found for {}", target))
        })?;

    Ok((addr.ip(), Some(target.to_string())))
}

/// Run a traceroute with the configured probe method.
pub async fn run_trace<S: TraceSocketTrait>(
    config: &TraceConfig,
    socket: &S,
    tx: mpsc::Sender<ProbeResult>,
) -> Result<TraceResult> {
    match config.method {
        ProbeMethod::Icmp => run_icmp_trace(config, socket, tx).await,
        ProbeMethod::Udp => run_udp_trace(config, socket, tx).await,
        ProbeMethod::TcpSyn => run_tcp_trace(config, socket, tx).await,
    }
}

// ---------------------------------------------------------------------------
// ICMP traceroute (existing logic)
// ---------------------------------------------------------------------------

/// Run a sequential ICMP traceroute.
///
/// For each TTL from first_ttl to max_ttl, sends `probes_per_hop` ICMP Echo Requests
/// and waits for responses. Sends each ProbeResult on `tx` as it arrives.
/// Returns the complete TraceResult when done.
async fn run_icmp_trace<S: TraceSocketTrait>(
    config: &TraceConfig,
    socket: &S,
    tx: mpsc::Sender<ProbeResult>,
) -> Result<TraceResult> {
    let started_at = SystemTime::now();
    let (target_ip, hostname) = resolve_target(&config.target).await?;

    let identifier = generate_identifier();
    let mut tracker = ProbeTracker::new(identifier);
    let mut hops: Vec<HopResult> = Vec::new();
    let mut reached_destination = false;

    // Generate a payload for our probes
    let payload_size = config.packet_size.saturating_sub(8); // subtract ICMP header
    let payload = vec![0u8; payload_size];

    for ttl in config.first_ttl..=config.max_ttl {
        let mut hop_probes = Vec::new();

        for probe_num in 0..config.probes_per_hop {
            let key = tracker.register_probe(ttl, probe_num);
            let packet = build_echo_request(key.identifier, key.sequence, &payload);

            let send_time = Instant::now();

            // Send the probe
            if let Err(e) = socket.send_probe(&packet, target_ip, ttl).await {
                tracing::warn!("Failed to send probe TTL={} probe={}: {}", ttl, probe_num, e);
                let result = ProbeResult {
                    ttl,
                    probe_num,
                    source: None,
                    rtt: None,
                    status: ProbeStatus::Error,
                    icmp_type: 0,
                    icmp_code: 0,
                    timestamp: SystemTime::now(),
                };
                let _ = tx.send(result.clone()).await;
                hop_probes.push(result);
                // Remove from tracker since we won't get a response
                tracker.match_response(key.identifier, key.sequence);
                continue;
            }

            // Wait for response
            let result = match recv_and_match_icmp(
                socket,
                &mut tracker,
                target_ip,
                send_time,
                ttl,
                probe_num,
                config.timeout,
            )
            .await
            {
                Ok(result) => result,
                Err(_) => ProbeResult {
                    ttl,
                    probe_num,
                    source: None,
                    rtt: None,
                    status: ProbeStatus::Timeout,
                    icmp_type: 0,
                    icmp_code: 0,
                    timestamp: SystemTime::now(),
                },
            };

            if result.status == ProbeStatus::Reply || result.status == ProbeStatus::Unreachable {
                reached_destination = true;
            }

            let _ = tx.send(result.clone()).await;
            hop_probes.push(result);

            // Inter-probe delay
            if probe_num + 1 < config.probes_per_hop {
                tokio::time::sleep(config.send_interval).await;
            }
        }

        let addr = HopResult::compute_addr(&hop_probes);
        hops.push(HopResult {
            ttl,
            probes: hop_probes,
            addr,
        });

        if reached_destination {
            break;
        }

        // Inter-hop delay
        if ttl < config.max_ttl {
            tokio::time::sleep(config.send_interval).await;
        }
    }

    Ok(TraceResult {
        target: target_ip,
        hostname,
        hops,
        reached_destination,
        started_at,
        completed_at: SystemTime::now(),
    })
}

/// Receive ICMP responses and try to match them to our outstanding ICMP probes.
/// Loops until we match the specific probe or timeout.
async fn recv_and_match_icmp<S: TraceSocketTrait>(
    socket: &S,
    tracker: &mut ProbeTracker,
    target_ip: IpAddr,
    send_time: Instant,
    expected_ttl: u8,
    expected_probe: u8,
    timeout: std::time::Duration,
) -> Result<ProbeResult> {
    let deadline = send_time + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(ProbeResult {
                ttl: expected_ttl,
                probe_num: expected_probe,
                source: None,
                rtt: None,
                status: ProbeStatus::Timeout,
                icmp_type: 0,
                icmp_code: 0,
                timestamp: SystemTime::now(),
            });
        }

        let recv = socket.recv_icmp(remaining).await?;

        let recv_result = match recv {
            Some(r) => r,
            None => {
                return Ok(ProbeResult {
                    ttl: expected_ttl,
                    probe_num: expected_probe,
                    source: None,
                    rtt: None,
                    status: ProbeStatus::Timeout,
                    icmp_type: 0,
                    icmp_code: 0,
                    timestamp: SystemTime::now(),
                });
            }
        };

        let rtt = send_time.elapsed();

        if let Some(result) =
            classify_icmp_response(&recv_result, tracker, target_ip, rtt)
        {
            if result.ttl == expected_ttl && result.probe_num == expected_probe {
                return Ok(result);
            }
        }
    }
}

/// Classify a received ICMP packet and match it to a tracked ICMP probe.
fn classify_icmp_response(
    recv: &RecvResult,
    tracker: &mut ProbeTracker,
    _target_ip: IpAddr,
    rtt: std::time::Duration,
) -> Option<ProbeResult> {
    let data = &recv.icmp_data;
    if data.is_empty() {
        return None;
    }

    let icmp_type = data[0];
    let icmp_code = if data.len() > 1 { data[1] } else { 0 };

    if is_echo_reply(icmp_type) {
        // Echo Reply from destination — extract identifier + sequence from reply
        if data.len() >= 8 {
            let identifier = u16::from_be_bytes([data[4], data[5]]);
            let sequence = u16::from_be_bytes([data[6], data[7]]);

            if let Some(record) = tracker.match_response(identifier, sequence) {
                return Some(ProbeResult {
                    ttl: record.ttl,
                    probe_num: record.probe_num,
                    source: Some(recv.source),
                    rtt: Some(rtt),
                    status: ProbeStatus::Reply,
                    icmp_type,
                    icmp_code,
                    timestamp: SystemTime::now(),
                });
            }
        }
    } else if is_time_exceeded(icmp_type) || is_dest_unreachable(icmp_type) {
        // Error message — parse the quoted original packet to find our probe
        if let Ok(error) = parse_icmp_error(data) {
            if error.original_header.protocol == 1 {
                // ICMP probe — match by identifier + sequence in the quoted ICMP header
                let identifier = error.original_header.icmp_identifier();
                let sequence = error.original_header.icmp_sequence();

                if let Some(record) = tracker.match_response(identifier, sequence) {
                    let status = if is_time_exceeded(icmp_type) {
                        ProbeStatus::TimeExceeded
                    } else {
                        ProbeStatus::Unreachable
                    };

                    return Some(ProbeResult {
                        ttl: record.ttl,
                        probe_num: record.probe_num,
                        source: Some(recv.source),
                        rtt: Some(rtt),
                        status,
                        icmp_type,
                        icmp_code,
                        timestamp: SystemTime::now(),
                    });
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// UDP traceroute
// ---------------------------------------------------------------------------

/// Run a sequential UDP traceroute.
///
/// Sends UDP packets to target:port with controlled TTL. Intermediate hops reply
/// with ICMP Time Exceeded. The destination replies with ICMP Port Unreachable
/// (type 3, code 3). We vary the destination port per probe for identification:
/// dst_port = base_port + (ttl - first_ttl) * probes_per_hop + probe_num.
async fn run_udp_trace<S: TraceSocketTrait>(
    config: &TraceConfig,
    socket: &S,
    tx: mpsc::Sender<ProbeResult>,
) -> Result<TraceResult> {
    let started_at = SystemTime::now();
    let (target_ip, hostname) = resolve_target(&config.target).await?;

    let udp_sender = UdpProbeSender::new()?;
    let local_port = udp_sender.local_port();
    let mut tracker = PortProbeTracker::new();
    let mut hops: Vec<HopResult> = Vec::new();
    let mut reached_destination = false;

    // UDP payload (just zeros)
    let payload_size = config.packet_size.saturating_sub(28); // subtract IP + UDP headers
    let payload = vec![0u8; payload_size];

    for ttl in config.first_ttl..=config.max_ttl {
        let mut hop_probes = Vec::new();

        for probe_num in 0..config.probes_per_hop {
            // Classic traceroute: vary dst_port per probe for identification
            let dst_port = config
                .port
                .wrapping_add((ttl as u16 - config.first_ttl as u16) * config.probes_per_hop as u16)
                .wrapping_add(probe_num as u16);

            let key = tracker.register_probe(local_port, dst_port, ttl, probe_num);
            let send_time = Instant::now();

            // Send the UDP probe
            if let Err(e) = udp_sender
                .send_probe(target_ip, dst_port, ttl, &payload)
                .await
            {
                tracing::warn!("Failed to send UDP probe TTL={} probe={}: {}", ttl, probe_num, e);
                let result = ProbeResult {
                    ttl,
                    probe_num,
                    source: None,
                    rtt: None,
                    status: ProbeStatus::Error,
                    icmp_type: 0,
                    icmp_code: 0,
                    timestamp: SystemTime::now(),
                };
                let _ = tx.send(result.clone()).await;
                hop_probes.push(result);
                tracker.match_response(key.src_port, key.dst_port);
                continue;
            }

            // Wait for ICMP response (Time Exceeded or Port Unreachable)
            let result = match recv_and_match_udp(
                socket,
                &mut tracker,
                send_time,
                ttl,
                probe_num,
                config.timeout,
            )
            .await
            {
                Ok(result) => result,
                Err(_) => ProbeResult {
                    ttl,
                    probe_num,
                    source: None,
                    rtt: None,
                    status: ProbeStatus::Timeout,
                    icmp_type: 0,
                    icmp_code: 0,
                    timestamp: SystemTime::now(),
                },
            };

            // For UDP, Port Unreachable (type 3, code 3) means destination reached
            if result.status == ProbeStatus::Unreachable
                && result.icmp_type == 3
                && result.icmp_code == 3
            {
                reached_destination = true;
            }

            let _ = tx.send(result.clone()).await;
            hop_probes.push(result);

            if probe_num + 1 < config.probes_per_hop {
                tokio::time::sleep(config.send_interval).await;
            }
        }

        let addr = HopResult::compute_addr(&hop_probes);
        hops.push(HopResult {
            ttl,
            probes: hop_probes,
            addr,
        });

        if reached_destination {
            break;
        }

        if ttl < config.max_ttl {
            tokio::time::sleep(config.send_interval).await;
        }
    }

    Ok(TraceResult {
        target: target_ip,
        hostname,
        hops,
        reached_destination,
        started_at,
        completed_at: SystemTime::now(),
    })
}

/// Receive ICMP responses and match them to outstanding UDP probes.
/// Matches by (src_port, dst_port) in the quoted UDP header from the ICMP error.
async fn recv_and_match_udp<S: TraceSocketTrait>(
    socket: &S,
    tracker: &mut PortProbeTracker,
    send_time: Instant,
    expected_ttl: u8,
    expected_probe: u8,
    timeout: std::time::Duration,
) -> Result<ProbeResult> {
    let deadline = send_time + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(ProbeResult {
                ttl: expected_ttl,
                probe_num: expected_probe,
                source: None,
                rtt: None,
                status: ProbeStatus::Timeout,
                icmp_type: 0,
                icmp_code: 0,
                timestamp: SystemTime::now(),
            });
        }

        let recv = socket.recv_icmp(remaining).await?;

        let recv_result = match recv {
            Some(r) => r,
            None => {
                return Ok(ProbeResult {
                    ttl: expected_ttl,
                    probe_num: expected_probe,
                    source: None,
                    rtt: None,
                    status: ProbeStatus::Timeout,
                    icmp_type: 0,
                    icmp_code: 0,
                    timestamp: SystemTime::now(),
                });
            }
        };

        let rtt = send_time.elapsed();

        if let Some(result) = classify_udp_response(&recv_result, tracker, rtt) {
            if result.ttl == expected_ttl && result.probe_num == expected_probe {
                return Ok(result);
            }
        }
    }
}

/// Classify a received ICMP packet and match it to a tracked UDP probe.
/// Looks for Time Exceeded or Destination Unreachable with protocol=17 (UDP)
/// in the quoted original header, then matches by (src_port, dst_port).
fn classify_udp_response(
    recv: &RecvResult,
    tracker: &mut PortProbeTracker,
    rtt: std::time::Duration,
) -> Option<ProbeResult> {
    let data = &recv.icmp_data;
    if data.is_empty() {
        return None;
    }

    let icmp_type = data[0];
    let icmp_code = if data.len() > 1 { data[1] } else { 0 };

    if is_time_exceeded(icmp_type) || is_dest_unreachable(icmp_type) {
        if let Ok(error) = parse_icmp_error(data) {
            if error.original_header.protocol == 17 {
                // UDP — match by src_port + dst_port
                let src_port = error.original_header.udp_src_port();
                let dst_port = error.original_header.udp_dst_port();

                if let Some(record) = tracker.match_response(src_port, dst_port) {
                    let status = if is_time_exceeded(icmp_type) {
                        ProbeStatus::TimeExceeded
                    } else {
                        ProbeStatus::Unreachable
                    };

                    return Some(ProbeResult {
                        ttl: record.ttl,
                        probe_num: record.probe_num,
                        source: Some(recv.source),
                        rtt: Some(rtt),
                        status,
                        icmp_type,
                        icmp_code,
                        timestamp: SystemTime::now(),
                    });
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// TCP traceroute
// ---------------------------------------------------------------------------

/// Run a sequential TCP SYN traceroute.
///
/// For each TTL, creates a TCP socket with that TTL and attempts connect() to target:port.
/// Intermediate hops send ICMP Time Exceeded (received on the ICMP socket).
/// If the destination is reached, connect() either succeeds (SYN-ACK) or gets
/// ConnectionRefused (RST). We use tokio::select! to race between ICMP response
/// and TCP connect completion.
async fn run_tcp_trace<S: TraceSocketTrait>(
    config: &TraceConfig,
    socket: &S,
    tx: mpsc::Sender<ProbeResult>,
) -> Result<TraceResult> {
    let started_at = SystemTime::now();
    let (target_ip, hostname) = resolve_target(&config.target).await?;

    let mut hops: Vec<HopResult> = Vec::new();
    let mut reached_destination = false;

    for ttl in config.first_ttl..=config.max_ttl {
        let mut hop_probes = Vec::new();

        for probe_num in 0..config.probes_per_hop {
            let send_time = Instant::now();

            // Race: TCP connect vs ICMP Time Exceeded
            let result = run_single_tcp_probe(
                socket,
                target_ip,
                config.port,
                ttl,
                probe_num,
                config.timeout,
                send_time,
            )
            .await;

            if result.status == ProbeStatus::Reply || result.status == ProbeStatus::Unreachable {
                reached_destination = true;
            }

            let _ = tx.send(result.clone()).await;
            hop_probes.push(result);

            if probe_num + 1 < config.probes_per_hop {
                tokio::time::sleep(config.send_interval).await;
            }
        }

        let addr = HopResult::compute_addr(&hop_probes);
        hops.push(HopResult {
            ttl,
            probes: hop_probes,
            addr,
        });

        if reached_destination {
            break;
        }

        if ttl < config.max_ttl {
            tokio::time::sleep(config.send_interval).await;
        }
    }

    Ok(TraceResult {
        target: target_ip,
        hostname,
        hops,
        reached_destination,
        started_at,
        completed_at: SystemTime::now(),
    })
}

/// Run a single TCP probe, racing the TCP connect against ICMP responses.
///
/// For intermediate hops (TTL expires), the ICMP socket receives Time Exceeded.
/// For the destination, the TCP connect completes (Connected or Refused).
async fn run_single_tcp_probe<S: TraceSocketTrait>(
    icmp_socket: &S,
    target: IpAddr,
    port: u16,
    ttl: u8,
    probe_num: u8,
    timeout: std::time::Duration,
    send_time: Instant,
) -> ProbeResult {
    // Use tokio::select! to race TCP connect against ICMP response
    tokio::select! {
        tcp_outcome = send_tcp_probe(target, port, ttl, timeout) => {
            match tcp_outcome {
                TcpProbeOutcome::Connected { rtt } => {
                    ProbeResult {
                        ttl,
                        probe_num,
                        source: Some(target),
                        rtt: Some(rtt),
                        status: ProbeStatus::Reply,
                        icmp_type: 0,
                        icmp_code: 0,
                        timestamp: SystemTime::now(),
                    }
                }
                TcpProbeOutcome::Refused { rtt } => {
                    // RST received — destination reached but port closed
                    ProbeResult {
                        ttl,
                        probe_num,
                        source: Some(target),
                        rtt: Some(rtt),
                        status: ProbeStatus::Reply,
                        icmp_type: 0,
                        icmp_code: 0,
                        timestamp: SystemTime::now(),
                    }
                }
                TcpProbeOutcome::Timeout => {
                    ProbeResult {
                        ttl,
                        probe_num,
                        source: None,
                        rtt: None,
                        status: ProbeStatus::Timeout,
                        icmp_type: 0,
                        icmp_code: 0,
                        timestamp: SystemTime::now(),
                    }
                }
                TcpProbeOutcome::Error(msg) => {
                    tracing::warn!("TCP probe error TTL={} probe={}: {}", ttl, probe_num, msg);
                    ProbeResult {
                        ttl,
                        probe_num,
                        source: None,
                        rtt: None,
                        status: ProbeStatus::Error,
                        icmp_type: 0,
                        icmp_code: 0,
                        timestamp: SystemTime::now(),
                    }
                }
            }
        }
        icmp_result = recv_icmp_for_tcp(icmp_socket, send_time, timeout) => {
            match icmp_result {
                Some((source, rtt, icmp_type, icmp_code)) => {
                    let status = if is_time_exceeded(icmp_type) {
                        ProbeStatus::TimeExceeded
                    } else if is_dest_unreachable(icmp_type) {
                        ProbeStatus::Unreachable
                    } else {
                        ProbeStatus::Error
                    };
                    ProbeResult {
                        ttl,
                        probe_num,
                        source: Some(source),
                        rtt: Some(rtt),
                        status,
                        icmp_type,
                        icmp_code,
                        timestamp: SystemTime::now(),
                    }
                }
                None => {
                    ProbeResult {
                        ttl,
                        probe_num,
                        source: None,
                        rtt: None,
                        status: ProbeStatus::Timeout,
                        icmp_type: 0,
                        icmp_code: 0,
                        timestamp: SystemTime::now(),
                    }
                }
            }
        }
    }
}

/// Listen on the ICMP socket for Time Exceeded / Dest Unreachable responses
/// with protocol=6 (TCP) in the quoted original header.
async fn recv_icmp_for_tcp<S: TraceSocketTrait>(
    socket: &S,
    send_time: Instant,
    timeout: std::time::Duration,
) -> Option<(IpAddr, std::time::Duration, u8, u8)> {
    let deadline = send_time + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }

        let recv = match socket.recv_icmp(remaining).await {
            Ok(Some(r)) => r,
            Ok(None) => return None,
            Err(_) => return None,
        };

        let data = &recv.icmp_data;
        if data.is_empty() {
            continue;
        }

        let icmp_type = data[0];
        let icmp_code = if data.len() > 1 { data[1] } else { 0 };

        if is_time_exceeded(icmp_type) || is_dest_unreachable(icmp_type) {
            if let Ok(error) = parse_icmp_error(data) {
                if error.original_header.protocol == 6 {
                    // TCP — this is a response to our TCP probe
                    let rtt = send_time.elapsed();
                    return Some((recv.source, rtt, icmp_type, icmp_code));
                }
            }
        }
        // Not for us — keep listening
    }
}
