use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use chrono::Utc;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::arp;
use crate::config::ScanConfig;
use crate::fingerprint::fingerprint_device;
use crate::oui;
use crate::ping_sweep::{self, PingSweepResult};
use crate::port_scan;
use crate::rdns;
use crate::result::{DiscoveredDevice, PortStatus, ScanEvent, ScanResult, SnmpDeviceInfo, TopologyLink};
use crate::config::SnmpConfig;
use crate::snmp::{client::SnmpClient, oids, v3_client::SnmpV3Client, walk};

/// Run a full network scan with the given config.
/// Returns a ScanResult and broadcasts ScanEvents for real-time progress.
pub async fn run_scan(
    config: &ScanConfig,
    tx: &broadcast::Sender<ScanEvent>,
) -> crate::Result<ScanResult> {
    let scan_id = uuid::Uuid::new_v4().to_string();
    let started_at = Utc::now();

    // Expand all targets to individual IPs
    let all_ips: Vec<IpAddr> = config
        .targets
        .iter()
        .flat_map(|t| t.expand())
        .collect();

    let subnets_scanned: Vec<String> = config
        .targets
        .iter()
        .map(|t| format!("{:?}", t))
        .collect();

    info!("scanning {} hosts", all_ips.len());

    // Phase 1: ICMP Ping Sweep
    let _ = tx.send(ScanEvent::PhaseStarted {
        phase: "ICMP Sweep".into(),
    });

    let ping_results = ping_sweep::ping_sweep(
        &all_ips,
        config.ping_timeout,
        config.ping_concurrency,
    )
    .await;

    let alive_hosts: Vec<&PingSweepResult> =
        ping_results.iter().filter(|r| r.alive).collect();

    info!("{}/{} hosts alive", alive_hosts.len(), all_ips.len());

    let _ = tx.send(ScanEvent::PhaseCompleted {
        phase: "ICMP Sweep".into(),
    });

    for host in &alive_hosts {
        let _ = tx.send(ScanEvent::HostDiscovered { ip: host.ip });
    }

    // Phase 2: ARP Cache
    let _ = tx.send(ScanEvent::PhaseStarted {
        phase: "ARP Lookup".into(),
    });

    let arp_table = if config.arp_lookup {
        arp::get_arp_table().await
    } else {
        std::collections::HashMap::new()
    };

    let _ = tx.send(ScanEvent::PhaseCompleted {
        phase: "ARP Lookup".into(),
    });

    // Phase 3: Port Scan + Fingerprint each alive host
    let _ = tx.send(ScanEvent::PhaseStarted {
        phase: "Port Scan".into(),
    });

    let total = alive_hosts.len();
    let mut devices = Vec::with_capacity(total);

    for (i, host) in alive_hosts.iter().enumerate() {
        let ports = port_scan::scan_ports(
            host.ip,
            &config.ports,
            config.port_timeout,
            config.port_concurrency,
        )
        .await;

        let mac = arp_table.get(&host.ip).cloned();
        let vendor = mac.as_deref().and_then(oui::lookup_vendor).map(String::from);

        let hostname = if config.rdns {
            rdns::reverse_dns(host.ip).await
        } else {
            None
        };

        let (device_type, os_guess) =
            fingerprint_device(host.ttl, &ports, vendor.as_deref());

        let subnet = config
            .targets
            .first()
            .map(|t| format!("{:?}", t));

        let device = DiscoveredDevice {
            ip: host.ip,
            mac,
            vendor,
            hostname,
            device_type,
            os_guess,
            ttl: host.ttl,
            ports,
            snmp_info: None,
            subnet,
            discovered_at: Utc::now(),
        };

        let _ = tx.send(ScanEvent::HostScanned {
            device: device.clone(),
        });
        let _ = tx.send(ScanEvent::Progress {
            done: i + 1,
            total,
        });

        devices.push(device);
    }

    let _ = tx.send(ScanEvent::PhaseCompleted {
        phase: "Port Scan".into(),
    });

    // Phase 4: SNMP Discovery
    // Determine SNMP mode: prefer snmp_config, fall back to legacy snmp_community
    let snmp_mode: Option<SnmpConfig> = config
        .snmp_config
        .clone()
        .or_else(|| config.snmp_community.clone().map(|c| SnmpConfig::V2c { community: c }));

    if let Some(ref snmp_cfg) = snmp_mode {
        let _ = tx.send(ScanEvent::PhaseStarted {
            phase: "SNMP Discovery".into(),
        });

        for device in &mut devices {
            let has_snmp_port = device
                .ports
                .iter()
                .any(|p| p.port == 161 && p.status == PortStatus::Open);

            if !has_snmp_port {
                continue;
            }

            let addr = SocketAddr::new(device.ip, 161);

            // GET system info + walk tables via v2c or v3
            let snmp_result = match snmp_cfg {
                SnmpConfig::V2c { community } => {
                    snmp_query_v2c(addr, community, device.ip).await
                }
                SnmpConfig::V3(v3cfg) => {
                    snmp_query_v3(addr, v3cfg, device.ip).await
                }
            };

            let (sys_descr, sys_name, sys_object_id, brand, model, interfaces, neighbors) = match snmp_result {
                Some(r) => r,
                None => continue,
            };

            // If SNMP revealed brand info, try to refine device_type
            if let Some(ref brand_str) = brand {
                let (new_type, _) =
                    fingerprint_device(device.ttl, &device.ports, Some(brand_str));
                device.device_type = new_type;
            }

            device.snmp_info = Some(SnmpDeviceInfo {
                sys_descr,
                sys_name,
                sys_object_id,
                brand,
                model,
                interfaces,
                neighbors,
            });

            info!("SNMP data collected for {}", device.ip);
        }

        let _ = tx.send(ScanEvent::PhaseCompleted {
            phase: "SNMP Discovery".into(),
        });
    }

    // Build basic topology links from ARP/gateway relationships
    let mut links = build_basic_links(&devices);

    // Add topology links from SNMP CDP/LLDP neighbor data
    for device in &devices {
        if let Some(ref snmp_info) = device.snmp_info {
            for neighbor in &snmp_info.neighbors {
                if let Some(remote_ip) = neighbor.remote_ip {
                    links.push(TopologyLink {
                        source_ip: device.ip,
                        target_ip: remote_ip,
                        link_type: neighbor.protocol.clone(),
                    });
                }
            }
        }
    }

    let result = ScanResult {
        scan_id,
        devices,
        links,
        started_at,
        completed_at: Utc::now(),
        subnets_scanned,
    };

    let _ = tx.send(ScanEvent::ScanCompleted {
        result: result.clone(),
    });

    Ok(result)
}

/// Build basic topology links: connect all devices to the likely gateway.
fn build_basic_links(devices: &[DiscoveredDevice]) -> Vec<TopologyLink> {
    let mut links = Vec::new();

    // Find likely gateway (router-type device, or lowest IP with high TTL)
    let gateway = devices.iter().find(|d| {
        matches!(
            d.device_type,
            crate::result::DeviceType::Router | crate::result::DeviceType::Firewall
        )
    });

    if let Some(gw) = gateway {
        for device in devices {
            if device.ip != gw.ip {
                links.push(TopologyLink {
                    source_ip: gw.ip,
                    target_ip: device.ip,
                    link_type: "gateway".to_string(),
                });
            }
        }
    }

    links
}

/// SNMP result tuple type used by the v2c/v3 query helpers.
type SnmpQueryResult = (
    Option<String>,                     // sys_descr
    Option<String>,                     // sys_name
    Option<String>,                     // sys_object_id
    Option<String>,                     // brand
    Option<String>,                     // model
    Vec<crate::result::SnmpInterface>,  // interfaces
    Vec<crate::result::SnmpNeighbor>,   // neighbors
);

/// Query a device via SNMPv2c.
async fn snmp_query_v2c(
    addr: SocketAddr,
    community: &str,
    device_ip: IpAddr,
) -> Option<SnmpQueryResult> {
    let client = SnmpClient::new(addr, community, Duration::from_secs(3));

    let sys_varbinds = match client
        .get(&[oids::SYS_DESCR, oids::SYS_NAME, oids::SYS_OBJECT_ID])
        .await
    {
        Ok(vb) => vb,
        Err(e) => {
            warn!("SNMP v2c GET failed for {}: {}", device_ip, e);
            return None;
        }
    };

    let (sys_descr, sys_name, sys_object_id) = walk::parse_sys_info(&sys_varbinds);
    let (brand, model) = sys_descr
        .as_deref()
        .map(walk::parse_brand_model)
        .unwrap_or((None, None));

    let interfaces = match client.walk(oids::IF_TABLE).await {
        Ok(vb) => walk::parse_interfaces(&vb),
        Err(e) => {
            warn!("SNMP ifTable walk failed for {}: {}", device_ip, e);
            Vec::new()
        }
    };

    let mut neighbors = match client.walk(oids::CDP_CACHE_TABLE).await {
        Ok(vb) => walk::parse_cdp_neighbors(&vb),
        Err(e) => {
            warn!("SNMP CDP walk failed for {}: {}", device_ip, e);
            Vec::new()
        }
    };

    match client.walk(oids::LLDP_REM_TABLE).await {
        Ok(vb) => neighbors.extend(walk::parse_lldp_neighbors(&vb)),
        Err(e) => warn!("SNMP LLDP walk failed for {}: {}", device_ip, e),
    }

    Some((sys_descr, sys_name, sys_object_id, brand, model, interfaces, neighbors))
}

/// Query a device via SNMPv3.
async fn snmp_query_v3(
    addr: SocketAddr,
    v3cfg: &crate::snmp::v3::SnmpV3Config,
    device_ip: IpAddr,
) -> Option<SnmpQueryResult> {
    let client = match SnmpV3Client::new(addr, v3cfg.clone(), Duration::from_secs(5)).await {
        Ok(c) => c,
        Err(e) => {
            warn!("SNMPv3 engine discovery failed for {}: {}", device_ip, e);
            return None;
        }
    };

    let sys_varbinds = match client
        .get(&[oids::SYS_DESCR, oids::SYS_NAME, oids::SYS_OBJECT_ID])
        .await
    {
        Ok(vb) => vb,
        Err(e) => {
            warn!("SNMPv3 GET failed for {}: {}", device_ip, e);
            return None;
        }
    };

    let (sys_descr, sys_name, sys_object_id) = walk::parse_sys_info(&sys_varbinds);
    let (brand, model) = sys_descr
        .as_deref()
        .map(walk::parse_brand_model)
        .unwrap_or((None, None));

    let interfaces = match client.walk(oids::IF_TABLE).await {
        Ok(vb) => walk::parse_interfaces(&vb),
        Err(e) => {
            warn!("SNMPv3 ifTable walk failed for {}: {}", device_ip, e);
            Vec::new()
        }
    };

    let mut neighbors = match client.walk(oids::CDP_CACHE_TABLE).await {
        Ok(vb) => walk::parse_cdp_neighbors(&vb),
        Err(e) => {
            warn!("SNMPv3 CDP walk failed for {}: {}", device_ip, e);
            Vec::new()
        }
    };

    match client.walk(oids::LLDP_REM_TABLE).await {
        Ok(vb) => neighbors.extend(walk::parse_lldp_neighbors(&vb)),
        Err(e) => warn!("SNMPv3 LLDP walk failed for {}: {}", device_ip, e),
    }

    Some((sys_descr, sys_name, sys_object_id, brand, model, interfaces, neighbors))
}
