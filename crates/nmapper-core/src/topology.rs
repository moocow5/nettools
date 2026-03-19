use std::collections::HashSet;
use std::net::IpAddr;

use crate::result::{DeviceType, DiscoveredDevice, TopologyLink};

/// A node in the topology graph representing a discovered device.
#[derive(Debug, Clone)]
pub struct TopologyNode {
    pub ip: IpAddr,
    pub device_type: DeviceType,
    /// Hostname if available, otherwise the IP as a string.
    pub label: String,
    /// Tier for hierarchical layout: 0 = routers/firewalls, 1 = switches/APs, 2 = endpoints.
    pub tier: u8,
    pub subnet: Option<String>,
}

/// A graph of topology nodes and edges built from scan data.
#[derive(Debug, Clone)]
pub struct TopologyGraph {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyLink>,
}

impl TopologyGraph {
    /// Build a topology graph from discovered devices and known links.
    ///
    /// Additional edges are inferred from SNMP CDP/LLDP neighbor tables when
    /// available on a device.
    pub fn from_scan(devices: &[DiscoveredDevice], links: &[TopologyLink]) -> Self {
        let device_ips: HashSet<IpAddr> = devices.iter().map(|d| d.ip).collect();

        let nodes: Vec<TopologyNode> = devices
            .iter()
            .map(|d| {
                let tier = match d.device_type {
                    DeviceType::Router | DeviceType::Firewall => 0,
                    DeviceType::Switch | DeviceType::AccessPoint => 1,
                    _ => 2,
                };
                let label = d
                    .hostname
                    .clone()
                    .unwrap_or_else(|| d.ip.to_string());
                TopologyNode {
                    ip: d.ip,
                    device_type: d.device_type,
                    label,
                    tier,
                    subnet: d.subnet.clone(),
                }
            })
            .collect();

        // Collect edges: start with the provided links, then add SNMP neighbor edges.
        let mut edge_set: HashSet<(IpAddr, IpAddr)> = HashSet::new();
        let mut edges: Vec<TopologyLink> = Vec::new();

        for link in links {
            let key = if link.source_ip <= link.target_ip {
                (link.source_ip, link.target_ip)
            } else {
                (link.target_ip, link.source_ip)
            };
            if edge_set.insert(key) {
                edges.push(link.clone());
            }
        }

        // Derive additional edges from SNMP CDP/LLDP neighbor data.
        for device in devices {
            if let Some(ref snmp) = device.snmp_info {
                for neighbor in &snmp.neighbors {
                    if let Some(remote_ip) = neighbor.remote_ip {
                        // Only add edges to devices we actually discovered.
                        if device_ips.contains(&remote_ip) {
                            let key = if device.ip <= remote_ip {
                                (device.ip, remote_ip)
                            } else {
                                (remote_ip, device.ip)
                            };
                            if edge_set.insert(key) {
                                edges.push(TopologyLink {
                                    source_ip: device.ip,
                                    target_ip: remote_ip,
                                    link_type: neighbor.protocol.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }

        TopologyGraph { nodes, edges }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{DiscoveredDevice, SnmpDeviceInfo, SnmpNeighbor, TopologyLink};
    use chrono::Utc;
    use std::net::IpAddr;

    fn make_device(ip: &str, dtype: DeviceType, hostname: Option<&str>) -> DiscoveredDevice {
        DiscoveredDevice {
            ip: ip.parse::<IpAddr>().unwrap(),
            mac: None,
            vendor: None,
            hostname: hostname.map(String::from),
            device_type: dtype,
            os_guess: None,
            ttl: None,
            ports: vec![],
            snmp_info: None,
            subnet: Some("10.0.0.0/24".into()),
            discovered_at: Utc::now(),
        }
    }

    #[test]
    fn test_tier_assignment() {
        let devices = vec![
            make_device("10.0.0.1", DeviceType::Router, Some("gw")),
            make_device("10.0.0.2", DeviceType::Switch, None),
            make_device("10.0.0.3", DeviceType::Server, Some("srv1")),
        ];
        let graph = TopologyGraph::from_scan(&devices, &[]);
        assert_eq!(graph.nodes[0].tier, 0);
        assert_eq!(graph.nodes[0].label, "gw");
        assert_eq!(graph.nodes[1].tier, 1);
        assert_eq!(graph.nodes[1].label, "10.0.0.2");
        assert_eq!(graph.nodes[2].tier, 2);
        assert_eq!(graph.nodes[2].label, "srv1");
    }

    #[test]
    fn test_snmp_neighbor_edges() {
        let mut router = make_device("10.0.0.1", DeviceType::Router, None);
        router.snmp_info = Some(SnmpDeviceInfo {
            sys_descr: None,
            sys_name: None,
            sys_object_id: None,
            brand: None,
            model: None,
            interfaces: vec![],
            neighbors: vec![SnmpNeighbor {
                local_port: "Gi0/1".into(),
                remote_ip: Some("10.0.0.2".parse().unwrap()),
                remote_hostname: None,
                remote_port: Some("Gi0/0".into()),
                protocol: "cdp".into(),
            }],
        });
        let switch = make_device("10.0.0.2", DeviceType::Switch, None);
        let devices = vec![router, switch];

        let graph = TopologyGraph::from_scan(&devices, &[]);
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].link_type, "cdp");
    }

    #[test]
    fn test_dedup_edges() {
        let devices = vec![
            make_device("10.0.0.1", DeviceType::Router, None),
            make_device("10.0.0.2", DeviceType::Switch, None),
        ];
        let links = vec![
            TopologyLink {
                source_ip: "10.0.0.1".parse().unwrap(),
                target_ip: "10.0.0.2".parse().unwrap(),
                link_type: "arp".into(),
            },
            TopologyLink {
                source_ip: "10.0.0.2".parse().unwrap(),
                target_ip: "10.0.0.1".parse().unwrap(),
                link_type: "arp".into(),
            },
        ];
        let graph = TopologyGraph::from_scan(&devices, &links);
        assert_eq!(graph.edges.len(), 1);
    }
}
