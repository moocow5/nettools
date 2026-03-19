use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::result::DeviceType;
use crate::topology::TopologyGraph;

const NODE_WIDTH: f64 = 120.0;
const NODE_HEIGHT: f64 = 80.0;
const H_SPACING: f64 = 160.0;
const V_SPACING: f64 = 200.0;
const MARGIN: f64 = 80.0;

/// Y positions for each tier.
const TIER_Y: [f64; 3] = [100.0, 300.0, 500.0];

/// A positioned node ready for rendering.
#[derive(Debug, Clone)]
pub struct LayoutNode {
    pub ip: IpAddr,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub tier: u8,
    pub label: String,
    pub device_type: DeviceType,
}

/// A positioned edge ready for rendering.
#[derive(Debug, Clone)]
pub struct LayoutEdge {
    pub source_x: f64,
    pub source_y: f64,
    pub target_x: f64,
    pub target_y: f64,
}

/// The complete layout of a topology graph with computed positions.
#[derive(Debug, Clone)]
pub struct Layout {
    pub nodes: Vec<LayoutNode>,
    pub edges: Vec<LayoutEdge>,
    pub width: f64,
    pub height: f64,
}

/// Compute a hierarchical Sugiyama-style layout from a topology graph.
///
/// Tier 0 (routers/firewalls) at the top, tier 1 (switches/APs) in the middle,
/// tier 2 (endpoints) at the bottom. Within each tier, nodes are grouped by
/// subnet and sorted by IP address.
pub fn compute_layout(graph: &TopologyGraph) -> Layout {
    // Group nodes by tier, then by subnet, sorted by IP.
    let mut tiers: BTreeMap<u8, Vec<&crate::topology::TopologyNode>> = BTreeMap::new();
    for node in &graph.nodes {
        tiers.entry(node.tier).or_default().push(node);
    }

    // Sort each tier: group by subnet then sort by IP within each subnet.
    for nodes in tiers.values_mut() {
        nodes.sort_by(|a, b| {
            a.subnet
                .cmp(&b.subnet)
                .then_with(|| cmp_ip(&a.ip, &b.ip))
        });
    }

    // Determine the maximum tier width so we can center rows.
    let max_tier_count = tiers.values().map(|v| v.len()).max().unwrap_or(0);
    let total_width = if max_tier_count == 0 {
        MARGIN * 2.0
    } else {
        (max_tier_count as f64) * H_SPACING + MARGIN * 2.0
    };

    // Place nodes.
    let mut layout_nodes: Vec<LayoutNode> = Vec::new();
    for (&tier, nodes) in &tiers {
        let y = if (tier as usize) < TIER_Y.len() {
            TIER_Y[tier as usize]
        } else {
            TIER_Y[2] + V_SPACING * (tier as f64 - 2.0)
        };
        let count = nodes.len();
        let row_width = count as f64 * H_SPACING;
        let x_offset = (total_width - row_width) / 2.0 + H_SPACING / 2.0;

        for (i, node) in nodes.iter().enumerate() {
            layout_nodes.push(LayoutNode {
                ip: node.ip,
                x: x_offset + i as f64 * H_SPACING,
                y,
                width: NODE_WIDTH,
                height: NODE_HEIGHT,
                tier: node.tier,
                label: node.label.clone(),
                device_type: node.device_type,
            });
        }
    }

    // Build a quick lookup from IP -> position for edge routing.
    let pos_map: BTreeMap<IpAddr, (f64, f64)> = layout_nodes
        .iter()
        .map(|n| (n.ip, (n.x, n.y)))
        .collect();

    // Create edges: source center-bottom to target center-top.
    let mut layout_edges: Vec<LayoutEdge> = Vec::new();
    for edge in &graph.edges {
        if let (Some(&(sx, sy)), Some(&(tx, ty))) =
            (pos_map.get(&edge.source_ip), pos_map.get(&edge.target_ip))
        {
            // If source is below target, swap so arrow goes top-down.
            let (sx, sy, tx, ty) = if sy <= ty {
                (sx, sy, tx, ty)
            } else {
                (tx, ty, sx, sy)
            };
            layout_edges.push(LayoutEdge {
                source_x: sx,
                source_y: sy + NODE_HEIGHT / 2.0,
                target_x: tx,
                target_y: ty - NODE_HEIGHT / 2.0,
            });
        }
    }

    let height = TIER_Y[2] + NODE_HEIGHT + MARGIN;

    Layout {
        nodes: layout_nodes,
        edges: layout_edges,
        width: total_width,
        height,
    }
}

/// Compare two IpAddr values for sorting.
fn cmp_ip(a: &IpAddr, b: &IpAddr) -> std::cmp::Ordering {
    match (a, b) {
        (IpAddr::V4(a4), IpAddr::V4(b4)) => a4.octets().cmp(&b4.octets()),
        (IpAddr::V6(a6), IpAddr::V6(b6)) => a6.octets().cmp(&b6.octets()),
        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{DeviceType, DiscoveredDevice, TopologyLink};
    use crate::topology::TopologyGraph;
    use chrono::Utc;

    fn make_device(ip: &str, dtype: DeviceType, hostname: Option<&str>) -> DiscoveredDevice {
        DiscoveredDevice {
            ip: ip.parse().unwrap(),
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
    fn test_layout_tiers_y_positions() {
        let devices = vec![
            make_device("10.0.0.1", DeviceType::Router, Some("gw")),
            make_device("10.0.0.2", DeviceType::Switch, None),
            make_device("10.0.0.3", DeviceType::Server, Some("srv")),
        ];
        let graph = TopologyGraph::from_scan(&devices, &[]);
        let layout = compute_layout(&graph);

        assert_eq!(layout.nodes.len(), 3);

        let router = layout.nodes.iter().find(|n| n.ip.to_string() == "10.0.0.1").unwrap();
        let switch = layout.nodes.iter().find(|n| n.ip.to_string() == "10.0.0.2").unwrap();
        let server = layout.nodes.iter().find(|n| n.ip.to_string() == "10.0.0.3").unwrap();

        assert!((router.y - 100.0).abs() < f64::EPSILON);
        assert!((switch.y - 300.0).abs() < f64::EPSILON);
        assert!((server.y - 500.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_layout_centering() {
        let devices = vec![
            make_device("10.0.0.1", DeviceType::Router, None),
            make_device("10.0.0.10", DeviceType::Server, None),
            make_device("10.0.0.11", DeviceType::Server, None),
            make_device("10.0.0.12", DeviceType::Server, None),
        ];
        let graph = TopologyGraph::from_scan(&devices, &[]);
        let layout = compute_layout(&graph);

        // The tier with 3 endpoints is the widest (3 nodes), tier 0 has 1 node.
        // Tier 0 single node should be centered.
        let router = layout.nodes.iter().find(|n| n.ip.to_string() == "10.0.0.1").unwrap();
        let servers: Vec<_> = layout.nodes.iter().filter(|n| n.tier == 2).collect();

        // Router should be at center of the row.
        let server_xs: Vec<f64> = servers.iter().map(|s| s.x).collect();
        let server_center = (server_xs.iter().cloned().fold(f64::INFINITY, f64::min)
            + server_xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max))
            / 2.0;
        assert!(
            (router.x - server_center).abs() < f64::EPSILON,
            "Router x={} should equal center of server row x={}",
            router.x,
            server_center,
        );
    }

    #[test]
    fn test_layout_edges() {
        let devices = vec![
            make_device("10.0.0.1", DeviceType::Router, None),
            make_device("10.0.0.2", DeviceType::Switch, None),
        ];
        let links = vec![TopologyLink {
            source_ip: "10.0.0.1".parse().unwrap(),
            target_ip: "10.0.0.2".parse().unwrap(),
            link_type: "arp".into(),
        }];
        let graph = TopologyGraph::from_scan(&devices, &links);
        let layout = compute_layout(&graph);

        assert_eq!(layout.edges.len(), 1);
        let edge = &layout.edges[0];
        // Source (router tier 0 y=100) bottom = 100 + 40 = 140
        assert!((edge.source_y - 140.0).abs() < f64::EPSILON);
        // Target (switch tier 1 y=300) top = 300 - 40 = 260
        assert!((edge.target_y - 260.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_empty_graph() {
        let graph = TopologyGraph::from_scan(&[], &[]);
        let layout = compute_layout(&graph);
        assert!(layout.nodes.is_empty());
        assert!(layout.edges.is_empty());
    }
}
