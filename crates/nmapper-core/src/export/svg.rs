use std::collections::HashMap;
use std::fmt::Write;
use std::net::IpAddr;

use crate::layout::Layout;
use crate::result::{DeviceType, DiscoveredDevice};

const MARGIN: f64 = 40.0;

/// Return a fill color for the given device type.
fn device_color(dt: DeviceType) -> &'static str {
    match dt {
        DeviceType::Router => "#4CAF50",
        DeviceType::Switch => "#00BCD4",
        DeviceType::Firewall => "#F44336",
        DeviceType::Server => "#FFEB3B",
        DeviceType::Printer => "#E91E63",
        DeviceType::AccessPoint => "#2196F3",
        DeviceType::Workstation => "#9E9E9E",
        DeviceType::IoT => "#FF9800",
        DeviceType::Unknown => "#9E9E9E",
    }
}

/// Return a short icon-style text label for a device type.
fn device_icon_text(dt: DeviceType) -> &'static str {
    match dt {
        DeviceType::Router => "\u{1F310}",      // globe
        DeviceType::Switch => "\u{1F500}",       // shuffle
        DeviceType::Firewall => "\u{1F6E1}",     // shield
        DeviceType::Server => "\u{1F5A5}",       // desktop
        DeviceType::Printer => "\u{1F5A8}",      // printer
        DeviceType::AccessPoint => "\u{1F4F6}",  // antenna
        DeviceType::Workstation => "\u{1F4BB}",   // laptop
        DeviceType::IoT => "\u{2699}",            // gear
        DeviceType::Unknown => "\u{2753}",        // question
    }
}

/// Export the layout to an SVG string.
///
/// Each device is drawn as a rounded rectangle colored by device type. Edges
/// are drawn as lines with arrowheads.
pub fn export_svg(layout: &Layout, devices: &[DiscoveredDevice]) -> String {
    let vb_width = layout.width + MARGIN * 2.0;
    let vb_height = layout.height + MARGIN * 2.0;

    // Build IP -> hostname lookup from devices.
    let hostname_map: HashMap<IpAddr, Option<&str>> = devices
        .iter()
        .map(|d| (d.ip, d.hostname.as_deref()))
        .collect();

    let mut svg = String::with_capacity(4096);

    // Build header without format macros to avoid issues with # in CSS/HTML
    svg.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    write!(
        svg,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {vb_width} {vb_height}\" width=\"{vb_width}\" height=\"{vb_height}\">\n"
    ).unwrap();
    svg.push_str("<defs>\n");
    svg.push_str("  <marker id=\"arrowhead\" markerWidth=\"10\" markerHeight=\"7\" refX=\"10\" refY=\"3.5\" orient=\"auto\">\n");
    svg.push_str("    <polygon points=\"0 0, 10 3.5, 0 7\" fill=\"#666\" />\n");
    svg.push_str("  </marker>\n");
    svg.push_str("</defs>\n");
    svg.push_str("<style>\n");
    svg.push_str("  .node-rect { stroke: #333; stroke-width: 1.5; rx: 8; ry: 8; }\n");
    svg.push_str("  .edge-line { stroke: #666; stroke-width: 1.5; marker-end: url(#arrowhead); }\n");
    svg.push_str("  .label { font-family: Arial, sans-serif; text-anchor: middle; font-size: 11px; fill: #333; }\n");
    svg.push_str("  .icon { font-size: 18px; text-anchor: middle; }\n");
    svg.push_str("</style>\n");
    write!(svg, "<rect width=\"{vb_width}\" height=\"{vb_height}\" fill=\"#fafafa\" />\n").unwrap();

    // Draw edges.
    for edge in &layout.edges {
        write!(
            svg,
            "<line class=\"edge-line\" x1=\"{sx}\" y1=\"{sy}\" x2=\"{tx}\" y2=\"{ty}\" />\n",
            sx = edge.source_x + MARGIN,
            sy = edge.source_y + MARGIN,
            tx = edge.target_x + MARGIN,
            ty = edge.target_y + MARGIN,
        )
        .unwrap();
    }

    // Draw nodes.
    for node in &layout.nodes {
        let x = node.x - node.width / 2.0 + MARGIN;
        let y = node.y - node.height / 2.0 + MARGIN;
        let cx = node.x + MARGIN;
        let color = device_color(node.device_type);
        let icon = device_icon_text(node.device_type);
        let hostname = hostname_map
            .get(&node.ip)
            .copied()
            .flatten()
            .unwrap_or("");

        write!(
            svg,
            "<rect class=\"node-rect\" x=\"{x}\" y=\"{y}\" width=\"{w}\" height=\"{h}\" fill=\"{color}\" />\n",
            w = node.width,
            h = node.height,
        )
        .unwrap();

        write!(
            svg,
            "<text class=\"icon\" x=\"{cx}\" y=\"{iy}\">{icon}</text>\n",
            iy = y + 28.0,
        )
        .unwrap();

        write!(
            svg,
            "<text class=\"label\" x=\"{cx}\" y=\"{ipy}\">{ip}</text>\n",
            ipy = y + 46.0,
            ip = node.ip,
        )
        .unwrap();

        if !hostname.is_empty() {
            write!(
                svg,
                "<text class=\"label\" x=\"{cx}\" y=\"{hy}\">{hostname}</text>\n",
                hy = y + 62.0,
                hostname = escape_xml(hostname),
            )
            .unwrap();
        }
    }

    svg.push_str("</svg>\n");
    svg
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
