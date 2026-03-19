# nettools

A unified network toolkit combining ping, traceroute, network mapping, and a real-time web dashboard into a single Rust binary.

## Features

- **Ping** -- ICMP, TCP SYN, TCP Connect, and UDP ping with statistics, alerting, and logging
- **Monitor** -- Multi-target live TUI dashboard with configurable alert thresholds
- **Trace** -- Classic traceroute with ICMP, UDP, and TCP probe methods
- **MTR** -- Continuous traceroute with rolling per-hop statistics
- **Scan** -- Network discovery with device fingerprinting, SNMP enrichment, and topology mapping
- **Diff** -- Compare two network scans to detect changes
- **Schedule** -- Automated recurring scans with optional web dashboard
- **Traps** -- SNMP trap listener
- **Export** -- Export data to JSON, CSV, SVG, or Visio (.vsdx) formats
- **Dashboard** -- Unified web UI for running and monitoring all tools from a browser

## Quick Start

### Prerequisites

- **Rust** 1.70+ (install via [rustup.rs](https://rustup.rs/))
- **C compiler** (Xcode CLI tools on macOS, `build-essential` on Linux, Visual Studio Build Tools on Windows)
- **Git**

### Build

```bash
git clone https://github.com/moocow5/nettools.git
cd nettools
cargo build --release
```

The binary will be at `target/release/nettools`.

### Run

```bash
# ICMP ping
./target/release/nettools ping 8.8.8.8

# Traceroute
./target/release/nettools trace 8.8.8.8

# MTR (continuous traceroute)
./target/release/nettools mtr 8.8.8.8

# Network scan
./target/release/nettools scan 192.168.1.0/24

# Launch web dashboard
./target/release/nettools dashboard
# Then open http://127.0.0.1:9090
```

## Web Dashboard

The dashboard provides a browser-based interface for all three tools with real-time streaming results.

| Tab | Description |
|-----|-------------|
| **Ping** | Configure and run pings with live RTT charting (Chart.js) |
| **Trace** | Continuous MTR-style traceroute with per-hop statistics |
| **Mapper** | Network discovery with interactive D3.js topology visualization |

All tabs support starting/stopping jobs, configuring parameters, and exporting results.

### Screenshots

**Ping Tab** -- Real-time RTT monitoring with statistics cards and timeline chart:

![Ping Tab](docs/images/ping-tab.png)

**Trace Tab** -- Per-hop statistics table with loss, latency, and jitter:

![Trace Tab](docs/images/trace-tab.png)

**Mapper Tab** -- Network topology visualization and device discovery:

![Mapper Tab](docs/images/mapper-tab.png)

**Discovered Devices** -- Sortable device table with IP, MAC, vendor, hostname, OS, and open ports:

![Discovered Devices](docs/images/mapper-devices.png)

## Commands

| Command | Description |
|---------|-------------|
| `ping <target>` | ICMP/TCP/UDP ping with statistics |
| `monitor <targets.toml>` | Multi-target live TUI dashboard |
| `trace <target>` | One-shot traceroute |
| `mtr <target>` | Continuous traceroute (MTR mode) |
| `scan <target>...` | Network discovery and port scanning |
| `diff` | Compare two network scans |
| `schedule <target>...` | Recurring scheduled scans |
| `traps` | SNMP trap listener |
| `export ping\|trace\|scan` | Export stored data |
| `dashboard [targets.toml]` | Launch web UI |

## Export Formats

| Tool | JSON | CSV | SVG | Visio (.vsdx) |
|------|------|-----|-----|----------------|
| Ping | Yes | Yes | -- | -- |
| Trace | Yes | Yes | -- | -- |
| Scan | Yes | Yes | Yes | Yes |

## Platform Support

| Feature | macOS | Linux | Windows |
|---------|-------|-------|---------|
| ICMP ping | Yes | Yes* | Yes |
| TCP Connect ping | Yes | Yes | Yes |
| TCP SYN ping | sudo | sudo/CAP_NET_RAW | Fallback to TCP Connect |
| UDP ping | Yes | Yes* | Yes |
| Traceroute (ICMP) | Yes | sudo/CAP_NET_RAW | Yes |
| Traceroute (UDP/TCP) | Yes | sudo/CAP_NET_RAW | Yes (Admin) |
| MTR | Yes | sudo/CAP_NET_RAW | Yes (Admin) |
| Network scan | Yes | Yes | Yes |
| SNMP | Yes | Yes | Yes |
| Web dashboard | Yes | Yes | Yes |

\* Linux requires `sysctl -w net.ipv4.ping_group_range="0 2147483647"` or `CAP_NET_RAW` for unprivileged ICMP.

## Architecture

Rust workspace with 5 crates:

```
crates/
  nping-core/      # Ping engine (ICMP, TCP, UDP)
  ntrace-core/     # Traceroute and MTR engine
  nmapper-core/    # Network scanner, SNMP, topology
  nettools-cli/    # Unified CLI (clap)
  nettools-web/    # Axum web server, SSE streaming
web-ui-unified/    # Frontend (HTML/JS/CSS, Chart.js, D3.js)
```

## Documentation

See the full **[User Guide](docs/USER_GUIDE.md)** for:

- Detailed build instructions for macOS, Linux, and Windows
- Complete CLI reference with all flags and options
- Web dashboard usage guide with screenshots
- Monitor targets file format and alert configuration
- Database file details
- Troubleshooting guide

A PDF version of the user guide is available at [`docs/Network_Tools_Suite_Guide.pdf`](docs/Network_Tools_Suite_Guide.pdf).

## License

All rights reserved.
