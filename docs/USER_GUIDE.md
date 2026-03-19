# nettools User Guide

**Version 1.0.0**

A unified network toolkit combining ping, traceroute, network mapping, and a real-time web dashboard into a single binary.

---

## Table of Contents

1. [Overview](#overview)
2. [Building from Source](#building-from-source)
   - [Prerequisites](#prerequisites)
   - [macOS](#macos)
   - [Linux](#linux)
   - [Windows](#windows)
   - [Release Build](#release-build)
3. [Privileges and Permissions](#privileges-and-permissions)
4. [Commands](#commands)
   - [ping](#ping)
   - [monitor](#monitor)
   - [trace](#trace)
   - [mtr](#mtr)
   - [scan](#scan)
   - [diff](#diff)
   - [schedule](#schedule)
   - [traps](#traps)
   - [export](#export)
   - [dashboard](#dashboard)
5. [Monitor Targets File](#monitor-targets-file)
6. [Web Dashboard](#web-dashboard)
   - [Launching the Dashboard](#launching-the-dashboard)
   - [Ping Tab](#ping-tab)
   - [Trace Tab](#trace-tab)
   - [Mapper Tab](#mapper-tab)
   - [Exporting Data](#exporting-data)
7. [Database Files](#database-files)
8. [Platform Support Matrix](#platform-support-matrix)
9. [Troubleshooting](#troubleshooting)

---

## Overview

`nettools` is a single Rust binary that provides:

- **Ping** — ICMP, TCP SYN, TCP Connect, and UDP ping with statistics, alerting, and logging
- **Monitor** — Multi-target live TUI dashboard with configurable alerts
- **Trace** — Classic traceroute with ICMP, UDP, and TCP probe methods
- **MTR** — Continuous traceroute with rolling per-hop statistics (like `mtr`)
- **Scan** — Network discovery with device fingerprinting, SNMP enrichment, and topology mapping
- **Diff** — Compare two network scans to detect changes
- **Schedule** — Automated recurring scans with optional web dashboard
- **Traps** — SNMP trap listener
- **Export** — Export stored ping, trace, and scan data to JSON, CSV, SVG, or Visio formats
- **Dashboard** — Unified web UI for running and monitoring all tools from a browser

All data is persisted in local SQLite databases, and the web dashboard streams results in real time via Server-Sent Events (SSE).

---

## Building from Source

### Prerequisites

All platforms require:

| Requirement        | Details                                                        |
|--------------------|----------------------------------------------------------------|
| **Rust toolchain** | Edition 2021, stable channel, version 1.70 or later            |
| **C compiler**     | Required by the bundled SQLite (`rusqlite` with `bundled` feature) |
| **Git**            | To clone the repository                                        |

**No external libraries** (libpcap, npcap, WinPcap, etc.) are required. All network I/O is implemented using Rust's `socket2` crate and platform-native APIs. SQLite is compiled from source automatically via the `rusqlite` bundled feature. The web UI assets (HTML, CSS, JavaScript) are embedded directly into the binary at compile time via `rust-embed`.

### Installing Rust

The recommended way to install Rust on all platforms is via [rustup](https://rustup.rs/), which manages the Rust toolchain (compiler, package manager, and standard library).

**macOS and Linux:**

Open a terminal and run:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the on-screen prompts. The default installation options are fine. When the installer finishes, it will display instructions to configure your current shell. Either restart your terminal or run:

```bash
source "$HOME/.cargo/env"
```

Verify the installation:

```bash
rustc --version
# Expected output: rustc 1.XX.X (xxxxxxx YYYY-MM-DD)

cargo --version
# Expected output: cargo 1.XX.X (xxxxxxx YYYY-MM-DD)
```

**Windows:**

Download and run the [rustup-init.exe](https://win.rustup.rs/) installer. Follow the prompts. You may need to install the Visual Studio C++ Build Tools first (see the Windows section below) — the installer will tell you if they are missing.

After installation, open a **new** PowerShell or Command Prompt window and verify:

```powershell
rustc --version
cargo --version
```

**Updating Rust:**

If you already have Rust installed, make sure it is up to date:

```bash
rustup update stable
```

### macOS

#### Step 1: Install Xcode Command Line Tools

macOS requires the Xcode Command Line Tools, which provide the `clang` C compiler, linker, and standard headers. Most Mac users already have these installed. To check:

```bash
xcode-select -p
```

If this prints a path (e.g., `/Library/Developer/CommandLineTools`), you are set. If not, install them:

```bash
xcode-select --install
```

A dialog will appear asking you to install the tools. Click "Install" and wait for the download to complete (typically 1-5 minutes depending on your connection).

#### Step 2: Install Git (if not already present)

macOS includes Git as part of the Xcode Command Line Tools. Verify:

```bash
git --version
# Expected output: git version 2.XX.X (Apple Git-XXX)
```

If you prefer a newer version, you can install via [Homebrew](https://brew.sh/):

```bash
brew install git
```

#### Step 3: Install Rust

If you have not already installed Rust, follow the instructions in [Installing Rust](#installing-rust) above.

#### Step 4: Clone and Build

```bash
git clone https://github.com/moocow5/nettools.git
cd nettools
cargo build
```

The first build will download and compile all dependencies (approximately 2-5 minutes on modern hardware). The debug binary will be at `target/debug/nettools`.

For an optimized release build:

```bash
cargo build --release
```

The release binary will be at `target/release/nettools`.

#### Step 5: Verify the Build

```bash
./target/debug/nettools --help
```

You should see the list of available commands (ping, trace, mtr, scan, etc.).

#### macOS Permissions

| Feature | Privileges Required |
|---------|-------------------|
| ICMP ping | None (uses unprivileged DGRAM sockets) |
| TCP Connect ping | None |
| TCP SYN ping | `sudo` (requires raw sockets) |
| UDP ping | None |
| Traceroute (all methods) | None |
| MTR | None |
| Network scan | None |
| SNMP trap listener | `sudo` (port 162 is privileged) |
| Web dashboard | None |

macOS allows unprivileged ICMP via `SOCK_DGRAM` sockets, so most features work without `sudo`. Only TCP SYN ping (which sends crafted raw packets) and the SNMP trap listener (which binds to privileged port 162) require elevated privileges.

**Running with sudo:**

```bash
sudo ./target/release/nettools ping 8.8.8.8 -m tcp
```

### Linux

#### Step 1: Install System Dependencies

Linux requires a C compiler, linker, and standard development headers. The exact packages depend on your distribution.

**Debian / Ubuntu / Linux Mint:**

```bash
sudo apt update
sudo apt install -y build-essential curl git pkg-config
```

This installs:
- `build-essential` — GCC, G++, make, libc development headers
- `curl` — needed by the Rust installer
- `git` — to clone the repository
- `pkg-config` — used by some Rust crates for finding system libraries

**Fedora / RHEL / CentOS / Rocky Linux / AlmaLinux:**

```bash
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y curl git pkg-config
```

On older CentOS/RHEL systems that use `yum`:

```bash
sudo yum groupinstall -y "Development Tools"
sudo yum install -y curl git pkgconfig
```

**Arch Linux / Manjaro:**

```bash
sudo pacman -S --needed base-devel curl git pkg-config
```

**openSUSE:**

```bash
sudo zypper install -y -t pattern devel_basis
sudo zypper install -y curl git pkg-config
```

**Alpine Linux:**

```bash
sudo apk add build-base curl git pkgconf
```

Note: Alpine uses `musl` libc. The build will produce a statically-linked binary by default if you use the `x86_64-unknown-linux-musl` target.

#### Step 2: Install Rust

If you have not already installed Rust, follow the instructions in [Installing Rust](#installing-rust) above.

#### Step 3: Clone and Build

```bash
git clone https://github.com/moocow5/nettools.git
cd nettools
cargo build
```

The first build will download and compile all dependencies. The debug binary will be at `target/debug/nettools`.

For an optimized release build:

```bash
cargo build --release
```

The release binary will be at `target/release/nettools`.

#### Step 4: Verify the Build

```bash
./target/debug/nettools --help
```

#### Linux Permissions

By default, Linux does **not** allow unprivileged users to create ICMP sockets. You will see errors like `could not create ICMP socket: Permission denied` unless you configure permissions.

| Feature | Privileges Required |
|---------|-------------------|
| ICMP ping | Needs setup (see below) |
| TCP Connect ping | None |
| TCP SYN ping | `sudo` or `CAP_NET_RAW` |
| UDP ping | Needs setup (see below) |
| Traceroute (all methods) | `sudo` or `CAP_NET_RAW` |
| MTR | `sudo` or `CAP_NET_RAW` |
| Network scan | Needs setup (see below) |
| SNMP trap listener | `sudo` (port 162 is privileged) |
| Web dashboard | None |

**Option A — Enable unprivileged ICMP system-wide (recommended for development):**

This allows all users on the system to create ICMP sockets without `sudo`:

```bash
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
```

To make this permanent across reboots, add the following line to `/etc/sysctl.conf` or create a new file `/etc/sysctl.d/99-icmp.conf`:

```
net.ipv4.ping_group_range = 0 2147483647
```

Then reload:

```bash
sudo sysctl --system
```

**Option B — Grant capabilities to the binary (recommended for production):**

This grants raw socket access to the specific `nettools` binary without giving blanket permissions:

```bash
sudo setcap cap_net_raw=ep ./target/release/nettools
```

After running this command, the binary can create ICMP and raw sockets without `sudo`. Note: you must re-run this command each time you rebuild the binary, as `cargo build` creates a new file.

**Option C — Run with sudo:**

The simplest but least convenient option:

```bash
sudo ./target/release/nettools ping 8.8.8.8
```

**Verifying permissions are configured correctly:**

```bash
# This should work without sudo after Option A or B:
./target/release/nettools ping 8.8.8.8 -c 3
```

#### Optional: Install as a System Binary

To install `nettools` so it is available from any directory:

```bash
sudo cp ./target/release/nettools /usr/local/bin/nettools
sudo setcap cap_net_raw=ep /usr/local/bin/nettools
```

Now you can run `nettools` from anywhere:

```bash
nettools ping 8.8.8.8
```

### Windows

#### Step 1: Install Visual Studio Build Tools

Rust on Windows requires the Microsoft C/C++ build tools for linking and compiling native dependencies (including the bundled SQLite).

1. Download the [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-studio-cpp-build-tools/) installer (free, no Visual Studio license required).
2. Run the installer.
3. In the **Workloads** tab, check **"Desktop development with C++"**.
4. In the **Individual components** tab on the right sidebar, ensure these are selected:
   - **MSVC v143 - VS 2022 C++ x64/x86 build tools** (or the latest version available)
   - **Windows 10 SDK** (or Windows 11 SDK, any recent version)
5. Click **Install** and wait for the download to complete (typically 2-6 GB).

Alternatively, if you already have **Visual Studio 2019 or later** (Community, Professional, or Enterprise) installed with the C++ workload, that will also work.

#### Step 2: Install Git

If you do not already have Git installed:

1. Download the [Git for Windows](https://git-scm.com/download/win) installer.
2. Run the installer with default options.
3. Open a **new** PowerShell or Command Prompt and verify:

```powershell
git --version
```

#### Step 3: Install Rust

1. Download and run [rustup-init.exe](https://win.rustup.rs/).
2. The installer will detect your Visual Studio installation. If it reports that the build tools are not found, go back to Step 1.
3. Accept the default options (stable toolchain, default host triple, PATH modification).
4. Open a **new** PowerShell or Command Prompt window after installation.
5. Verify:

```powershell
rustc --version
cargo --version
```

#### Step 4: Clone and Build

Open PowerShell or Command Prompt:

```powershell
git clone https://github.com/moocow5/nettools.git
cd nettools
cargo build
```

The first build will download and compile all dependencies. The debug binary will be at `target\debug\nettools.exe`.

For an optimized release build:

```powershell
cargo build --release
```

The release binary will be at `target\release\nettools.exe`.

#### Step 5: Verify the Build

```powershell
.\target\debug\nettools.exe --help
```

#### Windows Permissions and Limitations

Windows uses a different networking stack than Unix systems. The following features are supported:

| Feature | Status | Notes |
|---------|--------|-------|
| ICMP ping | Supported | Uses the Windows ICMP Helper API (`IcmpSendEcho`) |
| TCP Connect ping | Supported | Standard socket connection |
| TCP SYN ping | Supported (fallback) | Automatically falls back to TCP Connect timing (no raw sockets on Windows) |
| UDP ping | Supported | Uses standard `tokio::net::UdpSocket` |
| Traceroute (ICMP) | Supported (Admin) | Uses raw ICMP socket (`SOCK_RAW + IPPROTO_ICMP`) with TTL control. Requires Administrator privileges. |
| MTR | Supported (Admin) | Continuous traceroute using raw ICMP socket. All methods (ICMP/UDP/TCP) supported. Requires Administrator privileges. |
| Traceroute (UDP) | Supported (Admin) | Uses raw ICMP socket (`SOCK_RAW + IPPROTO_ICMP`) to receive Time Exceeded responses from UDP probes. Requires Administrator privileges. |
| Traceroute (TCP) | Supported (Admin) | Uses raw ICMP socket to receive Time Exceeded responses from TCP SYN probes. Requires Administrator privileges. |
| Network scan | Supported | ICMP ping sweep + port scanning |
| SNMP queries | Supported | Standard UDP sockets |
| SNMP trap listener | Supported | Requires Administrator privileges for port 162 |
| Web dashboard | Supported | All dashboard features work |
| Export (all formats) | Supported | JSON, CSV, SVG, Visio |

To run the SNMP trap listener on port 162, open PowerShell as **Administrator**:

```powershell
.\target\release\nettools.exe traps
```

Or use a non-privileged port:

```powershell
.\target\release\nettools.exe traps --bind 0.0.0.0:10162
```

#### Windows Firewall

Windows Firewall may prompt you to allow network access the first time you run `nettools`. Click **Allow access** when prompted. If you dismissed the prompt, you can manually add a firewall rule:

```powershell
# Run as Administrator
New-NetFirewallRule -DisplayName "nettools" -Direction Inbound -Program "$PWD\target\release\nettools.exe" -Action Allow
```

### Release Build

For optimized production binaries on any platform:

```bash
cargo build --release
```

| Build Type | Binary Location | Use Case |
|------------|----------------|----------|
| Debug | `target/debug/nettools` | Development and testing |
| Release | `target/release/nettools` | Production use |

Release builds enable compiler optimizations (`-O2`), LTO (link-time optimization), and strip debug symbols. They are significantly faster for network scanning and large-scale monitoring operations. The trade-off is longer compile times (typically 2-5 minutes vs. 30-60 seconds for debug).

### Cross-Compilation

If you want to build for a different target platform from your current machine, you can use Rust's cross-compilation support.

**Example: Build a Linux binary on macOS:**

```bash
# Add the Linux target
rustup target add x86_64-unknown-linux-gnu

# Build (requires a cross-linker — see https://github.com/cross-rs/cross for an easier approach)
cargo build --release --target x86_64-unknown-linux-gnu
```

For easier cross-compilation, consider using the [cross](https://github.com/cross-rs/cross) tool, which handles the cross-compilation toolchain automatically using Docker:

```bash
cargo install cross
cross build --release --target x86_64-unknown-linux-gnu
```

### Verifying Your Build

After building, you can run the built-in self-check:

```bash
# Show version and available commands
nettools --help

# Quick ICMP ping test (verifies socket permissions)
nettools ping 127.0.0.1 -c 3

# Quick dashboard test (verifies web server and embedded assets)
nettools dashboard &
# Open http://127.0.0.1:9090 in your browser, then stop with Ctrl+C
```

---

## Privileges and Permissions

Different features require different privilege levels depending on the platform:

| Feature               | macOS          | Linux                        | Windows                  |
|-----------------------|----------------|------------------------------|--------------------------|
| ICMP ping             | No privileges  | Needs setup (see below)      | No privileges            |
| TCP Connect ping      | No privileges  | No privileges                | No privileges            |
| TCP SYN ping          | `sudo`         | `sudo` or `CAP_NET_RAW`     | Falls back to TCP Connect |
| UDP ping              | No privileges  | Needs setup (see below)      | No privileges            |
| Traceroute (ICMP)     | No privileges  | `sudo` or `CAP_NET_RAW`     | Administrator            |
| Traceroute (UDP/TCP)  | No privileges  | `sudo` or `CAP_NET_RAW`     | Administrator            |
| MTR (all methods)     | No privileges  | `sudo` or `CAP_NET_RAW`     | Administrator            |
| Network scan          | No privileges  | Needs setup (see below)      | No privileges            |
| SNMP trap listener    | `sudo` (port 162) | `sudo` (port 162)        | Admin (port 162)         |

### Linux: Enabling Unprivileged ICMP

By default, Linux does not allow unprivileged users to create ICMP sockets. There are two approaches:

**Option A — Allow all users (recommended for development):**

```bash
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
```

To make this permanent, add to `/etc/sysctl.conf`:

```
net.ipv4.ping_group_range = 0 2147483647
```

**Option B — Grant capabilities to the binary:**

```bash
sudo setcap cap_net_raw=ep ./target/release/nettools
```

This grants raw socket access to the specific binary without requiring `sudo` for every invocation.

---

## Commands

### ping

Send ICMP, TCP, or UDP pings to a target host with detailed statistics.

```
nettools ping <TARGET> [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `TARGET` | Hostname or IP address to ping |

**Options:**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--count` | `-c` | integer | unlimited | Number of pings to send |
| `--interval` | `-i` | duration | `1s` | Interval between pings |
| `--timeout` | `-W` | duration | `2s` | Timeout for each ping response |
| `--size` | `-s` | integer | `56` | Payload size in bytes |
| `--ttl` | `-t` | integer | OS default | IP Time-To-Live (1-255) |
| `--tos` | | integer | `0` | IP Type-of-Service / DSCP value (0-255) |
| `--mode` | `-m` | string | `icmp` | Ping mode: `icmp`, `tcp`, `tcp-connect`, `udp` |
| `--port` | `-p` | integer | | Port number for TCP/UDP modes |
| `--pattern` | | string | | Payload fill pattern: `zeros`, `alt`, `random`, or hex byte (e.g., `0xff`) |
| `--quiet` | `-q` | flag | | Quiet mode — only show summary |
| `--output` | `-o` | string | `text` | Output format: `text`, `json`, `csv` |
| `--log` | | path | | Append results to a log file |

**Duration format:** Values like `1s`, `500ms`, `2s`, `100ms` are supported.

**Examples:**

```bash
# Basic ICMP ping
nettools ping 8.8.8.8

# 10 pings at 500ms intervals
nettools ping 8.8.8.8 -c 10 -i 500ms

# TCP Connect ping to port 443
nettools ping google.com -m tcp-connect -p 443

# UDP ping with custom size
nettools ping 8.8.8.8 -m udp -p 53 -s 128

# ICMP ping with TTL and ToS, output as JSON
nettools ping 1.1.1.1 -t 64 --tos 46 -o json

# Log results to a file
nettools ping 8.8.8.8 --log ping_results.txt
```

### monitor

Launch a live TUI dashboard monitoring multiple targets simultaneously. Targets are defined in a TOML configuration file (see [Monitor Targets File](#monitor-targets-file)).

```
nettools monitor <TARGETS_FILE> [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `TARGETS_FILE` | Path to the TOML targets configuration file |

**Options:**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--interval` | `-i` | duration | | Override the ping interval for all targets |
| `--db` | | path | `nping.db` | SQLite database file for persistence |

**Examples:**

```bash
# Monitor targets defined in targets.toml
nettools monitor targets.toml

# Override interval to 2 seconds for all targets
nettools monitor targets.toml -i 2s

# Use a custom database location
nettools monitor targets.toml --db /var/lib/nettools/nping.db
```

### trace

Perform a one-shot traceroute to a destination, displaying each hop along the path.

```
nettools trace <TARGET> [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `TARGET` | Hostname or IP address to trace |

**Options:**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--method` | `-m` | string | `icmp` | Probe method: `icmp`, `udp`, `tcp` |
| `--first-ttl` | `-f` | integer | `1` | First TTL (starting hop) |
| `--max-ttl` | `-M` | integer | `30` | Maximum TTL (maximum hops) |
| `--queries` | `-q` | integer | `3` | Number of probes per hop |
| `--timeout` | `-w` | duration | `2s` | Timeout per probe |
| `--send-wait` | `-z` | duration | `50ms` | Delay between sending probes |
| `--packet-size` | `-s` | integer | `60` | Packet size in bytes (minimum 28) |
| `--port` | `-p` | integer | auto | Destination port for UDP/TCP probes |
| `--output` | `-o` | string | `text` | Output format: `text`, `json`, `csv` |

**Examples:**

```bash
# Standard ICMP traceroute
nettools trace 8.8.8.8

# TCP traceroute to port 443
nettools trace google.com -m tcp -p 443

# UDP traceroute with 5 probes per hop
nettools trace 1.1.1.1 -m udp -q 5

# JSON output, max 20 hops
nettools trace 8.8.8.8 -M 20 -o json
```

### mtr

Continuous traceroute with rolling statistics — combines traceroute and ping into a live, updating display. Similar to the `mtr` utility.

```
nettools mtr <TARGET> [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `TARGET` | Hostname or IP address to trace |

**Options:**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--method` | `-m` | string | `icmp` | Probe method: `icmp`, `udp`, `tcp` |
| `--interval` | `-i` | duration | `1s` | Interval between rounds |
| `--count` | `-c` | integer | unlimited | Number of rounds to run |
| `--max-ttl` | `-M` | integer | `30` | Maximum TTL (maximum hops) |
| `--queries` | `-q` | integer | `1` | Number of probes per hop per round |
| `--timeout` | `-w` | duration | `2s` | Timeout per probe |
| `--no-dns` | | flag | | Disable reverse DNS lookups |
| `--asn` | | flag | | Enable ASN (Autonomous System Number) lookups |
| `--geo` | | flag | | Enable GeoIP lookups |

**Examples:**

```bash
# Basic continuous traceroute
nettools mtr 8.8.8.8

# 50 rounds with ASN lookups
nettools mtr 8.8.8.8 -c 50 --asn

# Fast interval, no DNS
nettools mtr 1.1.1.1 -i 500ms --no-dns

# TCP MTR to port 443
nettools mtr google.com -m tcp -p 443
```

### scan

Discover devices on a network with port scanning, device fingerprinting, and optional SNMP enrichment.

```
nettools scan <TARGET>... [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `TARGET` | One or more targets — CIDR ranges, IP ranges, or individual IPs |

**Target formats:**
- CIDR notation: `192.168.1.0/24`
- IP range: `10.0.0.1-10.0.0.254`
- Single IP: `192.168.1.1`

**Options:**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--ports` | | list | common ports | Comma-separated list of ports to scan |
| `--ping-timeout` | | integer | `1000` | ICMP ping timeout in milliseconds |
| `--concurrency` | | integer | `64` | Maximum concurrent pings |
| `--no-arp` | | flag | | Skip ARP cache lookup |
| `--no-rdns` | | flag | | Skip reverse DNS lookups |
| `--snmp-community` | | string | | SNMPv2c community string (enables SNMP queries) |
| `--snmp-v3-user` | | string | | SNMPv3 username |
| `--snmp-v3-auth-proto` | | string | `none` | SNMPv3 auth protocol: `none`, `md5`, `sha1` |
| `--snmp-v3-auth-pass` | | string | | SNMPv3 authentication password |
| `--snmp-v3-priv-proto` | | string | `none` | SNMPv3 privacy protocol: `none`, `des`, `aes128` |
| `--snmp-v3-priv-pass` | | string | | SNMPv3 privacy password |
| `--output` | `-o` | string | `text` | Output format: `text`, `json`, `csv` |

**Examples:**

```bash
# Scan a /24 subnet
nettools scan 192.168.1.0/24

# Scan multiple subnets
nettools scan 192.168.1.0/24 10.0.0.0/24

# Scan with specific ports
nettools scan 192.168.1.0/24 --ports 22,80,443,8080

# Scan with SNMPv2c enrichment
nettools scan 192.168.1.0/24 --snmp-community public

# Scan with SNMPv3 (authPriv)
nettools scan 192.168.1.0/24 \
  --snmp-v3-user admin \
  --snmp-v3-auth-proto sha1 \
  --snmp-v3-auth-pass authpass123 \
  --snmp-v3-priv-proto aes128 \
  --snmp-v3-priv-pass privpass123

# JSON output with higher concurrency
nettools scan 10.0.0.0/16 --concurrency 256 -o json
```

### diff

Compare two network scans to detect new, removed, or changed devices.

```
nettools diff [OPTIONS]
```

**Options:**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--scan1` | | string | | First (older) scan ID |
| `--scan2` | | string | | Second (newer) scan ID |
| `--db` | | path | `nmapper.db` | Database path |
| `--output` | `-o` | string | `text` | Output format: `text`, `json` |

If `--scan1` and `--scan2` are omitted, the two most recent scans in the database are compared.

**Examples:**

```bash
# Compare the two most recent scans
nettools diff

# Compare specific scan IDs
nettools diff --scan1 abc123 --scan2 def456

# JSON output
nettools diff -o json
```

### schedule

Run network scans automatically on a recurring schedule. Results are persisted to the database and optionally displayed in a live web dashboard.

```
nettools schedule <TARGET>... [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `TARGET` | One or more scan targets (same formats as `scan`) |

**Options:**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--interval` | | integer | `60` | Scan interval in minutes |
| `--db` | | path | `nmapper.db` | Database path |
| `--ports` | | list | | Comma-separated list of ports to scan |
| `--ping-timeout` | | integer | `1000` | ICMP ping timeout in milliseconds |
| `--concurrency` | | integer | `64` | Maximum concurrent pings |
| `--no-arp` | | flag | | Skip ARP cache lookup |
| `--no-rdns` | | flag | | Skip reverse DNS lookups |
| `--snmp-community` | | string | | SNMPv2c community string |
| `--snmp-v3-user` | | string | | SNMPv3 username |
| `--snmp-v3-auth-proto` | | string | `none` | SNMPv3 auth protocol |
| `--snmp-v3-auth-pass` | | string | | SNMPv3 auth password |
| `--snmp-v3-priv-proto` | | string | `none` | SNMPv3 privacy protocol |
| `--snmp-v3-priv-pass` | | string | | SNMPv3 privacy password |
| `--dashboard` | | flag | | Launch web dashboard alongside scans |
| `--bind` | | string | `127.0.0.1:9092` | Dashboard bind address (with `--dashboard`) |

**Examples:**

```bash
# Scan every 30 minutes
nettools schedule 192.168.1.0/24 --interval 30

# Scan hourly with dashboard
nettools schedule 192.168.1.0/24 --interval 60 --dashboard

# Scan with SNMP, custom bind address for dashboard
nettools schedule 192.168.1.0/24 10.0.0.0/24 \
  --interval 15 \
  --snmp-community public \
  --dashboard --bind 0.0.0.0:9092
```

### traps

Listen for incoming SNMP traps. Displays trap events in real time.

```
nettools traps [OPTIONS]
```

**Options:**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--bind` | | string | `0.0.0.0:162` | Bind address for the trap listener |

**Note:** SNMP traps use UDP port 162, which is a privileged port. You will need `sudo` or equivalent permissions.

**Examples:**

```bash
# Listen on default port 162 (requires sudo)
sudo nettools traps

# Listen on a non-privileged port
nettools traps --bind 0.0.0.0:10162
```

### export

Export stored results from the database to various file formats.

#### export ping

Export stored ping monitoring results.

```
nettools export ping [OPTIONS]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | | string | | Target host to export (omit to list available targets) |
| `--format` | `-f` | string | | Output format: `csv`, `json` |
| `--output` | `-o` | path | stdout | Output file path |
| `--from` | | string | | Start of time range (ISO 8601, e.g., `2026-03-16`) |
| `--to` | | string | | End of time range (ISO 8601) |
| `--limit` | `-n` | integer | | Maximum number of results |
| `--db` | | path | auto | SQLite database file |

**Examples:**

```bash
# List available targets
nettools export ping

# Export last 100 pings for a target as CSV
nettools export ping --target 8.8.8.8 -f csv -n 100

# Export to a file with time range
nettools export ping --target 8.8.8.8 -f json \
  --from 2026-03-01 --to 2026-03-18 -o ping_data.json
```

#### export trace

Export stored traceroute data.

```
nettools export trace [OPTIONS]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | | string | | Filter by target host |
| `--format` | `-f` | string | `json` | Output format: `json`, `csv` |
| `--output` | `-o` | path | stdout | Output file path |
| `--trace-id` | | string | | Export a specific trace run by ID |
| `--limit` | | integer | `50` | Maximum number of trace runs |
| `--db` | | path | `ntrace.db` | Database file path |

**Examples:**

```bash
# Export latest traces as JSON
nettools export trace

# Export traces for a specific target
nettools export trace --target 8.8.8.8 -o traces.json

# Export a specific trace run
nettools export trace --trace-id abc123 -f csv -o trace.csv
```

#### export scan

Export network scan results to file.

```
nettools export scan [OPTIONS]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | `-f` | string | required | Export format: `json`, `csv`, `svg`, `vsdx` |
| `--output` | `-o` | path | required | Output file path |
| `--db` | | path | `nmapper.db` | Database path |
| `--scan-id` | | string | latest | Scan ID to export |

**Examples:**

```bash
# Export latest scan as JSON
nettools export scan -f json -o scan.json

# Export as CSV
nettools export scan -f csv -o devices.csv

# Export topology as SVG
nettools export scan -f svg -o topology.svg

# Export topology as Visio (VSDX)
nettools export scan -f vsdx -o network.vsdx

# Export a specific scan
nettools export scan --scan-id abc123 -f json -o scan.json
```

### dashboard

Launch the unified web dashboard. This provides a browser-based interface for running and monitoring ping, traceroute, and network scans. See [Web Dashboard](#web-dashboard) for full details.

```
nettools dashboard [TARGETS_FILE] [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `TARGETS_FILE` | Optional path to a TOML targets file for background ping monitoring |

**Options:**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--bind` | `-b` | string | `127.0.0.1:9090` | Address to bind the web server |
| `--interval` | `-i` | duration | | Override ping interval for all targets |
| `--ping-db` | | path | `nping.db` | SQLite database for ping data |
| `--mapper-db` | | path | `nmapper.db` | SQLite database for scan data |

**Examples:**

```bash
# Launch dashboard (no background monitoring)
nettools dashboard

# Launch with background ping monitoring
nettools dashboard targets.toml

# Custom bind address (accessible from LAN)
nettools dashboard -b 0.0.0.0:8080

# Custom database locations
nettools dashboard targets.toml \
  --ping-db /var/lib/nettools/nping.db \
  --mapper-db /var/lib/nettools/nmapper.db
```

---

## Monitor Targets File

The monitor command and dashboard accept a TOML configuration file that defines which hosts to monitor. The file supports a global defaults section and per-target configuration with optional alert thresholds.

### Format

```toml
[global]
interval = "1s"           # Default interval for all targets

[[target]]
host = "8.8.8.8"          # Required: hostname or IP
label = "Google DNS"       # Optional: display label
mode = "icmp"              # Optional: icmp (default), tcp, tcp-connect, udp
port = 443                 # Optional: port for TCP/UDP modes
interval = "1s"            # Optional: per-target interval (overrides global)

[target.alert]             # Optional: alert thresholds
max_latency_ms = 100.0     # Alert if average latency exceeds this (ms)
max_jitter_ms = 50.0       # Alert if jitter exceeds this (ms)
max_loss_pct = 5.0         # Alert if packet loss exceeds this (%)
cooldown = "60s"           # Cooldown between repeated alerts
```

### Example targets.toml

```toml
[global]
interval = "1s"

[[target]]
host = "8.8.8.8"
label = "Google DNS"
mode = "icmp"
interval = "1s"

[target.alert]
max_latency_ms = 100.0
max_loss_pct = 5.0

[[target]]
host = "1.1.1.1"
label = "Cloudflare DNS"
mode = "icmp"

[[target]]
host = "google.com"
label = "Google"
mode = "tcp-connect"
port = 443
interval = "2s"

[[target]]
host = "cloudflare.com"
label = "Cloudflare"
mode = "tcp-connect"
port = 443
interval = "2s"

[[target]]
host = "9.9.9.9"
label = "Quad9 DNS"
mode = "icmp"
```

### Alert Fields

| Field | Type | Description |
|-------|------|-------------|
| `max_latency_ms` | float | Maximum acceptable average latency in milliseconds |
| `max_jitter_ms` | float | Maximum acceptable jitter in milliseconds |
| `max_loss_pct` | float | Maximum acceptable packet loss percentage (0.0-100.0) |
| `cooldown` | duration | Cooldown period between repeated alerts (default: `60s`) |

---

## Web Dashboard

The web dashboard provides a browser-based interface for configuring, running, and monitoring all three network tools. It features a dark theme, real-time updates via Server-Sent Events, and interactive visualizations.

### Launching the Dashboard

```bash
nettools dashboard
```

Then open your browser to **http://127.0.0.1:9090**.

To make the dashboard accessible from other machines on your network:

```bash
nettools dashboard -b 0.0.0.0:9090
```

The dashboard has three tabs: **Ping**, **Trace**, and **Mapper**.

### Ping Tab

![Ping Tab](images/ping-tab.png)

The Ping tab provides a full-featured ping interface with real-time RTT charting.

**Configuration fields:**

| Field | Description | Default |
|-------|-------------|---------|
| Target | IP address or hostname | `8.8.8.8` |
| Mode | ICMP, TCP, TCP Connect, or UDP | ICMP |
| Port | Port number for TCP/UDP modes | |
| Count | Number of pings (leave empty for unlimited) | unlimited |
| Interval | Time between pings | `1s` |
| Timeout | Response timeout | `2s` |
| Size (bytes) | Payload size | `56` |

**Advanced Options** (click to expand):

| Field | Description |
|-------|-------------|
| TTL | IP Time-To-Live (1-255) |
| ToS/DSCP | Type of Service value (0-255) |
| Pattern | Payload fill: Default, Zeros, Alt Bits, Random |

**Controls:**
- **Start Ping** — Begins pinging with the configured parameters
- **Stop** — Stops the active ping session

**Display sections:**
- **Target Cards** — Shows per-target statistics: last RTT, average RTT, packet loss, jitter, MOS score
- **RTT Timeline** — Real-time line chart (Chart.js) showing RTT over time
- **Recent Alerts** — Displays alert notifications when thresholds are exceeded

**Export options:** JSON, CSV

### Trace Tab

![Trace Tab](images/trace-tab.png)

The Trace tab runs a continuous traceroute (MTR-style) with rolling hop statistics.

**Configuration fields:**

| Field | Description | Default |
|-------|-------------|---------|
| Target | IP address or hostname | `8.8.8.8` |
| Method | ICMP, UDP, or TCP | ICMP |
| Port | Port number for UDP/TCP probes | auto |
| Max Hops | Maximum number of hops | `30` |
| Probes/Hop | Probes sent per hop per round | `1` |
| Interval | Time between rounds | `1s` |
| Rounds | Number of rounds (leave empty for unlimited) | unlimited |

**Advanced Options** (click to expand):

| Field | Description |
|-------|-------------|
| First TTL | Starting hop number (1-255) |
| Timeout | Timeout per probe |
| Send Wait | Delay between probes |
| Packet Size | Packet size in bytes (28-65500) |
| Disable DNS | Skip reverse DNS lookups |
| Enable ASN Lookup | Query ASN information for each hop |

**Controls:**
- **Start Trace** — Begins the continuous traceroute
- **Stop** — Stops the active trace

**Display sections:**
- **Info Bar** — Shows target, current round, and total hops discovered
- **Hop Statistics Table** — Per-hop table with columns: #, Host, Loss%, Snt, Last, Avg, Best, Wrst, StDev
- **RTT per Hop Chart** — Line chart showing RTT trends per hop across rounds

**Export options:** JSON

### Mapper Tab

![Mapper Tab](images/mapper-tab.png)

The Mapper tab performs network discovery scans with device fingerprinting and topology visualization.

**Configuration fields:**

| Field | Description | Default |
|-------|-------------|---------|
| Targets | Comma-separated CIDR ranges | `192.168.1.0/24` |
| Ports | Comma-separated port list | default common ports |
| Ping Timeout (ms) | ICMP timeout in milliseconds | `1000` |
| Concurrency | Maximum concurrent pings | `64` |
| Skip ARP | Disable ARP cache lookup | unchecked |
| Skip rDNS | Disable reverse DNS lookups | unchecked |

**SNMP Options** (click to expand):

| Field | Description |
|-------|-------------|
| SNMPv2c Community | Community string (e.g., `public`) |
| SNMPv3 User | SNMPv3 username |
| SNMPv3 Auth Proto | None, MD5, or SHA1 |
| SNMPv3 Auth Pass | Authentication password |
| SNMPv3 Priv Proto | None, DES, or AES128 |
| SNMPv3 Priv Pass | Privacy password |

**Controls:**
- **Start Scan** — Begins network discovery
- **Stop** — Stops the active scan

**Display sections:**
- **Progress Bar** — Shows current scan phase and completion percentage
- **Scan Information** — Displays scan ID, timestamps, subnet count, device count
- **Network Topology** — Interactive D3.js force-directed graph showing device relationships. Nodes are color-coded by tier (gateways=red, infrastructure=orange, endpoints=blue). Nodes are draggable and display tooltips with IP, hostname, and device type on hover.
- **Discovered Devices Table** — Sortable, filterable table showing IP, MAC, vendor, hostname, device type, OS guess, and open ports for each discovered device

![Discovered Devices](images/mapper-devices.png)

**Export options:** JSON, CSV, SVG, Visio (.vsdx)

### Exporting Data

All three tabs provide export buttons. Clicking an export button downloads the data directly to your browser.

| Tab | Formats | Description |
|-----|---------|-------------|
| Ping | JSON, CSV | Ping results with timestamps, RTT, status |
| Trace | JSON | Hop data with statistics |
| Mapper | JSON | Full scan result with all device details |
| Mapper | CSV | Device list as comma-separated values |
| Mapper | SVG | Network topology diagram as vector graphic |
| Mapper | Visio | Network topology as .vsdx file (opens in Microsoft Visio or compatible editors) |

### API Reference

The web dashboard exposes a REST + SSE API under `/api/`. All endpoints return JSON unless noted otherwise.

#### Global

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Which tools are currently active (ping, trace, mapper) |

#### Ping (`/api/ping/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/ping/targets` | All monitored targets with current stats |
| GET | `/api/ping/targets/{id}` | Single target detail |
| GET | `/api/ping/targets/{id}/history` | Recent in-memory ping results |
| GET | `/api/ping/targets/{id}/db-history` | Historical ping data from SQLite |
| GET | `/api/ping/events` | SSE stream: `ping_result`, `stats_update`, `alert_fired` |
| POST | `/api/ping/start` | Start a ping/monitor job (JSON body with all CLI flags) |
| POST | `/api/ping/stop` | Stop the running ping job |
| GET | `/api/ping/status` | Current ping job status |
| GET | `/api/ping/results` | Accumulated ping results for the current job |
| GET | `/api/ping/export` | Export ping data (query params: `format`, `host`) |
| GET | `/api/ping/export/hosts` | List hosts available for export |

#### Trace (`/api/trace/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/trace/hops` | Current hop data with per-hop statistics |
| GET | `/api/trace/info` | Target, round count, max TTL, all hops |
| GET | `/api/trace/events` | SSE stream: `hop_update`, `round_complete`, `path_change` |
| POST | `/api/trace/start` | Start a traceroute/MTR job (JSON body with all CLI flags) |
| POST | `/api/trace/stop` | Stop the running trace job |
| GET | `/api/trace/status` | Current trace job status |
| GET | `/api/trace/export` | Export trace data (query params: `format`) |

#### Mapper (`/api/mapper/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/mapper/devices` | All discovered devices from the current/last scan |
| GET | `/api/mapper/topology` | Topology graph (nodes + edges for D3.js) |
| GET | `/api/mapper/scan-info` | Scan metadata (ID, timestamps, subnets, device count) |
| GET | `/api/mapper/diff` | Diff between current and previous scan |
| GET | `/api/mapper/traps` | Recent SNMP trap events |
| GET | `/api/mapper/events` | SSE stream: scan progress, phase changes, completion |
| GET | `/api/mapper/trap-events` | SSE stream: live SNMP trap events |
| POST | `/api/mapper/start` | Start a network scan (JSON body with all CLI flags) |
| POST | `/api/mapper/stop` | Stop the running scan |
| GET | `/api/mapper/status` | Current scan job status |
| GET | `/api/mapper/export` | Export scan data (query params: `format`, `scan_id`) |

#### POST Body Examples

Start a ping job:
```json
{
  "target": "8.8.8.8",
  "method": "icmp",
  "count": 100,
  "interval": "1s",
  "timeout": "2s"
}
```

Start a traceroute:
```json
{
  "target": "google.com",
  "method": "tcp",
  "port": 443,
  "max_ttl": 30
}
```

Start a network scan:
```json
{
  "subnets": ["192.168.1.0/24"],
  "ports": [22, 80, 443],
  "snmp_community": "public"
}
```

---

## Database Files

`nettools` uses SQLite databases for persistence. By default, these are created in the current working directory:

| Database | Used By | Default Name | Contents |
|----------|---------|--------------|----------|
| Ping DB | `monitor`, `dashboard`, `export ping` | `nping.db` | Per-target ping results, RTT, status, alerts |
| Trace DB | `trace`, `mtr`, `export trace` | `ntrace.db` | Traceroute runs with hop-by-hop data |
| Mapper DB | `scan`, `schedule`, `diff`, `dashboard`, `export scan` | `nmapper.db` | Network scan results, devices, topology |

You can specify custom paths using `--db`, `--ping-db`, or `--mapper-db` flags depending on the command.

---

## Platform Support Matrix

| Feature | macOS | Linux | Windows |
|---------|-------|-------|---------|
| ICMP ping | Yes | Yes | Yes |
| TCP Connect ping | Yes | Yes | Yes |
| TCP SYN ping | Yes (sudo) | Yes (sudo/CAP_NET_RAW) | Falls back to TCP Connect |
| UDP ping | Yes | Yes | Yes |
| Traceroute (ICMP) | Yes | Yes (sudo/CAP_NET_RAW) | Yes (Admin) |
| Traceroute (UDP/TCP) | Yes | Yes (sudo/CAP_NET_RAW) | Yes (Admin) |
| MTR | Yes | Yes (sudo/CAP_NET_RAW) | Yes (Admin) |
| Network scan | Yes | Yes | Yes |
| SNMP queries | Yes | Yes | Yes |
| SNMP traps | Yes | Yes | Yes |
| Monitor TUI | Yes | Yes | Yes |
| Web dashboard | Yes | Yes | Yes |
| Export (all formats) | Yes | Yes | Yes |
| IPv6 ping | Yes | Yes | No |

---

## Troubleshooting

### "could not create ICMP socket"

**Linux:** Your user does not have permission to create ICMP sockets. Either:
- Run with `sudo`: `sudo nettools ping 8.8.8.8`
- Enable unprivileged ICMP: `sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"`
- Grant capabilities: `sudo setcap cap_net_raw=ep ./target/release/nettools`

**macOS:** This should not occur for ICMP. For TCP SYN mode, use `sudo`.

### "RAW ICMP socket: Permission denied"

This error occurs when using traceroute or MTR on Linux without sufficient privileges. Use `sudo` or grant `CAP_NET_RAW`:

```bash
sudo setcap cap_net_raw=ep ./target/release/nettools
```

### Dashboard shows "Disconnected"

- Verify the server is running (check terminal output)
- Ensure you're accessing the correct address and port
- Check for firewall rules blocking the port
- If bound to `127.0.0.1`, the dashboard is only accessible from localhost

### Scan finds no devices

- Verify your target range is correct (e.g., `192.168.1.0/24` not `192.168.1.0`)
- Try increasing the ping timeout: `--ping-timeout 3000`
- Some networks block ICMP — try scanning specific ports: `--ports 22,80,443`
- Disable ARP skip if enabled: ensure `--no-arp` is not set

### Export returns empty data

- Verify data exists in the database: run a scan or ping session first
- For ping exports, use `nettools export ping` without `--target` to list available targets
- Check the database path — exports use the default database name unless `--db` is specified

### Windows: Traceroute not working

All traceroute methods (ICMP, UDP, TCP) are supported on Windows. If you encounter issues:

- **All traceroute methods** (ICMP, UDP, TCP) require **Administrator privileges** because they use a raw ICMP socket (`SOCK_RAW + IPPROTO_ICMP`) to send probes and receive Time Exceeded responses
- If you see "Permission denied" or error 10013, run as Administrator
- Check that Windows Firewall is not blocking ICMP traffic
- Try running PowerShell or Command Prompt as Administrator:
  ```powershell
  .\target\release\nettools.exe trace 8.8.8.8 --method udp
  .\target\release\nettools.exe trace 8.8.8.8 --method tcp --port 443
  ```

### High packet loss in results

- Check your network connectivity independently
- Try increasing the timeout: `-W 5s`
- For TCP modes, ensure the target port is open
- Check for rate limiting on the target (reduce probe rate with `-i 2s`)

---

*Built with Rust. No external dependencies required.*
