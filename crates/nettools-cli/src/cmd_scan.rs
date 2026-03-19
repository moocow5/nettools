use std::time::Duration;

use clap::Args;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use nmapper_core::config::{ScanConfig, ScanTarget, SnmpConfig, DEFAULT_PORTS};
use nmapper_core::result::{DeviceType, ScanEvent, ScanResult};
use tokio::sync::broadcast;

#[derive(Args)]
pub struct ScanArgs {
    /// Target subnet, range, or IP (e.g. 192.168.1.0/24)
    pub target: Vec<String>,

    /// Ports to scan (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub ports: Option<Vec<u16>>,

    /// ICMP ping timeout in milliseconds
    #[arg(long, default_value = "1000")]
    pub ping_timeout: u64,

    /// Maximum concurrent pings
    #[arg(long, default_value = "64")]
    pub concurrency: usize,

    /// Skip ARP cache lookup
    #[arg(long)]
    pub no_arp: bool,

    /// Skip reverse DNS
    #[arg(long)]
    pub no_rdns: bool,

    /// SNMP v2c community string (enables SNMP queries)
    #[arg(long)]
    pub snmp_community: Option<String>,

    // --- SNMPv3 flags ---

    /// SNMPv3 username (enables SNMPv3 mode)
    #[arg(long)]
    pub snmp_v3_user: Option<String>,

    /// SNMPv3 auth protocol: none, md5, sha1
    #[arg(long, default_value = "none")]
    pub snmp_v3_auth_proto: String,

    /// SNMPv3 auth password
    #[arg(long)]
    pub snmp_v3_auth_pass: Option<String>,

    /// SNMPv3 privacy protocol: none, des, aes128
    #[arg(long, default_value = "none")]
    pub snmp_v3_priv_proto: String,

    /// SNMPv3 privacy password
    #[arg(long)]
    pub snmp_v3_priv_pass: Option<String>,

    /// Output format: text, json, csv
    #[arg(short, long, default_value = "text")]
    pub output: String,
}

pub async fn run(args: ScanArgs) -> anyhow::Result<()> {
    if args.target.is_empty() {
        anyhow::bail!("no target specified");
    }

    let targets: Vec<ScanTarget> = args
        .target
        .iter()
        .map(|t| ScanTarget::parse(t))
        .collect::<Result<Vec<_>, _>>()?;

    let snmp_config = SnmpConfig::from_flags(
        args.snmp_community.clone(),
        args.snmp_v3_user.clone(),
        Some(args.snmp_v3_auth_proto.clone()),
        args.snmp_v3_auth_pass.clone(),
        Some(args.snmp_v3_priv_proto.clone()),
        args.snmp_v3_priv_pass.clone(),
    );

    let config = ScanConfig {
        targets,
        ping_timeout: Duration::from_millis(args.ping_timeout),
        ping_concurrency: args.concurrency,
        ports: args.ports.unwrap_or_else(|| DEFAULT_PORTS.to_vec()),
        port_timeout: Duration::from_millis(500),
        port_concurrency: 128,
        arp_lookup: !args.no_arp,
        rdns: !args.no_rdns,
        snmp_community: args.snmp_community,
        snmp_config,
    };

    let (tx, mut rx) = broadcast::channel::<ScanEvent>(256);

    // Spawn progress printer
    let output_format = args.output.clone();
    let progress_handle = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            match &event {
                ScanEvent::PhaseStarted { phase } => {
                    if output_format == "text" {
                        eprintln!("[*] Starting: {}", phase);
                    }
                }
                ScanEvent::HostDiscovered { ip } => {
                    if output_format == "text" {
                        eprintln!("  [+] Host alive: {}", ip);
                    }
                }
                ScanEvent::Progress { done, total } => {
                    if output_format == "text" {
                        eprint!("\r  Scanning: {}/{}", done, total);
                    }
                }
                ScanEvent::PhaseCompleted { phase } => {
                    if output_format == "text" {
                        eprintln!("\n[*] Completed: {}", phase);
                    }
                }
                ScanEvent::ScanCompleted { .. } => break,
                _ => {}
            }
        }
    });

    let result = nmapper_core::engine::run_scan(&config, &tx).await?;

    let _ = progress_handle.await;

    match args.output.as_str() {
        "json" => print_json(&result)?,
        "csv" => print_csv(&result),
        _ => print_table(&result),
    }

    Ok(())
}

fn print_table(result: &ScanResult) {
    println!(
        "\nScan complete: {} devices found in {:.1}s\n",
        result.devices.len(),
        (result.completed_at - result.started_at).num_milliseconds() as f64 / 1000.0
    );

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        "IP Address",
        "MAC",
        "Vendor",
        "Hostname",
        "Type",
        "OS",
        "Open Ports",
    ]);

    for device in &result.devices {
        let mac = device.mac.as_deref().unwrap_or("-");
        let vendor = device.vendor.as_deref().unwrap_or("-");
        let hostname = device.hostname.as_deref().unwrap_or("-");
        let os = device.os_guess.as_deref().unwrap_or("-");
        let ports: String = device
            .ports
            .iter()
            .map(|p| {
                if let Some(svc) = &p.service {
                    format!("{}/{}", p.port, svc)
                } else {
                    p.port.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");

        let type_color = match device.device_type {
            DeviceType::Router => Color::Green,
            DeviceType::Switch => Color::Cyan,
            DeviceType::Firewall => Color::Red,
            DeviceType::Server => Color::Yellow,
            DeviceType::Printer => Color::Magenta,
            DeviceType::AccessPoint => Color::Blue,
            _ => Color::White,
        };

        table.add_row(vec![
            Cell::new(device.ip),
            Cell::new(mac),
            Cell::new(vendor),
            Cell::new(hostname),
            Cell::new(device.device_type).fg(type_color),
            Cell::new(os),
            Cell::new(if ports.is_empty() { "-".into() } else { ports }),
        ]);
    }

    println!("{table}");
}

fn print_json(result: &ScanResult) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(result)?);
    Ok(())
}

fn print_csv(result: &ScanResult) {
    println!("IP,MAC,Vendor,Hostname,Type,OS,Open Ports");
    for d in &result.devices {
        let ports: String = d
            .ports
            .iter()
            .map(|p| p.port.to_string())
            .collect::<Vec<_>>()
            .join(";");
        println!(
            "{},{},{},{},{},{},{}",
            d.ip,
            d.mac.as_deref().unwrap_or(""),
            d.vendor.as_deref().unwrap_or(""),
            d.hostname.as_deref().unwrap_or(""),
            d.device_type,
            d.os_guess.as_deref().unwrap_or(""),
            ports,
        );
    }
}
