use std::net::SocketAddr;
use std::time::Duration;

use clap::Args;
use nmapper_core::config::{SnmpConfig, DEFAULT_PORTS};
use nmapper_core::result::ScanEvent;
use nmapper_core::scheduler::{run_scheduled, ScheduleConfig};
use tokio::sync::broadcast;

#[derive(Args)]
pub struct ScheduleArgs {
    /// Targets to scan (subnets, ranges, IPs)
    pub target: Vec<String>,

    /// Scan interval in minutes
    #[arg(long, default_value = "60")]
    pub interval: u64,

    /// Database path
    #[arg(long, default_value = "nmapper.db")]
    pub db: String,

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

    /// SNMP v2c community string
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

    /// Launch web dashboard alongside scheduled scans
    #[arg(long)]
    pub dashboard: bool,

    /// Dashboard bind address (only with --dashboard)
    #[arg(long, default_value = "127.0.0.1:9092")]
    pub bind: String,
}

pub async fn run(args: ScheduleArgs) -> anyhow::Result<()> {
    if args.target.is_empty() {
        anyhow::bail!("no targets specified");
    }

    let snmp_config = SnmpConfig::from_flags(
        args.snmp_community.clone(),
        args.snmp_v3_user.clone(),
        Some(args.snmp_v3_auth_proto.clone()),
        args.snmp_v3_auth_pass.clone(),
        Some(args.snmp_v3_priv_proto.clone()),
        args.snmp_v3_priv_pass.clone(),
    );

    let config = ScheduleConfig {
        targets: args.target,
        interval: Duration::from_secs(args.interval * 60),
        db_path: args.db,
        ports: args.ports.unwrap_or_else(|| DEFAULT_PORTS.to_vec()),
        snmp_community: args.snmp_community,
        snmp_config,
        ping_timeout: Duration::from_millis(args.ping_timeout),
        ping_concurrency: args.concurrency,
        arp_lookup: !args.no_arp,
        rdns: !args.no_rdns,
    };

    let (tx, mut rx) = broadcast::channel::<ScanEvent>(256);

    // Optionally launch unified web dashboard
    if args.dashboard {
        let bind_addr: SocketAddr = args.bind.parse()?;
        let unified_state = nettools_web::AppState::new();
        let mapper_state = unified_state.mapper.clone();
        let mut dash_rx = tx.subscribe();

        // Relay scan results to web dashboard
        tokio::spawn(async move {
            while let Ok(event) = dash_rx.recv().await {
                // Forward all events to the mapper SSE broadcast
                let _ = mapper_state.event_tx().send(event.clone());
                if let ScanEvent::ScanCompleted { result } = &event {
                    mapper_state.update_result(result.clone()).await;
                }
            }
        });

        let dash_config = nettools_web::DashboardConfig { bind_addr };
        tokio::spawn(async move {
            if let Err(e) = nettools_web::serve(dash_config, unified_state).await {
                eprintln!("dashboard error: {}", e);
            }
        });

        eprintln!("[*] Dashboard running at http://{}", bind_addr);
    }

    // Spawn progress printer
    tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            match &event {
                ScanEvent::PhaseStarted { phase } => {
                    eprintln!("[*] Starting: {}", phase);
                }
                ScanEvent::HostDiscovered { ip } => {
                    eprintln!("  [+] Host alive: {}", ip);
                }
                ScanEvent::Progress { done, total } => {
                    eprint!("\r  Scanning: {}/{}", done, total);
                }
                ScanEvent::PhaseCompleted { phase } => {
                    eprintln!("\n[*] Completed: {}", phase);
                }
                ScanEvent::ScanCompleted { result } => {
                    eprintln!(
                        "[*] Scan {} finished: {} devices found",
                        result.scan_id,
                        result.devices.len()
                    );
                }
                _ => {}
            }
        }
    });

    run_scheduled(config, tx).await?;

    Ok(())
}
