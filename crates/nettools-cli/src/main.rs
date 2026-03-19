mod cmd_dashboard;
mod cmd_diff;
mod cmd_export;
mod cmd_monitor;
mod cmd_mtr;
mod cmd_ping;
mod cmd_scan;
mod cmd_schedule;
mod cmd_trace;
mod cmd_traps;
pub mod util;

use clap::{Parser, Subcommand};
use crossterm::style::{Color, Stylize};

#[derive(Parser)]
#[command(
    name = "nettools",
    version,
    about = "Unified network toolkit — ping, traceroute, and network mapping"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send ICMP/TCP/UDP pings to a target host
    Ping(cmd_ping::PingArgs),
    /// Monitor multiple targets with a live TUI dashboard
    Monitor(cmd_monitor::MonitorArgs),
    /// Trace the route to a destination host
    Trace(cmd_trace::TraceArgs),
    /// Continuous traceroute with rolling statistics (MTR mode)
    Mtr(cmd_mtr::MtrArgs),
    /// Discover devices on a network
    Scan(cmd_scan::ScanArgs),
    /// Compare two network scans
    Diff(cmd_diff::DiffArgs),
    /// Run network scans on a schedule
    Schedule(cmd_schedule::ScheduleArgs),
    /// Listen for SNMP traps
    Traps(cmd_traps::TrapArgs),
    /// Export stored data (ping, trace, or scan results)
    Export(cmd_export::ExportCommand),
    /// Launch the unified web dashboard
    Dashboard(cmd_dashboard::DashboardArgs),
}

#[tokio::main]
async fn main() {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .init();

    let cli = Cli::parse();

    let result: Result<(), Box<dyn std::error::Error>> = match cli.command {
        Commands::Ping(args) => cmd_ping::run(args).await.map_err(|e| e.into()),
        Commands::Monitor(args) => cmd_monitor::run(args).await.map_err(|e| e.into()),
        Commands::Trace(args) => cmd_trace::run(args).await,
        Commands::Mtr(args) => cmd_mtr::run(args).await,
        Commands::Scan(args) => cmd_scan::run(args).await.map_err(|e| e.into()),
        Commands::Diff(args) => cmd_diff::run(args).await.map_err(|e| e.into()),
        Commands::Schedule(args) => cmd_schedule::run(args).await.map_err(|e| e.into()),
        Commands::Traps(args) => cmd_traps::run(args).await.map_err(|e| e.into()),
        Commands::Export(args) => cmd_export::run(args).await.map_err(|e| e.into()),
        Commands::Dashboard(args) => cmd_dashboard::run(args).await.map_err(|e| e.into()),
    };

    if let Err(e) = result {
        eprintln!("{}", format!("error: {e}").with(Color::Red));
        std::process::exit(1);
    }
}
