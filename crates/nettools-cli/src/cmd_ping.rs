use std::io::Write;
use std::sync::Arc;

use crossterm::style::{Color, Stylize};
use tokio::sync::mpsc;

use nping_core::config::{PayloadPattern, PingConfig, PingMode};
use nping_core::result::{PingResult, PingStatus};
use nping_core::stats::PingStats;
use nping_core::IcmpSocket;

use crate::util::parse_duration;

#[derive(clap::Args)]
pub struct PingArgs {
    /// Target hostname or IP address
    pub target: String,

    /// Number of pings to send (default: infinite)
    #[arg(short = 'c', long)]
    pub count: Option<u64>,

    /// Interval between pings (e.g., "1s", "500ms")
    #[arg(short = 'i', long, default_value = "1s")]
    pub interval: String,

    /// Timeout for each ping
    #[arg(short = 'W', long, default_value = "2s")]
    pub timeout: String,

    /// Payload size in bytes
    #[arg(short = 's', long, default_value = "56")]
    pub size: usize,

    /// IP TTL
    #[arg(short = 't', long)]
    pub ttl: Option<u8>,

    /// IP ToS/DSCP value
    #[arg(long)]
    pub tos: Option<u8>,

    /// Ping mode: icmp, tcp, tcp-connect, udp
    #[arg(short = 'm', long, default_value = "icmp")]
    pub mode: String,

    /// Port for TCP/UDP modes
    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    /// Payload fill pattern: zeros, alt, random, or hex byte (e.g., 0xff)
    #[arg(long)]
    pub pattern: Option<String>,

    /// Quiet mode (only show summary)
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Output format: text (default), json, csv
    #[arg(short = 'o', long)]
    pub output: Option<String>,

    /// Log results to a file (append mode)
    #[arg(long)]
    pub log: Option<String>,
}

/// Format a single `PingResult` as a colored line for the terminal.
fn format_result(result: &PingResult, mode: PingMode) -> String {
    let seq_label = match mode {
        PingMode::Icmp => "icmp_seq",
        PingMode::Tcp | PingMode::TcpConnect => "tcp_seq",
        PingMode::Udp => "udp_seq",
    };

    match result.status {
        PingStatus::Success => {
            let rtt_ms = result
                .rtt_ms()
                .map(|ms| format!("{ms:.3}"))
                .unwrap_or_else(|| "?".into());
            let ttl_str = result
                .ttl
                .map(|t| format!(" ttl={t}"))
                .unwrap_or_default();
            let size_str = if result.packet_size > 0 {
                format!("{} bytes from {}: ", result.packet_size, result.target)
            } else {
                format!("Reply from {}: ", result.target)
            };
            format!(
                "{size_str}{seq_label}={}{ttl_str} time={rtt_ms} ms",
                result.seq,
            )
            .with(Color::Green)
            .to_string()
        }
        PingStatus::Timeout => format!("Request timeout for {seq_label}={}", result.seq)
            .with(Color::Red)
            .to_string(),
        PingStatus::Unreachable => format!(
            "Destination unreachable for {seq_label}={}",
            result.seq,
        )
        .with(Color::Yellow)
        .to_string(),
        PingStatus::Error => format!("Error for {seq_label}={}", result.seq)
            .with(Color::Red)
            .to_string(),
    }
}

/// Print the summary statistics block.
fn print_summary(target: &str, results: &[PingResult]) {
    let stats = PingStats::from_results(results);

    println!();
    println!("--- {target} ping statistics ---");
    println!(
        "{} transmitted, {} received, {:.0}% loss",
        stats.transmitted, stats.received, stats.loss_pct,
    );

    if let (Some(min), Some(avg), Some(max), Some(stddev)) = (
        stats.min_rtt_ms,
        stats.avg_rtt_ms,
        stats.max_rtt_ms,
        stats.stddev_rtt_ms,
    ) {
        println!(
            "rtt min/avg/max/stddev = {min:.3}/{avg:.3}/{max:.3}/{stddev:.3} ms",
        );
    }

    let jitter_str = stats
        .jitter_ms
        .map(|j| format!("{j:.3}"))
        .unwrap_or_else(|| "-".into());
    let mos_str = stats
        .mos
        .map(|m| format!("{m:.2}"))
        .unwrap_or_else(|| "-".into());
    println!("jitter: {jitter_str} ms | MOS: {mos_str}");
}

/// Parse a payload pattern string.
fn parse_pattern(s: &str) -> Result<PayloadPattern, String> {
    match s {
        "zeros" | "0" => Ok(PayloadPattern::Zeros),
        "alt" | "aa" => Ok(PayloadPattern::AltBits),
        "random" | "rand" => Ok(PayloadPattern::Random),
        _ => {
            // Try parsing as hex byte: "0xff" or "ff"
            let s = s.strip_prefix("0x").unwrap_or(s);
            let byte = u8::from_str_radix(s, 16)
                .map_err(|_| format!("invalid pattern: use 'zeros', 'alt', 'random', or a hex byte like '0xff'"))?;
            Ok(PayloadPattern::Byte(byte))
        }
    }
}

/// Main entry point for the `ping` subcommand.
pub async fn run(args: PingArgs) -> Result<(), String> {
    let interval = parse_duration(&args.interval)?;
    let timeout = parse_duration(&args.timeout)?;

    let mode = match args.mode.as_str() {
        "icmp" => PingMode::Icmp,
        "tcp" => PingMode::Tcp,
        "tcp-connect" => PingMode::TcpConnect,
        "udp" => PingMode::Udp,
        other => return Err(format!("unknown ping mode: '{other}'")),
    };

    let payload_pattern = match &args.pattern {
        Some(p) => parse_pattern(p)?,
        None => PayloadPattern::default(),
    };

    let config = PingConfig {
        target: args.target.clone(),
        mode,
        port: args.port,
        count: args.count,
        interval,
        timeout,
        packet_size: args.size,
        ttl: args.ttl,
        tos: args.tos,
        payload_pattern,
    };

    // Validate port requirement for non-ICMP modes.
    if matches!(config.mode, PingMode::Tcp | PingMode::TcpConnect | PingMode::Udp)
        && config.port.is_none()
    {
        return Err("--port is required for TCP/UDP modes".into());
    }

    // Print header.
    let port_str = config
        .port
        .map(|p| format!(":{p}"))
        .unwrap_or_default();
    println!(
        "PING {}{port_str} ({mode} mode):",
        args.target,
    );

    let (tx, mut rx) = mpsc::channel::<PingResult>(128);
    let quiet = args.quiet;
    let output_format = args.output.as_deref().unwrap_or("text");
    let target_display = args.target.clone();

    // Open log file if requested.
    let mut log_file = match &args.log {
        Some(path) => {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("failed to open log file {path}: {e}"))?;
            Some(f)
        }
        None => None,
    };

    // Shared results vector for Ctrl+C summary.
    let results: Arc<tokio::sync::Mutex<Vec<PingResult>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));

    // Create ICMP socket (needed for ICMP mode; other modes manage their own sockets).
    let socket = IcmpSocket::new().map_err(|e| e.to_string())?;

    // Apply socket options.
    if let Some(ttl) = config.ttl {
        socket.set_ttl(ttl).map_err(|e| format!("failed to set TTL: {e}"))?;
    }
    if let Some(tos) = config.tos {
        socket.set_tos(tos).map_err(|e| format!("failed to set ToS: {e}"))?;
    }

    let config_clone = config.clone();

    // Spawn the pinger as an async task.
    let pinger_handle = tokio::spawn(async move {
        if let Err(e) = nping_core::pinger::run(&config_clone, &socket, tx).await {
            eprintln!(
                "{}",
                format!("pinger error: {e}").with(Color::Red)
            );
        }
    });

    // Spawn a Ctrl+C watcher.
    let results_for_ctrlc = Arc::clone(&results);
    let target_for_ctrlc = target_display.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let locked = results_for_ctrlc.lock().await;
            print_summary(&target_for_ctrlc, &locked);
            std::process::exit(0);
        }
    });

    // Receive and display results as they arrive.
    while let Some(result) = rx.recv().await {
        match output_format {
            "json" => {
                if let Ok(json) = serde_json::to_string(&result) {
                    println!("{json}");
                }
            }
            "csv" => {
                if !quiet {
                    let rtt = result.rtt_ms().map(|v| format!("{v:.3}")).unwrap_or_default();
                    let status = format!("{:?}", result.status);
                    println!(
                        "{},{},{},{},{}",
                        result.seq, result.target, rtt, status, result.packet_size
                    );
                }
            }
            _ => {
                if !quiet {
                    println!("{}", format_result(&result, mode));
                }
            }
        }

        // Append to log file if enabled.
        if let Some(ref mut f) = log_file {
            if let Ok(json) = serde_json::to_string(&result) {
                let _ = writeln!(f, "{json}");
            }
        }

        results.lock().await.push(result);
    }

    // Channel closed — pinger finished (finite count).
    let _ = pinger_handle.await;

    let locked = results.lock().await;
    if output_format == "json" {
        // Print summary as JSON too.
        let stats = PingStats::from_results(&locked);
        if let Ok(json) = serde_json::to_string_pretty(&stats) {
            eprintln!("{json}");
        }
    } else {
        print_summary(&target_display, &locked);
    }

    Ok(())
}
