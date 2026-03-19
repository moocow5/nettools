use clap::Args;
use ntrace_core::config::TraceConfig;
use ntrace_core::engine::run_trace;
use ntrace_core::result::{ProbeResult, ProbeStatus};

use crate::util::{parse_duration, parse_method};

#[derive(Args)]
pub struct TraceArgs {
    /// Target host or IP address
    pub target: String,

    /// Probe method: icmp, udp, tcp
    #[arg(short = 'm', long, default_value = "icmp")]
    pub method: String,

    /// First TTL (starting hop)
    #[arg(short = 'f', long, default_value = "1")]
    pub first_ttl: u8,

    /// Maximum TTL (max hops)
    #[arg(short = 'M', long, default_value = "30")]
    pub max_ttl: u8,

    /// Number of probes per hop
    #[arg(short = 'q', long, default_value = "3")]
    pub queries: u8,

    /// Timeout per probe (e.g., "2s", "500ms")
    #[arg(short = 'w', long, default_value = "2s")]
    pub timeout: String,

    /// Delay between probes (e.g., "50ms")
    #[arg(short = 'z', long, default_value = "50ms")]
    pub send_wait: String,

    /// Packet size in bytes
    #[arg(short = 's', long, default_value = "60")]
    pub packet_size: usize,

    /// Port for UDP/TCP probes
    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    /// Output format: text, json, csv
    #[arg(short = 'o', long, default_value = "text")]
    pub output: String,
}

pub async fn run(args: TraceArgs) -> Result<(), Box<dyn std::error::Error>> {
    let method = parse_method(&args.method)?;
    let timeout = parse_duration(&args.timeout)?;
    let send_wait = parse_duration(&args.send_wait)?;

    let default_port = match method {
        ntrace_core::config::ProbeMethod::Udp => 33434,
        ntrace_core::config::ProbeMethod::TcpSyn => 80,
        ntrace_core::config::ProbeMethod::Icmp => 0,
    };

    let config = TraceConfig {
        target: args.target.clone(),
        method,
        first_ttl: args.first_ttl,
        max_ttl: args.max_ttl,
        probes_per_hop: args.queries,
        timeout,
        send_interval: send_wait,
        port: args.port.unwrap_or(default_port),
        packet_size: args.packet_size,
        concurrent: false,
        max_inflight: 16,
        paris_mode: false,
    };

    let socket = ntrace_core::TraceSocket::new()?;

    // Print header
    if args.output == "text" {
        println!(
            "traceroute to {} ({}), {} hops max, {} byte packets",
            args.target, config.target, config.max_ttl, config.packet_size,
        );
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProbeResult>(256);

    // Spawn the trace engine
    let trace_config = config.clone();
    let trace_handle = tokio::spawn(async move {
        run_trace(&trace_config, &socket, tx).await
    });

    // Collect results for output
    let mut all_probes: Vec<ProbeResult> = Vec::new();
    let mut current_ttl: u8 = 0;
    let mut ttl_probes: Vec<ProbeResult> = Vec::new();

    while let Some(result) = rx.recv().await {
        if args.output == "text" {
            // Print in classic traceroute format
            if result.ttl != current_ttl {
                // Print previous TTL line if any
                if current_ttl > 0 {
                    print_hop_line(current_ttl, &ttl_probes);
                }
                current_ttl = result.ttl;
                ttl_probes.clear();
            }
            ttl_probes.push(result.clone());
        }
        all_probes.push(result);
    }

    // Print last TTL line
    if args.output == "text" && !ttl_probes.is_empty() {
        print_hop_line(current_ttl, &ttl_probes);
    }

    // Wait for trace to complete
    let trace_result = trace_handle.await??;

    // Handle non-text outputs
    match args.output.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&trace_result)?);
        }
        "csv" => {
            let mut wtr = csv::Writer::from_writer(std::io::stdout());
            wtr.write_record(["ttl", "probe", "source", "rtt_ms", "status"])?;
            for probe in &all_probes {
                wtr.write_record([
                    probe.ttl.to_string(),
                    probe.probe_num.to_string(),
                    probe
                        .source
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "*".to_string()),
                    probe
                        .rtt_ms()
                        .map(|ms| format!("{:.3}", ms))
                        .unwrap_or_else(|| "*".to_string()),
                    probe.status.to_string(),
                ])?;
            }
            wtr.flush()?;
        }
        "text" => {} // already printed
        other => {
            eprintln!("Unknown output format '{}', using text", other);
        }
    }

    Ok(())
}

fn print_hop_line(ttl: u8, probes: &[ProbeResult]) {
    use std::io::Write;

    // Check if all probes were timeouts
    let all_timeout = probes.iter().all(|p| p.status == ProbeStatus::Timeout);
    if all_timeout {
        println!("{:>2}  * * *", ttl);
        return;
    }

    // Print TTL number and responding IP
    print!("{:>2}  ", ttl);

    let addr = probes.iter().find_map(|p| p.source);
    if let Some(ip) = addr {
        print!("{}", ip);
    }

    for probe in probes {
        match probe.status {
            ProbeStatus::Timeout => print!("  *"),
            ProbeStatus::Error => print!("  !E"),
            _ => {
                if let Some(ms) = probe.rtt_ms() {
                    print!("  {:.3} ms", ms);
                } else {
                    print!("  *");
                }
            }
        }
    }
    println!();

    std::io::stdout().flush().ok();
}
