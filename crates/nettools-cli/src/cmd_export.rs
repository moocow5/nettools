//! Unified export command with nested subcommands for ping, trace, and scan data.

use std::io::{self, Write};
use std::path::Path;

use clap::{Args, Subcommand};

// ==========================================================================
// Top-level export command
// ==========================================================================

#[derive(Args)]
pub struct ExportCommand {
    #[command(subcommand)]
    pub command: ExportSubcommand,
}

#[derive(Subcommand)]
pub enum ExportSubcommand {
    /// Export stored ping results to CSV or JSON
    Ping(PingExportArgs),
    /// Export stored traceroute data
    Trace(TraceExportArgs),
    /// Export network scan results to file
    Scan(ScanExportArgs),
}

pub async fn run(args: ExportCommand) -> anyhow::Result<()> {
    match args.command {
        ExportSubcommand::Ping(a) => run_ping_export(a).await.map_err(|e| anyhow::anyhow!(e)),
        ExportSubcommand::Trace(a) => run_trace_export(a).await.map_err(|e| anyhow::anyhow!("{}", e)),
        ExportSubcommand::Scan(a) => run_scan_export(a).await,
    }
}

// ==========================================================================
// Ping export (from nping-cli/src/cmd_export.rs)
// ==========================================================================

#[derive(Args)]
pub struct PingExportArgs {
    /// Target host to export data for (omit to list available targets)
    #[arg(long)]
    pub target: Option<String>,

    /// Output format: csv or json
    #[arg(short = 'f', long)]
    pub format: Option<String>,

    /// Output file path (default: stdout)
    #[arg(short = 'o', long)]
    pub output: Option<String>,

    /// Start of time range (ISO 8601, e.g. "2026-03-16")
    #[arg(long)]
    pub from: Option<String>,

    /// End of time range (ISO 8601, e.g. "2026-03-17")
    #[arg(long)]
    pub to: Option<String>,

    /// Maximum number of results
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,

    /// SQLite database file
    #[arg(long)]
    pub db: Option<String>,
}

async fn run_ping_export(args: PingExportArgs) -> Result<(), String> {
    let db_path = args.db.unwrap_or_else(|| "nping.db".into());

    let db = nping_core::db::Database::open(&db_path)
        .map_err(|e| format!("failed to open database {db_path}: {e}"))?;
    db.migrate()
        .await
        .map_err(|e| format!("db migration failed: {e}"))?;

    // If no target specified, list available hosts.
    let target = match args.target {
        Some(t) => t,
        None => {
            let hosts = db
                .list_hosts()
                .await
                .map_err(|e| format!("failed to list hosts: {e}"))?;
            if hosts.is_empty() {
                return Err("no data in database. Run 'nettools dashboard' or 'nettools monitor' with --db first.".into());
            }
            eprintln!("Available targets in {}:", db_path);
            for h in &hosts {
                eprintln!("  {h}");
            }
            return Err("specify a target with --target <host>".into());
        }
    };

    // Parse time range.
    let from_ms = args.from.as_ref().map(|s| parse_datetime_ms(s)).transpose()?;
    let to_ms = args.to.as_ref().map(|s| parse_datetime_ms(s)).transpose()?;

    let rows = db
        .query_results(&target, from_ms, to_ms, args.limit)
        .await
        .map_err(|e| format!("query failed: {e}"))?;

    if rows.is_empty() {
        return Err(format!("no results found for target '{target}'"));
    }

    eprintln!("Exporting {} results for {target}", rows.len());

    let format = args.format.as_deref().unwrap_or("csv");

    match format {
        "csv" => export_ping_csv(&rows, args.output.as_deref())?,
        "json" => export_ping_json(&rows, args.output.as_deref())?,
        other => return Err(format!("unknown format '{other}', use 'csv' or 'json'")),
    }

    Ok(())
}

fn export_ping_csv(
    rows: &[nping_core::db::ExportRow],
    output: Option<&str>,
) -> Result<(), String> {
    let writer: Box<dyn Write> = match output {
        Some(path) => {
            let f = std::fs::File::create(path)
                .map_err(|e| format!("failed to create {path}: {e}"))?;
            Box::new(f)
        }
        None => Box::new(io::stdout()),
    };

    let mut wtr = csv::Writer::from_writer(writer);

    wtr.write_record([
        "timestamp",
        "host",
        "mode",
        "seq",
        "rtt_ms",
        "rtt_us",
        "ttl",
        "packet_size",
        "status",
    ])
    .map_err(|e| format!("csv write error: {e}"))?;

    for row in rows {
        let ts = chrono::DateTime::from_timestamp_millis(row.timestamp_ms as i64)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| row.timestamp_ms.to_string());

        wtr.write_record(&[
            ts,
            row.host.clone(),
            row.mode.clone(),
            row.seq.to_string(),
            row.rtt_ms()
                .map(|v| format!("{:.3}", v))
                .unwrap_or_default(),
            row.rtt_us
                .map(|v| format!("{:.1}", v))
                .unwrap_or_default(),
            row.ttl
                .map(|t| t.to_string())
                .unwrap_or_default(),
            row.packet_size.to_string(),
            row.status.clone(),
        ])
        .map_err(|e| format!("csv write error: {e}"))?;
    }

    wtr.flush().map_err(|e| format!("csv flush error: {e}"))?;

    if let Some(path) = output {
        eprintln!("Written to {path}");
    }

    Ok(())
}

fn export_ping_json(
    rows: &[nping_core::db::ExportRow],
    output: Option<&str>,
) -> Result<(), String> {
    let json = serde_json::to_string_pretty(rows)
        .map_err(|e| format!("json serialization error: {e}"))?;

    match output {
        Some(path) => {
            std::fs::write(path, &json)
                .map_err(|e| format!("failed to write {path}: {e}"))?;
            eprintln!("Written to {path}");
        }
        None => {
            println!("{json}");
        }
    }

    Ok(())
}

/// Parse a datetime string into milliseconds since epoch.
fn parse_datetime_ms(s: &str) -> Result<i64, String> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.timestamp_millis());
    }
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(ndt.and_utc().timestamp_millis());
    }
    if let Ok(nd) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let ndt = nd.and_hms_opt(0, 0, 0).unwrap();
        return Ok(ndt.and_utc().timestamp_millis());
    }
    Err(format!(
        "invalid date format '{s}', use ISO 8601 (e.g. 2026-03-16 or 2026-03-16T12:00:00)"
    ))
}

// ==========================================================================
// Trace export (from ntrace-cli/src/cmd_export.rs)
// ==========================================================================

#[derive(Args)]
pub struct TraceExportArgs {
    /// Filter by target host or IP
    #[arg(long)]
    pub target: Option<String>,

    /// Output format: json, csv
    #[arg(short = 'f', long, default_value = "json")]
    pub format: String,

    /// Write output to a file instead of stdout
    #[arg(short = 'o', long)]
    pub output: Option<String>,

    /// Export a specific trace run by ID
    #[arg(long)]
    pub trace_id: Option<String>,

    /// Maximum number of runs to display
    #[arg(long, default_value = "50")]
    pub limit: usize,

    /// Path to the database file
    #[arg(long, default_value = "ntrace.db")]
    pub db: String,
}

async fn run_trace_export(args: TraceExportArgs) -> Result<(), Box<dyn std::error::Error>> {
    let db = ntrace_core::db::TraceDatabase::open(&args.db)?;
    db.migrate().await?;

    // If a specific trace_id is given, export its hops.
    if let Some(ref trace_id) = args.trace_id {
        let hops = db.query_hops(trace_id).await?;
        if hops.is_empty() {
            eprintln!("No hops found for trace_id '{}'", trace_id);
            return Ok(());
        }
        let output_str = format_trace_hops(&hops, &args.format)?;
        write_trace_output(&output_str, args.output.as_deref())?;
        return Ok(());
    }

    // If a target is given, show recent runs for that target.
    if let Some(ref target) = args.target {
        let runs = db.query_runs(Some(target), args.limit).await?;
        if runs.is_empty() {
            eprintln!("No runs found for target '{}'", target);
            return Ok(());
        }
        let output_str = format_trace_runs(&runs, &args.format)?;
        write_trace_output(&output_str, args.output.as_deref())?;
        return Ok(());
    }

    // Default: list available targets and recent runs.
    let targets = db.list_targets().await?;
    if targets.is_empty() {
        eprintln!("No trace data found in '{}'", args.db);
        return Ok(());
    }

    println!("Available targets:");
    for t in &targets {
        println!("  {}", t);
    }
    println!();

    let runs = db.query_runs(None, args.limit).await?;
    if !runs.is_empty() {
        println!("Recent runs:");
        println!(
            "{:<38} {:<20} {:<8} {:<14} {}",
            "TRACE ID", "TARGET", "METHOD", "STARTED", "REACHED"
        );
        for run in &runs {
            let started = format_trace_timestamp(run.started_at);
            let reached = if run.reached_dest { "yes" } else { "no" };
            println!(
                "{:<38} {:<20} {:<8} {:<14} {}",
                run.trace_id, run.target, run.method, started, reached
            );
        }
    }

    Ok(())
}

fn format_trace_runs(
    runs: &[ntrace_core::db::TraceRunRow],
    format: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match format {
        "json" => Ok(serde_json::to_string_pretty(runs)?),
        "csv" => {
            let mut wtr = csv::Writer::from_writer(Vec::new());
            wtr.write_record(["trace_id", "target", "method", "started_at", "completed_at", "reached_dest"])?;
            for run in runs {
                wtr.write_record([
                    &run.trace_id,
                    &run.target,
                    &run.method,
                    &run.started_at.to_string(),
                    &run.completed_at.map(|v| v.to_string()).unwrap_or_default(),
                    &run.reached_dest.to_string(),
                ])?;
            }
            wtr.flush()?;
            Ok(String::from_utf8(wtr.into_inner()?)?)
        }
        other => Err(format!("unknown format '{}': use json or csv", other).into()),
    }
}

fn format_trace_hops(
    hops: &[ntrace_core::db::TraceHopRow],
    format: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match format {
        "json" => Ok(serde_json::to_string_pretty(hops)?),
        "csv" => {
            let mut wtr = csv::Writer::from_writer(Vec::new());
            wtr.write_record([
                "ttl",
                "probe_num",
                "source_ip",
                "rtt_us",
                "status",
                "hostname",
                "asn",
                "asn_name",
                "country",
                "city",
                "timestamp_ms",
            ])?;
            for hop in hops {
                wtr.write_record([
                    &hop.ttl.to_string(),
                    &hop.probe_num.to_string(),
                    &hop.source_ip.clone().unwrap_or_default(),
                    &hop.rtt_us.map(|v| format!("{:.1}", v)).unwrap_or_default(),
                    &hop.status,
                    &hop.hostname.clone().unwrap_or_default(),
                    &hop.asn.map(|v| v.to_string()).unwrap_or_default(),
                    &hop.asn_name.clone().unwrap_or_default(),
                    &hop.country.clone().unwrap_or_default(),
                    &hop.city.clone().unwrap_or_default(),
                    &hop.timestamp_ms.to_string(),
                ])?;
            }
            wtr.flush()?;
            Ok(String::from_utf8(wtr.into_inner()?)?)
        }
        other => Err(format!("unknown format '{}': use json or csv", other).into()),
    }
}

fn write_trace_output(content: &str, path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    match path {
        Some(p) => {
            std::fs::write(p, content)?;
            eprintln!("Output written to {}", p);
        }
        None => {
            println!("{}", content);
        }
    }
    Ok(())
}

fn format_trace_timestamp(ms: u64) -> String {
    let secs = ms / 1000;
    let naive = chrono::DateTime::from_timestamp(secs as i64, 0);
    match naive {
        Some(dt) => dt.format("%Y-%m-%d %H:%M").to_string(),
        None => ms.to_string(),
    }
}

// ==========================================================================
// Scan export (from nmapper-cli/src/cmd_export.rs)
// ==========================================================================

#[derive(Args)]
pub struct ScanExportArgs {
    /// Export format: svg, vsdx, json, csv
    #[arg(short, long)]
    pub format: String,

    /// Output file path
    #[arg(short, long)]
    pub output: String,

    /// Database path
    #[arg(long, default_value = "nmapper.db")]
    pub db: String,

    /// Scan ID to export (latest if not specified)
    #[arg(long)]
    pub scan_id: Option<String>,
}

async fn run_scan_export(args: ScanExportArgs) -> anyhow::Result<()> {
    let db = nmapper_core::db::Database::open(&args.db)?;
    db.migrate().await?;

    let scan_id = match args.scan_id {
        Some(id) => id,
        None => {
            let scans = db.list_scans().await?;
            if scans.is_empty() {
                anyhow::bail!("No scans found in database");
            }
            scans[0].scan_id.clone()
        }
    };

    let result = db
        .load_scan(&scan_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Scan '{}' not found", scan_id))?;

    match args.format.as_str() {
        "json" => {
            let json = nmapper_core::export::json_export::export_json(&result)?;
            std::fs::write(&args.output, json)?;
        }
        "csv" => {
            let csv = nmapper_core::export::csv_export::export_csv(&result);
            std::fs::write(&args.output, csv)?;
        }
        "svg" => {
            let graph = nmapper_core::topology::TopologyGraph::from_scan(&result.devices, &result.links);
            let layout = nmapper_core::layout::compute_layout(&graph);
            let svg_content = nmapper_core::export::svg::export_svg(&layout, &result.devices);
            std::fs::write(&args.output, svg_content)?;
        }
        "vsdx" => {
            let graph = nmapper_core::topology::TopologyGraph::from_scan(&result.devices, &result.links);
            let layout = nmapper_core::layout::compute_layout(&graph);
            nmapper_core::export::vsdx::export_vsdx(&layout, &result.devices, Path::new(&args.output))?;
        }
        other => {
            anyhow::bail!(
                "Unsupported export format: '{}'. Supported formats: json, csv, svg, vsdx",
                other
            );
        }
    }

    eprintln!("Exported scan '{}' to {}", scan_id, args.output);
    Ok(())
}
