//! MTR (My Traceroute) TUI dashboard.

use std::collections::HashMap;
use std::io::{self, Write};
use std::time::Duration;

use clap::Args;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, CellAlignment, Table};
use crossterm::{
    cursor,
    event::{Event, KeyCode, KeyModifiers},
    execute,
    style::Stylize,
    terminal::{self, ClearType},
};
use tokio::sync::{broadcast, mpsc};

use ntrace_core::config::TraceConfig;
use ntrace_core::mtr::{MtrConfig, MtrEngine, MtrEvent};
use ntrace_core::stats::HopStats;

use crate::util::{parse_duration, parse_method};

// ---------------------------------------------------------------------------
// CLI Arguments
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct MtrArgs {
    /// Target host or IP address
    pub target: String,

    /// Probe method: icmp, udp, tcp
    #[arg(short = 'm', long, default_value = "icmp")]
    pub method: String,

    /// Interval between rounds (e.g., "1s", "500ms")
    #[arg(short = 'i', long, default_value = "1s")]
    pub interval: String,

    /// Number of rounds (unlimited if not set)
    #[arg(short = 'c', long)]
    pub count: Option<u64>,

    /// Maximum TTL (max hops)
    #[arg(short = 'M', long, default_value = "30")]
    pub max_ttl: u8,

    /// Number of probes per hop per round
    #[arg(short = 'q', long, default_value = "1")]
    pub queries: u8,

    /// Timeout per probe (e.g., "2s", "500ms")
    #[arg(short = 'w', long, default_value = "2s")]
    pub timeout: String,

    /// Disable reverse DNS lookups
    #[arg(long)]
    pub no_dns: bool,

    /// Enable ASN lookups
    #[arg(long)]
    pub asn: bool,

    /// Enable GeoIP lookups (requires enrichment feature)
    #[arg(long)]
    pub geo: bool,
}

// ---------------------------------------------------------------------------
// Terminal restore guard
// ---------------------------------------------------------------------------

struct TerminalGuard;

impl TerminalGuard {
    fn new() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(
            stdout,
            terminal::EnterAlternateScreen,
            cursor::Hide,
            terminal::Clear(ClearType::All)
        )?;
        Ok(TerminalGuard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let mut stdout = io::stdout();
        let _ = execute!(stdout, cursor::Show, terminal::LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

// ---------------------------------------------------------------------------
// Dashboard state
// ---------------------------------------------------------------------------

struct HopData {
    stats: HopStats,
    hostname: Option<String>,
    asn: Option<u32>,
    asn_name: Option<String>,
}

struct MtrState {
    target: String,
    hops: HashMap<u8, HopData>,
    max_ttl_seen: u8,
    round: u64,
    reached: bool,
}

impl MtrState {
    fn new(target: String) -> Self {
        Self {
            target,
            hops: HashMap::new(),
            max_ttl_seen: 0,
            round: 0,
            reached: false,
        }
    }

    fn apply_event(&mut self, event: MtrEvent) {
        match event {
            MtrEvent::ProbeResult { .. } => {
                // Individual results are folded into HopUpdate
            }
            MtrEvent::HopUpdate {
                ttl,
                stats,
                hostname,
                asn,
                asn_name,
            } => {
                self.hops.insert(
                    ttl,
                    HopData {
                        stats,
                        hostname,
                        asn,
                        asn_name,
                    },
                );
            }
            MtrEvent::PathChange { .. } => {
                // Could display path change indicator; for now we just update via HopUpdate
            }
            MtrEvent::RoundComplete {
                round,
                reached_destination,
                max_ttl_seen,
            } => {
                self.round = round;
                self.reached = reached_destination;
                if max_ttl_seen > self.max_ttl_seen {
                    self.max_ttl_seen = max_ttl_seen;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_dashboard(state: &MtrState) {
    let mut stdout = io::stdout();

    let _ = execute!(
        stdout,
        cursor::MoveTo(0, 0),
        terminal::Clear(ClearType::All)
    );

    let title = format!(
        "ntrace mtr to {} — round {}{}",
        state.target,
        state.round,
        if state.reached { " (reached)" } else { "" }
    );
    let _ = write!(stdout, "{}\r\n\r\n", title.bold());

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            Cell::new("#").set_alignment(CellAlignment::Right),
            Cell::new("Host"),
            Cell::new("Loss%"),
            Cell::new("Snt"),
            Cell::new("Last"),
            Cell::new("Avg"),
            Cell::new("Best"),
            Cell::new("Wrst"),
            Cell::new("StDev"),
        ]);

    let max_ttl = state.max_ttl_seen;
    for ttl in 1..=max_ttl {
        if let Some(hop) = state.hops.get(&ttl) {
            let host = format_host(hop);

            let loss_str = format!("{:.1}%", hop.stats.loss_pct);
            let snt_str = hop.stats.sent.to_string();
            let last_str = fmt_rtt(hop.stats.last_rtt_ms);
            let avg_str = fmt_rtt(hop.stats.avg_rtt_ms);
            let best_str = fmt_rtt(hop.stats.min_rtt_ms);
            let wrst_str = fmt_rtt(hop.stats.max_rtt_ms);
            let stdev_str = fmt_rtt(hop.stats.stddev_rtt_ms);

            let loss_cell = color_loss_cell(&loss_str, hop.stats.loss_pct);
            let last_cell = color_rtt_cell(&last_str, hop.stats.last_rtt_ms);
            let avg_cell = color_rtt_cell(&avg_str, hop.stats.avg_rtt_ms);
            let best_cell = color_rtt_cell(&best_str, hop.stats.min_rtt_ms);
            let wrst_cell = color_rtt_cell(&wrst_str, hop.stats.max_rtt_ms);

            table.add_row(vec![
                Cell::new(ttl).set_alignment(CellAlignment::Right),
                Cell::new(&host),
                loss_cell,
                Cell::new(&snt_str),
                last_cell,
                avg_cell,
                best_cell,
                wrst_cell,
                Cell::new(&stdev_str),
            ]);
        } else {
            table.add_row(vec![
                Cell::new(ttl).set_alignment(CellAlignment::Right),
                Cell::new("???"),
                Cell::new("--"),
                Cell::new("--"),
                Cell::new("--"),
                Cell::new("--"),
                Cell::new("--"),
                Cell::new("--"),
                Cell::new("--"),
            ]);
        }
    }

    for line in table.to_string().lines() {
        let _ = write!(stdout, "{}\r\n", line);
    }

    let _ = write!(
        stdout,
        "\r\n{}",
        "Press 'q' or Ctrl+C to exit.".dark_grey()
    );

    let _ = stdout.flush();
}

fn format_host(hop: &HopData) -> String {
    let ip_str = hop
        .stats
        .addr
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "???".to_string());

    let mut parts = Vec::new();

    if let Some(ref name) = hop.hostname {
        parts.push(format!("{} ({})", name, ip_str));
    } else {
        parts.push(ip_str);
    }

    if let Some(asn) = hop.asn {
        if let Some(ref name) = hop.asn_name {
            parts.push(format!("[AS{} {}]", asn, name));
        } else {
            parts.push(format!("[AS{}]", asn));
        }
    }

    parts.join(" ")
}

fn fmt_rtt(rtt: Option<f64>) -> String {
    match rtt {
        Some(ms) => format!("{:.1}", ms),
        None => "--".to_string(),
    }
}

fn color_loss_cell(text: &str, loss_pct: f64) -> Cell {
    let color = if loss_pct > 10.0 {
        comfy_table::Color::Red
    } else if loss_pct > 0.0 {
        comfy_table::Color::Yellow
    } else {
        comfy_table::Color::Green
    };
    Cell::new(text).fg(color)
}

fn color_rtt_cell(text: &str, rtt_ms: Option<f64>) -> Cell {
    let color = match rtt_ms {
        Some(v) if v > 150.0 => comfy_table::Color::Red,
        Some(v) if v > 50.0 => comfy_table::Color::Yellow,
        Some(_) => comfy_table::Color::Green,
        None => comfy_table::Color::White,
    };
    Cell::new(text).fg(color)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(args: MtrArgs) -> Result<(), Box<dyn std::error::Error>> {
    let method = parse_method(&args.method)?;
    let interval = parse_duration(&args.interval)?;
    let timeout = parse_duration(&args.timeout)?;

    let default_port = match method {
        ntrace_core::config::ProbeMethod::Udp => 33434,
        ntrace_core::config::ProbeMethod::TcpSyn => 80,
        ntrace_core::config::ProbeMethod::Icmp => 0,
    };

    let trace_config = TraceConfig {
        target: args.target.clone(),
        method,
        first_ttl: 1,
        max_ttl: args.max_ttl,
        probes_per_hop: args.queries,
        timeout,
        send_interval: Duration::from_millis(50),
        port: default_port,
        packet_size: 60,
        concurrent: false,
        max_inflight: 16,
        paris_mode: false,
    };

    let mtr_config = MtrConfig {
        trace: trace_config,
        interval,
        rolling_window: 100,
        resolve_dns: !args.no_dns,
        lookup_asn: args.asn,
        lookup_geo: args.geo,
        max_rounds: args.count,
    };

    let engine = MtrEngine::new(mtr_config);
    let mut event_rx: broadcast::Receiver<MtrEvent> = engine.subscribe();

    let socket = ntrace_core::TraceSocket::new()?;

    // Shutdown channel
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    // Set up terminal
    let _guard = TerminalGuard::new().map_err(|e| format!("terminal setup failed: {e}"))?;

    // Dashboard state
    let mut state = MtrState::new(args.target.clone());

    // Initial render
    render_dashboard(&state);

    // Spawn the MTR engine
    let engine_handle = tokio::spawn(async move {
        if let Err(e) = engine.run(socket, shutdown_rx).await {
            tracing::error!("mtr engine failed: {e}");
        }
    });

    // Main loop — poll at ~200ms
    loop {
        // Drain all pending events (non-blocking)
        loop {
            match event_rx.try_recv() {
                Ok(ev) => state.apply_event(ev),
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    tracing::warn!("mtr event receiver lagged by {n} messages");
                    break;
                }
                Err(broadcast::error::TryRecvError::Closed) => {
                    // Engine finished (max_rounds reached)
                    // Do one final render and exit
                    render_dashboard(&state);
                    // Wait a moment so user can see final state
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    return Ok(());
                }
            }
        }

        // Check for keyboard input (non-blocking)
        if crossterm::event::poll(Duration::from_millis(0)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = crossterm::event::read() {
                if key.code == KeyCode::Char('q')
                    || (key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL))
                {
                    break;
                }
            }
        }

        render_dashboard(&state);

        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Signal the engine to shut down
    let _ = shutdown_tx.send(()).await;
    engine_handle.abort();
    let _ = engine_handle.await;

    Ok(())
}
