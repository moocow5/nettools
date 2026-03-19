use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, CellAlignment, Table};
use crossterm::{
    cursor,
    event::{Event, KeyCode, KeyModifiers},
    execute,
    style::{Color, Stylize},
    terminal::{self, ClearType},
};
use tokio::sync::{broadcast, mpsc};

use nping_core::alert::{AlertConfig, FiredAlert};
use nping_core::db::{self, Database};
use nping_core::monitor::{Monitor, MonitorConfig, MonitorEvent, TargetConfig, TargetStats};
use nping_core::stats::PingStats;

#[derive(clap::Args)]
pub struct MonitorArgs {
    /// Path to the targets TOML configuration file
    pub targets: String,

    /// Override ping interval for all targets (e.g., "1s", "500ms")
    #[arg(short = 'i', long)]
    pub interval: Option<String>,

    /// SQLite database file for persistence
    #[arg(long, default_value = "nping.db")]
    pub db: String,
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

struct DashboardState {
    targets: Vec<TargetConfig>,
    stats: HashMap<usize, TargetStats>,
    last_alert: Option<FiredAlert>,
}

impl DashboardState {
    fn new(targets: Vec<TargetConfig>) -> Self {
        Self {
            targets,
            stats: HashMap::new(),
            last_alert: None,
        }
    }

    fn apply_event(&mut self, event: MonitorEvent) {
        match event {
            MonitorEvent::PingResult { .. } => {
                // Raw results are already folded into StatsUpdate.
            }
            MonitorEvent::StatsUpdate { target_id, stats } => {
                self.stats.insert(target_id, stats);
            }
            MonitorEvent::AlertFired { target_id: _, alert } => {
                self.last_alert = Some(alert);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_dashboard(state: &DashboardState) {
    let mut stdout = io::stdout();

    let _ = execute!(
        stdout,
        cursor::MoveTo(0, 0),
        terminal::Clear(ClearType::All)
    );

    let title = format!(
        "nping monitor — {} target{}",
        state.targets.len(),
        if state.targets.len() == 1 { "" } else { "s" }
    );
    let _ = write!(stdout, "{}\r\n\r\n", title.bold());

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            Cell::new("#").set_alignment(CellAlignment::Right),
            Cell::new("Host"),
            Cell::new("Label"),
            Cell::new("Mode"),
            Cell::new("Status"),
            Cell::new("Last RTT"),
            Cell::new("Avg RTT"),
            Cell::new("Loss%"),
            Cell::new("Jitter"),
            Cell::new("MOS"),
        ]);

    for (idx, target) in state.targets.iter().enumerate() {
        let label = target.label.as_deref().unwrap_or("-");

        let (status_str, status_color) = if let Some(ts) = state.stats.get(&idx) {
            if ts.is_up {
                ("UP".to_string(), Color::Green)
            } else {
                ("DOWN".to_string(), Color::Red)
            }
        } else {
            ("--".to_string(), Color::Grey)
        };

        let ping_stats: Option<&PingStats> = state.stats.get(&idx).map(|ts| &ts.stats);

        let last_rtt = state
            .stats
            .get(&idx)
            .and_then(|ts| ts.last_rtt_ms)
            .map(|v| format!("{:.1}ms", v))
            .unwrap_or_else(|| "--".into());

        let avg_rtt = ping_stats
            .and_then(|s| s.avg_rtt_ms)
            .map(|v| format!("{:.1}ms", v))
            .unwrap_or_else(|| "--".into());

        let loss_pct = ping_stats
            .map(|s| format!("{:.1}%", s.loss_pct))
            .unwrap_or_else(|| "--".into());

        let jitter = ping_stats
            .and_then(|s| s.jitter_ms)
            .map(|v| format!("{:.1}ms", v))
            .unwrap_or_else(|| "--".into());

        let mos = ping_stats
            .and_then(|s| s.mos)
            .map(|v| format!("{:.2}", v))
            .unwrap_or_else(|| "--".into());

        let last_rtt_cell = color_rtt_cell(
            &last_rtt,
            state.stats.get(&idx).and_then(|ts| ts.last_rtt_ms),
        );
        let avg_rtt_cell = color_rtt_cell(&avg_rtt, ping_stats.and_then(|s| s.avg_rtt_ms));

        table.add_row(vec![
            Cell::new(idx + 1).set_alignment(CellAlignment::Right),
            Cell::new(&target.host),
            Cell::new(label),
            Cell::new(&target.mode),
            Cell::new(&status_str).fg(comfy_table_color(status_color)),
            last_rtt_cell,
            avg_rtt_cell,
            Cell::new(&loss_pct),
            Cell::new(&jitter),
            Cell::new(&mos),
        ]);
    }

    for line in table.to_string().lines() {
        let _ = write!(stdout, "{}\r\n", line);
    }

    let _ = write!(stdout, "\r\n");
    if let Some(ref alert) = state.last_alert {
        let alert_line = format!("ALERT: {}", alert.message);
        let _ = write!(stdout, "{}\r\n", alert_line.with(Color::Red).bold());
    }

    let _ = write!(
        stdout,
        "\r\n{}",
        "Press 'q' or Ctrl+C to exit.".dark_grey()
    );

    let _ = stdout.flush();
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

fn comfy_table_color(c: Color) -> comfy_table::Color {
    match c {
        Color::Green => comfy_table::Color::Green,
        Color::Red => comfy_table::Color::Red,
        Color::Yellow => comfy_table::Color::Yellow,
        Color::Grey => comfy_table::Color::Grey,
        _ => comfy_table::Color::White,
    }
}

// ---------------------------------------------------------------------------
// TOML config parsing
// ---------------------------------------------------------------------------

/// Intermediate TOML structure supporting a `[global]` section with defaults.
#[derive(serde::Deserialize)]
struct TargetsFile {
    #[serde(default)]
    global: Option<GlobalSection>,
    #[serde(rename = "target")]
    targets: Vec<TargetEntry>,
}

#[derive(serde::Deserialize)]
struct GlobalSection {
    interval: Option<String>,
}

#[derive(serde::Deserialize)]
struct TargetEntry {
    host: String,
    label: Option<String>,
    #[serde(default = "default_mode")]
    mode: String,
    port: Option<u16>,
    interval: Option<String>,
    #[serde(default)]
    alert: Option<AlertConfig>,
}

fn default_mode() -> String {
    "icmp".into()
}

pub fn parse_targets_file(path: &str) -> Result<MonitorConfig, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let file: TargetsFile =
        toml::from_str(&content).map_err(|e| format!("failed to parse {path}: {e}"))?;

    let global_interval = file
        .global
        .as_ref()
        .and_then(|g| g.interval.clone())
        .unwrap_or_else(|| "1s".into());

    let targets: Vec<TargetConfig> = file
        .targets
        .into_iter()
        .map(|entry| TargetConfig {
            host: entry.host,
            label: entry.label,
            mode: entry.mode,
            port: entry.port,
            interval: entry.interval.unwrap_or_else(|| global_interval.clone()),
            alert: entry.alert,
        })
        .collect();

    Ok(MonitorConfig { target: targets })
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(args: MonitorArgs) -> Result<(), String> {
    let mut config = parse_targets_file(&args.targets)?;

    // CLI-level interval override applies to all targets.
    if let Some(ref interval) = args.interval {
        for t in &mut config.target {
            t.interval = interval.clone();
        }
    }

    let targets_snapshot = config.target.clone();

    // Open SQLite database for persistence.
    let database = Database::open(&args.db)
        .map_err(|e| format!("failed to open database {}: {e}", args.db))?;
    database
        .migrate()
        .await
        .map_err(|e| format!("db migration failed: {e}"))?;
    let db = Arc::new(database);

    // Create the monitor and subscribe to its event stream.
    let monitor = Monitor::new(config);
    let mut event_rx: broadcast::Receiver<MonitorEvent> = monitor.subscribe();
    let db_event_rx = monitor.subscribe();

    // Spawn DB writer.
    let target_info: Vec<(usize, String, String)> = targets_snapshot
        .iter()
        .enumerate()
        .map(|(id, t)| (id, t.host.clone(), t.mode.clone()))
        .collect();
    let _db_handle = db::spawn_db_writer(Arc::clone(&db), db_event_rx, target_info);

    // Shutdown channel for the monitor.
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    // Set up terminal.
    let _guard = TerminalGuard::new().map_err(|e| format!("terminal setup failed: {e}"))?;

    // Dashboard state.
    let mut state = DashboardState::new(targets_snapshot);

    // Initial render.
    render_dashboard(&state);

    // Spawn the monitor in the background.
    let monitor_handle = tokio::spawn(async move {
        if let Err(e) = monitor.run(shutdown_rx).await {
            tracing::error!("monitor failed: {e}");
        }
    });

    // Main loop — poll at ~200ms.
    loop {
        // Drain all pending events (non-blocking).
        loop {
            match event_rx.try_recv() {
                Ok(ev) => state.apply_event(ev),
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    tracing::warn!("monitor event receiver lagged by {n} messages");
                    break;
                }
                Err(broadcast::error::TryRecvError::Closed) => {
                    return Ok(());
                }
            }
        }

        // Check for keyboard input (non-blocking).
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

    // Signal the monitor to shut down.
    let _ = shutdown_tx.send(()).await;
    // Also abort in case it's stuck.
    monitor_handle.abort();
    let _ = monitor_handle.await;

    Ok(())
}
