use clap::Args;
use nmapper_core::db::Database;
use nmapper_core::diff::compare_scans;

#[derive(Args)]
pub struct DiffArgs {
    /// First scan ID (older)
    #[arg(long)]
    pub scan1: Option<String>,

    /// Second scan ID (newer)
    #[arg(long)]
    pub scan2: Option<String>,

    /// Database path
    #[arg(long, default_value = "nmapper.db")]
    pub db: String,

    /// Output format: text, json
    #[arg(short, long, default_value = "text")]
    pub output: String,
}

pub async fn run(args: DiffArgs) -> anyhow::Result<()> {
    let db = Database::open(&args.db)?;
    db.migrate().await?;

    // Determine which two scans to compare.
    let (id1, id2) = match (args.scan1, args.scan2) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            let scans = db.list_scans().await?;
            if scans.len() < 2 {
                anyhow::bail!(
                    "need at least 2 scans in the database to diff (found {})",
                    scans.len()
                );
            }
            // list_scans returns newest first
            (scans[1].scan_id.clone(), scans[0].scan_id.clone())
        }
    };

    let old = db
        .load_scan(&id1)
        .await?
        .ok_or_else(|| anyhow::anyhow!("scan '{}' not found", id1))?;

    let new = db
        .load_scan(&id2)
        .await?
        .ok_or_else(|| anyhow::anyhow!("scan '{}' not found", id2))?;

    let diff = compare_scans(&old, &new);

    match args.output.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&diff)?);
        }
        _ => {
            print!("{}", diff);
        }
    }

    Ok(())
}
