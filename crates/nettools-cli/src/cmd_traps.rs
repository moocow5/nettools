use clap::Args;
use nmapper_core::trap::{listen_traps, TrapEvent};
use tokio::sync::broadcast;

#[derive(Args)]
pub struct TrapArgs {
    /// Bind address for trap listener
    #[arg(long, default_value = "0.0.0.0:162")]
    pub bind: String,
}

pub async fn run(args: TrapArgs) -> anyhow::Result<()> {
    let bind_addr = args
        .bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address '{}': {}", args.bind, e))?;

    let (tx, mut rx) = broadcast::channel::<TrapEvent>(256);

    // Spawn the trap listener.
    tokio::spawn(async move {
        if let Err(e) = listen_traps(bind_addr, tx).await {
            eprintln!("trap listener error: {}", e);
        }
    });

    eprintln!("Listening for SNMP traps on {}", bind_addr);

    // Print each received trap as JSON to stdout.
    while let Ok(event) = rx.recv().await {
        match serde_json::to_string(&event) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("failed to serialize trap event: {}", e),
        }
    }

    Ok(())
}
