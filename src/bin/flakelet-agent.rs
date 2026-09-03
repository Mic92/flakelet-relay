use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use flakelet_relay::agent::config::Config;
use flakelet_relay::agent::conn::{Conn, Connected};
use flakelet_relay::agent::jobs::Jobs;
use flakelet_relay::client::{Client, Url};
use flakelet_relay::{logging, tls};

#[derive(Parser)]
#[command(version, about = "Runs flakelet updates on request of a relay")]
struct Cli {
    #[arg(long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    logging::init();
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    let cfg = Config::load(&cli.config)?;
    let identity = cfg.cert.as_deref().zip(cfg.key.as_deref());
    let client = Arc::new(Client::new(
        tls::client(cfg.ca_file.as_deref(), identity).map_err(|e| e.to_string())?,
    ));
    let jobs = Jobs::new(cfg.flakelets.clone(), cfg.flakelet_command.clone());
    let urls: Vec<Url> = cfg
        .relays
        .iter()
        .map(|r| Url::parse(r))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;

    let connected = Arc::new(Connected::new(urls.len()));
    for url in urls {
        let conn = Conn {
            url,
            client: client.clone(),
            token_command: cfg.token_command.clone(),
            jobs: jobs.clone(),
            flakelets: cfg.flakelets.clone(),
            connected: connected.clone(),
        };
        tokio::spawn(conn.run());
    }
    // Ready means config loaded, not relay reached, so an agent updated
    // during a relay outage is not rolled back for it.
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
    logging::shutdown_signal().await;
    Ok(())
}
