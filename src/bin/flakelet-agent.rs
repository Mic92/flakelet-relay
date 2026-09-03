use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use flakelet_relay::agent::config::Config;
use flakelet_relay::agent::conn::{Conn, Connected};
use flakelet_relay::agent::jobs::Jobs;
use flakelet_relay::client::{Client, Url};
use flakelet_relay::{logging, srv, tls};
use tokio::task::JoinHandle;

#[derive(Parser)]
#[command(version, about = "Runs flakelet updates on request of a relay")]
struct Cli {
    #[arg(long)]
    config: PathBuf,
    /// Job table location, defaults to $STATE_DIRECTORY.
    #[arg(
        long,
        env = "STATE_DIRECTORY",
        default_value = "/var/lib/flakelet-agent"
    )]
    state_dir: PathBuf,
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
    let jobs = Jobs::new(
        cfg.flakelets.clone(),
        cfg.flakelet_command.clone(),
        cli.state_dir.join("jobs"),
    );
    let fixed: Vec<Url> = cfg
        .relays
        .iter()
        .map(|r| Url::parse(r))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let connected = Arc::new(Connected::default());
    let spawn = {
        let (client, jobs, connected, cfg) =
            (client.clone(), jobs.clone(), connected.clone(), cfg.clone());
        move |url: Url| {
            let conn = Conn {
                url,
                client: client.clone(),
                token_command: cfg.token_command.clone(),
                jobs: jobs.clone(),
                flakelets: cfg.flakelets.clone(),
                connected: connected.clone(),
            };
            tokio::spawn(conn.run())
        }
    };
    tokio::spawn(async move {
        let mut conns: HashMap<String, JoinHandle<()>> = HashMap::new();
        loop {
            let mut want = fixed.clone();
            let mut refresh = Duration::from_hours(24);
            if let Some(domain) = &cfg.relay_srv {
                match srv::relays(domain).await {
                    Ok((urls, ttl)) => {
                        want.extend(urls);
                        refresh = ttl.max(Duration::from_mins(1));
                    }
                    // Keep the current set on lookup failure.
                    Err(e) => {
                        tracing::warn!("{e}");
                        let retry = if conns.is_empty() { 5 } else { 60 };
                        tokio::time::sleep(Duration::from_secs(retry)).await;
                        continue;
                    }
                }
            }
            let want: HashMap<String, Url> = want.into_iter().map(|u| (u.to_string(), u)).collect();
            conns.retain(|k, h| {
                let keep = want.contains_key(k);
                if !keep {
                    tracing::info!(relay = k, "relay removed");
                    h.abort();
                }
                keep
            });
            for (k, url) in want {
                conns.entry(k).or_insert_with(|| spawn(url));
            }
            connected.set_total(conns.len());
            tokio::time::sleep(refresh).await;
        }
    });
    // Ready means config loaded, not relay reached, so an agent updated
    // during a relay outage is not rolled back for it.
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
    logging::shutdown_signal().await;
    Ok(())
}
