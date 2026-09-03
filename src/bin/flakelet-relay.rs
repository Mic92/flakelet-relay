use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use flakelet_relay::auth::issuers::Issuers;
use flakelet_relay::auth::policy::Policy;
use flakelet_relay::client::Client;
use flakelet_relay::relay::config::Config;
use flakelet_relay::relay::server;
use flakelet_relay::relay::state::Relay;
use flakelet_relay::{logging, tls};

#[derive(Parser)]
#[command(version, about = "Relay between CI and flakelet agents")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the relay.
    Serve {
        #[arg(long)]
        config: PathBuf,
        /// JWKS cache directory; defaults to $CACHE_DIRECTORY.
        #[arg(long, env = "CACHE_DIRECTORY")]
        cache_dir: Option<PathBuf>,
    },
    /// Evaluate policy offline: exit 0 if every target is allowed.
    CheckPolicy {
        config: PathBuf,
        /// Principals, then `--`, then host/flakelet targets.
        #[arg(required = true, num_args = 1..)]
        principals: Vec<String>,
        #[arg(last = true, required = true)]
        targets: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    logging::init();
    match Cli::parse().cmd {
        Cmd::Serve { config, cache_dir } => match serve(config, cache_dir).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                tracing::error!("{e}");
                ExitCode::FAILURE
            }
        },
        Cmd::CheckPolicy {
            config,
            principals,
            targets,
        } => check_policy(&config, &principals, &targets),
    }
}

async fn serve(path: PathBuf, cache_dir: Option<PathBuf>) -> Result<(), String> {
    let cfg = Config::load(&path)?;
    let issuer_client =
        Client::new(tls::client(cfg.issuer_ca_file.as_deref(), None).map_err(|e| e.to_string())?);
    let issuers = Issuers::new(cfg.issuers.clone(), cache_dir, issuer_client);
    let relay = Arc::new(Relay::new(cfg.clone(), issuers));

    let mut tasks = tokio::task::JoinSet::new();
    if let Some(addr) = cfg.listen_http {
        tasks.spawn(server::run_http(relay.clone(), addr));
    }
    if let (Some(addr), Some(t)) = (cfg.listen_tls, &cfg.tls) {
        let server_cfg = tls::server(&t.cert, &t.key, &t.client_cas).map_err(|e| e.to_string())?;
        tasks.spawn(server::run_tls(relay.clone(), addr, server_cfg));
    }
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
    tokio::select! {
        r = tasks.join_next() => match r {
            Some(Ok(Err(e))) => Err(e.to_string()),
            Some(Err(e)) => Err(e.to_string()),
            _ => Ok(()),
        },
        () = logging::shutdown_signal() => Ok(()),
    }
}

fn check_policy(config: &PathBuf, principals: &[String], targets: &[String]) -> ExitCode {
    let data = match std::fs::read(config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{}: {e}", config.display());
            return ExitCode::FAILURE;
        }
    };
    let policy: Policy = match serde_json::from_slice(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}: {e}", config.display());
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = policy.validate() {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    let mut ok = true;
    for t in targets {
        let Some((h, f)) = t.split_once('/') else {
            eprintln!("{t}: not host/flakelet");
            return ExitCode::FAILURE;
        };
        if let Some(r) = policy.rule_for(principals, h, f) {
            println!("{t}\tallowed by {r}");
        } else {
            println!("{t}\tdenied");
            ok = false;
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
