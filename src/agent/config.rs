use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// Relay base URLs (`https://host:port`), all connected at once.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Domain with `_flakelet-relay._tcp` SRV records, re-resolved on TTL
    /// expiry but at most once a minute.
    #[serde(default)]
    pub relay_srv: Option<String>,
    /// Pin for the relay server certificate. WebPKI roots if unset.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub cert: Option<PathBuf>,
    #[serde(default)]
    pub key: Option<PathBuf>,
    /// Prints a bearer token on stdout. Used when no cert is configured.
    #[serde(default)]
    pub token_command: Option<Vec<String>>,
    /// Local allowlist, also what `hello` advertises.
    pub flakelets: Vec<String>,
    #[serde(default = "default_flakelet")]
    pub flakelet_command: PathBuf,
    #[serde(default)]
    pub retention: Retention,
    /// Seconds between `flakelet status` polls for out-of-band changes.
    #[serde(default = "default_status_interval")]
    pub status_interval: u64,
}

fn default_status_interval() -> u64 {
    60
}

/// How long the job table keeps entries. Logs dominate the size, so
/// they go first. Summaries are a few hundred bytes each.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Retention {
    pub keep_jobs_days: u64,
    pub keep_logs_days: u64,
    pub max_jobs: usize,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            keep_jobs_days: 90,
            keep_logs_days: 14,
            max_jobs: 5000,
        }
    }
}

fn default_flakelet() -> PathBuf {
    "flakelet".into()
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let data = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        let cfg: Config =
            serde_json::from_slice(&data).map_err(|e| format!("{}: {e}", path.display()))?;
        if cfg.relays.is_empty() && cfg.relay_srv.is_none() {
            return Err("no relays configured".into());
        }
        if cfg.cert.is_some() != cfg.key.is_some() {
            return Err("cert and key go together".into());
        }
        if cfg.cert.is_none() && cfg.token_command.is_none() {
            return Err("either cert/key or tokenCommand is required".into());
        }
        Ok(cfg)
    }
}
