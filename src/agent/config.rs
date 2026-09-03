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
    /// Pin for the relay server certificate; WebPKI roots if unset.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub cert: Option<PathBuf>,
    #[serde(default)]
    pub key: Option<PathBuf>,
    /// Prints a bearer token on stdout; used when no cert is configured.
    #[serde(default)]
    pub token_command: Option<Vec<String>>,
    /// Local allowlist, also what `hello` advertises.
    pub flakelets: Vec<String>,
    #[serde(default = "default_flakelet")]
    pub flakelet_command: PathBuf,
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
