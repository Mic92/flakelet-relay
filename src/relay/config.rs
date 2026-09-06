use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::auth::issuers::IssuerConfig;
use crate::auth::policy::Policy;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tls {
    pub cert: PathBuf,
    pub key: PathBuf,
    #[serde(default, rename = "clientCAs")]
    pub client_cas: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// Shown in `accepted` and `welcome` so logs say which relay handled a job.
    pub name: String,
    /// Bearer-only HTTP listener for nginx to proxy to.
    #[serde(default)]
    pub listen_http: Option<SocketAddr>,
    /// TLS listener for agents and cert-bearing clients.
    #[serde(default)]
    pub listen_tls: Option<SocketAddr>,
    #[serde(default)]
    pub tls: Option<Tls>,
    #[serde(default)]
    pub issuers: BTreeMap<String, IssuerConfig>,
    /// CA bundle for talking to issuers. WebPKI roots if unset.
    #[serde(default)]
    pub issuer_ca_file: Option<PathBuf>,
    #[serde(flatten)]
    pub policy: Policy,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let data = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        let cfg: Config =
            serde_json::from_slice(&data).map_err(|e| format!("{}: {e}", path.display()))?;
        cfg.policy.validate()?;
        if cfg.listen_tls.is_some() && cfg.tls.is_none() {
            return Err("listenTls needs tls.cert and tls.key".into());
        }
        if cfg.listen_http.is_none() && cfg.listen_tls.is_none() {
            return Err("neither listenHttp nor listenTls set".into());
        }
        Ok(cfg)
    }
}
