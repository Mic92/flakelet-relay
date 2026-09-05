//! Configured OIDC issuers with a JWKS cache that survives issuer outages.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use super::jwt::{self, Jwks};
use crate::client::Client;
use crate::oidc;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerConfig {
    /// Issuer URL as it appears in `iss`; discovery is fetched below it.
    pub url: String,
    pub audience: String,
    #[serde(default)]
    pub principal_claims: Vec<String>,
    /// OAuth client for browser login to the dashboard. Its id is
    /// accepted as a second audience.
    #[serde(default)]
    pub login: Option<Login>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    pub client_id: String,
    #[serde(default)]
    pub client_secret_file: Option<PathBuf>,
}

/// Who a verified token speaks for.
pub struct Identity {
    pub principals: Vec<String>,
    /// `preferred_username`, `email` or `sub`, for display only.
    pub name: String,
}

const REFRESH: Duration = Duration::from_mins(10);
pub const MAX_STALE: Duration = Duration::from_hours(24);

struct Cached {
    jwks: Jwks,
    fetched: SystemTime,
    next_try: SystemTime,
}

pub struct Issuers {
    configs: BTreeMap<String, IssuerConfig>,
    cache: Mutex<BTreeMap<String, Cached>>,
    cache_dir: Option<PathBuf>,
    client: Client,
}

impl Issuers {
    #[must_use]
    pub fn new(
        configs: BTreeMap<String, IssuerConfig>,
        cache_dir: Option<PathBuf>,
        client: Client,
    ) -> Self {
        let s = Self {
            configs,
            cache: Mutex::default(),
            cache_dir,
            client,
        };
        s.load_disk();
        s
    }

    fn cache_file(&self, name: &str) -> Option<PathBuf> {
        self.cache_dir
            .as_ref()
            .map(|d| d.join(format!("jwks-{name}.json")))
    }

    fn load_disk(&self) {
        let mut cache = self.cache.lock().expect("poisoned");
        for name in self.configs.keys() {
            let Some(f) = self.cache_file(name) else {
                continue;
            };
            let Ok(data) = std::fs::read(&f) else {
                continue;
            };
            let Ok(jwks) = serde_json::from_slice::<Jwks>(&data) else {
                continue;
            };
            let fetched = std::fs::metadata(&f)
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            cache.insert(
                name.clone(),
                Cached {
                    jwks,
                    fetched,
                    next_try: fetched + REFRESH,
                },
            );
        }
    }

    async fn fetch(&self, cfg: &IssuerConfig) -> Result<Jwks, String> {
        let d = oidc::discover(&self.client, &cfg.url).await?;
        oidc::get_json(&self.client, &d.jwks_uri).await
    }

    /// JWKS for `name`, refreshing if older than 10 min and falling back
    /// to a stale copy for up to 24 h.
    async fn jwks(&self, name: &str, cfg: &IssuerConfig) -> Option<Jwks> {
        let now = SystemTime::now();
        let due = self
            .cache
            .lock()
            .expect("poisoned")
            .get(name)
            .is_none_or(|c| now >= c.next_try);
        if due {
            match self.fetch(cfg).await {
                Ok(jwks) => {
                    if let Some(f) = self.cache_file(name)
                        && let Ok(data) = serde_json::to_vec(&jwks)
                    {
                        let _ = std::fs::write(f, data);
                    }
                    tracing::debug!(issuer = name, keys = jwks.keys.len(), "jwks refreshed");
                    self.cache.lock().expect("poisoned").insert(
                        name.to_owned(),
                        Cached {
                            jwks,
                            fetched: now,
                            next_try: now + REFRESH,
                        },
                    );
                }
                Err(e) => {
                    tracing::warn!(issuer = name, "jwks refresh failed: {e}");
                    if let Some(c) = self.cache.lock().expect("poisoned").get_mut(name) {
                        c.next_try = now + Duration::from_secs(30);
                    }
                }
            }
        }
        let cache = self.cache.lock().expect("poisoned");
        let c = cache.get(name)?;
        if now.duration_since(c.fetched).unwrap_or_default() > MAX_STALE {
            tracing::error!(issuer = name, "jwks older than 24h, refusing");
            return None;
        }
        Some(c.jwks.clone())
    }

    pub fn configs(&self) -> &BTreeMap<String, IssuerConfig> {
        &self.configs
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Principals from the first issuer matching the token's `iss` that
    /// verifies it, else the reason.
    pub async fn authenticate(&self, token: &str) -> Result<Vec<String>, String> {
        self.identify(token).await.map(|i| i.principals)
    }

    pub async fn identify(&self, token: &str) -> Result<Identity, String> {
        let iss = unverified_iss(token).ok_or("malformed token")?;
        let mut last = String::from("unknown issuer");
        for (name, cfg) in &self.configs {
            if cfg.url.trim_end_matches('/') != iss.trim_end_matches('/') {
                continue;
            }
            let Some(jwks) = self.jwks(name, cfg).await else {
                last = "no keys".into();
                continue;
            };
            let mut auds = vec![cfg.audience.as_str()];
            auds.extend(cfg.login.as_ref().map(|l| l.client_id.as_str()));
            match jwt::verify(token, &jwks, &cfg.url, &auds, SystemTime::now()) {
                Ok(claims) => {
                    let name_of = |k: &str| {
                        claims
                            .extra
                            .get(k)
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    };
                    return Ok(Identity {
                        principals: jwt::principals(name, &claims, &cfg.principal_claims),
                        name: name_of("preferred_username")
                            .or_else(|| name_of("email"))
                            .unwrap_or_else(|| claims.sub.clone()),
                    });
                }
                Err(jwt::Error::Issuer) => {}
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }
}

fn unverified_iss(token: &str) -> Option<String> {
    oidc::unverified_claims(token)?
        .get("iss")?
        .as_str()
        .map(str::to_owned)
}
