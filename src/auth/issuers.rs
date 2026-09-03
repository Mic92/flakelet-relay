//! Configured OIDC issuers with a JWKS cache that survives issuer outages.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use http_body_util::BodyExt as _;
use hyper::Request;
use serde::Deserialize;

use super::jwt::{self, JtiSet, Jwks};
use crate::client::{Client, Url};
use crate::http::Body;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerConfig {
    /// Issuer URL as it appears in `iss`; discovery is fetched below it.
    pub url: String,
    pub audience: String,
    #[serde(default)]
    pub principal_claims: Vec<String>,
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
    jti: JtiSet,
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
            jti: JtiSet::default(),
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

    async fn get_json<T: for<'a> Deserialize<'a>>(&self, url: &str) -> Result<T, String> {
        let u = Url::parse(url).map_err(|e| e.to_string())?;
        let req = Request::get(if u.path.is_empty() { "/" } else { &u.path })
            .body(Body::empty())
            .map_err(|e| e.to_string())?;
        let resp = self.client.send(&u, req).await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("{url}: {}", resp.status()));
        }
        let body = http_body_util::Limited::new(resp.into_body(), 1 << 20)
            .collect()
            .await
            .map_err(|e| format!("{url}: {e}"))?
            .to_bytes();
        serde_json::from_slice(&body).map_err(|e| format!("{url}: {e}"))
    }

    async fn fetch(&self, cfg: &IssuerConfig) -> Result<Jwks, String> {
        #[derive(Deserialize)]
        struct Discovery {
            jwks_uri: String,
        }
        let d: Discovery = self
            .get_json(&format!(
                "{}/.well-known/openid-configuration",
                cfg.url.trim_end_matches('/')
            ))
            .await?;
        self.get_json(&d.jwks_uri).await
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

    /// Principals from the first issuer matching the token's `iss` that
    /// verifies it, else the reason.
    pub async fn authenticate(&self, token: &str) -> Result<Vec<String>, String> {
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
            match jwt::verify(token, &jwks, &cfg.url, &cfg.audience, SystemTime::now()) {
                Ok(claims) => {
                    self.jti
                        .check(&claims, SystemTime::now())
                        .map_err(|e| e.to_string())?;
                    return Ok(jwt::principals(name, &claims, &cfg.principal_claims));
                }
                Err(jwt::Error::Issuer) => {}
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }
}

fn unverified_iss(token: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Iss {
        iss: String,
    }
    let p = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(p)
        .ok()?;
    serde_json::from_slice::<Iss>(&bytes).ok().map(|i| i.iss)
}
