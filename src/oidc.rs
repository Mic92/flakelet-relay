//! OIDC client bits shared by the relay (discovery, JWKS) and push
//! (device flow, refresh).

use std::fmt::Write as _;
use std::time::Duration;

use http_body_util::BodyExt as _;
use hyper::Request;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::client::{Client, Url};
use crate::http::Body;

#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub jwks_uri: String,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tokens {
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    5
}

async fn read<T: DeserializeOwned>(
    url: &str,
    resp: hyper::Response<hyper::body::Incoming>,
) -> Result<T, String> {
    let status = resp.status();
    let body = http_body_util::Limited::new(resp.into_body(), 1 << 20)
        .collect()
        .await
        .map_err(|e| format!("{url}: {e}"))?
        .to_bytes();
    serde_json::from_slice(&body).map_err(|e| {
        format!(
            "{url}: {status}: {e}: {}",
            String::from_utf8_lossy(&body).trim()
        )
    })
}

pub async fn get_json<T: DeserializeOwned>(client: &Client, url: &str) -> Result<T, String> {
    let u = Url::parse(url).map_err(|e| e.to_string())?;
    let req = Request::get(if u.path.is_empty() { "/" } else { &u.path })
        .body(Body::empty())
        .map_err(|e| e.to_string())?;
    let resp = client.send(&u, req).await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("{url}: {}", resp.status()));
    }
    read(url, resp).await
}

fn form_encode(fields: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (k, v) in fields {
        if !out.is_empty() {
            out.push('&');
        }
        for (i, s) in [k, v].iter().enumerate() {
            if i == 1 {
                out.push('=');
            }
            for b in s.bytes() {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    out.push(char::from(b));
                } else {
                    let _ = write!(out, "%{b:02X}");
                }
            }
        }
    }
    out
}

#[derive(Debug, Deserialize)]
pub struct OAuthError {
    pub error: String,
    #[serde(default)]
    pub error_description: Option<String>,
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)?;
        if let Some(d) = &self.error_description {
            write!(f, ": {d}")?;
        }
        Ok(())
    }
}

/// `Err` first: replies with only optional fields would match an error
/// body too.
#[derive(Deserialize)]
#[serde(untagged)]
enum Reply<T> {
    Err(OAuthError),
    Ok(T),
}

/// POST a form. OAuth reports errors as `400 {"error": ...}`, returned
/// as the inner `Err` so callers can act on the code.
pub async fn post_form<T: DeserializeOwned>(
    client: &Client,
    url: &str,
    fields: &[(&str, &str)],
) -> Result<Result<T, OAuthError>, String> {
    let u = Url::parse(url).map_err(|e| e.to_string())?;
    let req = Request::post(if u.path.is_empty() { "/" } else { &u.path })
        .header(
            hyper::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(hyper::header::ACCEPT, "application/json")
        .body(Body::from(form_encode(fields)))
        .map_err(|e| e.to_string())?;
    let resp = client.send(&u, req).await.map_err(|e| e.to_string())?;
    Ok(match read(url, resp).await? {
        Reply::Ok(t) => Ok(t),
        Reply::Err(e) => Err(e),
    })
}

pub async fn discover(client: &Client, issuer: &str) -> Result<Discovery, String> {
    get_json(
        client,
        &format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        ),
    )
    .await
}

/// Claims of a JWT without verifying it. For routing (`iss`) and cache
/// expiry (`exp`) only.
#[must_use]
pub fn unverified_claims(token: &str) -> Option<serde_json::Value> {
    use base64::Engine as _;
    let p = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(p)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// OAuth2 device authorization grant. `prompt` is called once with the
/// code the user has to confirm in a browser.
pub async fn device_login(
    client: &Client,
    issuer: &str,
    client_id: &str,
    scope: &str,
    prompt: impl FnOnce(&DeviceCode),
) -> Result<Tokens, String> {
    let d = discover(client, issuer).await?;
    let device_ep = d
        .device_authorization_endpoint
        .ok_or("issuer has no device_authorization_endpoint")?;
    let token_ep = d.token_endpoint.ok_or("issuer has no token_endpoint")?;
    let code: DeviceCode = post_form(
        client,
        &device_ep,
        &[("client_id", client_id), ("scope", scope)],
    )
    .await?
    .map_err(|e| format!("{device_ep}: {e}"))?;
    prompt(&code);
    let mut interval = Duration::from_secs(code.interval.max(1));
    loop {
        tokio::time::sleep(interval).await;
        let fields = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", code.device_code.as_str()),
            ("client_id", client_id),
        ];
        match post_form(client, &token_ep, &fields).await? {
            Ok(t) => return Ok(t),
            Err(e) if e.error == "authorization_pending" => {}
            Err(e) if e.error == "slow_down" => interval += Duration::from_secs(5),
            Err(e) => return Err(e.to_string()),
        }
    }
}

pub async fn refresh(
    client: &Client,
    issuer: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<Tokens, String> {
    let d = discover(client, issuer).await?;
    let token_ep = d.token_endpoint.ok_or("issuer has no token_endpoint")?;
    let fields = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    post_form(client, &token_ep, &fields)
        .await?
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_forms() {
        assert_eq!(
            form_encode(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("scope", "openid groups")
            ]),
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&scope=openid%20groups"
        );
    }
}
