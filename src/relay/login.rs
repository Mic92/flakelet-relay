//! Browser login: OIDC authorization code flow with PKCE against an
//! issuer that has `login` configured. The result is a signed cookie
//! carrying the principals, which the API accepts like a bearer token.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hyper::body::Incoming;
use hyper::{Request, StatusCode};
use ring::digest;
use serde::{Deserialize, Serialize};

use crate::auth::issuers::Identity;
use crate::http::Resp;
use crate::oidc;
use crate::relay::session::{self, cookie, set_cookie};
use crate::relay::state::Relay;
use crate::relay::ui::{fail, query, redirect, with_cookie};

const SESSION: &str = "flr_session";
const LOGIN: &str = "flr_login";
const SESSION_AGE: Duration = Duration::from_hours(12);

#[derive(Serialize, Deserialize)]
pub struct Session {
    #[serde(rename = "p")]
    pub principals: Vec<String>,
    #[serde(rename = "n")]
    pub name: String,
    #[serde(rename = "e")]
    exp: u64,
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The session from the request's cookie, if valid and unexpired.
pub fn current(relay: &Relay, req: &Request<Incoming>) -> Option<Session> {
    let s: Session = relay.signer.open(cookie(req, SESSION)?)?;
    (s.exp > now()).then_some(s)
}

#[derive(Serialize, Deserialize)]
struct LoginState {
    issuer: String,
    state: String,
    verifier: String,
}

/// Where the issuer sends the browser back to. The relay sits behind a
/// proxy or serves TLS itself, so the scheme is always https.
fn redirect_uri(req: &Request<Incoming>) -> String {
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    format!("https://{host}/ui/callback")
}

/// Redirect to the issuer named in `?issuer=`, else the first one with
/// `login` configured.
pub async fn start(relay: &Relay, req: &Request<Incoming>) -> Resp {
    let wanted = query(req, "issuer");
    let Some((name, cfg, l)) = relay
        .issuers
        .configs()
        .iter()
        .filter(|(n, _)| wanted.as_deref().is_none_or(|w| w == n.as_str()))
        .find_map(|(n, c)| Some((n, c, c.login.as_ref()?)))
    else {
        return fail(StatusCode::NOT_FOUND, "no issuer has login configured");
    };
    let d = match oidc::discover(relay.issuers.client(), &cfg.url).await {
        Ok(d) => d,
        Err(e) => return fail(StatusCode::BAD_GATEWAY, &e),
    };
    let Some(authz) = d.authorization_endpoint else {
        return fail(
            StatusCode::BAD_GATEWAY,
            "issuer has no authorization endpoint",
        );
    };
    let st = LoginState {
        issuer: name.clone(),
        state: session::random(),
        verifier: session::random(),
    };
    let challenge = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        digest::digest(&digest::SHA256, st.verifier.as_bytes()),
    );
    let url = format!(
        "{authz}{}{}",
        if authz.contains('?') { '&' } else { '?' },
        oidc::form_encode(&[
            ("response_type", "code"),
            ("client_id", &l.client_id),
            ("redirect_uri", &redirect_uri(req)),
            ("scope", "openid profile email groups"),
            ("state", &st.state),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ])
    );
    with_cookie(
        redirect(&url),
        &set_cookie(LOGIN, &relay.signer.seal(&st), 600),
    )
}

pub async fn callback(relay: &Relay, req: &Request<Incoming>) -> Resp {
    let Some(st) = cookie(req, LOGIN).and_then(|c| relay.signer.open::<LoginState>(c)) else {
        return fail(StatusCode::BAD_REQUEST, "login expired, start over");
    };
    if query(req, "state").as_deref() != Some(st.state.as_str()) {
        return fail(StatusCode::BAD_REQUEST, "state mismatch");
    }
    let Some(code) = query(req, "code") else {
        return fail(
            StatusCode::UNAUTHORIZED,
            &query(req, "error").unwrap_or_else(|| "no code".into()),
        );
    };
    let identity = match exchange(relay, req, &st, &code).await {
        Ok(i) => i,
        Err(e) => {
            tracing::info!(issuer = st.issuer, "login failed: {e}");
            return fail(StatusCode::UNAUTHORIZED, &e);
        }
    };
    tracing::info!(name = identity.name, principals = ?identity.principals, "login");
    let sess = Session {
        principals: identity.principals,
        name: identity.name,
        exp: now() + SESSION_AGE.as_secs(),
    };
    let r = with_cookie(redirect("/ui/"), &set_cookie(LOGIN, "", 0));
    with_cookie(
        r,
        &set_cookie(SESSION, &relay.signer.seal(&sess), SESSION_AGE.as_secs()),
    )
}

async fn exchange(
    relay: &Relay,
    req: &Request<Incoming>,
    st: &LoginState,
    code: &str,
) -> Result<Identity, String> {
    let cfg = relay
        .issuers
        .configs()
        .get(&st.issuer)
        .ok_or("unknown issuer")?;
    let l = cfg.login.as_ref().ok_or("login not configured")?;
    let secret = match &l.client_secret_file {
        Some(f) => tokio::fs::read_to_string(f)
            .await
            .map_err(|e| format!("{}: {e}", f.display()))?,
        None => String::new(),
    };
    let d = oidc::discover(relay.issuers.client(), &cfg.url).await?;
    let token_ep = d.token_endpoint.ok_or("issuer has no token endpoint")?;
    let redirect_uri = redirect_uri(req);
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &redirect_uri),
        ("client_id", &l.client_id),
        ("code_verifier", &st.verifier),
    ];
    if !secret.is_empty() {
        form.push(("client_secret", secret.trim()));
    }
    let t: oidc::Tokens = oidc::post_form(relay.issuers.client(), &token_ep, &form)
        .await?
        .map_err(|e| e.to_string())?;
    let id = t.id_token.ok_or("no id_token in response")?;
    relay.issuers.identify(&id).await
}

pub(crate) fn logout() -> Resp {
    with_cookie(redirect("/ui/login"), &set_cookie(SESSION, "", 0))
}
