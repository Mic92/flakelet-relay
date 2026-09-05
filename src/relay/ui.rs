//! Server-rendered dashboard under `/ui/`. Login is the OIDC
//! authorization code flow with PKCE against an issuer that has `login`
//! configured; the result is a signed cookie carrying the principals.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use maud::{DOCTYPE, Markup, html};
use ring::digest;
use serde::{Deserialize, Serialize};

use crate::http::{self, Resp};
use crate::oidc;
use crate::proto::{JobState, JobSummary, Status};
use crate::relay::session::{self, cookie, set_cookie};
use crate::relay::state::{HostFlakelet, Relay};

const SESSION: &str = "flr_session";
const LOGIN: &str = "flr_login";
const SESSION_AGE: Duration = Duration::from_hours(12);
const CSS: &str = include_str!("ui.css");

#[derive(Serialize, Deserialize)]
pub struct Session {
    #[serde(rename = "p")]
    pub principals: Vec<String>,
    #[serde(rename = "n")]
    pub name: String,
    #[serde(rename = "e")]
    exp: u64,
}

#[derive(Serialize, Deserialize)]
struct LoginState {
    issuer: String,
    state: String,
    verifier: String,
}

fn now() -> u64 {
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

fn redirect(to: &str) -> Resp {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(hyper::header::LOCATION, to)
        .body(http::Body::empty())
        .expect("static headers")
}

fn page(status: StatusCode, m: &Markup) -> Resp {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        .header("Referrer-Policy", "same-origin")
        .body(m.clone().into_string().into())
        .expect("static headers")
}

fn fail(status: StatusCode, msg: &str) -> Resp {
    page(
        status,
        &layout(
            "",
            None,
            "",
            &html! { main { p.notice { (msg) } p { a href="/ui/login" { "Log in again" } } } },
        ),
    )
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

/// Raw query parameter. All values handled here are URL-safe tokens.
fn query<'a>(req: &'a Request<Incoming>, key: &str) -> Option<&'a str> {
    req.uri().query()?.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then_some(v)
    })
}

pub async fn handle(relay: Arc<Relay>, req: Request<Incoming>) -> Resp {
    let path = &req.uri().path()["/ui/".len()..];
    match (req.method(), path) {
        (&Method::GET, "static/app.css") => Response::builder()
            .header(hyper::header::CONTENT_TYPE, "text/css")
            .header(hyper::header::CACHE_CONTROL, "max-age=300")
            .body(String::from(CSS).into())
            .expect("static headers"),
        (&Method::GET, "login") => login(&relay, &req).await,
        (&Method::GET, "callback") => callback(&relay, &req).await,
        (&Method::POST, "logout") => {
            let mut r = redirect("/ui/login");
            r.headers_mut().insert(
                hyper::header::SET_COOKIE,
                set_cookie(SESSION, "", 0).parse().expect("ascii"),
            );
            r
        }
        (&Method::GET, p) => {
            let Some(sess) = current(&relay, &req) else {
                return redirect("/ui/login");
            };
            match p {
                "" => page(StatusCode::OK, &flakelets_page(&relay, &sess)),
                "hosts" => page(StatusCode::OK, &hosts_page(&relay, &sess)),
                "jobs" => page(StatusCode::OK, &jobs_page(&relay, &sess)),
                _ => fail(StatusCode::NOT_FOUND, "no such page"),
            }
        }
        _ => fail(StatusCode::NOT_FOUND, "no such page"),
    }
}

/// Redirect to the issuer named in `?issuer=`, else the first one with
/// `login` configured.
async fn login(relay: &Relay, req: &Request<Incoming>) -> Resp {
    let wanted = query(req, "issuer");
    let Some((name, cfg, l)) = relay
        .issuers
        .configs()
        .iter()
        .filter(|(n, _)| wanted.is_none_or(|w| w == n.as_str()))
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
    let mut r = redirect(&url);
    r.headers_mut().insert(
        hyper::header::SET_COOKIE,
        set_cookie(LOGIN, &relay.signer.seal(&st), 600)
            .parse()
            .expect("ascii"),
    );
    r
}

async fn callback(relay: &Relay, req: &Request<Incoming>) -> Resp {
    let Some(st) = cookie(req, LOGIN).and_then(|c| relay.signer.open::<LoginState>(c)) else {
        return fail(StatusCode::BAD_REQUEST, "login expired, start over");
    };
    if query(req, "state") != Some(&st.state) {
        return fail(StatusCode::BAD_REQUEST, "state mismatch");
    }
    let Some(code) = query(req, "code") else {
        return fail(
            StatusCode::UNAUTHORIZED,
            query(req, "error").unwrap_or("no code"),
        );
    };
    let identity = match exchange(relay, req, &st, code).await {
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
    let mut r = redirect("/ui/");
    r.headers_mut().append(
        hyper::header::SET_COOKIE,
        set_cookie(SESSION, &relay.signer.seal(&sess), SESSION_AGE.as_secs())
            .parse()
            .expect("ascii"),
    );
    r.headers_mut().append(
        hyper::header::SET_COOKIE,
        set_cookie(LOGIN, "", 0).parse().expect("ascii"),
    );
    r
}

async fn exchange(
    relay: &Relay,
    req: &Request<Incoming>,
    st: &LoginState,
    code: &str,
) -> Result<crate::auth::issuers::Identity, String> {
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

fn layout(name: &str, sess: Option<&Session>, tab: &str, body: &Markup) -> Markup {
    let nav = [("", "Flakelets"), ("hosts", "Hosts"), ("jobs", "Jobs")];
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "flakelet-relay" }
                link rel="stylesheet" href="/ui/static/app.css";
            }
            body {
                a.skip href="#main" { "Skip to content" }
                header.top {
                    h1 { "flakelet-relay " span { (name) } }
                    @if let Some(s) = sess {
                        nav aria-label="Sections" {
                            @for (p, label) in nav {
                                a href={"/ui/" (p)} .on[p == tab] aria-current=[(p == tab).then_some("page")] { (label) }
                            }
                        }
                        form.me method="post" action="/ui/logout" {
                            "Signed in as " b { (s.name) } " "
                            button { "Log out" }
                        }
                    }
                }
                div #main tabindex="-1" { (body) }
            }
        }
    }
}

fn ago(ts: u64) -> String {
    let d = now().saturating_sub(ts);
    match d {
        0..60 => format!("{d}s ago"),
        60..3600 => format!("{}m ago", d / 60),
        3600..86_400 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86_400),
    }
}

/// CSS class and label for one target's state.
fn state_of(state: JobState, status: Option<Status>) -> (&'static str, &'static str) {
    match (state, status) {
        (JobState::Pending, _) => ("running", "pending"),
        (JobState::Running, _) => ("running", "updating"),
        (JobState::Done, Some(s)) => (if s.ok() { "ok" } else { "failed" }, s.as_str()),
        (JobState::Done | JobState::Unknown, _) => ("failed", "unknown"),
    }
}

fn last_state(h: &HostFlakelet) -> (&'static str, &'static str) {
    h.last
        .as_ref()
        .map_or(("never", "never deployed"), |j| state_of(j.state, j.status))
}

fn short_rev(r: &str) -> &str {
    let tail = r.rsplit(['/', ':', '=']).next().unwrap_or(r);
    &tail[..tail.len().min(12)]
}

fn flakelets_page(relay: &Relay, sess: &Session) -> Markup {
    let rows = relay.host_flakelets(&sess.principals);
    let mut by: BTreeMap<&str, Vec<&HostFlakelet>> = BTreeMap::new();
    for r in &rows {
        by.entry(&r.flakelet).or_default().push(r);
    }
    layout(
        &relay.cfg.name,
        Some(sess),
        "",
        &html! { main {
            table {
                caption.sr { "Flakelets across connected hosts" }
                thead { tr {
                    th scope="col" { "Flakelet" }
                    th scope="col" { "Hosts" }
                    th scope="col" { "Revision" }
                    th scope="col" { "Last deploy" }
                    th scope="col" { "Status" }
                } }
                tbody {
                    @if by.is_empty() { tr { td colspan="5" .dim { "No connected host runs a flakelet you may see." } } }
                    @for (name, hosts) in &by {
                        @let last = hosts.iter().filter_map(|h| h.last.as_ref()).max_by_key(|j| j.created);
                        @let revs: std::collections::BTreeSet<_> = hosts.iter().filter_map(|h| h.revision.as_deref()).collect();
                        @let bad = hosts.iter().filter(|h| last_state(h).0 == "failed").count();
                        @let running = hosts.iter().any(|h| last_state(h).0 == "running");
                        @let (cls, label) = if running { ("updating", "updating") }
                            else if bad > 0 { ("degraded", "degraded") }
                            else if revs.len() > 1 { ("drift", "drift") }
                            else { ("healthy", "healthy") };
                        tr {
                            th scope="row" .name { (name) }
                            td {
                                span.sq aria-hidden="true" {
                                    @for h in hosts { span class=(last_state(h).0) title={(h.host) ": " (last_state(h).1)} {} }
                                }
                                (hosts.len() - bad) "/" (hosts.len())
                                span.sr { " hosts ok" }
                            }
                            td.mono {
                                @match revs.len() {
                                    0 => span.faint { "–" },
                                    1 => span title=(revs.first().unwrap()) { (short_rev(revs.first().unwrap())) },
                                    n => span.st.drift { (n) " revisions" },
                                }
                            }
                            td {
                                @if let Some(j) = last {
                                    (ago(j.created))
                                    @if let Some(c) = &j.caller { span.dim { " by " (c.lines().next().unwrap_or_default()) } }
                                } @else { span.faint { "–" } }
                            }
                            td { span class={"pill " (cls)} { (label) } }
                        }
                    }
                }
            }
        } },
    )
}

fn hosts_page(relay: &Relay, sess: &Session) -> Markup {
    let policy = &relay.cfg.policy;
    let agents: Vec<_> = relay
        .agent_infos()
        .into_iter()
        .filter_map(|mut a| {
            a.flakelets.retain(|f| {
                policy
                    .rule_for(&sess.principals, &a.host, &f.name)
                    .is_some()
            });
            (!a.flakelets.is_empty()).then_some(a)
        })
        .collect();
    layout(
        &relay.cfg.name,
        Some(sess),
        "hosts",
        &html! { main {
            table {
                caption.sr { "Connected hosts" }
                thead { tr { th scope="col" { "Host" } th scope="col" { "Agent" } th scope="col" { "Flakelets" } } }
                tbody {
                    @if agents.is_empty() { tr { td colspan="3" .dim { "No connected hosts." } } }
                    @for a in &agents {
                        tr {
                            th scope="row" .name { (a.host) }
                            td.dim { (a.version) }
                            td {
                                @for f in &a.flakelets {
                                    span.tag { (f.name) @if let Some(g) = f.generation { span.faint { "@" (g) } } } " "
                                }
                            }
                        }
                    }
                }
            }
        } },
    )
}

fn jobs_page(relay: &Relay, sess: &Session) -> Markup {
    let jobs: Vec<JobSummary> = relay.job_summaries(&sess.principals);
    layout(
        &relay.cfg.name,
        Some(sess),
        "jobs",
        &html! { main {
            table {
                caption.sr { "Recent deploys, newest first" }
                thead { tr { th scope="col" { "When" } th scope="col" { "Caller" } th scope="col" { "Targets" } th scope="col" { "Id" } } }
                tbody {
                    @if jobs.is_empty() { tr { td colspan="4" .dim { "No deploys recorded." } } }
                    @for j in jobs.iter().take(200) {
                        tr {
                            td { (ago(j.created)) }
                            td.trunc title=(j.caller) { (j.caller.lines().next().unwrap_or_default()) }
                            td.wrap {
                                @for t in &j.targets {
                                    @let (cls, label) = state_of(t.state, t.status);
                                    span class={"pill " (cls)} { (t.target) span.sr { ": " } " " span.l { (label) } } " "
                                }
                            }
                            td.mono.faint { (j.id.get(..8).unwrap_or(&j.id)) }
                        }
                    }
                }
            }
        } },
    )
}
