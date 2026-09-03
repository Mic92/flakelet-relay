use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use flakelet_relay::client::{Client, Url, token_command};
use flakelet_relay::http::{self, Body};
use flakelet_relay::proto::{
    AgentsResponse, ApiError, DeployRequest, Event, Target, Wave, random_id,
};
use flakelet_relay::{oidc, srv, sse, tls};
use http_body_util::BodyExt as _;
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use hyper::{Request, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(
    version,
    about = "Ask relays to run flakelet updates and follow the result"
)]
struct Cli {
    /// Relay base URL, tried in order.
    #[arg(long = "relay", env = "FLAKELET_RELAY", value_delimiter = ',')]
    relays: Vec<String>,
    /// Domain with `_flakelet-relay._tcp` SRV records, appended after --relay.
    #[arg(long, env = "FLAKELET_RELAY_SRV")]
    relay_srv: Option<String>,
    #[arg(long, env = "FLAKELET_RELAY_CA_FILE")]
    ca_file: Option<PathBuf>,
    #[arg(long, requires = "key")]
    cert: Option<PathBuf>,
    #[arg(long, requires = "cert")]
    key: Option<PathBuf>,
    /// Command printing a bearer token.
    #[arg(long, env = "FLAKELET_RELAY_TOKEN_COMMAND", value_delimiter = ' ', num_args = 1..)]
    token_command: Option<Vec<String>>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Log in with the OAuth2 device flow and cache the token for later
    /// calls that have neither a certificate nor a token command.
    Login {
        #[arg(long, env = "FLAKELET_RELAY_ISSUER")]
        issuer: String,
        #[arg(
            long,
            env = "FLAKELET_RELAY_CLIENT_ID",
            default_value = "flakelet-push"
        )]
        client_id: String,
        #[arg(long, default_value = "openid offline_access email groups")]
        scope: String,
    },
    /// Deploy targets; `--wave` separates waves.
    Deploy {
        /// Client id for idempotent retries; random if unset.
        #[arg(long)]
        id: Option<String>,
        /// Abort after this long without any event for a running target.
        #[arg(long, default_value = "300")]
        idle_timeout: u64,
        /// Abort after this long overall.
        #[arg(long, default_value = "3600")]
        max_time: u64,
        /// Exit 0 once the relay accepted the job instead of following it,
        /// for deploys that restart the caller itself.
        #[arg(long)]
        detach: bool,
        /// `host/flakelet`, with `--wave` between waves.
        #[arg(required = true, num_args = 1.., allow_hyphen_values = true)]
        targets: Vec<String>,
    },
    /// List connected agents visible to you.
    Agents,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("flakelet-push: {e}");
            ExitCode::from(2)
        }
    }
}

struct Ctx {
    client: Client,
    relays: Vec<Url>,
    bearer: Option<String>,
}

impl Ctx {
    fn request(
        &self,
        method: hyper::Method,
        url: &Url,
        path: &str,
        body: Body,
    ) -> Result<Request<Body>, String> {
        let mut b = Request::builder()
            .method(method)
            .uri(format!("{}{path}", url.path))
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "text/event-stream, application/json");
        if let Some(t) = &self.bearer {
            b = b.header(AUTHORIZATION, format!("Bearer {t}"));
        }
        b.body(body).map_err(|e| e.to_string())
    }
}

/// What `push login` leaves in `$XDG_STATE_HOME/flakelet-push/token.json`.
#[derive(Serialize, Deserialize)]
struct Saved {
    issuer: String,
    client_id: String,
    token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

fn token_path() -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME").map_or_else(
        || PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/state"),
        PathBuf::from,
    );
    base.join("flakelet-push/token.json")
}

fn exp(token: &str) -> u64 {
    oidc::unverified_claims(token)
        .and_then(|c| c.get("exp")?.as_u64())
        .unwrap_or(0)
}

fn save(saved: &Saved) -> Result<(), String> {
    let path = token_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(&serde_json::to_vec(saved).expect("serializable"))
            .map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Pick the relay's bearer from tokens: the `id_token` is the JWT with
/// `aud = client_id` the relay can verify. Access tokens may be opaque.
fn bearer_of(t: &oidc::Tokens) -> Result<String, String> {
    t.id_token
        .clone()
        .or_else(|| t.access_token.clone())
        .ok_or_else(|| "issuer returned no token".into())
}

/// Cached token from `push login`, refreshed if it expires within a
/// minute and a refresh token is available.
async fn cached_token(client: &Client) -> Result<Option<String>, String> {
    let path = token_path();
    let Ok(data) = std::fs::read(&path) else {
        return Ok(None);
    };
    let mut saved: Saved =
        serde_json::from_slice(&data).map_err(|e| format!("{}: {e}", path.display()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if exp(&saved.token) > now + 60 {
        return Ok(Some(saved.token));
    }
    let Some(rt) = &saved.refresh_token else {
        return Err(format!(
            "token in {} expired, run `flakelet-push login`",
            path.display()
        ));
    };
    let t = oidc::refresh(client, &saved.issuer, &saved.client_id, rt)
        .await
        .map_err(|e| format!("refreshing token: {e}. Run `flakelet-push login`"))?;
    saved.token = bearer_of(&t)?;
    if t.refresh_token.is_some() {
        saved.refresh_token = t.refresh_token;
    }
    save(&saved)?;
    Ok(Some(saved.token))
}

async fn login(
    client: &Client,
    issuer: String,
    client_id: String,
    scope: &str,
) -> Result<(), String> {
    let t = oidc::device_login(client, &issuer, &client_id, scope, |c| {
        let uri = c
            .verification_uri_complete
            .as_deref()
            .unwrap_or(&c.verification_uri);
        eprintln!("Open {uri} and confirm code {}", c.user_code);
    })
    .await?;
    let token = bearer_of(&t)?;
    let who = oidc::unverified_claims(&token)
        .and_then(|c| c.get("email").or(c.get("sub"))?.as_str().map(str::to_owned))
        .unwrap_or_default();
    save(&Saved {
        issuer,
        client_id,
        token,
        refresh_token: t.refresh_token,
    })?;
    eprintln!(
        "Logged in as {who}, token saved to {}",
        token_path().display()
    );
    Ok(())
}

async fn run(cli: Cli) -> Result<bool, String> {
    let identity = cli.cert.as_deref().zip(cli.key.as_deref());
    let client =
        Client::new(tls::client(cli.ca_file.as_deref(), identity).map_err(|e| e.to_string())?);
    let mut relays = cli
        .relays
        .iter()
        .map(|r| Url::parse(r))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    if let Some(domain) = &cli.relay_srv {
        relays.extend(srv::relays(domain).await?.0);
    }
    if let Cmd::Login {
        issuer,
        client_id,
        scope,
    } = cli.cmd
    {
        return login(&client, issuer, client_id, &scope)
            .await
            .map(|()| true);
    }
    let bearer = match &cli.token_command {
        Some(cmd) => Some(token_command(cmd)?),
        None if cli.cert.is_none() => cached_token(&client).await?,
        None => None,
    };
    let ctx = Ctx {
        client,
        relays,
        bearer,
    };
    match cli.cmd {
        Cmd::Login { .. } => unreachable!(),
        Cmd::Agents => agents(&ctx).await.map(|()| true),
        Cmd::Deploy {
            id,
            idle_timeout,
            max_time,
            detach,
            targets,
        } => {
            let id = id.unwrap_or_else(random_id);
            let waves = parse_waves(&targets)?;
            let req = DeployRequest {
                id,
                waves,
                options: std::collections::BTreeMap::new(),
            };
            tokio::time::timeout(
                Duration::from_secs(max_time),
                deploy(&ctx, &req, Duration::from_secs(idle_timeout), detach),
            )
            .await
            .unwrap_or_else(|_| Err(format!("no result after {max_time}s")))
        }
    }
}

fn parse_waves(args: &[String]) -> Result<Vec<Wave>, String> {
    let mut waves = vec![Wave {
        targets: Vec::new(),
    }];
    for a in args {
        if a == "--wave" {
            waves.push(Wave {
                targets: Vec::new(),
            });
        } else if a.starts_with('-') {
            return Err(format!("unexpected flag {a}"));
        } else {
            let t = Target { target: a.clone() };
            if t.split().is_none() {
                return Err(format!("{a}: expected host/flakelet"));
            }
            waves.last_mut().expect("nonempty").targets.push(t);
        }
    }
    waves.retain(|w| !w.targets.is_empty());
    if waves.is_empty() {
        return Err("no targets".into());
    }
    Ok(waves)
}

async fn agents(ctx: &Ctx) -> Result<(), String> {
    let body = open(ctx, |url| {
        ctx.request(hyper::Method::GET, url, "/v1/agents", Body::empty())
    })
    .await?;
    let body = http::read_body(body, 1 << 20)
        .await
        .map_err(|_| "reading agents")?;
    let a: AgentsResponse = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    for agent in a.agents {
        let names: Vec<_> = agent.flakelets.into_iter().map(|f| f.name).collect();
        println!("{}\t{}\t{}", agent.host, agent.version, names.join(","));
    }
    Ok(())
}

fn api_error(status: StatusCode, body: &[u8]) -> String {
    match serde_json::from_slice::<ApiError>(body) {
        Ok(e) if e.targets.is_empty() => format!("{status}: {}: {}", e.code, e.message),
        Ok(e) => {
            let t: Vec<_> = e.targets.into_iter().map(|t| t.target).collect();
            format!("{status}: {}: {} ({})", e.code, e.message, t.join(", "))
        }
        Err(_) => format!("{status}: {}", String::from_utf8_lossy(body).trim()),
    }
}

enum Followed {
    Result(bool),
    /// The stream broke after it was accepted. Worth resuming elsewhere.
    Lost(String),
}

/// POST the deploy, follow the stream, and if a relay dies mid-stream
/// resume via `GET /v1/jobs/<id>` on whichever relay answers.
async fn deploy(
    ctx: &Ctx,
    dr: &DeployRequest,
    idle: Duration,
    detach: bool,
) -> Result<bool, String> {
    let payload = serde_json::to_string(dr).expect("serializable");
    let path = format!("/v1/jobs/{}", dr.id);
    let mut printer = Printer {
        detach,
        ..Default::default()
    };
    let mut first = true;
    loop {
        let body = open(ctx, |url| {
            if first {
                ctx.request(
                    hyper::Method::POST,
                    url,
                    "/v1/deploy",
                    payload.clone().into(),
                )
            } else {
                ctx.request(hyper::Method::GET, url, &path, Body::empty())
            }
        })
        .await?;
        first = false;
        match follow(body, idle, &mut printer).await? {
            Followed::Result(ok) => return Ok(ok),
            Followed::Lost(reason) => {
                eprintln!("flakelet-push: {reason}, resuming job {}", dr.id);
            }
        }
    }
}

/// Try each relay in turn, and the whole list again with backoff for up
/// to 30 s while errors are transient: relay unreachable, 503 (agent not
/// connected there right now) or `unknown_job` on resume (agent not back
/// yet) are all expected shortly after a restart on either side.
async fn open(
    ctx: &Ctx,
    request: impl Fn(&Url) -> Result<Request<Body>, String>,
) -> Result<hyper::body::Incoming, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut backoff = Duration::from_secs(1);
    let mut last = String::from("no relays");
    loop {
        for url in &ctx.relays {
            let resp = match ctx.client.send(url, request(url)?).await {
                Ok(r) => r,
                Err(e) => {
                    last = format!("{url}: {e}");
                    continue;
                }
            };
            let status = resp.status();
            if status.is_success() {
                return Ok(resp.into_body());
            }
            let body = http::read_body(resp.into_body(), 1 << 16)
                .await
                .unwrap_or_default();
            let code = serde_json::from_slice::<ApiError>(&body).map(|e| e.code);
            last = format!("{url}: {}", api_error(status, &body));
            let transient =
                status == StatusCode::SERVICE_UNAVAILABLE || code.is_ok_and(|c| c == "unknown_job");
            if !transient {
                return Err(last);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(last);
        }
        eprintln!("flakelet-push: {last}, retrying in {}s", backoff.as_secs());
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(8));
    }
}

/// Renders events and remembers what was shown so a resumed stream does
/// not repeat lines.
#[derive(Default)]
struct Printer {
    /// Report success as soon as the first wave started.
    detach: bool,
    seen: std::collections::HashMap<String, u64>,
    done: std::collections::HashSet<String>,
}

impl Printer {
    /// `Some(ok)` once the result arrived.
    fn print(&mut self, ev: Event) -> Option<bool> {
        let mut out = std::io::stderr().lock();
        match ev {
            Event::Accepted { job, relay, agents } => {
                let a: Vec<_> = agents
                    .iter()
                    .map(|a| format!("{} {}", a.host, a.version))
                    .collect();
                let _ = writeln!(
                    out,
                    "» job {job} via {} {} (agents: {})",
                    relay.name,
                    relay.version,
                    a.join(", ")
                );
            }
            Event::Wave { index } => {
                let _ = writeln!(out, "» wave {index}");
                if self.detach {
                    let _ = writeln!(out, "» detached, not waiting for the result");
                    return Some(true);
                }
            }
            Event::Log { target, seq, line } => {
                let seen = self.seen.entry(target.clone()).or_default();
                if seq == 0 || seq > *seen {
                    *seen = (*seen).max(seq);
                    let _ = writeln!(out, "{target} | {line}");
                }
            }
            Event::Progress { .. } | Event::Unknown => {}
            Event::Done { target, body } => {
                if self.done.insert(target.clone()) {
                    let g = body
                        .generation
                        .map(|g| format!(" (generation {g})"))
                        .unwrap_or_default();
                    let _ = writeln!(out, "» {target}: {}{g}", body.status.as_str());
                    for l in body.tail.unwrap_or_default() {
                        let _ = writeln!(out, "{target} │ {}", l.line);
                    }
                }
            }
            Event::Result {
                ok,
                targets: _,
                skipped,
            } => {
                if !skipped.is_empty() {
                    let s: Vec<_> = skipped.into_iter().map(|t| t.target).collect();
                    let _ = writeln!(out, "» skipped: {}", s.join(", "));
                }
                let _ = writeln!(out, "» {}", if ok { "ok" } else { "failed" });
                return Some(ok);
            }
        }
        None
    }
}

/// `Err` only for the idle timeout, which no other relay can fix.
async fn follow(
    mut body: hyper::body::Incoming,
    idle: Duration,
    printer: &mut Printer,
) -> Result<Followed, String> {
    let mut parser = sse::Parser::default();
    loop {
        let frame = match tokio::time::timeout(idle, body.frame()).await {
            Err(_) => return Err(format!("no event for {}s", idle.as_secs())),
            Ok(None) => return Ok(Followed::Lost("stream ended without result".into())),
            Ok(Some(Err(e))) => return Ok(Followed::Lost(format!("stream: {e}"))),
            Ok(Some(Ok(f))) => f,
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        for ev in parser.push(&data) {
            if let Some(ok) = printer.print(ev) {
                return Ok(Followed::Result(ok));
            }
        }
    }
}
