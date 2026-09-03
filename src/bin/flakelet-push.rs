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
use flakelet_relay::{sse, tls};
use http_body_util::BodyExt as _;
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use hyper::{Request, StatusCode};

#[derive(Parser)]
#[command(
    version,
    about = "Ask relays to run flakelet updates and follow the result"
)]
struct Cli {
    /// Relay base URL, tried in order.
    #[arg(
        long = "relay",
        required = true,
        env = "FLAKELET_RELAY",
        value_delimiter = ','
    )]
    relays: Vec<String>,
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
        Ok(ok) => {
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("flakelet-push: {e}");
            ExitCode::from(2)
        }
    }
}

struct Ctx {
    client: Client,
    relays: Vec<Url>,
    token_command: Option<Vec<String>>,
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
        if let Some(cmd) = &self.token_command {
            b = b.header(AUTHORIZATION, format!("Bearer {}", token_command(cmd)?));
        }
        b.body(body).map_err(|e| e.to_string())
    }
}

async fn run(cli: Cli) -> Result<bool, String> {
    let identity = cli.cert.as_deref().zip(cli.key.as_deref());
    let client =
        Client::new(tls::client(cli.ca_file.as_deref(), identity).map_err(|e| e.to_string())?);
    let relays = cli
        .relays
        .iter()
        .map(|r| Url::parse(r))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let ctx = Ctx {
        client,
        relays,
        token_command: cli.token_command,
    };
    match cli.cmd {
        Cmd::Agents => agents(&ctx).await.map(|()| true),
        Cmd::Deploy {
            id,
            idle_timeout,
            max_time,
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
                deploy(&ctx, &req, Duration::from_secs(idle_timeout)),
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
    let mut last = String::from("no relays");
    for url in &ctx.relays {
        let req = ctx.request(hyper::Method::GET, url, "/v1/agents", Body::empty())?;
        let resp = match ctx.client.send(url, req).await {
            Ok(r) => r,
            Err(e) => {
                last = format!("{url}: {e}");
                eprintln!("flakelet-push: {last}");
                continue;
            }
        };
        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes();
        if !status.is_success() {
            return Err(api_error(status, &body));
        }
        let a: AgentsResponse = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        for agent in a.agents {
            let names: Vec<_> = agent.flakelets.into_iter().map(|f| f.name).collect();
            println!("{}\t{}\t{}", agent.host, agent.version, names.join(","));
        }
        return Ok(());
    }
    Err(last)
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

/// Try relays in order. 503 means the agent is not connected to this
/// relay right now, which is expected for a short while after either
/// side restarted, so it is retried with exponential backoff for 30 s
/// before moving on. Everything else is final.
async fn deploy(ctx: &Ctx, dr: &DeployRequest, idle: Duration) -> Result<bool, String> {
    let payload = serde_json::to_string(dr).expect("serializable");
    let mut last = String::from("no relays");
    for url in &ctx.relays {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut backoff = Duration::from_secs(1);
        loop {
            let req = ctx.request(
                hyper::Method::POST,
                url,
                "/v1/deploy",
                payload.clone().into(),
            )?;
            let resp = match ctx.client.send(url, req).await {
                Ok(r) => r,
                Err(e) => {
                    last = format!("{url}: {e}");
                    eprintln!("flakelet-push: {last}");
                    break;
                }
            };
            let status = resp.status();
            if status.is_success() {
                return follow(resp.into_body(), idle).await;
            }
            let body = http::read_body(resp.into_body(), 1 << 16)
                .await
                .unwrap_or_default();
            last = format!("{url}: {}", api_error(status, &body));
            if status != StatusCode::SERVICE_UNAVAILABLE {
                return Err(last);
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            eprintln!("flakelet-push: {last}, retrying in {}s", backoff.as_secs());
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(8));
        }
    }
    Err(last)
}

async fn follow(mut body: hyper::body::Incoming, idle: Duration) -> Result<bool, String> {
    let mut parser = sse::Parser::default();
    let mut out = std::io::stderr().lock();
    loop {
        let frame = match tokio::time::timeout(idle, body.frame()).await {
            Err(_) => return Err(format!("no event for {}s", idle.as_secs())),
            Ok(None) => return Err("stream ended without result".into()),
            Ok(Some(Err(e))) => return Err(format!("stream: {e}")),
            Ok(Some(Ok(f))) => f,
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        for ev in parser.push(&data) {
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
                }
                Event::Log { target, line, .. } => {
                    let _ = writeln!(out, "{target} | {line}");
                }
                Event::Progress { .. } | Event::Unknown => {}
                Event::Done { target, body } => {
                    let g = body
                        .generation
                        .map(|g| format!(" (generation {g})"))
                        .unwrap_or_default();
                    let _ = writeln!(out, "» {target}: {}{g}", body.status.as_str());
                    for l in body.tail.unwrap_or_default() {
                        let _ = writeln!(out, "{target} │ {}", l.line);
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
                    return Ok(ok);
                }
            }
        }
    }
}
