//! Client-facing endpoints: deploy, agents, metrics.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use tokio::sync::mpsc;

use crate::http::{self, Body, Resp};
use crate::proto::{
    AgentsResponse, ApiError, DeployRequest, DoneBody, Event, Frame, RelayInfo, Status, Target,
    TargetStatus, job_id,
};
use crate::relay::agent_conn;
use crate::relay::state::{Outgoing, Relay, Sub};
use crate::{proto, sse};

/// `peer` are the principals proven by the transport (client cert SANs).
pub async fn handle(relay: Arc<Relay>, peer: Vec<String>, req: Request<Incoming>) -> Resp {
    let r = match (req.method(), req.uri().path()) {
        (&Method::GET, "/v1/agent") => agent_conn::upgrade(relay, peer, req).await,
        (&Method::POST, "/v1/deploy") => deploy(relay, peer, req).await,
        (&Method::GET, "/v1/agents") => agents(&relay, peer, &req).await,
        (&Method::GET, "/metrics") => Ok(http::text(StatusCode::OK, relay.metrics())),
        (&Method::GET, "/health") => Ok(http::text(StatusCode::OK, String::from("ok\n"))),
        _ => Err(http::error(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such endpoint",
        )),
    };
    r.unwrap_or_else(|e| e)
}

/// Transport principals plus those from a bearer token. Empty is 401.
pub async fn authenticate(
    relay: &Relay,
    mut principals: Vec<String>,
    req: &Request<Incoming>,
) -> Result<Vec<String>, Resp> {
    let mut reason = String::from("no credentials");
    if let Some(tok) = http::bearer(req) {
        match relay.issuers.authenticate(tok).await {
            Ok(p) => principals.extend(p),
            Err(e) => {
                tracing::info!("bearer rejected: {e}");
                reason = e;
            }
        }
    }
    if principals.is_empty() {
        return Err(http::error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            reason,
        ));
    }
    principals.sort();
    principals.dedup();
    Ok(principals)
}

async fn agents(relay: &Relay, peer: Vec<String>, req: &Request<Incoming>) -> Result<Resp, Resp> {
    let principals = authenticate(relay, peer, req).await?;
    let policy = &relay.cfg.policy;
    let agents = relay
        .agent_infos()
        .into_iter()
        .filter_map(|mut a| {
            a.flakelets
                .retain(|f| policy.rule_for(&principals, &a.host, &f.name).is_some());
            (!a.flakelets.is_empty()).then_some(a)
        })
        .collect();
    Ok(http::json(StatusCode::OK, &AgentsResponse { agents }))
}

struct Planned {
    target: String,
    host: String,
    flakelet: String,
    rule: String,
}

fn api_error(code: &str, message: &str, targets: &[&Planned]) -> ApiError {
    let targets = targets
        .iter()
        .map(|p| Target {
            target: p.target.clone(),
        })
        .collect();
    ApiError {
        code: code.into(),
        message: message.into(),
        targets,
    }
}

type Check = (
    StatusCode,
    &'static str,
    &'static str,
    Option<&'static str>,
    fn(&Relay, &Planned) -> bool,
);

/// Per-target checks in order. The first one any target fails rejects
/// the whole request with that class. Policy comes before existence so
/// callers cannot probe for host names.
const CHECKS: [Check; 4] = [
    (
        StatusCode::BAD_REQUEST,
        "bad_target",
        "targets must be host/flakelet",
        None,
        |_, p| p.host.is_empty(),
    ),
    (
        StatusCode::FORBIDDEN,
        "target_denied",
        "not allowed by policy",
        Some("denied"),
        |_, p| p.rule.is_empty(),
    ),
    (
        StatusCode::NOT_FOUND,
        "unknown_host",
        "no such host in relay configuration",
        None,
        |r, p| !r.cfg.policy.agents.contains_key(&p.host),
    ),
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "agent_unavailable",
        "agent not connected or flakelet not advertised",
        Some("unavailable"),
        |r, p| !r.has_flakelet(&p.host, &p.flakelet),
    ),
];

fn plan(
    relay: &Relay,
    principals: &[String],
    dr: &DeployRequest,
) -> Result<Vec<Vec<Planned>>, (StatusCode, ApiError)> {
    if dr.id.is_empty() || dr.waves.iter().all(|w| w.targets.is_empty()) {
        return Err((
            StatusCode::BAD_REQUEST,
            api_error("bad_request", "id and targets required", &[]),
        ));
    }
    if let Some(k) = dr.options.keys().next() {
        let msg = format!("no agent supports option {k}");
        return Err((
            StatusCode::BAD_REQUEST,
            api_error("unsupported_option", &msg, &[]),
        ));
    }
    let waves: Vec<Vec<Planned>> = dr
        .waves
        .iter()
        .map(|w| {
            w.targets
                .iter()
                .map(|t| {
                    let (host, flakelet) = t.split().unwrap_or(("", ""));
                    let rule = relay
                        .cfg
                        .policy
                        .rule_for(principals, host, flakelet)
                        .unwrap_or("");
                    Planned {
                        target: t.target.clone(),
                        host: host.into(),
                        flakelet: flakelet.into(),
                        rule: rule.into(),
                    }
                })
                .collect()
        })
        .collect();
    for (status, code, message, metric, failed) in CHECKS {
        let hit: Vec<_> = waves
            .iter()
            .flatten()
            .filter(|p| failed(relay, p))
            .collect();
        if hit.is_empty() {
            continue;
        }
        if let Some(m) = metric {
            for p in &hit {
                relay.count_deploy(&p.rule, &p.host, &p.flakelet, m);
            }
        }
        return Err((status, api_error(code, message, &hit)));
    }
    Ok(waves)
}

async fn deploy(
    relay: Arc<Relay>,
    peer: Vec<String>,
    req: Request<Incoming>,
) -> Result<Resp, Resp> {
    let principals = authenticate(&relay, peer, &req).await?;
    let body = http::read_body(req.into_body(), 64 << 10).await?;
    let dr: DeployRequest = serde_json::from_slice(&body)
        .map_err(|e| http::error(StatusCode::BAD_REQUEST, "bad_request", e.to_string()))?;
    let waves = plan(&relay, &principals, &dr).map_err(|(s, e)| http::json(s, &e))?;

    let caller = principals.join("\n");
    let job = job_id(&caller, &dr.id);
    tracing::info!(job, caller, targets = ?waves.iter().flatten().map(|p| &p.target).collect::<Vec<_>>(), "deploy accepted");
    let mut agents = relay.agent_infos();
    agents.retain(|a| waves.iter().flatten().any(|p| p.host == a.host));
    for a in &mut agents {
        a.flakelets.clear();
    }
    let accepted = Event::Accepted {
        job: job.clone(),
        relay: RelayInfo {
            name: relay.cfg.name.clone(),
            version: proto::VERSION.into(),
            capabilities: Vec::new(),
        },
        agents,
    };
    let (tx, body) = Body::channel(64);
    tokio::spawn(run_job(relay, job, waves, tx, accepted));
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/event-stream")
        .header(hyper::header::CACHE_CONTROL, "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(body)
        .expect("static headers"))
}

/// Per-target id sent to the agent. Derived from the job so `/v1/jobs`
/// can recompute it, distinct per flakelet so one host running two
/// targets of the same job does not dedup them into one.
fn agent_job_id(job: &str, target: &str) -> String {
    job_id(job, target)
}

async fn run_job(
    relay: Arc<Relay>,
    job: String,
    waves: Vec<Vec<Planned>>,
    tx: mpsc::Sender<Bytes>,
    accepted: Event,
) {
    let out = |ev: Event| {
        let tx = tx.clone();
        async move { tx.send(Bytes::from(sse::encode(&ev))).await.is_ok() }
    };
    if !out(accepted).await {
        return;
    }
    let mut results: Vec<TargetStatus> = Vec::new();
    let mut skipped: Vec<Target> = Vec::new();
    let mut ok = true;
    for (index, wave) in waves.into_iter().enumerate() {
        if !ok {
            skipped.extend(wave.into_iter().map(|p| Target { target: p.target }));
            continue;
        }
        if !out(Event::Wave { index }).await {
            return;
        }
        let Some(statuses) = run_wave(&relay, &job, &wave, &out).await else {
            return;
        };
        ok = statuses.iter().all(|t| t.status.ok());
        results.extend(statuses);
    }
    tracing::info!(job, ok, "deploy finished");
    let _ = out(Event::Result {
        ok,
        targets: results,
        skipped,
    })
    .await;
}

/// Start every target of the wave and forward frames until each has a
/// result. `None` if the client went away.
async fn run_wave<F, Fut>(
    relay: &Relay,
    job: &str,
    wave: &[Planned],
    out: &F,
) -> Option<Vec<TargetStatus>>
where
    F: Fn(Event) -> Fut,
    Fut: Future<Output = bool>,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<(usize, Frame)>();
    let refused = |i: usize, reason: &str| {
        let ack = Frame::Ack {
            id: String::new(),
            accepted: false,
            reason: Some(reason.into()),
        };
        let _ = tx.send((i, ack));
    };
    for (i, p) in wave.iter().enumerate() {
        let id = agent_job_id(job, &p.target);
        let start = Frame::Start {
            id: id.clone(),
            flakelet: p.flakelet.clone(),
            rule: p.rule.clone(),
            options: BTreeMap::default(),
        };
        let sub = Sub {
            index: i,
            tx: tx.clone(),
            start: start.clone(),
        };
        relay.subscribe(&p.host, &id, sub);
        match relay.agent_tx(&p.host) {
            Some(a) if a.send(Outgoing::Frame(start)).await.is_ok() => {}
            _ => refused(i, "agent connection lost"),
        }
    }
    let unsubscribe = |p: &Planned| relay.unsubscribe(&p.host, &agent_job_id(job, &p.target));
    let mut statuses = Vec::new();
    // Highest seq forwarded per target. A reconnecting agent replays from
    // the beginning and the client should not see lines twice.
    let mut seen = vec![0u64; wave.len()];
    while statuses.len() < wave.len() {
        let (i, frame) = rx.recv().await.expect("we hold a sender");
        let p = &wave[i];
        let target = p.target.clone();
        let mut events = Vec::new();
        let done = match frame {
            Frame::Log { seq, line, .. } => {
                if seq > seen[i] {
                    seen[i] = seq;
                    events.push(Event::Log { target, seq, line });
                }
                None
            }
            Frame::Progress { .. } => {
                events.push(Event::Progress { target });
                None
            }
            Frame::Done { body, .. } => Some(body),
            Frame::Ack {
                accepted: false,
                reason,
                ..
            } => {
                let line = format!("agent refused: {}", reason.unwrap_or_default());
                events.push(Event::Log {
                    target,
                    seq: 0,
                    line,
                });
                Some(DoneBody {
                    status: Status::Failed,
                    ..Default::default()
                })
            }
            _ => None,
        };
        if let Some(body) = done {
            unsubscribe(p);
            relay.count_deploy(&p.rule, &p.host, &p.flakelet, body.status.as_str());
            statuses.push(TargetStatus {
                target: p.target.clone(),
                status: body.status,
            });
            events.push(Event::Done {
                target: p.target.clone(),
                body,
            });
        }
        for ev in events {
            if !out(ev).await {
                wave.iter().for_each(unsubscribe);
                return None;
            }
        }
    }
    Some(statuses)
}
